use crate::config::{AttestationMode, Config};
use crate::AppState;
use coop_attestation::{
    build_statement_from_receipt_json, bytes_to_hex, encode_public_key_pem, key_id,
    read_private_key_file, sign_statement, verify_attestation, ArtifactDigest, SigningKey,
    SubjectArtifact, VerificationPolicy,
};
use coop_store::{AttestationSourceJob, PersistAttestationOutcome, Store};
use serde::Serialize;
#[cfg(test)]
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub const RESULT_ARTIFACT_MEDIA_TYPE: &str = "application/vnd.coop.execution-result.v1+json";
pub const DSSE_ENVELOPE_MEDIA_TYPE: &str = "application/vnd.dsse.envelope.v1+json";
const RESULT_ARTIFACT_TYPE: &str =
    // Immutable v1 wire identity. The repository rename must not invalidate
    // existing result artifacts or signed evidence.
    "https://github.com/sambai-dev/coop/blob/main/docs/api.md#execution-result-artifact-v1";
const OUTBOX_PAGE: i64 = 32;
const IDLE_POLL: Duration = Duration::from_millis(250);
const ERROR_POLL: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct AttestationService {
    signing_key: Option<Arc<SigningKey>>,
    key_id: Option<Arc<str>>,
    public_key_pem: Option<Arc<str>>,
}

impl AttestationService {
    pub fn from_config(config: &Config) -> Result<Self, String> {
        match config.attestation_mode {
            AttestationMode::Off => Ok(Self {
                signing_key: None,
                key_id: None,
                public_key_pem: None,
            }),
            AttestationMode::Sign => {
                let path = config.attestation_key_file.as_deref().ok_or_else(|| {
                    "attestation signing mode has no configured private key".to_string()
                })?;
                let signing_key = read_private_key_file(Path::new(path))
                    .map_err(|error| format!("failed to load attestation signing key: {error}"))?;
                let verifying_key = signing_key.verifying_key();
                let derived_key_id = key_id(&verifying_key);
                let public_key_pem = encode_public_key_pem(&verifying_key)
                    .map_err(|error| format!("failed to encode attestation public key: {error}"))?;
                Ok(Self {
                    signing_key: Some(Arc::new(signing_key)),
                    key_id: Some(Arc::from(derived_key_id)),
                    public_key_pem: Some(Arc::from(public_key_pem)),
                })
            }
        }
    }

    pub fn enabled(&self) -> bool {
        self.signing_key.is_some()
    }

    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    pub fn public_key_pem(&self) -> Option<&str> {
        self.public_key_pem.as_deref()
    }

    pub async fn process_pending_once(&self, store: &Store) -> Result<ProcessReport, String> {
        let job_ids = store
            .pending_attestation_job_ids(OUTBOX_PAGE)
            .await
            .map_err(|error| format!("load attestation outbox: {error}"))?;
        let mut report = ProcessReport {
            observed: job_ids.len(),
            ..ProcessReport::default()
        };
        for job_id in job_ids {
            let result = if self.enabled() {
                self.sign_one(store, &job_id).await
            } else {
                store
                    .waive_pending_attestation(&job_id)
                    .await
                    .map(|_| ())
                    .map_err(|error| format!("waive attestation under off policy: {error}"))
            };
            match result {
                Ok(()) => report.completed += 1,
                Err(error) => {
                    report.failed += 1;
                    if let Err(defer_error) = store.defer_pending_attestation(&job_id, 1_000).await
                    {
                        tracing::warn!(
                            job_id,
                            error = %error,
                            defer_error = %defer_error,
                            "durable attestation work remains pending and retry scheduling failed"
                        );
                    } else {
                        tracing::warn!(job_id, error = %error, "durable attestation work remains pending");
                    }
                }
            }
        }
        Ok(report)
    }

    async fn sign_one(&self, store: &Store, job_id: &str) -> Result<(), String> {
        let source = match store
            .attestation_source(job_id)
            .await
            .map_err(|error| format!("load terminal attestation source: {error}"))?
        {
            Some(source) => source,
            None => return Ok(()),
        };
        let events = store
            .events_for(job_id)
            .await
            .map_err(|error| format!("load terminal result events: {error}"))?;
        let artifact = result_artifact_bytes(&source, &events)?;
        let result_digest = ArtifactDigest::from_bytes(&artifact);
        let subject_name = format!("coop://jobs/{job_id}/result");
        let subject = SubjectArtifact::from_digest(
            &subject_name,
            RESULT_ARTIFACT_MEDIA_TYPE,
            result_digest.clone(),
        )
        .map_err(|error| format!("build attestation subject: {error}"))?;
        let receipt: Value = serde_json::from_str(&source.receipt_json)
            .map_err(|error| format!("parse terminal receipt: {error}"))?;
        let receipt_sha256 = receipt
            .get("receipt_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| "terminal receipt has no receipt_sha256".to_string())?;
        if coop_store::compute_receipt_sha256(&receipt) != receipt_sha256 {
            return Err("terminal receipt integrity digest does not match".to_string());
        }
        let statement = build_statement_from_receipt_json(
            &source.tenant,
            job_id,
            &subject,
            source.receipt_json.as_bytes(),
        )
        .map_err(|error| format!("build in-toto execution statement: {error}"))?;
        let signing_key = self
            .signing_key
            .as_deref()
            .ok_or_else(|| "attestation signer is disabled".to_string())?;
        let envelope = sign_statement(&statement, &[signing_key])
            .map_err(|error| format!("sign DSSE execution statement: {error}"))?;
        let envelope_json = envelope
            .to_json_bytes()
            .map_err(|error| format!("encode DSSE envelope: {error}"))?;
        let verifying_key = signing_key.verifying_key();
        verify_attestation(
            &envelope_json,
            &result_digest,
            &[verifying_key],
            &VerificationPolicy::default()
                .with_tenant(&source.tenant)
                .with_subject_name(&subject_name)
                .with_media_type(RESULT_ARTIFACT_MEDIA_TYPE),
        )
        .map_err(|error| format!("self-verify DSSE envelope: {error}"))?;
        let result_sha256 = sha256_hex(&artifact);
        let envelope_sha256 = sha256_hex(&envelope_json);
        let key_id = self
            .key_id()
            .ok_or_else(|| "attestation key id is unavailable".to_string())?;
        match store
            .persist_attestation(
                job_id,
                &source.receipt_json,
                receipt_sha256,
                RESULT_ARTIFACT_MEDIA_TYPE,
                &artifact,
                &result_sha256,
                &envelope_json,
                &envelope_sha256,
                key_id,
            )
            .await
            .map_err(|error| format!("persist immutable execution attestation: {error}"))?
        {
            PersistAttestationOutcome::Created | PersistAttestationOutcome::Existing => Ok(()),
            PersistAttestationOutcome::StaleReceipt => {
                Err("terminal receipt changed before attestation persistence".to_string())
            }
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProcessReport {
    pub observed: usize,
    pub completed: usize,
    pub failed: usize,
}

#[derive(Serialize)]
struct ResultArtifactV1<'a> {
    #[serde(rename = "_type")]
    artifact_type: &'static str,
    schema_version: u32,
    job_id: &'a str,
    tenant: &'a str,
    status: &'a str,
    exit_code: Option<i32>,
    created_at_ms: i64,
    started_at_ms: Option<i64>,
    finished_at_ms: i64,
    duration_ms: Option<i64>,
    receipt_sha256: &'a str,
    stdout: String,
    stderr: String,
    truncated: bool,
    violations: Vec<Value>,
}

fn result_artifact_bytes(
    source: &AttestationSourceJob,
    events: &[coop_store::EventRow],
) -> Result<Vec<u8>, String> {
    let receipt: Value = serde_json::from_str(&source.receipt_json)
        .map_err(|error| format!("parse terminal receipt: {error}"))?;
    let receipt_sha256 = receipt
        .get("receipt_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "terminal receipt has no receipt_sha256".to_string())?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut truncated = false;
    let mut violations = Vec::new();
    for event in events {
        match event.kind.as_str() {
            "stdout" | "stderr" => {
                if let Some(line) = event.data.get("line").and_then(Value::as_str) {
                    if event.kind == "stdout" {
                        stdout.push(line);
                    } else {
                        stderr.push(line);
                    }
                }
            }
            "truncated" => truncated = true,
            "violation" => violations.push(event.data.clone()),
            _ => {}
        }
    }
    let artifact = serde_json::to_value(ResultArtifactV1 {
        artifact_type: RESULT_ARTIFACT_TYPE,
        schema_version: 1,
        job_id: &source.job_id,
        tenant: &source.tenant,
        status: &source.status,
        exit_code: source.exit_code,
        created_at_ms: source.created_at_ms,
        started_at_ms: source.started_at_ms,
        finished_at_ms: source.finished_at_ms,
        duration_ms: source
            .started_at_ms
            .map(|started| source.finished_at_ms.saturating_sub(started)),
        receipt_sha256,
        stdout: stdout.join("\n"),
        stderr: stderr.join("\n"),
        truncated,
        violations,
    })
    .map_err(|error| format!("encode terminal result artifact: {error}"))?;
    let bytes = coop_store::canonical_json(&artifact).into_bytes();
    if bytes.len() > coop_store::MAX_RESULT_ARTIFACT_BYTES {
        return Err(format!(
            "terminal result artifact exceeds {} bytes",
            coop_store::MAX_RESULT_ARTIFACT_BYTES
        ));
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    bytes_to_hex(Sha256::digest(bytes).as_slice())
}

pub fn spawn_worker(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut shutdown = state.shutdown.subscribe();
        loop {
            if *shutdown.borrow() {
                return;
            }
            let delay = match state
                .attestations
                .process_pending_once(state.store.as_ref())
                .await
            {
                Ok(report) if report.observed == OUTBOX_PAGE as usize => Duration::ZERO,
                Ok(report) if report.failed != 0 => ERROR_POLL,
                Ok(_) => IDLE_POLL,
                Err(error) => {
                    tracing::warn!(error = %error, "could not poll durable attestation outbox");
                    ERROR_POLL
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown.wait_for(|value| *value) => return,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service(seed: u8) -> AttestationService {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = signing_key.verifying_key();
        AttestationService {
            signing_key: Some(Arc::new(signing_key)),
            key_id: Some(Arc::from(key_id(&verifying_key))),
            public_key_pem: Some(Arc::from(encode_public_key_pem(&verifying_key).unwrap())),
        }
    }

    fn test_db(label: &str) -> std::path::PathBuf {
        std::env::temp_dir()
            .join(format!("coop-attestation-{label}-{}", uuid::Uuid::now_v7()))
            .join("coop.db")
    }

    #[test]
    fn result_artifact_is_canonical_and_deterministic() {
        let source = AttestationSourceJob {
            job_id: "job-1".to_string(),
            tenant: "tenant-a".to_string(),
            status: "succeeded".to_string(),
            created_at_ms: 1,
            started_at_ms: Some(2),
            finished_at_ms: 5,
            exit_code: Some(0),
            receipt_json: concat!(
                "{\"job_id\":\"job-1\",\"receipt_sha256\":",
                "\"4c1348e14ac12d93ef90c93dd5ae31441480587630d5ea88b0e0832b873ebbd8\"}"
            )
            .to_string(),
        };
        let events = vec![coop_store::EventRow {
            seq: 1,
            ts_ms: 2,
            kind: "stdout".to_string(),
            data: json!({"line":"hello"}),
            prev_hash: String::new(),
            event_hash: "a".repeat(64),
            hash_version: 1,
        }];
        let first = result_artifact_bytes(&source, &events).unwrap();
        let second = result_artifact_bytes(&source, &events).unwrap();
        assert_eq!(first, second);
        assert!(std::str::from_utf8(&first)
            .unwrap()
            .starts_with("{\"_type\""));
        let artifact: Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(artifact["tenant"], "tenant-a");
    }

    #[tokio::test]
    async fn signer_backfills_exact_verifiable_bytes_after_restart_for_every_terminal_path() {
        let db = test_db("restart");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job_with_event(
                "queued-cancel",
                "tenant-a",
                "python",
                r#"{"language":"python","code":"print(1)"}"#,
            )
            .await
            .unwrap();
        store
            .cancel_queued_with_event(
                "queued-cancel",
                "tenant-a",
                Some(&json!({"killed_by":"cancelled_before_start"})),
            )
            .await
            .unwrap();
        store
            .create_job_with_event(
                "restart-recovery",
                "tenant-a",
                "python",
                r#"{"language":"python","code":"print(2)"}"#,
            )
            .await
            .unwrap();
        store
            .start_with_event_if_queued("restart-recovery", &json!({"limits":{}}))
            .await
            .unwrap();
        assert_eq!(store.recover_stale_running().await.unwrap(), 1);
        assert_eq!(
            store.pending_attestation_job_ids(10).await.unwrap().len(),
            2
        );
        drop(store);

        let store = Store::open(&db).await.unwrap();
        let service = test_service(11);
        let report = service.process_pending_once(&store).await.unwrap();
        assert_eq!(report.observed, 2);
        assert_eq!(report.completed, 2);
        assert_eq!(report.failed, 0);
        assert!(store
            .pending_attestation_job_ids(10)
            .await
            .unwrap()
            .is_empty());

        let verifying_key = service.signing_key.as_ref().unwrap().verifying_key();
        for job_id in ["queued-cancel", "restart-recovery"] {
            let stored = store.get_attestation(job_id).await.unwrap().unwrap();
            let digest = ArtifactDigest::from_bytes(&stored.result_artifact);
            let verified = verify_attestation(
                &stored.envelope_json,
                &digest,
                &[verifying_key],
                &VerificationPolicy::default()
                    .with_tenant("tenant-a")
                    .with_subject_name(format!("coop://jobs/{job_id}/result"))
                    .with_media_type(RESULT_ARTIFACT_MEDIA_TYPE),
            )
            .unwrap();
            assert_eq!(verified.statement().predicate().execution_id(), job_id);
            assert_eq!(verified.statement().predicate().tenant(), "tenant-a");
            assert_eq!(verified.subject_sha256(), stored.metadata.result_sha256);
            let artifact: Value = serde_json::from_slice(&stored.result_artifact).unwrap();
            assert_eq!(artifact["job_id"], job_id);
            assert_eq!(artifact["tenant"], "tenant-a");
            assert_eq!(artifact["receipt_sha256"], stored.metadata.receipt_sha256);
        }
        let replay = service.process_pending_once(&store).await.unwrap();
        assert_eq!(replay.observed, 0);
    }

    #[tokio::test]
    async fn explicit_off_waives_current_outbox_but_a_signed_restart_reseeds_backfill() {
        let db = test_db("off-then-on");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job_with_event("job", "tenant-a", "python", "{}")
            .await
            .unwrap();
        store
            .finalize_with_event("job", "succeeded", Some(0), 1, None)
            .await
            .unwrap();
        let off = AttestationService {
            signing_key: None,
            key_id: None,
            public_key_pem: None,
        };
        assert_eq!(off.process_pending_once(&store).await.unwrap().completed, 1);
        assert!(store
            .pending_attestation_job_ids(10)
            .await
            .unwrap()
            .is_empty());
        assert!(store.get_attestation("job").await.unwrap().is_none());
        drop(store);

        let reopened = Store::open(&db).await.unwrap();
        assert_eq!(
            reopened.pending_attestation_job_ids(10).await.unwrap(),
            vec!["job"]
        );
        let signer = test_service(19);
        let report = signer.process_pending_once(&reopened).await.unwrap();
        assert_eq!(report.completed, 1, "{report:?}");
        assert!(reopened.get_attestation("job").await.unwrap().is_some());
    }

    #[test]
    fn malformed_private_key_fails_startup_without_echoing_file_contents() {
        let root = std::env::temp_dir().join(format!(
            "coop-malformed-attestation-key-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let key = root.join("signing.pem");
        std::fs::write(&key, b"definitely-not-private-key-material").unwrap();
        let key_path = key.to_string_lossy().to_string();
        let source = |name: &str| match name {
            "ROOKHOLD_API_KEYS" => Some("local:test-key".to_string()),
            "ROOKHOLD_ATTESTATION_MODE" => Some("sign".to_string()),
            "ROOKHOLD_ATTESTATION_KEY_FILE" => Some(key_path.clone()),
            _ => None,
        };
        let config = Config::from_sources(&source, false).unwrap();
        let error = AttestationService::from_config(&config)
            .err()
            .expect("malformed key must fail startup");
        assert!(error.contains("failed to load attestation signing key"));
        assert!(!error.contains("definitely-not-private-key-material"));
    }
}
