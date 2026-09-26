use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use coop_store::{
    canonical_json, capacity_error_kind, compute_receipt_sha256, is_idempotency_conflict,
    CapacityErrorKind, CreateJobOutcome, IdempotencyLookup, IdempotencyRequest, JobCursor,
    ListJobsQuery, PersistAttestationOutcome, StorageLimits, Store, ATTESTATION_RESERVE_BYTES,
    JOB_COMPLETION_RESERVE_BYTES, MAX_EVENT_BATCH_SIZE, MAX_RETENTION_EVENTS_PER_BATCH,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, Row, SqliteConnection};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn sha256_hex(input: &[u8]) -> String {
    Sha256::digest(input)
        .as_slice()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn test_db(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!(
            "coop-store-{label}-{}-{nanos}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
        .join("coop.db")
}

async fn raw_connection(db: &Path) -> SqliteConnection {
    std::fs::create_dir_all(db.parent().unwrap()).unwrap();
    let options = SqliteConnectOptions::new()
        .filename(db)
        .create_if_missing(true);
    SqliteConnection::connect_with(&options).await.unwrap()
}

async fn total_charged_bytes(db: &Path) -> i64 {
    let mut connection = raw_connection(db).await;
    let charged =
        sqlx::query_scalar("SELECT charged_bytes FROM storage_usage_total WHERE singleton = 1")
            .fetch_one(&mut connection)
            .await
            .unwrap();
    connection.close().await.unwrap();
    charged
}

async fn rewrite_accounting_guards_to_r1(
    connection: &mut SqliteConnection,
    owned_write_sentinel: i64,
) {
    sqlx::query("PRAGMA writable_schema = ON")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE sqlite_schema
         SET sql = replace(
             replace(sql, 'coop-accounting-guard-r2', 'coop-accounting-guard-r1'),
             'accounting_validation_revision != 3', ?1
         )
         WHERE type = 'trigger'
           AND instr(sql, 'coop-accounting-guard-r2') > 0",
    )
    .bind(format!(
        "accounting_validation_revision != {owned_write_sentinel}"
    ))
    .execute(&mut *connection)
    .await
    .unwrap();
    sqlx::query("PRAGMA writable_schema = OFF")
        .execute(&mut *connection)
        .await
        .unwrap();
}

fn bound_attestation_bytes(
    job_id: &str,
    tenant: &str,
    receipt_sha256: &str,
    result_media_type: &str,
    status: &str,
) -> (Vec<u8>, Vec<u8>) {
    let result = serde_json::to_vec(&json!({
        "schema_version": 1,
        "job_id": job_id,
        "tenant": tenant,
        "receipt_sha256": receipt_sha256,
        "status": status,
    }))
    .unwrap();
    let result_sha256 = sha256_hex(&result);
    let subject_name = format!("coop://jobs/{job_id}/result");
    let statement = serde_json::to_vec(&json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": subject_name.clone(),
            "digest": {"sha256": result_sha256.clone()},
            "mediaType": result_media_type,
        }],
        "predicateType": "https://github.com/sambai-dev/coop/blob/main/crates/coop-attestation/FORMAT.md#predicate-v1",
        "predicate": {
            "schemaVersion": 1,
            "executionId": job_id,
            "tenant": tenant,
            "result": {
                "name": subject_name,
                "mediaType": result_media_type,
                "sizeBytes": result.len(),
                "sha256": result_sha256,
            },
            "receipt": {
                "job_id": job_id,
                "receipt_sha256": receipt_sha256,
            },
        },
    }))
    .unwrap();
    let envelope = serde_json::to_vec(&json!({
        "payloadType": "application/vnd.in-toto+json",
        "payload": BASE64_STANDARD.encode(statement),
        "signatures": [{"keyid": "sha256:test", "sig": "AA=="}],
    }))
    .unwrap();
    (result, envelope)
}

fn unbound_attestation_bytes(
    job_id: &str,
    tenant: &str,
    receipt_sha256: &str,
    result_media_type: &str,
    status: &str,
) -> (Vec<u8>, Vec<u8>) {
    let (bound_result, bound_envelope) =
        bound_attestation_bytes(job_id, tenant, receipt_sha256, result_media_type, status);
    let mut result: serde_json::Value = serde_json::from_slice(&bound_result).unwrap();
    result.as_object_mut().unwrap().remove("tenant");
    let result = serde_json::to_vec(&result).unwrap();
    let result_sha256 = sha256_hex(&result);

    let mut envelope: serde_json::Value = serde_json::from_slice(&bound_envelope).unwrap();
    let payload = BASE64_STANDARD
        .decode(envelope["payload"].as_str().unwrap())
        .unwrap();
    let mut statement: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    statement["predicate"]
        .as_object_mut()
        .unwrap()
        .remove("tenant");
    statement["subject"][0]["digest"]["sha256"] = json!(result_sha256.clone());
    statement["predicate"]["result"]["sha256"] = json!(result_sha256);
    statement["predicate"]["result"]["sizeBytes"] = json!(result.len());
    envelope["payload"] = json!(BASE64_STANDARD.encode(serde_json::to_vec(&statement).unwrap()));
    (result, serde_json::to_vec(&envelope).unwrap())
}

#[cfg(target_os = "macos")]
#[test]
fn macos_store_opens_beneath_the_trusted_system_temp_alias() {
    sqlx::test_block_on(async {
        let db = std::env::temp_dir().join(format!(
            "coop-store-macos-temp-alias-{}-{}-{}.db",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ));
        let store = Store::open(&db)
            .await
            .expect("macOS /var or /tmp system alias and exact temp root must be trusted");
        store
            .create_job("job", "tenant-a", "python", "{}")
            .await
            .unwrap();
        assert!(store.get_job_summary("job").await.unwrap().is_some());
    });
}

async fn create_v1_schema(connection: &mut SqliteConnection) {
    sqlx::query(
        "CREATE TABLE jobs (
            job_id TEXT PRIMARY KEY,
            tenant TEXT NOT NULL,
            language TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            spec_json TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            started_at_ms INTEGER,
            finished_at_ms INTEGER,
            exit_code INTEGER
        )",
    )
    .execute(&mut *connection)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL,
            ts_ms INTEGER NOT NULL,
            kind TEXT NOT NULL,
            data_json TEXT NOT NULL
        )",
    )
    .execute(&mut *connection)
    .await
    .unwrap();
}

async fn create_v2_schema(connection: &mut SqliteConnection) {
    sqlx::query(
        "CREATE TABLE schema_migrations (
             version INTEGER PRIMARY KEY,
             applied_at_ms INTEGER NOT NULL
         )",
    )
    .execute(&mut *connection)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE jobs (
             job_id TEXT PRIMARY KEY NOT NULL,
             tenant TEXT NOT NULL,
             language TEXT NOT NULL,
             status TEXT NOT NULL DEFAULT 'queued',
             spec_json TEXT NOT NULL,
             effective_spec_json TEXT,
             receipt_json TEXT,
             created_at_ms INTEGER NOT NULL,
             started_at_ms INTEGER,
             finished_at_ms INTEGER,
             exit_code INTEGER
         )",
    )
    .execute(&mut *connection)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE events (
             seq INTEGER PRIMARY KEY AUTOINCREMENT,
             job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
             ts_ms INTEGER NOT NULL,
             kind TEXT NOT NULL,
             data_json TEXT NOT NULL,
             prev_hash TEXT NOT NULL DEFAULT '',
             event_hash TEXT NOT NULL DEFAULT '',
             hash_version INTEGER NOT NULL DEFAULT 0
         )",
    )
    .execute(&mut *connection)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO schema_migrations(version, applied_at_ms)
         VALUES (1, 1), (2, 2)",
    )
    .execute(&mut *connection)
    .await
    .unwrap();
    sqlx::query("PRAGMA user_version = 2")
        .execute(&mut *connection)
        .await
        .unwrap();
}

fn canonical_spec_sha256(spec_json: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(spec_json).unwrap();
    sha256_hex(canonical_json(&value).as_bytes())
}

#[test]
fn readiness_probe_requires_current_versions_and_both_data_tables() {
    sqlx::test_block_on(async {
        for missing in ["jobs", "events"] {
            let db = test_db(&format!("readiness-missing-{missing}"));
            let store = Store::open(&db).await.unwrap();
            store.readiness_probe().await.unwrap();
            let current_version = store.schema_version().await.unwrap();
            let mut connection = raw_connection(&db).await;
            sqlx::query(&format!("DROP TABLE {missing}"))
                .execute(&mut connection)
                .await
                .unwrap();
            assert_eq!(
                store.schema_version().await.unwrap(),
                current_version,
                "the old version-only probe falsely stayed green"
            );
            assert!(
                store.readiness_probe().await.is_err(),
                "missing {missing} must fail readiness"
            );
        }

        let db = test_db("readiness-version");
        let store = Store::open(&db).await.unwrap();
        let current_version = store.schema_version().await.unwrap();
        let mut connection = raw_connection(&db).await;
        sqlx::query("PRAGMA user_version = 1")
            .execute(&mut connection)
            .await
            .unwrap();
        let error = store.readiness_probe().await.unwrap_err();
        assert!(error.to_string().contains("schema mismatch"), "{error}");
        let unchanged: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(unchanged, 1, "readiness must not migrate or repair schema");

        sqlx::query(&format!("PRAGMA user_version = {current_version}"))
            .execute(&mut connection)
            .await
            .unwrap();
        // Model an offline/corrupting writer that bypassed Rookhold's immutable
        // migration-history guard. Readiness must detect the marker drift but
        // must never repair it as a side effect.
        sqlx::query("DROP TRIGGER coop_schema_migrations_storage_guard_delete")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = ?1")
            .bind(current_version)
            .execute(&mut connection)
            .await
            .unwrap();
        assert!(store.readiness_probe().await.is_err());
        let history: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(
            history,
            current_version - 1,
            "readiness must not repair migration history"
        );
    });
}

#[test]
fn migrates_v01_database_without_fabricating_event_hashes() {
    sqlx::test_block_on(async {
        let db = test_db("migration");
        std::fs::create_dir_all(db.parent().unwrap()).unwrap();
        let options = SqliteConnectOptions::new()
            .filename(&db)
            .create_if_missing(true);
        let mut connection = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE jobs (
                job_id TEXT PRIMARY KEY,
                tenant TEXT NOT NULL,
                language TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                spec_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                started_at_ms INTEGER,
                finished_at_ms INTEGER,
                exit_code INTEGER
            )",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                ts_ms INTEGER NOT NULL,
                kind TEXT NOT NULL,
                data_json TEXT NOT NULL
            )",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO jobs VALUES
                ('legacy', 'tenant-a', 'python', 'succeeded', '{}', 10, 11, 12, 0),
                ('quarantined', '', 'python', 'queued', '{}', 20, NULL, NULL, NULL),
                ('invalid-json', 'tenant-a', 'python', 'queued', 'not-json', 30, NULL, NULL, NULL)",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO events(job_id, ts_ms, kind, data_json)
             VALUES
                ('legacy', 11, 'stdout', '{\"line\":\"kept\"}'),
                ('invalid-json', 31, 'stdout', 'not-json')",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query("PRAGMA user_version = 1")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        let store = Store::open(&db).await.unwrap();
        assert_eq!(store.schema_version().await.unwrap(), 4);
        let legacy = store.get_job("legacy").await.unwrap().unwrap();
        assert_eq!(legacy.status, "succeeded");
        assert!(legacy.effective_spec_json.is_none());
        assert!(legacy.receipt_json.is_none());
        let quarantined = store.get_job("quarantined").await.unwrap().unwrap();
        assert_eq!(quarantined.tenant, "__legacy_invalid__:quarantined");
        let invalid = store.get_job("invalid-json").await.unwrap().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&invalid.spec_json).unwrap(),
            json!({"legacy_invalid_spec_json":"not-json"})
        );
        assert_eq!(
            store.events_for("invalid-json").await.unwrap()[0].data,
            json!({"legacy_invalid_data_json":"not-json"})
        );
        store
            .finalize_with_event("invalid-json", "error", None, 0, None)
            .await
            .unwrap()
            .unwrap();
        let invalid = store.get_job("invalid-json").await.unwrap().unwrap();
        let receipt: serde_json::Value =
            serde_json::from_str(invalid.receipt_json.as_deref().unwrap()).unwrap();
        assert_eq!(receipt["event_chain"]["complete"], false);
        assert_eq!(receipt["event_chain"]["legacy_events"], 1);
        assert_eq!(receipt["event_chain"]["verified_events"], 1);

        let events = store.events_for("legacy").await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data["line"], "kept");
        assert_eq!(events[0].hash_version, 0);
        assert!(events[0].event_hash.is_empty());
        let verification = store.verify_event_chain("legacy").await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.head.legacy_event_count, 1);
        assert_eq!(verification.head.verified_event_count, 0);
        assert!(verification.head.head_hash.is_none());
    });
}

#[test]
fn lifecycle_events_receipt_and_hash_chain_commit_together() {
    sqlx::test_block_on(async {
        let db = test_db("lifecycle");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("job", "tenant-a", "python", r#"{"code":"print(1)"}"#)
            .await
            .unwrap();
        let effective = json!({"language":"python","limits":{"wall_seconds":5}});
        let started = store
            .start_with_event_if_queued("job", &effective)
            .await
            .unwrap()
            .unwrap();
        let finished = store
            .finalize_with_event(
                "job",
                "succeeded",
                Some(0),
                8,
                Some(&json!({
                    "policy":"default",
                    "job_id":"caller-value",
                    "outcome":"failed",
                    "exit_code":99,
                    "created_at_ms":-1,
                    "started_at_ms":-1,
                    "finished_at_ms":0,
                    "duration_ms":0,
                    "receipt_sha256":"caller-value",
                })),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(store
            .finalize_with_event("job", "failed", Some(1), 9, None)
            .await
            .unwrap()
            .is_none());
        assert!(store
            .append_event_row("job", "stdout", &json!({"line":"too late"}))
            .await
            .is_err());

        let row = store.get_job("job").await.unwrap().unwrap();
        assert_eq!(row.status, "succeeded");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(row.effective_spec_json.as_deref().unwrap())
                .unwrap(),
            effective
        );
        let receipt: serde_json::Value =
            serde_json::from_str(row.receipt_json.as_deref().unwrap()).unwrap();
        assert_eq!(receipt["policy"], "default");
        assert_eq!(receipt["version"], 1);
        assert_eq!(receipt["job_id"], "job");
        assert_eq!(receipt["outcome"], "succeeded");
        assert_eq!(receipt["exit_code"], 0);
        assert_eq!(receipt["created_at_ms"], row.created_at_ms);
        assert_eq!(receipt["started_at_ms"], row.started_at_ms.unwrap());
        assert_eq!(receipt["finished_at_ms"], row.finished_at_ms.unwrap());
        assert_eq!(receipt["duration_ms"], 8);
        assert_eq!(receipt["event_chain"]["head"], finished.event_hash);
        assert_eq!(receipt["event_chain"]["events"], 3);
        assert_eq!(receipt["event_chain"]["event_count"], 3);
        assert_eq!(receipt["event_chain"]["complete"], true);
        assert_eq!(
            receipt["receipt_sha256"].as_str().unwrap(),
            compute_receipt_sha256(&receipt)
        );

        let events = store.events_for("job").await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind, "accepted");
        assert_eq!(events[1].kind, "started");
        assert_eq!(events[2].kind, "finished");
        assert_eq!(started.prev_hash, events[0].event_hash);
        assert_eq!(finished.prev_hash, started.event_hash);
        let verification = store.verify_event_chain("job").await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.head.head_hash, Some(finished.event_hash));
    });
}

#[test]
fn terminal_finalize_atomically_replaces_initial_effective_spec_and_binds_its_digest() {
    sqlx::test_block_on(async {
        let db = test_db("observed-effective-spec");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("job", "tenant-a", "python", r#"{"code":"print(1)"}"#)
            .await
            .unwrap();
        let initial = json!({
            "backend": null,
            "network_allowed": null,
            "limit_enforcement": null,
        });
        let started = store
            .start_with_event_if_queued("job", &initial)
            .await
            .unwrap()
            .unwrap();
        assert!(started.data.get("effective_spec_sha256").is_none());
        assert_eq!(
            started.data["initial_effective_spec_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );

        let observed = json!({
            "backend": "linux_namespaces",
            "network_allowed": false,
            "limit_enforcement": {
                "memory": "cgroup_v2",
                "cpu": "rlimit",
            },
        });
        let finished = store
            .finalize_with_event_and_effective_spec(
                "job",
                "succeeded",
                Some(0),
                7,
                Some(&observed),
                None,
            )
            .await
            .unwrap()
            .unwrap();
        let row = store.get_job("job").await.unwrap().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(row.effective_spec_json.as_deref().unwrap())
                .unwrap(),
            observed
        );
        let expected_digest = sha256_hex(canonical_json(&observed).as_bytes());
        assert_eq!(finished.data["effective_spec_sha256"], expected_digest);
        assert!(store.verify_event_chain("job").await.unwrap().valid);
    });
}

#[test]
fn raw_event_deletion_dirties_validation_and_cannot_be_laundered_by_store_writes() {
    sqlx::test_block_on(async {
        let db = test_db("raw-event-delete");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("job", "tenant-a", "python", "{}")
            .await
            .unwrap();

        let mut connection = raw_connection(&db).await;
        sqlx::query("DELETE FROM events WHERE job_id = 'job'")
            .execute(&mut connection)
            .await
            .unwrap();
        let revision: i64 = sqlx::query_scalar(
            "SELECT row_validation_revision FROM store_integrity WHERE singleton = 1",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(revision, 0);
        connection.close().await.unwrap();

        let error = store
            .append_event_row("job", "stdout", &json!({"line":"must fail"}))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("row validation is stale"));
    });
}

#[test]
fn batch_append_is_ordered_chained_bounded_and_atomic() {
    sqlx::test_block_on(async {
        let db = test_db("event-batch");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("job", "tenant-a", "python", r#"{"code":"print(1)"}"#)
            .await
            .unwrap();
        let started = store
            .start_with_event_if_queued("job", &json!({"language":"python"}))
            .await
            .unwrap()
            .unwrap();

        assert!(store
            .append_events_batch("missing", &[])
            .await
            .unwrap()
            .is_empty());
        let pending = vec![
            ("stdout".to_string(), json!({"line":"one"})),
            ("stderr".to_string(), json!({"line":"two"})),
            ("stdout".to_string(), json!({"line":"three"})),
        ];
        let appended = store.append_events_batch("job", &pending).await.unwrap();
        assert_eq!(appended.len(), pending.len());
        assert_eq!(
            appended
                .iter()
                .map(|event| event.kind.as_str())
                .collect::<Vec<_>>(),
            ["stdout", "stderr", "stdout"]
        );
        assert_eq!(appended[0].prev_hash, started.event_hash);
        for pair in appended.windows(2) {
            assert_eq!(pair[1].seq, pair[0].seq + 1);
            assert_eq!(pair[1].prev_hash, pair[0].event_hash);
        }
        assert_eq!(appended[0].data["line"], "one");
        assert_eq!(appended[2].data["line"], "three");
        assert!(store.verify_event_chain("job").await.unwrap().valid);

        let oversized = (0..=MAX_EVENT_BATCH_SIZE)
            .map(|index| ("stdout".to_string(), json!({"index":index})))
            .collect::<Vec<_>>();
        assert!(store.append_events_batch("job", &oversized).await.is_err());

        // Force the second insert to fail inside SQLite, proving that the
        // first insert from the same batch cannot escape the transaction.
        let options = SqliteConnectOptions::new().filename(&db);
        let mut connection = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TRIGGER reject_test_event
             BEFORE INSERT ON events
             WHEN NEW.kind = 'force_batch_failure'
             BEGIN
                 SELECT RAISE(ABORT, 'forced batch failure');
             END",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();

        let before = store.events_for("job").await.unwrap();
        let before_head = before.last().unwrap().event_hash.clone();
        assert!(store
            .append_events_batch(
                "job",
                &[
                    ("stdout".to_string(), json!({"line":"must roll back"})),
                    ("force_batch_failure".to_string(), json!({})),
                ],
            )
            .await
            .is_err());
        let after = store.events_for("job").await.unwrap();
        assert_eq!(after.len(), before.len());
        assert_eq!(after.last().unwrap().event_hash, before_head);
        assert!(store.verify_event_chain("job").await.unwrap().valid);
    });
}

#[test]
fn cancellation_pagination_and_retention_are_strict_and_bounded() {
    sqlx::test_block_on(async {
        let db = test_db("queries");
        let store = Store::open(&db).await.unwrap();
        for (job_id, tenant, language) in [
            ("a1", "tenant-a", "python"),
            ("a2", "tenant-a", "node"),
            ("a3", "tenant-a", "python"),
            ("b1", "tenant-b", "python"),
        ] {
            store
                .create_job(job_id, tenant, language, "{}")
                .await
                .unwrap();
        }
        assert!(store
            .cancel_queued_with_event("a2", "tenant-b", None)
            .await
            .unwrap()
            .is_none());
        store
            .cancel_queued_with_event("a2", "tenant-a", None)
            .await
            .unwrap()
            .unwrap();
        store
            .finalize_with_event("a1", "succeeded", Some(0), 1, None)
            .await
            .unwrap()
            .unwrap();

        let filtered = store
            .list_jobs_page(ListJobsQuery {
                tenant: Some("tenant-a".to_string()),
                status: Some("succeeded".to_string()),
                language: Some("python".to_string()),
                limit: 50,
                ..ListJobsQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].job_id, "a1");
        assert!(store.list_jobs(Some(""), 50).await.unwrap().is_empty());

        let filtered_summaries = store
            .list_job_summaries_page(ListJobsQuery {
                tenant: Some("tenant-a".to_string()),
                status: Some("succeeded".to_string()),
                language: Some("python".to_string()),
                limit: 50,
                ..ListJobsQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(filtered_summaries.len(), 1);
        assert_eq!(filtered_summaries[0].job_id, "a1");
        assert!(store
            .list_job_summaries_page(ListJobsQuery {
                tenant: Some(String::new()),
                ..ListJobsQuery::default()
            })
            .await
            .unwrap()
            .is_empty());

        let first = store
            .list_jobs_page(ListJobsQuery {
                tenant: Some("tenant-a".to_string()),
                limit: 2,
                ..ListJobsQuery::default()
            })
            .await
            .unwrap();
        let cursor_row = first.last().unwrap();
        let second = store
            .list_jobs_page(ListJobsQuery {
                tenant: Some("tenant-a".to_string()),
                before: Some(JobCursor {
                    created_at_ms: cursor_row.created_at_ms,
                    job_id: cursor_row.job_id.clone(),
                }),
                limit: 2,
                ..ListJobsQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 1);
        assert!(!first
            .iter()
            .any(|left| second.iter().any(|right| left.job_id == right.job_id)));

        let summary_first = store
            .list_job_summaries_page(ListJobsQuery {
                tenant: Some("tenant-a".to_string()),
                limit: 2,
                ..ListJobsQuery::default()
            })
            .await
            .unwrap();
        let summary_second = store
            .list_job_summaries_page(ListJobsQuery {
                tenant: Some("tenant-a".to_string()),
                before: Some(JobCursor::from(summary_first.last().unwrap())),
                limit: 2,
                ..ListJobsQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(summary_first.len(), 2);
        assert_eq!(summary_second.len(), 1);
        assert!(!summary_first.iter().any(|left| summary_second
            .iter()
            .any(|right| left.job_id == right.job_id)));

        for line in 1..=3 {
            store
                .append_event_row("a3", "stdout", &json!({"line":line}))
                .await
                .unwrap();
        }
        let event_page = store.events_after("a3", 0, 2).await.unwrap();
        assert_eq!(event_page.len(), 2);
        assert_eq!(
            store
                .events_after("a3", event_page[1].seq, 2)
                .await
                .unwrap()
                .len(),
            2
        );

        std::thread::sleep(std::time::Duration::from_millis(5));
        let first_prune = store.prune_older_than_batch(0, 1).await.unwrap();
        assert_eq!(first_prune.jobs_deleted, 1);
        assert_eq!(first_prune.events_deleted, 2);
        assert!(first_prune.more_remaining);
        let second_prune = store.prune_older_than_batch(0, 1).await.unwrap();
        assert_eq!(second_prune.jobs_deleted, 1);
        assert_eq!(second_prune.events_deleted, 2);
        assert!(!second_prune.more_remaining);
        assert!(store.get_job("a3").await.unwrap().is_some());
        assert!(store.get_job("b1").await.unwrap().is_some());
        store.compact().await.unwrap();
    });
}

#[test]
fn running_recovery_preserves_queued_work_and_emits_terminal_evidence() {
    sqlx::test_block_on(async {
        let db = test_db("recovery");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("queued", "tenant-a", "python", "{}")
            .await
            .unwrap();
        store
            .create_job(
                "running",
                "tenant-a",
                "python",
                &json!({
                    "code":"print(1)",
                    "stdin":"input",
                    "limits":{"wall_seconds":10}
                })
                .to_string(),
            )
            .await
            .unwrap();
        store
            .start_with_event_if_queued(
                "running",
                &json!({"limits":{"wall_seconds":5},"effective":true}),
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(store.recover_stale_running().await.unwrap(), 1);
        assert_eq!(
            store.get_job("queued").await.unwrap().unwrap().status,
            "queued"
        );
        let recovered = store.get_job("running").await.unwrap().unwrap();
        assert_eq!(recovered.status, "error");
        assert_eq!(store.queued_job_ids(10).await.unwrap(), ["queued"]);
        let receipt: serde_json::Value =
            serde_json::from_str(recovered.receipt_json.as_deref().unwrap()).unwrap();
        assert_eq!(receipt["terminal_reason"], "server_restarted");
        assert_eq!(receipt["killed_by"], "server_restarted");
        assert_eq!(receipt["evidence_complete"], false);
        assert_eq!(receipt["created_at_ms"], recovered.created_at_ms);
        assert_eq!(receipt["started_at_ms"], recovered.started_at_ms.unwrap());
        assert_eq!(receipt["requested_limits"]["wall_seconds"], 10);
        assert_eq!(receipt["code_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(receipt["stdin_sha256"].as_str().unwrap().len(), 64);
        for unavailable in [
            "backend",
            "seccomp",
            "network_allowed",
            "bootstrap_ready",
            "limit_enforcement",
            "effective_limits",
            "policy_sha256",
            "resource_usage",
            "output",
        ] {
            assert!(
                receipt.get(unavailable).is_none(),
                "{unavailable} was fabricated"
            );
        }
        assert_eq!(
            receipt["receipt_sha256"].as_str().unwrap(),
            compute_receipt_sha256(&receipt)
        );
        let events = store.events_for("running").await.unwrap();
        assert_eq!(events.last().unwrap().data["reason"], "server_restarted");
        assert!(store.verify_event_chain("running").await.unwrap().valid);
    });
}

#[test]
fn running_recovery_is_bounded_idempotent_and_atomic_between_rows() {
    sqlx::test_block_on(async {
        let db = test_db("bounded-running-recovery");
        let store = Store::open(&db).await.unwrap();
        let mut connection = raw_connection(&db).await;
        // Exercise the supported decoded maximum of 1 MiB each for code and
        // stdin without retaining all 256 requested/effective specs in memory.
        let maximal_spec = format!(
            r#"{{"code":"{}","stdin":"{}"}}"#,
            "x".repeat(1024 * 1024),
            "y".repeat(1024 * 1024)
        );
        sqlx::query(
            "WITH RECURSIVE sequence(n) AS (
                 VALUES(1) UNION ALL SELECT n + 1 FROM sequence WHERE n < 256
             )
             INSERT INTO jobs(
                 job_id, tenant, language, status, spec_json,
                 effective_spec_json, created_at_ms, started_at_ms, admitted_mem_mb
             )
             SELECT printf('running-%03d', n), 'tenant-a', 'python', 'running',
                    CASE WHEN n = 256 THEN ?1 ELSE '{}' END,
                    CASE WHEN n = 256 THEN ?1 ELSE '{}' END,
                    n, n, 256
             FROM sequence",
        )
        .bind(&maximal_spec)
        .execute(&mut connection)
        .await
        .unwrap();
        drop(maximal_spec);

        // Raw fixture writes deliberately dirty the durable validation marker.
        // Revalidate before exercising the normal Store write path; the
        // failure trigger is installed afterward so this maintenance pass
        // does not reconcile it away.
        store.validate_integrity().await.unwrap();

        // Fail after 128 independently committed jobs. The failing job has
        // already been updated when its event insert runs, so rollback must
        // restore the complete running state and leave no partial evidence.
        sqlx::query(
            "CREATE TRIGGER fail_mid_recovery
             BEFORE INSERT ON events
             WHEN NEW.job_id = 'running-129' AND NEW.kind = 'finished'
             BEGIN
                 SELECT RAISE(ABORT, 'forced recovery event failure');
             END",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();

        let error = store.recover_stale_running().await.unwrap_err();
        assert!(error.to_string().contains("forced recovery event failure"));
        let mut connection = raw_connection(&db).await;
        let recovered: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE status = 'error'")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        let still_running: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE status = 'running'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!((recovered, still_running), (128, 128));
        let partial_evidence: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE job_id = 'running-129'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(partial_evidence, 0);
        let receipt: Option<String> =
            sqlx::query_scalar("SELECT receipt_json FROM jobs WHERE job_id = 'running-129'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert!(receipt.is_none());

        sqlx::query("DROP TRIGGER fail_mid_recovery")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        assert_eq!(store.recover_stale_running().await.unwrap(), 128);
        assert_eq!(store.recover_stale_running().await.unwrap(), 0);
        let maximal = store.get_job("running-256").await.unwrap().unwrap();
        assert_eq!(maximal.status, "error");
        let receipt: serde_json::Value =
            serde_json::from_str(maximal.receipt_json.as_deref().unwrap()).unwrap();
        assert_eq!(receipt["code_sha256"].as_str().unwrap().len(), 64);
        assert_eq!(receipt["stdin_sha256"].as_str().unwrap().len(), 64);
        assert!(store.verify_event_chain("running-129").await.unwrap().valid);
        assert!(store.verify_event_chain("running-256").await.unwrap().valid);
    });
}

#[test]
fn current_markers_require_current_tables_and_v3_downgrades_fail_closed() {
    sqlx::test_block_on(async {
        let false_current = test_db("false-current-marker");
        let mut connection = raw_connection(&false_current).await;
        create_v1_schema(&mut connection).await;
        sqlx::query("PRAGMA user_version = 2")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        let error = Store::open(&false_current).await.unwrap_err();
        assert!(
            error.to_string().contains("missing required column"),
            "unexpected schema validation error: {error}"
        );

        let missing_history = test_db("missing-history");
        let store = Store::open(&missing_history).await.unwrap();
        let mut connection = raw_connection(&missing_history).await;
        assert!(sqlx::query("DELETE FROM schema_migrations")
            .execute(&mut connection)
            .await
            .is_err());
        sqlx::query("DROP TRIGGER coop_schema_migrations_storage_guard_delete")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        drop(store);
        let error = Store::open(&missing_history).await.unwrap_err();
        assert!(
            error.to_string().contains("physical v3 schema"),
            "unexpected missing-history error: {error}"
        );

        let lost_markers = test_db("lost-current-markers");
        let store = Store::open(&lost_markers).await.unwrap();
        store
            .create_job("preserved", "tenant-a", "python", "{}")
            .await
            .unwrap();
        store
            .finalize_with_event("preserved", "succeeded", Some(0), 0, None)
            .await
            .unwrap()
            .unwrap();
        let mut connection = raw_connection(&lost_markers).await;
        sqlx::query("PRAGMA user_version = 0")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        drop(store);
        let error = Store::open(&lost_markers).await.unwrap_err();
        assert!(
            error.to_string().contains("physical v3 schema"),
            "unexpected downgraded-marker error: {error}"
        );
    });
}

#[test]
fn genuine_v2_migrates_memory_accounting_and_reconciles_covering_indexes() {
    sqlx::test_block_on(async {
        let db = test_db("covering-index-reconciliation");
        let mut connection = raw_connection(&db).await;
        create_v2_schema(&mut connection).await;
        sqlx::query(
            "INSERT INTO jobs(
                 job_id, tenant, language, status, spec_json, created_at_ms
             ) VALUES (
                 'v2-queued', 'tenant-a', 'python', 'queued',
                 '{\"language\":\"python\",\"code\":\"pass\",\"limits\":{\"mem_mb\":512}}', 1
             )",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        // Genuine v2 installations can carry these older non-covering forms.
        // Migration must replace them and derive durable admitted memory.
        sqlx::query(
            "CREATE INDEX idx_jobs_tenant_created
             ON jobs(tenant, created_at_ms DESC, job_id DESC)",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query("CREATE INDEX idx_jobs_status ON jobs(status)")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        let store = Store::open(&db).await.unwrap();
        assert_eq!(store.schema_version().await.unwrap(), 4);
        assert_eq!(
            store.job_requested_mem_mb("v2-queued").await.unwrap(),
            Some(512)
        );
        let mut connection = raw_connection(&db).await;
        let rows = sqlx::query(
            "SELECT name, sql FROM sqlite_schema
             WHERE type = 'index' AND name IN (
                 'idx_jobs_tenant_created_summary',
                 'idx_jobs_tenant_status_created_summary',
                 'idx_jobs_tenant_language_created_summary',
                 'idx_jobs_tenant_status_language_created_summary',
                 'idx_jobs_id_summary',
                 'idx_jobs_status_created_recovery_v3'
             ) ORDER BY name",
        )
        .fetch_all(&mut connection)
        .await
        .unwrap();
        assert_eq!(rows.len(), 6);
        for row in rows {
            let sql = row.get::<String, _>("sql").to_ascii_lowercase();
            for blob in ["spec_json", "effective_spec_json", "receipt_json"] {
                assert!(
                    !sql.contains(blob),
                    "{} unexpectedly indexes {blob}: {sql}",
                    row.get::<String, _>("name")
                );
            }
        }
        let stale: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'index'
               AND name IN ('idx_jobs_tenant_created', 'idx_jobs_status')",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(stale, 0);
        connection.close().await.unwrap();
        drop(store);
    });
}

#[test]
fn legacy_non_integer_storage_is_normalized_and_new_text_timestamps_are_rejected() {
    sqlx::test_block_on(async {
        let db = test_db("storage-classes");
        let mut connection = raw_connection(&db).await;
        create_v1_schema(&mut connection).await;
        sqlx::query(
            "INSERT INTO jobs VALUES
             ('weird', 'tenant-a', 'python', 'succeeded', '{}',
              'not-an-integer', 3.5, 'not-an-integer', 'not-an-integer'),
             ('wide-exit', 'tenant-a', 'python', 'succeeded', '{}',
              1, NULL, 2, 2147483648)",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO events(job_id, ts_ms, kind, data_json)
             VALUES ('weird', 'not-an-integer', 'stdout', '{}')",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query("PRAGMA user_version = 1")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        let store = Store::open(&db).await.unwrap();
        let row = store.get_job("weird").await.unwrap().unwrap();
        assert_eq!(row.created_at_ms, 0);
        assert!(row.started_at_ms.is_none());
        assert!(row.finished_at_ms.is_some());
        assert!(row.exit_code.is_none());
        assert!(store
            .get_job("wide-exit")
            .await
            .unwrap()
            .unwrap()
            .exit_code
            .is_none());
        assert_eq!(store.events_for("weird").await.unwrap()[0].ts_ms, 0);

        let mut connection = raw_connection(&db).await;
        let invalid_insert = sqlx::query(
            "INSERT INTO jobs(job_id, tenant, language, status, spec_json, created_at_ms)
             VALUES ('bad-time', 'tenant-a', 'python', 'queued', '{}', 'junk')",
        )
        .execute(&mut connection)
        .await;
        assert!(invalid_insert.is_err());
        let wide_exit = sqlx::query(
            "INSERT INTO jobs(
                 job_id, tenant, language, status, spec_json,
                 created_at_ms, finished_at_ms, exit_code
             ) VALUES (
                 'bad-exit', 'tenant-a', 'python', 'succeeded', '{}',
                 0, 1, 2147483648
             )",
        )
        .execute(&mut connection)
        .await;
        assert!(wide_exit.is_err());
        connection.close().await.unwrap();
    });
}

#[test]
fn shape_compatible_current_database_with_poisoned_types_fails_closed() {
    sqlx::test_block_on(async {
        let db = test_db("current-storage-poison");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("poisoned", "tenant-a", "python", "{}")
            .await
            .unwrap();
        drop(store);

        let mut connection = raw_connection(&db).await;
        sqlx::query("DROP TRIGGER coop_jobs_storage_guard_update")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("UPDATE jobs SET created_at_ms = 'not-an-integer' WHERE job_id = 'poisoned'")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        let error = Store::open(&db).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("jobs contains values incompatible"),
            "unexpected validation error: {error}"
        );
    });
}

#[test]
fn current_database_with_invalid_utf8_fails_closed() {
    sqlx::test_block_on(async {
        let db = test_db("current-invalid-utf8");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("invalid-utf8", "tenant-a", "python", "{}")
            .await
            .unwrap();
        drop(store);

        let mut connection = raw_connection(&db).await;
        sqlx::query("DROP TRIGGER coop_jobs_storage_guard_update")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE jobs SET language = CAST(X'80' AS TEXT)
             WHERE job_id = 'invalid-utf8'",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();

        let error = Store::open(&db).await.unwrap_err();
        assert!(
            error.to_string().contains("invalid UTF-8"),
            "unexpected validation error: {error}"
        );
    });
}

#[test]
fn json_valid_payload_with_invalid_utf8_still_fails_closed() {
    sqlx::test_block_on(async {
        let db = test_db("json-valid-invalid-utf8");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("invalid-json-utf8", "tenant-a", "python", "{}")
            .await
            .unwrap();

        let mut connection = raw_connection(&db).await;
        sqlx::query("DROP TRIGGER coop_jobs_storage_guard_update")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut connection)
            .await
            .unwrap();
        // SQLite reports this as syntactically valid JSON even though the
        // string value contains the lone invalid UTF-8 byte 0x80.
        sqlx::query(
            "UPDATE jobs
             SET spec_json = CAST(X'7B2278223A2280227D' AS TEXT)
             WHERE job_id = 'invalid-json-utf8'",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        let json_valid: i64 = sqlx::query_scalar(
            "SELECT json_valid(spec_json) FROM jobs WHERE job_id = 'invalid-json-utf8'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(json_valid, 1);
        let validation_revision: i64 = sqlx::query_scalar(
            "SELECT row_validation_revision FROM store_integrity WHERE singleton = 1",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(validation_revision, 0);
        connection.close().await.unwrap();

        let write_error = store
            .create_job("must-not-launder", "tenant-a", "python", "{}")
            .await
            .unwrap_err();
        assert!(
            write_error.to_string().contains("row validation is stale"),
            "unexpected dirty-marker write error: {write_error}"
        );
        drop(store);
        let error = Store::open(&db).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("jobs.spec_json contains invalid UTF-8"),
            "unexpected validation error: {error}"
        );
    });
}

#[test]
fn validated_max_payload_writes_keep_healthy_reopen_on_the_bounded_fast_path() {
    sqlx::test_block_on(async {
        let db = test_db("validated-fast-reopen");
        let store = Store::open(&db).await.unwrap();
        let requested = json!({
            "code": "x".repeat(1024 * 1024),
            "stdin": "y".repeat(1024 * 1024),
        })
        .to_string();
        store
            .create_job("maximal", "tenant-a", "python", &requested)
            .await
            .unwrap();
        let effective = json!({
            "code": "a".repeat(1024 * 1024),
            "stdin": "b".repeat(1024 * 1024),
        });
        store
            .start_with_event_if_queued("maximal", &effective)
            .await
            .unwrap()
            .unwrap();
        let receipt = json!({
            "output": {
                "stdout": "s".repeat(1024 * 1024),
                "stderr": "e".repeat(1024 * 1024),
            }
        });
        store
            .finalize_with_event("maximal", "succeeded", Some(0), 1, Some(&receipt))
            .await
            .unwrap()
            .unwrap();

        let mut connection = raw_connection(&db).await;
        let before: i64 =
            sqlx::query_scalar("SELECT full_scan_count FROM store_integrity WHERE singleton = 1")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let revision: i64 = sqlx::query_scalar(
            "SELECT row_validation_revision FROM store_integrity WHERE singleton = 1",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(revision, 3);
        let accounting_revision: i64 = sqlx::query_scalar(
            "SELECT accounting_validation_revision FROM store_integrity WHERE singleton = 1",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(accounting_revision, 2);
        connection.close().await.unwrap();
        drop(store);

        // A healthy same-revision reopen must not re-read the multi-megabyte
        // JSON columns. The durable counter changes only when the O(bytes)
        // validator actually runs.
        let reopened = Store::open(&db).await.unwrap();
        let mut connection = raw_connection(&db).await;
        let after_reopen: i64 =
            sqlx::query_scalar("SELECT full_scan_count FROM store_integrity WHERE singleton = 1")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(after_reopen, before);
        let accounting_after_reopen: i64 = sqlx::query_scalar(
            "SELECT accounting_validation_revision FROM store_integrity WHERE singleton = 1",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(accounting_after_reopen, accounting_revision);
        connection.close().await.unwrap();

        reopened.validate_integrity().await.unwrap();
        let mut connection = raw_connection(&db).await;
        let after_explicit_check: i64 =
            sqlx::query_scalar("SELECT full_scan_count FROM store_integrity WHERE singleton = 1")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(after_explicit_check, before + 1);
    });
}

#[test]
fn current_database_with_malformed_json_fails_closed() {
    sqlx::test_block_on(async {
        let db = test_db("current-malformed-json");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("malformed-json", "tenant-a", "python", "{}")
            .await
            .unwrap();
        drop(store);

        let mut connection = raw_connection(&db).await;
        sqlx::query("DROP TRIGGER coop_jobs_storage_guard_update")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE jobs SET spec_json = 'not-json'
             WHERE job_id = 'malformed-json'",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();

        let error = Store::open(&db).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("jobs contains values incompatible"),
            "unexpected validation error: {error}"
        );
    });
}

#[test]
fn owned_storage_guards_are_recreated_on_open() {
    sqlx::test_block_on(async {
        let db = test_db("stale-storage-guard");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("guarded", "tenant-a", "python", "{}")
            .await
            .unwrap();
        drop(store);

        let mut connection = raw_connection(&db).await;
        sqlx::query("DROP TRIGGER coop_jobs_storage_guard_update")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TRIGGER coop_jobs_storage_guard_update
             BEFORE UPDATE ON jobs BEGIN SELECT 1; END",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();

        let store = Store::open(&db).await.unwrap();
        let mut connection = raw_connection(&db).await;
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut connection)
            .await
            .unwrap();
        let poisoned = sqlx::query(
            "UPDATE jobs SET created_at_ms = 'not-an-integer'
             WHERE job_id = 'guarded'",
        )
        .execute(&mut connection)
        .await;
        assert!(poisoned.is_err());
        connection.close().await.unwrap();
        assert!(store.get_job("guarded").await.unwrap().is_some());
    });
}

#[test]
fn invalid_event_sequences_and_exhausted_autoincrement_fail_closed() {
    sqlx::test_block_on(async {
        let db = test_db("event-sequence-domain");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("job", "tenant-a", "python", "{}")
            .await
            .unwrap();
        let mut connection = raw_connection(&db).await;
        let non_positive = sqlx::query(
            "INSERT INTO events(
                 seq, job_id, ts_ms, kind, data_json,
                 prev_hash, event_hash, hash_version
             ) VALUES (0, 'job', 0, 'legacy', '{}', '', '', 0)",
        )
        .execute(&mut connection)
        .await;
        assert!(non_positive.is_err());
        sqlx::query(
            "UPDATE sqlite_sequence SET seq = 9223372036854775807
             WHERE name = 'events'",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();
        drop(store);

        let error = Store::open(&db).await.unwrap_err();
        assert!(
            error.to_string().contains("AUTOINCREMENT counter"),
            "unexpected sequence validation error: {error}"
        );

        for (label, corrupt) in [
            (
                "lowered-event-counter",
                "UPDATE sqlite_sequence SET seq = 0 WHERE name = 'events'",
            ),
            (
                "missing-event-counter",
                "DELETE FROM sqlite_sequence WHERE name = 'events'",
            ),
        ] {
            let db = test_db(label);
            let store = Store::open(&db).await.unwrap();
            store
                .create_job("job", "tenant-a", "python", "{}")
                .await
                .unwrap();
            drop(store);
            let mut connection = raw_connection(&db).await;
            sqlx::query(corrupt).execute(&mut connection).await.unwrap();
            connection.close().await.unwrap();
            let error = Store::open(&db).await.unwrap_err();
            assert!(
                error.to_string().contains("AUTOINCREMENT counter"),
                "unexpected sequence validation error: {error}"
            );
        }
    });
}

#[test]
fn legacy_migration_preserves_the_deleted_sequence_high_watermark() {
    sqlx::test_block_on(async {
        let db = test_db("legacy-sequence-high-watermark");
        let mut connection = raw_connection(&db).await;
        create_v1_schema(&mut connection).await;
        sqlx::query(
            "INSERT INTO jobs VALUES
             ('legacy', 'tenant-a', 'python', 'queued', '{}', 1, NULL, NULL, NULL)",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO events(job_id, ts_ms, kind, data_json) VALUES
             ('legacy', 1, 'legacy', '{}'),
             ('legacy', 2, 'legacy', '{}'),
             ('legacy', 3, 'legacy', '{}')",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query("DELETE FROM events WHERE seq = 3")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version = 1")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        let store = Store::open(&db).await.unwrap();
        let appended = store
            .append_event_row("legacy", "stdout", &json!({"line":"new"}))
            .await
            .unwrap();
        assert_eq!(appended.seq, 4);
        assert_eq!(
            store
                .events_for("legacy")
                .await
                .unwrap()
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            [1, 2, 4]
        );
    });
}

#[test]
fn queued_recovery_cursor_is_stable_when_earlier_rows_disappear() {
    sqlx::test_block_on(async {
        let db = test_db("queued-pages");
        let store = Store::open(&db).await.unwrap();
        for (job_id, tenant) in [("q1", "tenant-a"), ("q2", "tenant-b"), ("q3", "tenant-c")] {
            store
                .create_job(job_id, tenant, "python", "{}")
                .await
                .unwrap();
        }

        let first = store.queued_jobs_page(None, 2).await.unwrap();
        assert_eq!(
            first
                .iter()
                .map(|row| row.job_id.as_str())
                .collect::<Vec<_>>(),
            ["q1", "q2"]
        );
        assert_eq!(first[0].tenant, "tenant-a");
        let cursor = JobCursor::from(first.last().unwrap());
        store
            .cancel_queued_with_event("q1", "tenant-a", None)
            .await
            .unwrap()
            .unwrap();
        let second = store.queued_jobs_page(Some(&cursor), 2).await.unwrap();
        assert_eq!(
            second
                .iter()
                .map(|row| row.job_id.as_str())
                .collect::<Vec<_>>(),
            ["q3"]
        );
    });
}

#[test]
fn job_page_supports_one_internal_lookahead_row() {
    sqlx::test_block_on(async {
        let db = test_db("job-lookahead");
        let store = Store::open(&db).await.unwrap();
        let mut connection = raw_connection(&db).await;
        sqlx::query(
            "WITH RECURSIVE sequence(n) AS (
                 VALUES(1) UNION ALL SELECT n + 1 FROM sequence WHERE n < 501
             )
             INSERT INTO jobs(
                 job_id, tenant, language, status, spec_json, created_at_ms, admitted_mem_mb
             )
             SELECT printf('job-%03d', n), 'tenant-a', 'python', 'queued', '{}', 42, 256
             FROM sequence",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();

        assert_eq!(store.list_jobs(None, 501).await.unwrap().len(), 500);
        assert_eq!(
            store
                .list_jobs_page(ListJobsQuery {
                    limit: 501,
                    ..ListJobsQuery::default()
                })
                .await
                .unwrap()
                .len(),
            501
        );
        assert_eq!(
            store
                .list_job_summaries_page(ListJobsQuery {
                    limit: 501,
                    ..ListJobsQuery::default()
                })
                .await
                .unwrap()
                .len(),
            501
        );
    });
}

#[test]
fn job_summary_page_does_not_load_maximal_payload_columns() {
    sqlx::test_block_on(async {
        let db = test_db("job-summary-projection");
        let store = Store::open(&db).await.unwrap();
        let mut connection = raw_connection(&db).await;
        sqlx::query(
            "WITH RECURSIVE sequence(n) AS (
                 VALUES(1) UNION ALL SELECT n + 1 FROM sequence WHERE n < 500
             )
             INSERT INTO jobs(
                 job_id, tenant, language, status, spec_json, created_at_ms, admitted_mem_mb
             )
             SELECT printf('job-%03d', n), 'tenant-a', 'python', 'queued', '{}', 42, 256
             FROM sequence",
        )
        .execute(&mut connection)
        .await
        .unwrap();

        // A requested spec can contain 1 MiB each of code and stdin. Exercise
        // that decoded-size boundary in every omitted JSON column.
        let maximal_payload = format!(r#"{{"payload":"{}"}}"#, "x".repeat(2 * 1024 * 1024));
        sqlx::query(
            "INSERT INTO jobs(
                 job_id, tenant, language, status, spec_json,
                 effective_spec_json, receipt_json, created_at_ms, admitted_mem_mb
             ) VALUES (
                 'job-501', 'tenant-a', 'python', 'queued', ?1, ?1, ?1, 42, 256
             )",
        )
        .bind(&maximal_payload)
        .execute(&mut connection)
        .await
        .unwrap();
        drop(maximal_payload);

        connection.close().await.unwrap();
        // Fixture-only raw writes are explicitly reconciled while the store
        // is still under test ownership. Ordinary reopen now fails closed on
        // a dirty current-v3 revision instead of laundering those edits.
        store.validate_integrity().await.unwrap();
        drop(store);
        // A healthy open must not return the maximal JSON blobs merely to
        // validate the summary projection.
        let store = Store::open(&db).await.unwrap();

        let summaries = store
            .list_job_summaries_page(ListJobsQuery {
                limit: 501,
                ..ListJobsQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(summaries.len(), 501);
        assert_eq!(summaries[0].job_id, "job-501");
        assert_eq!(summaries[0].tenant, "tenant-a");
        let point = store.get_job_summary("job-501").await.unwrap().unwrap();
        assert_eq!(point.job_id, "job-501");
        assert_eq!(point.status, "queued");

        // Poison an omitted column after startup. If the summary query ever
        // regresses to SELECT * (or decodes the full JobRow), SQLx will reject
        // this invalid UTF-8 value just as the compatibility API does below.
        let mut connection = raw_connection(&db).await;
        sqlx::query("DROP TRIGGER coop_jobs_storage_guard_update")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE jobs SET spec_json = CAST(X'80' AS TEXT)
             WHERE job_id = 'job-501'",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();

        assert_eq!(
            store
                .list_job_summaries_page(ListJobsQuery {
                    limit: 501,
                    ..ListJobsQuery::default()
                })
                .await
                .unwrap()
                .len(),
            501
        );
        assert_eq!(
            store
                .get_job_summary("job-501")
                .await
                .unwrap()
                .unwrap()
                .status,
            "queued"
        );
        assert!(store.get_job("job-501").await.is_err());
        assert!(store
            .list_jobs_page(ListJobsQuery {
                limit: 501,
                ..ListJobsQuery::default()
            })
            .await
            .is_err());
    });
}

#[test]
fn oversized_retention_history_is_drained_under_a_hard_event_budget() {
    sqlx::test_block_on(async {
        let db = test_db("retention-event-budget");
        let store = Store::open(&db).await.unwrap();
        let spec = "{}";
        let request = IdempotencyRequest {
            key: "heavy-retention-key".to_string(),
            request_sha256: canonical_spec_sha256(spec),
        };
        store
            .create_job_with_event_idempotent(
                "heavy",
                "tenant-a",
                "python",
                spec,
                256,
                Some(&request),
            )
            .await
            .unwrap();
        store
            .finalize_with_event("heavy", "succeeded", Some(0), 0, None)
            .await
            .unwrap()
            .unwrap();

        let legacy_rows = (MAX_RETENTION_EVENTS_PER_BATCH + 8) as i64;
        let mut connection = raw_connection(&db).await;
        sqlx::query(
            "WITH RECURSIVE sequence(n) AS (
                 VALUES(1) UNION ALL SELECT n + 1 FROM sequence WHERE n < ?2
             )
             INSERT INTO events(job_id, ts_ms, kind, data_json)
             SELECT ?1, n, 'legacy', '{}' FROM sequence",
        )
        .bind("heavy")
        .bind(legacy_rows)
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();
        store.validate_integrity().await.unwrap();

        let idempotency_bytes = 64
            + "tenant-a".len() as i64
            + request.key.len() as i64
            + request.request_sha256.len() as i64
            + "heavy".len() as i64;
        let mut connection = raw_connection(&db).await;
        let retained_before: i64 = sqlx::query_scalar(
            "SELECT retained_bytes FROM job_storage_usage WHERE job_id = 'heavy'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        let receipt_bytes: i64 = sqlx::query_scalar(
            "SELECT length(CAST(receipt_json AS BLOB)) FROM jobs WHERE job_id = 'heavy'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));
        let expected_events = legacy_rows as u64 + 2;
        let first = store.prune_older_than_batch(0, 1).await.unwrap();
        assert_eq!(first.jobs_deleted, 0);
        assert_eq!(first.events_deleted, MAX_RETENTION_EVENTS_PER_BATCH);
        assert!(first.more_remaining);
        assert!(store.get_job("heavy").await.unwrap().is_none());
        assert!(store.get_job_summary("heavy").await.unwrap().is_none());
        assert!(store.events_for("heavy").await.unwrap().is_empty());
        assert!(store.list_jobs(None, 10).await.unwrap().is_empty());
        assert_eq!(store.last_seq("heavy").await.unwrap(), 0);
        assert_eq!(
            store.event_chain_head("heavy").await.unwrap().event_count,
            0
        );
        assert!(store.count_by_status().await.unwrap().is_empty());
        let mut connection = raw_connection(&db).await;
        let physical_job: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE job_id = 'heavy'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let tombstone: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM retention_tombstones WHERE job_id = 'heavy'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let remaining_events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE job_id = 'heavy'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let mapping_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM idempotency_keys WHERE job_id = 'heavy'")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let retained_after: i64 = sqlx::query_scalar(
            "SELECT retained_bytes FROM job_storage_usage WHERE job_id = 'heavy'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(physical_job, 1);
        assert_eq!(tombstone, 1);
        assert_eq!(mapping_count, 0);
        assert_eq!(
            retained_before - retained_after,
            MAX_RETENTION_EVENTS_PER_BATCH as i64 * (64 + "legacy".len() as i64 + 2)
                + receipt_bytes
                + idempotency_bytes
        );
        assert_eq!(
            remaining_events as u64,
            expected_events - MAX_RETENTION_EVENTS_PER_BATCH
        );
        connection.close().await.unwrap();

        // A restart between chunks preserves both the hidden-state invariant
        // and the ability for the next sweep to resume draining.
        drop(store);
        let store = Store::open(&db).await.unwrap();
        assert!(store.get_job("heavy").await.unwrap().is_none());
        assert!(store.events_for("heavy").await.unwrap().is_empty());

        let second = store.prune_older_than_batch(0, 1).await.unwrap();
        assert_eq!(second.jobs_deleted, 1);
        assert_eq!(
            second.events_deleted,
            expected_events - MAX_RETENTION_EVENTS_PER_BATCH
        );
        assert!(!second.more_remaining);
        assert!(store.get_job("heavy").await.unwrap().is_none());
    });
}

#[test]
fn idempotency_mapping_bytes_are_exact_and_enforced_at_the_quota_boundary() {
    sqlx::test_block_on(async {
        let tenant = "tenant-é";
        let job_id = "quota-é";
        let spec = r#"{"language":"python","code":"print('é')"}"#;
        let request = IdempotencyRequest {
            key: "boundary-key".to_string(),
            request_sha256: canonical_spec_sha256(spec),
        };
        let mapping_bytes = 64_u64
            + tenant.len() as u64
            + request.key.len() as u64
            + request.request_sha256.len() as u64
            + job_id.len() as u64;

        let unkeyed_db = test_db("idempotency-unkeyed-charge");
        let unkeyed_store = Store::open(&unkeyed_db).await.unwrap();
        unkeyed_store
            .create_job_with_event_idempotent(job_id, tenant, "python", spec, 256, None)
            .await
            .unwrap();
        drop(unkeyed_store);
        let unkeyed_charge = total_charged_bytes(&unkeyed_db).await;

        let keyed_db = test_db("idempotency-keyed-charge");
        let keyed_store = Store::open(&keyed_db).await.unwrap();
        keyed_store
            .create_job_with_event_idempotent(job_id, tenant, "python", spec, 256, Some(&request))
            .await
            .unwrap();
        drop(keyed_store);
        let keyed_charge = total_charged_bytes(&keyed_db).await;
        assert_eq!(
            keyed_charge - unkeyed_charge,
            mapping_bytes as i64,
            "the durable mapping must charge one row overhead plus its four text fields"
        );

        let quota_db = test_db("idempotency-exact-quota");
        let unkeyed_charge = unkeyed_charge as u64;
        let limits = StorageLimits::new(unkeyed_charge * 2, unkeyed_charge, 0);
        let quota_store = Store::open_with_limits(&quota_db, limits).await.unwrap();
        let error = quota_store
            .create_job_with_event_idempotent(job_id, tenant, "python", spec, 256, Some(&request))
            .await
            .unwrap_err();
        assert_eq!(capacity_error_kind(&error), Some(CapacityErrorKind::Tenant));
        assert!(quota_store.get_job(job_id).await.unwrap().is_none());
        assert_eq!(
            quota_store
                .lookup_idempotency(tenant, &request)
                .await
                .unwrap(),
            IdempotencyLookup::Miss
        );

        quota_store
            .create_job_with_event_idempotent(job_id, tenant, "python", spec, 256, None)
            .await
            .unwrap();
        assert_eq!(total_charged_bytes(&quota_db).await, unkeyed_charge as i64);
    });
}

#[test]
fn idempotency_accounting_rebuilds_on_restart_and_releases_on_expiry() {
    sqlx::test_block_on(async {
        let db = test_db("idempotency-accounting-restart");
        let tenant = "tenant-restart";
        let job_id = "restart-job";
        let spec = r#"{"language":"python","code":"pass"}"#;
        let request = IdempotencyRequest {
            key: "restart-key".to_string(),
            request_sha256: canonical_spec_sha256(spec),
        };
        let expected_mapping_bytes = 64_i64
            + tenant.len() as i64
            + request.key.len() as i64
            + request.request_sha256.len() as i64
            + job_id.len() as i64;

        let store = Store::open(&db).await.unwrap();
        store
            .create_job_with_event_idempotent(job_id, tenant, "python", spec, 256, Some(&request))
            .await
            .unwrap();
        drop(store);

        let mut connection = raw_connection(&db).await;
        let measured_mapping_bytes: i64 = sqlx::query_scalar(
            "SELECT 64
                  + length(CAST(tenant AS BLOB))
                  + length(CAST(idempotency_key AS BLOB))
                  + length(CAST(request_sha256 AS BLOB))
                  + length(CAST(job_id AS BLOB))
             FROM idempotency_keys WHERE job_id = ?1",
        )
        .bind(job_id)
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(measured_mapping_bytes, expected_mapping_bytes);
        let retained_before: i64 =
            sqlx::query_scalar("SELECT retained_bytes FROM job_storage_usage WHERE job_id = ?1")
                .bind(job_id)
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let charged_before: i64 =
            sqlx::query_scalar("SELECT charged_bytes FROM storage_usage_total WHERE singleton = 1")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let tenant_before: i64 =
            sqlx::query_scalar("SELECT charged_bytes FROM tenant_storage_usage WHERE tenant = ?1")
                .bind(tenant)
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(charged_before, tenant_before);

        // Reproduce the revision-1 persisted state: its ledgers and aggregates
        // are internally consistent, but omit the durable idempotency row.
        sqlx::query(
            "UPDATE job_storage_usage
             SET retained_bytes = retained_bytes - ?2 WHERE job_id = ?1",
        )
        .bind(job_id)
        .bind(measured_mapping_bytes)
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE store_integrity SET accounting_validation_revision = 1
             WHERE singleton = 1",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        rewrite_accounting_guards_to_r1(&mut connection, 2).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT charged_bytes FROM storage_usage_total WHERE singleton = 1",
            )
            .fetch_one(&mut connection)
            .await
            .unwrap(),
            charged_before - measured_mapping_bytes
        );
        connection.close().await.unwrap();

        let store = Store::open(&db).await.unwrap();
        let mut connection = raw_connection(&db).await;
        let rebuilt = sqlx::query(
            "SELECT usage.retained_bytes,
                    total.charged_bytes AS total_bytes,
                    tenant_usage.charged_bytes AS tenant_bytes,
                    integrity.accounting_validation_revision
             FROM job_storage_usage AS usage
             CROSS JOIN storage_usage_total AS total
             INNER JOIN tenant_storage_usage AS tenant_usage
                ON tenant_usage.tenant = usage.tenant
             CROSS JOIN store_integrity AS integrity
             WHERE usage.job_id = ?1 AND total.singleton = 1
               AND integrity.singleton = 1",
        )
        .bind(job_id)
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(rebuilt.get::<i64, _>("retained_bytes"), retained_before);
        assert_eq!(rebuilt.get::<i64, _>("total_bytes"), charged_before);
        assert_eq!(rebuilt.get::<i64, _>("tenant_bytes"), tenant_before);
        assert_eq!(rebuilt.get::<i64, _>("accounting_validation_revision"), 2);
        connection.close().await.unwrap();
        store.validate_integrity().await.unwrap();

        store
            .finalize_with_event(job_id, "succeeded", Some(0), 1, None)
            .await
            .unwrap()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let report = store.prune_older_than_batch(0, 1).await.unwrap();
        assert_eq!(report.jobs_deleted, 1);
        assert_eq!(
            store.lookup_idempotency(tenant, &request).await.unwrap(),
            IdempotencyLookup::Miss
        );

        let mut connection = raw_connection(&db).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT charged_bytes FROM storage_usage_total WHERE singleton = 1",
            )
            .fetch_one(&mut connection)
            .await
            .unwrap(),
            0
        );
        for table in [
            "job_storage_usage",
            "tenant_storage_usage",
            "idempotency_keys",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&mut connection)
                .await
                .unwrap();
            assert_eq!(count, 0, "{table} retained an expired job charge");
        }
        connection.close().await.unwrap();
        drop(store);
        Store::open(&db)
            .await
            .unwrap()
            .validate_integrity()
            .await
            .unwrap();
    });
}

#[test]
fn logical_storage_quota_is_atomic_tenant_scoped_and_reopen_safe() {
    sqlx::test_block_on(async {
        let db = test_db("logical-quota");
        let per_job = JOB_COMPLETION_RESERVE_BYTES + 16 * 1024;
        let limits = StorageLimits::new(per_job * 3, per_job + 1024, 0);
        let store = Store::open_with_limits(&db, limits).await.unwrap();
        let spec = r#"{"language":"python","code":"print('é')","limits":{"mem_mb":64}}"#;
        store
            .create_job_with_event_idempotent("quota-one", "tenant-a", "python", spec, 64, None)
            .await
            .unwrap();
        let error = store
            .create_job_with_event_idempotent("quota-two", "tenant-a", "python", spec, 64, None)
            .await
            .unwrap_err();
        assert_eq!(capacity_error_kind(&error), Some(CapacityErrorKind::Tenant));
        assert!(store.get_job("quota-two").await.unwrap().is_none());

        store
            .create_job_with_event_idempotent("quota-other", "tenant-b", "python", spec, 64, None)
            .await
            .unwrap();
        store
            .create_job_with_event_idempotent("quota-third", "tenant-c", "python", spec, 64, None)
            .await
            .unwrap();
        let error = store
            .create_job_with_event_idempotent("quota-global", "tenant-d", "python", spec, 64, None)
            .await
            .unwrap_err();
        assert_eq!(capacity_error_kind(&error), Some(CapacityErrorKind::Global));
        drop(store);
        let reopened = Store::open_with_limits(&db, limits).await.unwrap();
        reopened.validate_integrity().await.unwrap();
    });
}

#[test]
fn restart_backfill_rebuilds_exact_reserve_and_preserves_quota_full_state() {
    sqlx::test_block_on(async {
        let db = test_db("attestation-reseed-quota");
        let limits = StorageLimits::new(75 * 1024 * 1024, 50 * 1024 * 1024, 0);
        let store = Store::open_with_limits(&db, limits).await.unwrap();
        store
            .create_job_with_event("legacy", "tenant-a", "python", "{}")
            .await
            .unwrap();
        store
            .finalize_with_event("legacy", "succeeded", Some(0), 1, None)
            .await
            .unwrap();
        assert!(store.waive_pending_attestation("legacy").await.unwrap());
        store
            .create_job_with_event("queued", "tenant-b", "python", "{}")
            .await
            .unwrap();
        drop(store);

        let reopened = Store::open_with_limits(&db, limits).await.unwrap();
        assert_eq!(
            reopened.pending_attestation_job_ids(10).await.unwrap(),
            vec!["legacy"]
        );
        let mut connection = raw_connection(&db).await;
        let reserve: i64 = sqlx::query_scalar(
            "SELECT reserved_bytes FROM job_storage_usage WHERE job_id = 'legacy'",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(reserve as u64, ATTESTATION_RESERVE_BYTES);
        let aggregates_match: i64 = sqlx::query_scalar(
            "SELECT (SELECT charged_bytes FROM storage_usage_total WHERE singleton = 1)
                    = (SELECT SUM(retained_bytes + reserved_bytes) FROM job_storage_usage)",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(aggregates_match, 1);
        connection.close().await.unwrap();

        let tenant_full = reopened
            .create_job_with_event("tenant-full", "tenant-a", "python", "{}")
            .await
            .unwrap_err();
        assert_eq!(
            capacity_error_kind(&tenant_full),
            Some(CapacityErrorKind::Tenant)
        );
        let global_full = reopened
            .create_job_with_event("global-full", "tenant-c", "python", "{}")
            .await
            .unwrap_err();
        assert_eq!(
            capacity_error_kind(&global_full),
            Some(CapacityErrorKind::Global)
        );

        assert!(reopened.waive_pending_attestation("legacy").await.unwrap());
        reopened
            .create_job_with_event("after-release", "tenant-c", "python", "{}")
            .await
            .unwrap();
        reopened.validate_integrity().await.unwrap();
    });
}

#[test]
fn accounting_revision_upgrade_repairs_idempotency_bytes_and_pending_reserve() {
    sqlx::test_block_on(async {
        let db = test_db("attestation-reserve-revision-upgrade");
        let tenant = "tenant-a";
        let job_id = "historical";
        let spec = "{}";
        let request = IdempotencyRequest {
            key: "historical-key".to_string(),
            request_sha256: canonical_spec_sha256(spec),
        };
        let store = Store::open(&db).await.unwrap();
        store
            .create_job_with_event_idempotent(job_id, tenant, "python", spec, 256, Some(&request))
            .await
            .unwrap();
        store
            .finalize_with_event(job_id, "succeeded", Some(0), 1, None)
            .await
            .unwrap();
        assert!(store.waive_pending_attestation(job_id).await.unwrap());
        drop(store);

        let mut connection = raw_connection(&db).await;
        let retained_before_outbox: i64 =
            sqlx::query_scalar("SELECT retained_bytes FROM job_storage_usage WHERE job_id = ?1")
                .bind(job_id)
                .fetch_one(&mut connection)
                .await
                .unwrap();
        let mapping_bytes: i64 = sqlx::query_scalar(
            "SELECT 64
                  + length(CAST(tenant AS BLOB))
                  + length(CAST(idempotency_key AS BLOB))
                  + length(CAST(request_sha256 AS BLOB))
                  + length(CAST(job_id AS BLOB))
             FROM idempotency_keys WHERE job_id = ?1",
        )
        .bind(job_id)
        .fetch_one(&mut connection)
        .await
        .unwrap();
        let row_revision: i64 = sqlx::query_scalar(
            "SELECT row_validation_revision FROM store_integrity WHERE singleton = 1",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO attestation_outbox(
                 job_id, pending_since_ms, attempt_count, next_attempt_ms
             ) VALUES (?1, 1, 0, 1)",
        )
        .bind(job_id)
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE job_storage_usage
             SET retained_bytes = retained_bytes
                 + 64 + length(CAST(job_id AS BLOB)) - ?2,
                 reserved_bytes = 0
             WHERE job_id = ?1",
        )
        .bind(job_id)
        .bind(mapping_bytes)
        .execute(&mut connection)
        .await
        .unwrap();
        // Recreate the clean revision emitted by the prior implementation's
        // buggy rebuild. It omitted both durable idempotency-row bytes and the
        // pending terminal reserve. Revision 2 must repair both in one trusted
        // revision-1 upgrade; genuinely dirty revision 0 still fails closed.
        sqlx::query(
            "UPDATE store_integrity
             SET row_validation_revision = ?1,
                 accounting_validation_revision = 1
             WHERE singleton = 1",
        )
        .bind(row_revision)
        .execute(&mut connection)
        .await
        .unwrap();
        // The previous clean revision also used the r1 trigger definitions
        // and transaction-local accounting sentinel 2. Reproduce that exact
        // on-disk generation so the compatibility path cannot be accidental.
        rewrite_accounting_guards_to_r1(&mut connection, 2).await;
        connection.close().await.unwrap();

        let repaired = Store::open(&db).await.unwrap();
        let mut connection = raw_connection(&db).await;
        let row = sqlx::query(
            "SELECT usage.retained_bytes, usage.reserved_bytes,
                    total.charged_bytes AS total_bytes,
                    tenant_usage.charged_bytes AS tenant_bytes,
                    integrity.accounting_validation_revision,
                    integrity.full_scan_count
             FROM job_storage_usage AS usage
             CROSS JOIN storage_usage_total AS total
             INNER JOIN tenant_storage_usage AS tenant_usage
                ON tenant_usage.tenant = usage.tenant
             CROSS JOIN store_integrity AS integrity
             WHERE usage.job_id = ?1 AND total.singleton = 1
               AND integrity.singleton = 1",
        )
        .bind(job_id)
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(
            row.get::<i64, _>("reserved_bytes") as u64,
            ATTESTATION_RESERVE_BYTES
        );
        let expected_retained = retained_before_outbox + 64 + job_id.len() as i64;
        assert_eq!(row.get::<i64, _>("retained_bytes"), expected_retained);
        let expected_charged = expected_retained + ATTESTATION_RESERVE_BYTES as i64;
        assert_eq!(row.get::<i64, _>("total_bytes"), expected_charged);
        assert_eq!(row.get::<i64, _>("tenant_bytes"), expected_charged);
        assert_eq!(row.get::<i64, _>("accounting_validation_revision"), 2);
        let full_scan_count = row.get::<i64, _>("full_scan_count");
        connection.close().await.unwrap();
        assert_eq!(
            repaired.lookup_idempotency(tenant, &request).await.unwrap(),
            IdempotencyLookup::Replay {
                job_id: job_id.to_string()
            }
        );
        assert_eq!(
            repaired.pending_attestation_job_ids(10).await.unwrap(),
            vec![job_id]
        );
        drop(repaired);

        let reopened = Store::open(&db).await.unwrap();
        let mut connection = raw_connection(&db).await;
        let reopened_full_scan_count: i64 =
            sqlx::query_scalar("SELECT full_scan_count FROM store_integrity WHERE singleton = 1")
                .fetch_one(&mut connection)
                .await
                .unwrap();
        assert_eq!(reopened_full_scan_count, full_scan_count);
        connection.close().await.unwrap();
        reopened.validate_integrity().await.unwrap();
    });
}

#[test]
fn mismatched_revision_two_and_revision_one_guards_never_take_the_fast_path() {
    sqlx::test_block_on(async {
        let db = test_db("accounting-generation-mismatch");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job_with_event("mismatch", "tenant-a", "python", "{}")
            .await
            .unwrap();
        drop(store);

        let mut connection = raw_connection(&db).await;
        rewrite_accounting_guards_to_r1(&mut connection, 2).await;
        connection.close().await.unwrap();

        // Reopen SQLite so it loads the rewritten exact r1/sentinel-2 trigger
        // generation, then mutate the ledger. With marker 2 those dirty
        // triggers deliberately do not change the revision; only coherent
        // generation/revision gating can keep this state off the fast path.
        let mut connection = raw_connection(&db).await;
        sqlx::query(
            "UPDATE job_storage_usage
             SET retained_bytes = retained_bytes + 1 WHERE job_id = 'mismatch'",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        let revision: i64 = sqlx::query_scalar(
            "SELECT accounting_validation_revision FROM store_integrity WHERE singleton = 1",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(revision, 2);
        connection.close().await.unwrap();

        let error = Store::open(&db).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("logical storage accounting disagrees with retained rows"),
            "mismatched trigger generation was not fully validated: {error}"
        );
    });
}

#[test]
fn trusted_predecessors_quarantine_unbound_attestation_once() {
    sqlx::test_block_on(async {
        for (label, accounting_revision, owned_write_sentinel) in [
            ("unbound-attestation-revision-one", 1_i64, 2_i64),
            ("unbound-attestation-storage-only-r2", 2_i64, 3_i64),
        ] {
            let db = test_db(label);
            let store = Store::open(&db).await.unwrap();
            store
                .create_job_with_event("legacy-evidence", "tenant-a", "python", "{}")
                .await
                .unwrap();
            store
                .finalize_with_event("legacy-evidence", "succeeded", Some(0), 1, None)
                .await
                .unwrap();
            let receipt_json = store
                .get_job("legacy-evidence")
                .await
                .unwrap()
                .unwrap()
                .receipt_json
                .unwrap();
            let receipt: serde_json::Value = serde_json::from_str(&receipt_json).unwrap();
            let receipt_sha256 = receipt["receipt_sha256"].as_str().unwrap();
            drop(store);

            let result_media_type = "application/vnd.coop.execution-result.v1+json";
            let (result, envelope) = unbound_attestation_bytes(
                "legacy-evidence",
                "tenant-a",
                receipt_sha256,
                result_media_type,
                "succeeded",
            );
            let result_sha256 = sha256_hex(&result);
            let envelope_sha256 = sha256_hex(&envelope);
            let mut connection = raw_connection(&db).await;
            let row_revision: i64 = sqlx::query_scalar(
                "SELECT row_validation_revision FROM store_integrity WHERE singleton = 1",
            )
            .fetch_one(&mut connection)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO job_attestations(
                 job_id, receipt_sha256, result_media_type, result_artifact,
                 result_sha256, envelope_json, envelope_sha256, key_id, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'sha256:legacy', 1)",
            )
            .bind("legacy-evidence")
            .bind(receipt_sha256)
            .bind(result_media_type)
            .bind(&result)
            .bind(&result_sha256)
            .bind(&envelope)
            .bind(&envelope_sha256)
            .execute(&mut connection)
            .await
            .unwrap();
            sqlx::query("DELETE FROM attestation_outbox WHERE job_id = 'legacy-evidence'")
                .execute(&mut connection)
                .await
                .unwrap();
            sqlx::query(
                "UPDATE job_storage_usage
             SET retained_bytes = retained_bytes
                 - (64 + length(CAST(job_id AS BLOB)))
                 + (SELECT 64
                      + length(CAST(attestation.job_id AS BLOB))
                      + length(CAST(attestation.receipt_sha256 AS BLOB))
                      + length(CAST(attestation.result_media_type AS BLOB))
                      + length(attestation.result_artifact)
                      + length(CAST(attestation.result_sha256 AS BLOB))
                      + length(attestation.envelope_json)
                      + length(CAST(attestation.envelope_sha256 AS BLOB))
                      + length(CAST(attestation.key_id AS BLOB))
                    FROM job_attestations AS attestation
                    WHERE attestation.job_id = job_storage_usage.job_id),
                 reserved_bytes = 0
             WHERE job_id = 'legacy-evidence'",
            )
            .execute(&mut connection)
            .await
            .unwrap();
            sqlx::query(
                "UPDATE store_integrity
             SET row_validation_revision = ?1,
                 accounting_validation_revision = ?2
             WHERE singleton = 1",
            )
            .bind(row_revision)
            .bind(accounting_revision)
            .execute(&mut connection)
            .await
            .unwrap();
            rewrite_accounting_guards_to_r1(&mut connection, owned_write_sentinel).await;
            connection.close().await.unwrap();

            let reopened = Store::open(&db).await.unwrap();
            assert!(reopened
                .get_attestation("legacy-evidence")
                .await
                .unwrap()
                .is_none());
            assert_eq!(
                reopened.pending_attestation_job_ids(10).await.unwrap(),
                vec!["legacy-evidence"]
            );
            let mut connection = raw_connection(&db).await;
            let reserve: i64 = sqlx::query_scalar(
                "SELECT reserved_bytes FROM job_storage_usage WHERE job_id = 'legacy-evidence'",
            )
            .fetch_one(&mut connection)
            .await
            .unwrap();
            assert_eq!(reserve as u64, ATTESTATION_RESERVE_BYTES);
            let full_scan_count: i64 = sqlx::query_scalar(
                "SELECT full_scan_count FROM store_integrity WHERE singleton = 1",
            )
            .fetch_one(&mut connection)
            .await
            .unwrap();
            connection.close().await.unwrap();

            drop(reopened);
            let reopened = Store::open(&db).await.unwrap();
            let mut connection = raw_connection(&db).await;
            let reopened_full_scan_count: i64 = sqlx::query_scalar(
                "SELECT full_scan_count FROM store_integrity WHERE singleton = 1",
            )
            .fetch_one(&mut connection)
            .await
            .unwrap();
            assert_eq!(reopened_full_scan_count, full_scan_count);
            connection.close().await.unwrap();
            reopened.validate_integrity().await.unwrap();
        }
    });
}

#[test]
fn concurrent_near_quota_creates_have_exactly_one_winner() {
    sqlx::test_block_on(async {
        let db = test_db("logical-quota-race");
        let per_job = JOB_COMPLETION_RESERVE_BYTES + 16 * 1024;
        let limits = StorageLimits::new(per_job * 2, per_job + 1024, 0);
        let store = std::sync::Arc::new(Store::open_with_limits(&db, limits).await.unwrap());
        let spec = r#"{"language":"python","code":"print(1)"}"#;
        let left_store = std::sync::Arc::clone(&store);
        let right_store = std::sync::Arc::clone(&store);
        let (left, right) = futures_util::future::join(
            async move {
                left_store
                    .create_job_with_event_idempotent(
                        "race-left",
                        "tenant-a",
                        "python",
                        spec,
                        256,
                        None,
                    )
                    .await
            },
            async move {
                right_store
                    .create_job_with_event_idempotent(
                        "race-right",
                        "tenant-a",
                        "python",
                        spec,
                        256,
                        None,
                    )
                    .await
            },
        )
        .await;
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        let failure = left.err().or_else(|| right.err()).unwrap();
        assert_eq!(
            capacity_error_kind(&failure),
            Some(CapacityErrorKind::Tenant)
        );
    });
}

#[test]
fn idempotency_is_tenant_scoped_fingerprint_bound_and_retention_coupled() {
    sqlx::test_block_on(async {
        let db = test_db("idempotency");
        let store = Store::open(&db).await.unwrap();
        let first_spec = r#"{"language":"python","code":"print(1)"}"#;
        let request = IdempotencyRequest {
            key: "opaque-key-1".to_string(),
            request_sha256: canonical_spec_sha256(first_spec),
        };
        let first = store
            .create_job_with_event_idempotent(
                "idem-job",
                "tenant-a",
                "python",
                first_spec,
                256,
                Some(&request),
            )
            .await
            .unwrap();
        assert!(matches!(first, CreateJobOutcome::Created(_)));
        drop(store);
        let store = Store::open(&db).await.unwrap();
        let replay = store
            .create_job_with_event_idempotent(
                "unused-generated-id",
                "tenant-a",
                "python",
                first_spec,
                256,
                Some(&request),
            )
            .await
            .unwrap();
        assert_eq!(
            replay,
            CreateJobOutcome::Replayed {
                job_id: "idem-job".to_string()
            }
        );
        assert_eq!(store.events_for("idem-job").await.unwrap().len(), 1);
        assert!(store
            .get_job("unused-generated-id")
            .await
            .unwrap()
            .is_none());

        let conflict_spec = r#"{"language":"python","code":"print(2)"}"#;
        let conflict = IdempotencyRequest {
            key: request.key.clone(),
            request_sha256: canonical_spec_sha256(conflict_spec),
        };
        let error = store
            .create_job_with_event_idempotent(
                "conflict-job",
                "tenant-a",
                "python",
                conflict_spec,
                256,
                Some(&conflict),
            )
            .await
            .unwrap_err();
        assert!(is_idempotency_conflict(&error));
        assert_eq!(
            store
                .lookup_idempotency("tenant-b", &request)
                .await
                .unwrap(),
            IdempotencyLookup::Miss
        );

        store
            .finalize_with_event("idem-job", "succeeded", Some(0), 1, None)
            .await
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        store.prune_older_than_batch(0, 1).await.unwrap();
        assert_eq!(
            store
                .lookup_idempotency("tenant-a", &request)
                .await
                .unwrap(),
            IdempotencyLookup::Miss
        );
    });
}

#[test]
fn current_v3_accounting_mutations_dirty_the_durable_revision_and_fail_closed() {
    sqlx::test_block_on(async {
        for (label, mutation) in [
            (
                "job-ledger",
                "UPDATE job_storage_usage SET retained_bytes = retained_bytes + 1 WHERE job_id = 'guarded'",
            ),
            (
                "global-total",
                "UPDATE storage_usage_total SET charged_bytes = charged_bytes + 1 WHERE singleton = 1",
            ),
            (
                "tenant-total",
                "UPDATE tenant_storage_usage SET charged_bytes = charged_bytes + 1 WHERE tenant = 'tenant-a'",
            ),
            (
                "idempotency",
                "DELETE FROM idempotency_keys WHERE tenant = 'tenant-a' AND idempotency_key = 'guard-key'",
            ),
            (
                "tombstone",
                "INSERT INTO retention_tombstones(job_id, marked_at_ms) VALUES ('guarded', 0)",
            ),
        ] {
            let db = test_db(label);
            let store = Store::open(&db).await.unwrap();
            let spec = r#"{"language":"python","code":"pass"}"#;
            let request = IdempotencyRequest {
                key: "guard-key".to_string(),
                request_sha256: canonical_spec_sha256(spec),
            };
            store
                .create_job_with_event_idempotent(
                    "guarded",
                    "tenant-a",
                    "python",
                    spec,
                    256,
                    Some(&request),
                )
                .await
                .unwrap();
            drop(store);

            let mut connection = raw_connection(&db).await;
            sqlx::query(mutation)
                .execute(&mut connection)
                .await
                .unwrap();
            let revision: i64 = sqlx::query_scalar(
                "SELECT accounting_validation_revision FROM store_integrity WHERE singleton = 1",
            )
            .fetch_one(&mut connection)
            .await
            .unwrap();
            assert_eq!(revision, 0, "{label} did not dirty accounting validation");
            connection.close().await.unwrap();

            let error = Store::open(&db)
                .await
                .expect_err("raw current-v3 accounting edits must fail closed");
            assert!(
                error.to_string().contains("modified outside an owned write"),
                "unexpected {label} error: {error}"
            );
        }
    });
}

#[test]
fn v3_identity_and_admitted_memory_fields_are_immutable() {
    sqlx::test_block_on(async {
        let db = test_db("v3-immutable-fields");
        let store = Store::open(&db).await.unwrap();
        let spec = r#"{"language":"python","code":"pass"}"#;
        let request = IdempotencyRequest {
            key: "immutable-key".to_string(),
            request_sha256: canonical_spec_sha256(spec),
        };
        store
            .create_job_with_event_idempotent(
                "immutable",
                "tenant-a",
                "python",
                spec,
                256,
                Some(&request),
            )
            .await
            .unwrap();

        let mut connection = raw_connection(&db).await;
        for mutation in [
            "UPDATE jobs SET job_id = 'renamed' WHERE job_id = 'immutable'",
            "UPDATE jobs SET tenant = 'tenant-b' WHERE job_id = 'immutable'",
            "UPDATE jobs SET language = 'node' WHERE job_id = 'immutable'",
            "UPDATE jobs SET spec_json = '{\"language\":\"node\",\"code\":\"pass\"}' WHERE job_id = 'immutable'",
            "UPDATE jobs SET created_at_ms = created_at_ms + 1 WHERE job_id = 'immutable'",
            "UPDATE jobs SET admitted_mem_mb = 512 WHERE job_id = 'immutable'",
            "UPDATE events SET kind = 'rewritten' WHERE job_id = 'immutable'",
            "UPDATE job_storage_usage SET tenant = 'tenant-b' WHERE job_id = 'immutable'",
            "UPDATE job_storage_usage SET requested_mem_mb = 512 WHERE job_id = 'immutable'",
            "UPDATE idempotency_keys SET idempotency_key = 'rewritten' WHERE tenant = 'tenant-a'",
            "UPDATE schema_migrations SET applied_at_ms = applied_at_ms + 1 WHERE version = 3",
            "DELETE FROM schema_migrations WHERE version = 3",
        ] {
            assert!(
                sqlx::query(mutation)
                    .execute(&mut connection)
                    .await
                    .is_err(),
                "immutable mutation unexpectedly succeeded: {mutation}"
            );
        }
        connection.close().await.unwrap();
        assert!(store.get_job("immutable").await.unwrap().is_some());
    });
}

#[test]
fn current_v3_valid_range_lifecycle_edits_are_dirty_and_fail_closed() {
    sqlx::test_block_on(async {
        let db = test_db("v3-valid-raw-lifecycle");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("raw-lifecycle", "tenant-a", "python", "{}")
            .await
            .unwrap();
        drop(store);

        let mut connection = raw_connection(&db).await;
        sqlx::query(
            "UPDATE jobs SET status = 'running', started_at_ms = 1
             WHERE job_id = 'raw-lifecycle'",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        let revisions = sqlx::query(
            "SELECT row_validation_revision, accounting_validation_revision
             FROM store_integrity WHERE singleton = 1",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(revisions.get::<i64, _>("row_validation_revision"), 0);
        assert_eq!(revisions.get::<i64, _>("accounting_validation_revision"), 0);
        connection.close().await.unwrap();

        let error = Store::open(&db).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("modified outside an owned write"),
            "unexpected raw lifecycle error: {error}"
        );
    });
}

#[test]
fn admitted_memory_ledger_mismatch_and_cross_tenant_foreign_keys_fail_closed() {
    sqlx::test_block_on(async {
        let mismatch_db = test_db("admitted-memory-ledger-mismatch");
        let store = Store::open(&mismatch_db).await.unwrap();
        let spec = r#"{"language":"python","code":"pass","limits":{"mem_mb":512}}"#;
        store
            .create_job_with_event_idempotent("memory-job", "tenant-a", "python", spec, 512, None)
            .await
            .unwrap();
        drop(store);
        let mut connection = raw_connection(&mismatch_db).await;
        sqlx::query("DROP TRIGGER coop_job_storage_guard_update")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE job_storage_usage SET requested_mem_mb = 256 WHERE job_id = 'memory-job'",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();
        let error = Store::open(&mismatch_db).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("accounting disagrees with retained rows"),
            "unexpected admitted-memory mismatch error: {error}"
        );

        let fk_db = test_db("composite-tenant-foreign-keys");
        let store = Store::open(&fk_db).await.unwrap();
        store
            .create_job("parent", "tenant-a", "python", "{}")
            .await
            .unwrap();
        let mut connection = raw_connection(&fk_db).await;
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&mut connection)
            .await
            .unwrap();
        for table in ["job_storage_usage", "idempotency_keys"] {
            let rows = sqlx::query(&format!("PRAGMA foreign_key_list({table})"))
                .fetch_all(&mut connection)
                .await
                .unwrap();
            assert_eq!(rows.len(), 2, "{table} must have one two-column FK");
            let id = rows[0].get::<i64, _>("id");
            assert!(rows.iter().all(|row| {
                row.get::<i64, _>("id") == id
                    && row.get::<String, _>("table") == "jobs"
                    && row
                        .get::<String, _>("on_delete")
                        .eq_ignore_ascii_case("CASCADE")
            }));
            let pairs = rows
                .iter()
                .map(|row| (row.get::<String, _>("from"), row.get::<String, _>("to")))
                .collect::<Vec<_>>();
            assert!(pairs.contains(&("tenant".to_string(), "tenant".to_string())));
            assert!(pairs.contains(&("job_id".to_string(), "job_id".to_string())));
        }

        let idempotency_fk_error = sqlx::query(
            "INSERT INTO idempotency_keys(
                 tenant, idempotency_key, request_sha256, job_id, created_at_ms
             ) VALUES ('tenant-b', 'wrong-tenant', ?1, 'parent', 1)",
        )
        .bind(canonical_spec_sha256("{}"))
        .execute(&mut connection)
        .await;
        assert!(idempotency_fk_error.is_err());

        let mut tx = connection.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO jobs(
                 job_id, tenant, language, status, spec_json, created_at_ms, admitted_mem_mb
             ) VALUES ('raw-parent', 'tenant-a', 'python', 'queued', '{}', 1, 256)",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        let ledger_fk_error = sqlx::query(
            "INSERT INTO job_storage_usage(
                 job_id, tenant, retained_bytes, reserved_bytes, requested_mem_mb
             ) VALUES ('raw-parent', 'tenant-b', 1, 0, 256)",
        )
        .execute(&mut *tx)
        .await;
        assert!(ledger_fk_error.is_err());
        tx.rollback().await.unwrap();
    });
}

#[test]
fn current_schema_missing_idempotency_table_fails_closed() {
    sqlx::test_block_on(async {
        let db = test_db("missing-idempotency-table");
        let store = Store::open(&db).await.unwrap();
        let spec = r#"{"language":"python","code":"print(1)"}"#;
        let request = IdempotencyRequest {
            key: "durable-key".to_string(),
            request_sha256: canonical_spec_sha256(spec),
        };
        store
            .create_job_with_event_idempotent(
                "durable-idempotent-job",
                "tenant-a",
                "python",
                spec,
                256,
                Some(&request),
            )
            .await
            .unwrap();
        drop(store);
        let mut connection = raw_connection(&db).await;
        sqlx::query("DROP TABLE idempotency_keys")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        let error = Store::open(&db)
            .await
            .expect_err("v3 mapping loss must not become an idempotency miss");
        assert!(
            error.to_string().contains("partial v3 physical schema")
                || error.to_string().contains("idempotency mappings"),
            "{error}"
        );
    });
}

#[test]
fn filesystem_reserve_rejects_growth_but_not_open_or_recovery() {
    sqlx::test_block_on(async {
        let db = test_db("filesystem-reserve");
        let limits = StorageLimits::new(i64::MAX as u64, i64::MAX as u64, u64::MAX);
        let store = Store::open_with_limits(&db, limits).await.unwrap();
        let error = store
            .create_job("blocked", "tenant-a", "python", r#"{"code":"print(1)"}"#)
            .await
            .unwrap_err();
        assert_eq!(
            capacity_error_kind(&error),
            Some(CapacityErrorKind::Filesystem)
        );
        assert!(store.get_job("blocked").await.unwrap().is_none());
        drop(store);
        Store::open_with_limits(&db, limits).await.unwrap();
    });
}

#[test]
fn retention_commit_failure_rolls_back_and_releases_the_writer() {
    sqlx::test_block_on(async {
        let db = test_db("retention-commit-rollback");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("expired", "tenant-a", "python", "{}")
            .await
            .unwrap();
        store
            .finalize_with_event("expired", "succeeded", Some(0), 0, None)
            .await
            .unwrap()
            .unwrap();

        let mut connection = raw_connection(&db).await;
        sqlx::query("CREATE TABLE retention_parent(id INTEGER PRIMARY KEY)")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE retention_child(
                 parent_id INTEGER REFERENCES retention_parent(id)
                     DEFERRABLE INITIALLY DEFERRED
             )",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER force_retention_commit_failure
             AFTER DELETE ON jobs WHEN OLD.job_id = 'expired'
             BEGIN
                 INSERT INTO retention_child(parent_id) VALUES (999);
             END",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();

        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(store.prune_older_than_batch(0, 1).await.is_err());
        assert!(store.get_job("expired").await.unwrap().is_some());
        store
            .create_job("after-failure", "tenant-a", "python", "{}")
            .await
            .unwrap();
        store.compact().await.unwrap();
    });
}

#[test]
fn migration_commit_failure_does_not_leave_partial_history() {
    sqlx::test_block_on(async {
        let db = test_db("migration-commit-rollback");
        let mut connection = raw_connection(&db).await;
        create_v2_schema(&mut connection).await;
        sqlx::query("CREATE TABLE migration_parent(id INTEGER PRIMARY KEY)")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE migration_child(
                 parent_id INTEGER REFERENCES migration_parent(id)
                     DEFERRABLE INITIALLY DEFERRED
             )",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER force_migration_commit_failure
             AFTER INSERT ON schema_migrations
             BEGIN
                 INSERT INTO migration_child(parent_id) VALUES (999);
             END",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();

        assert!(Store::open(&db).await.is_err());
        let mut connection = raw_connection(&db).await;
        let history_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_migrations")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(history_count, 2);
        let user_version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(user_version, 2);
        connection.close().await.unwrap();
    });
}

#[test]
fn rejects_blank_identity_and_invalid_json() {
    sqlx::test_block_on(async {
        let db = test_db("validation");
        let store = Store::open(&db).await.unwrap();
        assert!(store.create_job("blank", "", "python", "{}").await.is_err());
        assert!(store
            .create_job("invalid", "tenant-a", "python", "not-json")
            .await
            .is_err());
        assert!(store.list_jobs(None, 50).await.unwrap().is_empty());
    });
}

#[test]
fn schema_v3_migrates_to_v4_and_current_markers_fail_closed_on_partial_attestation_schema() {
    sqlx::test_block_on(async {
        let db = test_db("attestation-v4-migration");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job_with_event("legacy-terminal", "tenant-a", "python", "{}")
            .await
            .unwrap();
        store
            .finalize_with_event("legacy-terminal", "succeeded", Some(0), 1, None)
            .await
            .unwrap();
        drop(store);
        let mut connection = raw_connection(&db).await;
        sqlx::query("DROP TABLE attestation_outbox")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("DROP TABLE job_attestations")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("DROP TRIGGER coop_schema_migrations_storage_guard_delete")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("DELETE FROM schema_migrations WHERE version = 4")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version = 3")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        let migrated = Store::open(&db).await.unwrap();
        assert_eq!(migrated.schema_version().await.unwrap(), 4);
        assert_eq!(
            migrated.pending_attestation_job_ids(10).await.unwrap(),
            vec!["legacy-terminal"]
        );
        let mut connection = raw_connection(&db).await;
        let ledger = sqlx::query(
            "SELECT usage.retained_bytes, usage.reserved_bytes,
                    total.charged_bytes AS global_bytes,
                    tenant.charged_bytes AS tenant_bytes
             FROM job_storage_usage AS usage
             CROSS JOIN storage_usage_total AS total
             INNER JOIN tenant_storage_usage AS tenant ON tenant.tenant = usage.tenant
             WHERE usage.job_id = 'legacy-terminal' AND total.singleton = 1",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        let retained = ledger.get::<i64, _>("retained_bytes");
        assert_eq!(
            ledger.get::<i64, _>("reserved_bytes") as u64,
            ATTESTATION_RESERVE_BYTES
        );
        assert_eq!(
            ledger.get::<i64, _>("global_bytes"),
            retained + ATTESTATION_RESERVE_BYTES as i64
        );
        assert_eq!(
            ledger.get::<i64, _>("tenant_bytes"),
            retained + ATTESTATION_RESERVE_BYTES as i64
        );
        connection.close().await.unwrap();
        drop(migrated);

        let mut connection = raw_connection(&db).await;
        sqlx::query("DROP TABLE job_attestations")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        let error = Store::open(&db).await.unwrap_err();
        assert!(error.to_string().contains("partially present"), "{error}");
    });
}

#[test]
fn terminal_outbox_and_exact_attestation_persistence_are_idempotent_immutable_and_retained() {
    sqlx::test_block_on(async {
        let db = test_db("attestation-persistence");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job_with_event(
                "attested",
                "tenant-a",
                "python",
                r#"{"language":"python","code":"print(1)"}"#,
            )
            .await
            .unwrap();
        store
            .finalize_with_event(
                "attested",
                "succeeded",
                Some(0),
                4,
                Some(&json!({"policy":"default"})),
            )
            .await
            .unwrap();
        assert_eq!(
            store.pending_attestation_job_ids(10).await.unwrap(),
            vec!["attested"]
        );
        let receipt_json = store
            .get_job("attested")
            .await
            .unwrap()
            .unwrap()
            .receipt_json
            .unwrap();
        let receipt: serde_json::Value = serde_json::from_str(&receipt_json).unwrap();
        let receipt_sha256 = receipt["receipt_sha256"].as_str().unwrap();
        let result_media_type = "application/vnd.coop.execution-result.v1+json";
        let (unbound_result, unbound_envelope) = unbound_attestation_bytes(
            "attested",
            "tenant-a",
            receipt_sha256,
            result_media_type,
            "succeeded",
        );
        let unbound_result_sha256 = sha256_hex(&unbound_result);
        let unbound_envelope_sha256 = sha256_hex(&unbound_envelope);
        let unbound_error = store
            .persist_attestation(
                "attested",
                &receipt_json,
                receipt_sha256,
                result_media_type,
                &unbound_result,
                &unbound_result_sha256,
                &unbound_envelope,
                &unbound_envelope_sha256,
                "sha256:test-key",
            )
            .await
            .unwrap_err();
        assert!(
            unbound_error
                .to_string()
                .contains("authoritative job tenant"),
            "{unbound_error}"
        );
        assert_eq!(
            store.pending_attestation_job_ids(10).await.unwrap(),
            vec!["attested"]
        );

        let (result, envelope) = bound_attestation_bytes(
            "attested",
            "tenant-a",
            receipt_sha256,
            result_media_type,
            "succeeded",
        );
        let result_sha256 = sha256_hex(&result);
        let envelope_sha256 = sha256_hex(&envelope);
        let outcome = store
            .persist_attestation(
                "attested",
                &receipt_json,
                receipt_sha256,
                result_media_type,
                &result,
                &result_sha256,
                &envelope,
                &envelope_sha256,
                "sha256:test-key",
            )
            .await
            .unwrap();
        assert_eq!(outcome, PersistAttestationOutcome::Created);
        assert!(store
            .pending_attestation_job_ids(10)
            .await
            .unwrap()
            .is_empty());
        let stored = store.get_attestation("attested").await.unwrap().unwrap();
        assert_eq!(stored.result_artifact, result);
        assert_eq!(stored.envelope_json, envelope);
        assert_eq!(stored.metadata.receipt_sha256, receipt_sha256);

        let replay = store
            .persist_attestation(
                "attested",
                &receipt_json,
                receipt_sha256,
                result_media_type,
                &result,
                &result_sha256,
                &envelope,
                &envelope_sha256,
                "sha256:test-key",
            )
            .await
            .unwrap();
        assert_eq!(replay, PersistAttestationOutcome::Existing);
        let different = br#"{"job_id":"attested","status":"failed"}"#;
        let different_sha = sha256_hex(different);
        let error = store
            .persist_attestation(
                "attested",
                &receipt_json,
                receipt_sha256,
                "application/vnd.coop.execution-result.v1+json",
                different,
                &different_sha,
                &envelope,
                &envelope_sha256,
                "sha256:test-key",
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("immutable"), "{error}");

        drop(store);
        let mut connection = raw_connection(&db).await;
        sqlx::query(
            "UPDATE store_integrity
             SET accounting_validation_revision = 1
             WHERE singleton = 1",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        rewrite_accounting_guards_to_r1(&mut connection, 2).await;
        connection.close().await.unwrap();
        let store = Store::open(&db).await.unwrap();
        let preserved = store.get_attestation("attested").await.unwrap().unwrap();
        assert_eq!(preserved.result_artifact, result);
        assert_eq!(preserved.envelope_json, envelope);
        assert!(store
            .pending_attestation_job_ids(10)
            .await
            .unwrap()
            .is_empty());

        let (jobs, _) = store.prune_older_than(0).await.unwrap();
        assert_eq!(jobs, 1);
        assert!(store.get_attestation("attested").await.unwrap().is_none());
    });
}

#[test]
fn raw_attestation_byte_tampering_dirties_validation_and_fails_reopen() {
    sqlx::test_block_on(async {
        let db = test_db("attestation-tamper");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job_with_event("job", "tenant-a", "python", "{}")
            .await
            .unwrap();
        store
            .finalize_with_event("job", "succeeded", Some(0), 1, None)
            .await
            .unwrap();
        let receipt_json = store
            .get_job("job")
            .await
            .unwrap()
            .unwrap()
            .receipt_json
            .unwrap();
        let receipt: serde_json::Value = serde_json::from_str(&receipt_json).unwrap();
        let receipt_sha256 = receipt["receipt_sha256"].as_str().unwrap();
        let result_media_type = "application/json";
        let (result, envelope) = bound_attestation_bytes(
            "job",
            "tenant-a",
            receipt_sha256,
            result_media_type,
            "succeeded",
        );
        let result_sha256 = sha256_hex(&result);
        let envelope_sha256 = sha256_hex(&envelope);
        store
            .persist_attestation(
                "job",
                &receipt_json,
                receipt_sha256,
                result_media_type,
                &result,
                &result_sha256,
                &envelope,
                &envelope_sha256,
                "sha256:test",
            )
            .await
            .unwrap();
        drop(store);
        let mut connection = raw_connection(&db).await;
        assert!(sqlx::query(
            "UPDATE job_attestations
             SET result_artifact = CAST('{\"ok\":false}' AS BLOB)
             WHERE job_id = 'job'",
        )
        .execute(&mut connection)
        .await
        .is_err());
        // Even if an offline writer first removes the immutable-update guard,
        // startup validation still catches the exact-byte digest mismatch.
        sqlx::query("DROP TRIGGER coop_attestations_storage_guard_update")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE job_attestations
             SET result_artifact = CAST('{\"ok\":false}' AS BLOB)
             WHERE job_id = 'job'",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();
        let error = Store::open(&db).await.unwrap_err();
        assert!(error.to_string().contains("digest mismatch"), "{error}");
    });
}

#[cfg(unix)]
#[test]
fn database_parent_file_and_sidecars_are_owner_only() {
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;

    sqlx::test_block_on(async {
        let db = test_db("permissions");
        let store = Store::open(&db).await.unwrap();
        store
            .create_job("job", "tenant-a", "python", "{}")
            .await
            .unwrap();
        store.compact().await.unwrap();
        assert_eq!(
            std::fs::metadata(db.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&db).unwrap().permissions().mode() & 0o777,
            0o600
        );
        for suffix in ["-wal", "-shm"] {
            let candidate = PathBuf::from(format!("{}{suffix}", db.display()));
            if candidate.exists() {
                assert_eq!(
                    std::fs::metadata(candidate).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }

        let symlink_db = test_db("symlink");
        std::fs::create_dir_all(symlink_db.parent().unwrap()).unwrap();
        let target = symlink_db.with_extension("target");
        std::fs::write(&target, []).unwrap();
        symlink(&target, &symlink_db).unwrap();
        assert!(Store::open(&symlink_db).await.is_err());
    });
}
