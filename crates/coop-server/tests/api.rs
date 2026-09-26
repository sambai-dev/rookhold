use axum::body::Body;
use axum::http::{header, Request, StatusCode, Version};
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use coop_attestation::{
    bytes_to_hex, dsse_v1_pae, key_id, verify_attestation, write_private_key_file_new,
    ArtifactDigest, SigningKey, VerificationPolicy, DSSE_PAYLOAD_TYPE,
};
use coop_server::config::Config;
use coop_server::scheduler;
use coop_store::Store;
use ed25519_dalek::Signer as _;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, SqliteConnection};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;

const TERMINAL: [&str; 6] = [
    "succeeded",
    "failed",
    "timed_out",
    "oom_killed",
    "cancelled",
    "error",
];

fn test_config(db: &std::path::Path) -> Config {
    let mut api_keys = HashMap::new();
    api_keys.insert("test-key".to_string(), "t1".to_string());
    api_keys.insert("other-key".to_string(), "t2".to_string());
    Config {
        attestation_mode: coop_server::config::AttestationMode::Off,
        attestation_key_file: None,
        addr: "127.0.0.1:0".to_string(),
        db_path: db.to_string_lossy().into_owned(),
        api_keys,
        metrics_token: Some("test-metrics-token".to_string()),
        credentials: Default::default(),
        jwt: None,
        workers: 2,
        tenant_concurrency: 4,
        tenant_queue_capacity: 64,
        rate_per_min: 10_000,
        max_job_mem_mb: 1024,
        memory_budget_mb: 4096,
        storage_global_mb: 16 * 1024,
        storage_tenant_mb: 4 * 1024,
        storage_free_reserve_mb: 0,
        sandbox: "off".to_string(),
        jobs_root: std::env::temp_dir()
            .join(format!("coop-jobs-test-{}", uuid::Uuid::now_v7()))
            .to_string_lossy()
            .into_owned(),
        rootfs: None,
        sandbox_helper: None,
        gvisor_runsc: None,
        gvisor_rootfs_sha256: None,
        gvisor_platform: "systrap".to_string(),
        gvisor_uid: 65_534,
        gvisor_gid: 65_534,
        production: false,
        unsafe_allow_naive: false,
        unsafe_allow_public_dev: false,
        python_bin: None,
        node_bin: None,
        bash_bin: None,
        retention_hours: 0,
        sweep_interval_secs: 3600,
        seccomp: false,
    }
}

fn loopback_addr() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

async fn raw_connection(db: &std::path::Path) -> SqliteConnection {
    SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .filename(db)
            .create_if_missing(true),
    )
    .await
    .unwrap()
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

fn legacy_unbound_signed_bytes(
    job_id: &str,
    receipt_sha256: &str,
    receipt: &serde_json::Value,
    result_media_type: &str,
    signing_key: &SigningKey,
) -> (Vec<u8>, Vec<u8>) {
    let artifact = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "job_id": job_id,
        "receipt_sha256": receipt_sha256,
        "status": "succeeded",
    }))
    .unwrap();
    let artifact_sha256 = bytes_to_hex(Sha256::digest(&artifact).as_slice());
    let subject_name = format!("coop://jobs/{job_id}/result");
    let statement = serde_json::to_vec(&serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{
            "name": subject_name.clone(),
            "digest": {"sha256": artifact_sha256.clone()},
            "mediaType": result_media_type,
        }],
        "predicateType": "https://github.com/sambai-dev/coop/blob/main/crates/coop-attestation/FORMAT.md#predicate-v1",
        "predicate": {
            "schemaVersion": 1,
            "executionId": job_id,
            "result": {
                "name": subject_name,
                "mediaType": result_media_type,
                "sizeBytes": artifact.len(),
                "sha256": artifact_sha256,
            },
            "receipt": receipt,
        },
    }))
    .unwrap();
    let pae = dsse_v1_pae(DSSE_PAYLOAD_TYPE, &statement).unwrap();
    let envelope = serde_json::to_vec(&serde_json::json!({
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": BASE64_STANDARD.encode(statement),
        "signatures": [{
            "keyid": "sha256:legacy",
            "sig": BASE64_STANDARD.encode(signing_key.sign(&pae).to_bytes()),
        }],
    }))
    .unwrap();
    (artifact, envelope)
}

async fn spawn_app() -> Router {
    spawn_app_with_limits(2, 4).await
}

async fn spawn_app_with_limits(workers: usize, tenant_concurrency: usize) -> Router {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let mut cfg = test_config(&db);
    cfg.workers = workers;
    cfg.tenant_concurrency = tenant_concurrency;
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (app, state, queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .expect("build app");
    scheduler::spawn_workers(state, queue_rx);
    app
}

async fn build_scoped_app() -> (Router, coop_server::AppState, HashMap<&'static str, String>) {
    let db = std::env::temp_dir().join(format!("coop-scoped-test-{}.db", uuid::Uuid::now_v7()));
    let root =
        std::env::temp_dir().join(format!("coop-scoped-credentials-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&root).unwrap();
    let pepper = [0x42_u8; 32];
    let mut keys = HashMap::new();
    for (name, marker) in [
        ("submit", 'a'),
        ("read", 'b'),
        ("cancel", 'c'),
        ("service", 'd'),
        ("metrics", 'e'),
        ("other-read", 'f'),
        ("other-cancel", 'g'),
    ] {
        keys.insert(
            name,
            format!("coop_{name}_{}", marker.to_string().repeat(43)),
        );
    }
    let scopes = [
        ("submit", "tenant-a", "jobs:submit"),
        ("read", "tenant-a", "jobs:read"),
        ("cancel", "tenant-a", "jobs:cancel"),
        ("service", "tenant-a", "service:read"),
        ("metrics", "tenant-a", "metrics:read"),
        ("other-read", "tenant-b", "jobs:read"),
        ("other-cancel", "tenant-b", "jobs:cancel"),
    ];
    let credentials = scopes
        .into_iter()
        .map(|(name, tenant, scope)| {
            let key = keys.get(name).unwrap();
            let mut hmac = Hmac::<Sha256>::new_from_slice(&pepper).unwrap();
            hmac.update(key.as_bytes());
            let digest = hmac.finalize().into_bytes();
            serde_json::json!({
                "key_id": name,
                "tenant_id": tenant,
                "principal_id": format!("principal-{name}"),
                "digest_hmac_sha256": digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                "scopes": [scope],
                "created_at_ms": 1,
                "expires_at_ms": i64::MAX
            })
        })
        .collect::<Vec<_>>();
    let credentials_path = root.join("credentials.json");
    let pepper_path = root.join("pepper");
    std::fs::write(
        &credentials_path,
        serde_json::json!({"version":1,"credentials":credentials}).to_string(),
    )
    .unwrap();
    std::fs::write(
        &pepper_path,
        pepper
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .unwrap();
    let mut cfg = test_config(&db);
    cfg.api_keys.clear();
    cfg.credentials =
        coop_server::auth::CredentialStore::load(&credentials_path, &pepper_path, false).unwrap();
    let store = Arc::new(Store::open(&db).await.unwrap());
    let (app, state, queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .unwrap();
    tokio::spawn(async move {
        let _queue_rx = queue_rx;
        std::future::pending::<()>().await;
    });
    (app, state, keys)
}

async fn spawn_scoped_app() -> (Router, HashMap<&'static str, String>) {
    let (app, _state, keys) = build_scoped_app().await;
    (app, keys)
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let res = app.clone().oneshot(req).await.expect("oneshot");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .expect("body");
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::String(
            String::from_utf8_lossy(&bytes).into_owned(),
        ))
    };
    (status, value)
}

async fn start_http1_server(
    app: Router,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<io::Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP/1 regression listener");
    let address = listener.local_addr().expect("HTTP/1 listener address");
    let listener =
        coop_server::transport::WriteTimeoutListener::new(listener, Duration::from_secs(1));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        coop_server::transport::serve(listener, app, async {
            let _ = shutdown_rx.await;
        })
        .await
    });
    (address, shutdown_tx, server)
}

async fn read_http_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut chunk = [0_u8; 1_024];
    loop {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP peer closed before a complete response head",
            ));
        }
        response.extend_from_slice(&chunk[..count]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(response);
        }
        if response.len() > 16 * 1_024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response head exceeded 16 KiB",
            ));
        }
    }
}

async fn wait_for_peer_close(stream: &mut TcpStream) -> io::Result<()> {
    let mut buffer = [0_u8; 1_024];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(())
            }
            Err(error) => return Err(error),
        }
    }
}

async fn assert_partial_http1_submit_closes(
    address: std::net::SocketAddr,
    key: Option<&str>,
    content_type: &str,
    expected: StatusCode,
) {
    let authorization = key.map_or_else(String::new, |key| {
        format!("Authorization: Bearer {key}\r\n")
    });
    let request = format!(
        "POST /v1/jobs HTTP/1.1\r\nHost: coop.test\r\n{authorization}Content-Type: {content_type}\r\nContent-Length: 1048576\r\nConnection: keep-alive\r\n\r\n{{"
    );
    assert_incomplete_http1_request_closes(address, &request, expected).await;
}

async fn assert_incomplete_http1_request_closes(
    address: std::net::SocketAddr,
    request: &str,
    expected: StatusCode,
) {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect HTTP/1 regression client");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write deliberately incomplete HTTP/1 request");

    let response = tokio::time::timeout(Duration::from_secs(1), read_http_head(&mut stream))
        .await
        .expect("early rejection response deadline")
        .expect("read early rejection response");
    let response = String::from_utf8_lossy(&response).to_ascii_lowercase();
    assert!(
        response.starts_with(&format!("http/1.1 {}", expected.as_u16())),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("\r\nconnection: close\r\n"),
        "HTTP/1 early rejection did not announce connection close: {response}"
    );
    tokio::time::timeout(Duration::from_secs(1), wait_for_peer_close(&mut stream))
        .await
        .expect("incomplete HTTP/1 body was closed instead of drained")
        .expect("observe HTTP/1 peer close");
}

async fn assert_complete_json_rejection_is_http1_reusable(
    address: std::net::SocketAddr,
    key: &str,
    rejected_json: &str,
    chunked: bool,
) {
    let first = if chunked {
        format!(
            "POST /v1/jobs HTTP/1.1\r\nHost: coop.test\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n{:x}\r\n{rejected_json}\r\n0\r\n\r\n",
            rejected_json.len()
        )
    } else {
        format!(
            "POST /v1/jobs HTTP/1.1\r\nHost: coop.test\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{rejected_json}",
            rejected_json.len()
        )
    };
    let request =
        format!("{first}GET /healthz HTTP/1.1\r\nHost: coop.test\r\nConnection: close\r\n\r\n");
    let mut stream = TcpStream::connect(address)
        .await
        .expect("connect reusable HTTP/1 regression client");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("pipeline malformed submission and health probe");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("reused HTTP/1 response deadline")
        .expect("read reused HTTP/1 responses");
    let response = String::from_utf8_lossy(&response).to_ascii_lowercase();
    let first_head = response
        .split_once("\r\n\r\n")
        .map(|(head, _)| head)
        .expect("first HTTP/1 response head");
    assert!(first_head.starts_with("http/1.1 400"), "{response}");
    assert!(
        !first_head.contains("\r\nconnection: close"),
        "fully consumed malformed JSON must retain keep-alive: {response}"
    );
    assert!(
        response.contains("http/1.1 200"),
        "the same HTTP/1 connection did not serve the pipelined health probe: {response}"
    );
}

async fn assert_early_http2_submit_stays_session_local(
    app: &Router,
    key: Option<&str>,
    content_type: &str,
    expected: StatusCode,
) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/jobs")
        .version(Version::HTTP_2)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, "1048576");
    if let Some(key) = key {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from("{")).expect("HTTP/2 request"))
        .await
        .expect("HTTP/2 response");
    assert_eq!(response.status(), expected);
    assert!(
        !response.headers().contains_key(header::CONNECTION),
        "HTTP/2 rejection must reset only its stream"
    );
}

fn request(method: &str, uri: &str, key: Option<&str>, body: Option<String>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(k) = key {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {k}"));
    }
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    builder
        .body(Body::from(body.unwrap_or_default()))
        .expect("request")
}

async fn send_idempotent(
    app: &Router,
    idempotency_key: &str,
    body: &str,
) -> (StatusCode, Option<String>, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/jobs")
                .header(header::AUTHORIZATION, "Bearer test-key")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", idempotency_key)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let replayed = response
        .headers()
        .get("idempotency-replayed")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, replayed, serde_json::from_slice(&bytes).unwrap())
}

async fn wait_terminal(app: &Router, job_id: &str) -> serde_json::Value {
    wait_terminal_with_key(app, job_id, "test-key").await
}

async fn wait_terminal_with_key(app: &Router, job_id: &str, key: &str) -> serde_json::Value {
    for _ in 0..150 {
        let (status, body) = send(
            app,
            request("GET", &format!("/v1/jobs/{job_id}"), Some(key), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        if body["status"]
            .as_str()
            .map(|s| TERMINAL.contains(&s))
            .unwrap_or(false)
        {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("job {job_id} did not reach a terminal state in time");
}

#[tokio::test]
async fn signed_attestation_surfaces_return_exact_verifiable_tenant_scoped_bytes() {
    let root = std::env::temp_dir().join(format!("coop-api-attestation-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&root).unwrap();
    let db = root.join("coop.db");
    let key_path = root.join("attestation-key.pem");
    let signing_key = SigningKey::from_bytes(&[37_u8; 32]);
    let verifying_key = signing_key.verifying_key();
    write_private_key_file_new(&key_path, &signing_key).unwrap();

    let mut cfg = test_config(&db);
    cfg.attestation_mode = coop_server::config::AttestationMode::Sign;
    cfg.attestation_key_file = Some(key_path.to_string_lossy().into_owned());
    let store = Arc::new(Store::open(&db).await.unwrap());
    let (app, _state, _queue_rx) = coop_server::build_app(cfg, Arc::clone(&store), loopback_addr())
        .await
        .unwrap();
    store
        .create_job_with_event(
            "signed-job",
            "t1",
            "python",
            r#"{"language":"python","code":"print(1)"}"#,
        )
        .await
        .unwrap();
    store
        .append_event("signed-job", "stdout", &serde_json::json!({"line":"hello"}))
        .await
        .unwrap();
    store
        .finalize_with_event(
            "signed-job",
            "succeeded",
            Some(0),
            2,
            Some(&serde_json::json!({"policy":"default"})),
        )
        .await
        .unwrap();

    let mut signed_detail = None;
    for _ in 0..200 {
        let (status, detail) = send(
            &app,
            request("GET", "/v1/jobs/signed-job", Some("test-key"), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{detail}");
        if detail["attestation"]["available"] == true {
            signed_detail = Some(detail);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let detail = signed_detail.expect("attestation worker did not persist the signed job");
    assert_eq!(detail["attestation"]["tenant"], "t1");
    assert_eq!(
        detail["attestation"]["envelope_url"],
        "/v1/jobs/signed-job/attestation"
    );

    let capabilities = send(
        &app,
        request("GET", "/v1/capabilities", Some("test-key"), None),
    )
    .await;
    assert_eq!(capabilities.0, StatusCode::OK);
    assert_eq!(capabilities.1["features"]["signed_attestations"], true);
    assert_eq!(capabilities.1["attestations"]["enabled"], true);
    assert_eq!(
        capabilities.1["attestations"]["public_key_url"],
        "/v1/attestation/public-key"
    );
    let (public_status, public) = send(
        &app,
        request("GET", "/v1/attestation/public-key", Some("test-key"), None),
    )
    .await;
    assert_eq!(public_status, StatusCode::OK, "{public}");
    assert_eq!(public["algorithm"], "Ed25519");
    assert!(public["trust_notice"]
        .as_str()
        .unwrap()
        .contains("not a trust anchor"));

    for path in [
        "/v1/jobs/signed-job/attestation",
        "/v1/jobs/signed-job/result-artifact",
    ] {
        let (foreign_status, foreign) =
            send(&app, request("GET", path, Some("other-key"), None)).await;
        assert_eq!(foreign_status, StatusCode::NOT_FOUND, "{foreign}");
        assert_eq!(foreign["error"]["code"], "job_not_found");
    }

    let envelope_response = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/jobs/signed-job/attestation",
            Some("test-key"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(envelope_response.status(), StatusCode::OK);
    assert_eq!(
        envelope_response.headers()[header::CONTENT_TYPE],
        coop_server::attestation::DSSE_ENVELOPE_MEDIA_TYPE
    );
    let envelope_sha256 = envelope_response.headers()["x-content-sha256"]
        .to_str()
        .unwrap()
        .to_string();
    let envelope = axum::body::to_bytes(envelope_response.into_body(), 3 << 20)
        .await
        .unwrap();
    assert_eq!(
        bytes_to_hex(Sha256::digest(&envelope).as_slice()),
        envelope_sha256
    );

    let result_response = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/jobs/signed-job/result-artifact",
            Some("test-key"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(result_response.status(), StatusCode::OK);
    assert_eq!(
        result_response.headers()[header::CONTENT_TYPE],
        coop_server::attestation::RESULT_ARTIFACT_MEDIA_TYPE
    );
    let result = axum::body::to_bytes(result_response.into_body(), 17 << 20)
        .await
        .unwrap();
    let digest = ArtifactDigest::from_bytes(&result);
    let verified = verify_attestation(
        &envelope,
        &digest,
        &[verifying_key],
        &VerificationPolicy::default()
            .with_tenant("t1")
            .with_subject_name("coop://jobs/signed-job/result")
            .with_media_type(coop_server::attestation::RESULT_ARTIFACT_MEDIA_TYPE),
    )
    .unwrap();
    assert_eq!(
        verified.statement().predicate().execution_id(),
        "signed-job"
    );
    assert_eq!(verified.statement().predicate().tenant(), "t1");
    let artifact: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(artifact["tenant"], "t1");
    assert_eq!(artifact["stdout"], "hello");
    assert_eq!(artifact["receipt_sha256"], detail["receipt_sha256"]);
}

#[tokio::test]
async fn restart_quarantines_unbound_evidence_before_api_advertisement_and_resigns() {
    let root = std::env::temp_dir().join(format!(
        "coop-api-unbound-attestation-upgrade-{}",
        uuid::Uuid::now_v7()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let db = root.join("coop.db");
    let key_path = root.join("attestation-key.pem");
    let signing_key = SigningKey::from_bytes(&[53_u8; 32]);
    let verifying_key = signing_key.verifying_key();
    write_private_key_file_new(&key_path, &signing_key).unwrap();

    let seed = Store::open(&db).await.unwrap();
    seed.create_job_with_event(
        "legacy-signed",
        "t1",
        "python",
        r#"{"language":"python","code":"print(1)"}"#,
    )
    .await
    .unwrap();
    seed.finalize_with_event("legacy-signed", "succeeded", Some(0), 1, None)
        .await
        .unwrap();
    let receipt_json = seed
        .get_job("legacy-signed")
        .await
        .unwrap()
        .unwrap()
        .receipt_json
        .unwrap();
    let receipt: serde_json::Value = serde_json::from_str(&receipt_json).unwrap();
    let receipt_sha256 = receipt["receipt_sha256"].as_str().unwrap();
    let result_media_type = coop_server::attestation::RESULT_ARTIFACT_MEDIA_TYPE;
    let (legacy_result, legacy_envelope) = legacy_unbound_signed_bytes(
        "legacy-signed",
        receipt_sha256,
        &receipt,
        result_media_type,
        &signing_key,
    );
    assert!(verify_attestation(
        &legacy_envelope,
        &ArtifactDigest::from_bytes(&legacy_result),
        &[verifying_key],
        &VerificationPolicy::default().with_tenant("t1"),
    )
    .is_err());
    drop(seed);

    let legacy_result_sha256 = bytes_to_hex(Sha256::digest(&legacy_result).as_slice());
    let legacy_envelope_sha256 = bytes_to_hex(Sha256::digest(&legacy_envelope).as_slice());
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
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
    )
    .bind("legacy-signed")
    .bind(receipt_sha256)
    .bind(result_media_type)
    .bind(&legacy_result)
    .bind(&legacy_result_sha256)
    .bind(&legacy_envelope)
    .bind(&legacy_envelope_sha256)
    .bind(key_id(&verifying_key))
    .execute(&mut connection)
    .await
    .unwrap();
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
    rewrite_accounting_guards_to_r1(&mut connection, 2).await;
    connection.close().await.unwrap();

    let store = Arc::new(Store::open(&db).await.unwrap());
    assert!(store
        .get_attestation("legacy-signed")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        store.pending_attestation_job_ids(10).await.unwrap(),
        vec!["legacy-signed"]
    );

    let (off_app, off_state, _off_queue_rx) =
        coop_server::build_app(test_config(&db), Arc::clone(&store), loopback_addr())
            .await
            .unwrap();
    let (off_status, off_detail) = send(
        &off_app,
        request("GET", "/v1/jobs/legacy-signed", Some("test-key"), None),
    )
    .await;
    assert_eq!(off_status, StatusCode::OK, "{off_detail}");
    assert_eq!(off_detail["attestation"]["available"], false);
    assert_eq!(off_detail["attestation"]["tenant"], serde_json::Value::Null);
    off_state.begin_shutdown();
    drop(off_app);
    drop(off_state);
    drop(store);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let store = Arc::new(Store::open(&db).await.unwrap());
    assert_eq!(
        store.pending_attestation_job_ids(10).await.unwrap(),
        vec!["legacy-signed"]
    );

    let mut cfg = test_config(&db);
    cfg.attestation_mode = coop_server::config::AttestationMode::Sign;
    cfg.attestation_key_file = Some(key_path.to_string_lossy().into_owned());
    let (app, _state, _queue_rx) = coop_server::build_app(cfg, Arc::clone(&store), loopback_addr())
        .await
        .unwrap();
    let mut detail = serde_json::Value::Null;
    for _ in 0..200 {
        let response = send(
            &app,
            request("GET", "/v1/jobs/legacy-signed", Some("test-key"), None),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        detail = response.1;
        if detail["attestation"]["available"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(detail["attestation"]["available"], true, "{detail}");
    assert_eq!(detail["attestation"]["tenant"], "t1");

    let envelope_response = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/jobs/legacy-signed/attestation",
            Some("test-key"),
            None,
        ))
        .await
        .unwrap();
    let envelope = axum::body::to_bytes(envelope_response.into_body(), 3 << 20)
        .await
        .unwrap();
    let result_response = app
        .clone()
        .oneshot(request(
            "GET",
            "/v1/jobs/legacy-signed/result-artifact",
            Some("test-key"),
            None,
        ))
        .await
        .unwrap();
    let result = axum::body::to_bytes(result_response.into_body(), 17 << 20)
        .await
        .unwrap();
    assert_ne!(&envelope[..], legacy_envelope.as_slice());
    assert_ne!(&result[..], legacy_result.as_slice());
    let verified = verify_attestation(
        &envelope,
        &ArtifactDigest::from_bytes(&result),
        &[verifying_key],
        &VerificationPolicy::default().with_tenant("t1"),
    )
    .unwrap();
    assert_eq!(verified.statement().predicate().tenant(), "t1");
    let result: serde_json::Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(result["tenant"], "t1");
}

fn python_name() -> &'static str {
    if cfg!(windows) {
        "python"
    } else {
        "python3"
    }
}

fn python_available() -> bool {
    std::process::Command::new(python_name())
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn rejects_missing_api_key() {
    let app = spawn_app().await;
    let response = app
        .oneshot(request(
            "POST",
            "/v1/jobs",
            None,
            Some(r#"{"language":"python","code":"print(1)"}"#.into()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE),
        Some(&header::HeaderValue::from_static(
            "Bearer realm=\"rookhold\""
        ))
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "missing_api_key", "{body}");
    assert!(body["error"]["request_id"].is_string(), "{body}");
    assert_eq!(body["error"]["retryable"], false, "{body}");
}

#[tokio::test]
async fn invalid_and_malformed_bearers_return_rfc6750_challenges() {
    let app = spawn_app().await;
    let invalid = app
        .clone()
        .oneshot(request("GET", "/v1/whoami", Some("wrong-key"), None))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        invalid.headers().get(header::WWW_AUTHENTICATE),
        Some(&header::HeaderValue::from_static(
            "Bearer realm=\"rookhold\", error=\"invalid_token\""
        ))
    );

    let malformed = app
        .oneshot(
            Request::builder()
                .uri("/v1/whoami")
                .header(header::AUTHORIZATION, "Basic secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        malformed.headers().get(header::WWW_AUTHENTICATE),
        Some(&header::HeaderValue::from_static(
            "Bearer realm=\"rookhold\", error=\"invalid_request\""
        ))
    );
}

#[tokio::test]
async fn early_submit_rejections_close_http1_bodies_without_closing_http2_sessions() {
    let (app, state, keys) = build_scoped_app().await;
    let key = |name| keys.get(name).unwrap().as_str();

    // Framing is the exact HTTP/1 drain boundary. Zero/no body does not need
    // a connection close, while any nonzero or transfer-coded body fails
    // closed when an early layer returns before extraction.
    for (framing, should_close) in [
        (None, false),
        (Some((header::CONTENT_LENGTH, "0")), false),
        (Some((header::CONTENT_LENGTH, "00")), true),
        (Some((header::TRANSFER_ENCODING, "chunked")), true),
    ] {
        let framing_label = format!("{framing:?}");
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/jobs")
            .version(Version::HTTP_11)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some((name, value)) = framing {
            builder = builder.header(name, value);
        }
        let response = app
            .clone()
            .oneshot(builder.body(Body::from("{")).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().contains_key(header::CONNECTION),
            should_close,
            "unexpected close policy for framing {framing_label}"
        );
    }

    let (address, shutdown, server) = start_http1_server(app.clone()).await;

    assert_partial_http1_submit_closes(address, None, "application/json", StatusCode::UNAUTHORIZED)
        .await;
    assert_incomplete_http1_request_closes(
        address,
        "POST /v1/jobs HTTP/1.1\r\nHost: coop.test\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n1\r\n{\r\n",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_partial_http1_submit_closes(
        address,
        Some(key("read")),
        "application/json",
        StatusCode::FORBIDDEN,
    )
    .await;

    let body_capacity = [
        state.submit_body_admission.try_acquire("holder-a").unwrap(),
        state.submit_body_admission.try_acquire("holder-a").unwrap(),
        state.submit_body_admission.try_acquire("holder-b").unwrap(),
        state.submit_body_admission.try_acquire("holder-b").unwrap(),
    ];
    assert_partial_http1_submit_closes(
        address,
        Some(key("submit")),
        "application/json",
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    drop(body_capacity);

    assert_partial_http1_submit_closes(
        address,
        Some(key("submit")),
        "text/plain",
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
    )
    .await;
    for rejected_json in [
        r#"{"language":"python","code":}"#,
        r#"{"language":1,"code":"print(1)"}"#,
    ] {
        for chunked in [false, true] {
            assert_complete_json_rejection_is_http1_reusable(
                address,
                key("submit"),
                rejected_json,
                chunked,
            )
            .await;
        }
    }

    assert_early_http2_submit_stays_session_local(
        &app,
        None,
        "application/json",
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_early_http2_submit_stays_session_local(
        &app,
        Some(key("read")),
        "application/json",
        StatusCode::FORBIDDEN,
    )
    .await;
    let body_capacity = [
        state.submit_body_admission.try_acquire("holder-a").unwrap(),
        state.submit_body_admission.try_acquire("holder-a").unwrap(),
        state.submit_body_admission.try_acquire("holder-b").unwrap(),
        state.submit_body_admission.try_acquire("holder-b").unwrap(),
    ];
    assert_early_http2_submit_stays_session_local(
        &app,
        Some(key("submit")),
        "application/json",
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    drop(body_capacity);
    assert_early_http2_submit_stays_session_local(
        &app,
        Some(key("submit")),
        "text/plain",
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
    )
    .await;

    let semantic_body = r#"{"language":"not-a-runtime","code":"print(1)"}"#;
    let semantic_rejection = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/jobs")
                .version(Version::HTTP_11)
                .header(header::AUTHORIZATION, format!("Bearer {}", key("submit")))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_LENGTH, semantic_body.len())
                .body(Body::from(semantic_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(semantic_rejection.status(), StatusCode::BAD_REQUEST);
    assert!(
        !semantic_rejection
            .headers()
            .contains_key(header::CONNECTION),
        "a fully extracted semantic rejection retains HTTP/1 keep-alive"
    );

    for _ in 0..=state.cfg.rate_per_min {
        let _ = state.rate.check("tenant-a");
    }
    assert_partial_http1_submit_closes(
        address,
        Some(key("submit")),
        "application/json",
        StatusCode::TOO_MANY_REQUESTS,
    )
    .await;
    assert_early_http2_submit_stays_session_local(
        &app,
        Some(key("submit")),
        "application/json",
        StatusCode::TOO_MANY_REQUESTS,
    )
    .await;

    shutdown.send(()).expect("stop HTTP/1 regression server");
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("HTTP/1 regression server shutdown deadline")
        .expect("HTTP/1 regression server task")
        .expect("HTTP/1 regression server stopped cleanly");
}

#[tokio::test]
async fn indexed_credentials_enforce_every_route_scope_and_preserve_tenant_404s() {
    let (app, keys) = spawn_scoped_app().await;
    let key = |name| keys.get(name).unwrap().as_str();
    let payload = r#"{"language":"python","code":"print(1)"}"#.to_string();

    let denied = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/jobs",
            Some(key("read")),
            Some(payload.clone()),
        ))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        denied.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        denied.headers().get(header::WWW_AUTHENTICATE),
        Some(&header::HeaderValue::from_static(
            "Bearer realm=\"rookhold\", error=\"insufficient_scope\", scope=\"jobs:submit\""
        ))
    );

    let (status, created) = send(
        &app,
        request("POST", "/v1/jobs", Some(key("submit")), Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let job_id = created["job_id"].as_str().unwrap();

    for (method, path, expected) in [
        ("GET", "/v1/jobs".to_string(), StatusCode::OK),
        ("GET", format!("/v1/jobs/{job_id}"), StatusCode::OK),
        ("GET", format!("/v1/jobs/{job_id}/replay"), StatusCode::OK),
        (
            "GET",
            format!("/v1/jobs/{job_id}/result?wait_seconds=0"),
            StatusCode::ACCEPTED,
        ),
        (
            "POST",
            format!("/v1/jobs/{job_id}/stream-ticket"),
            StatusCode::OK,
        ),
    ] {
        let (status, body) = send(&app, request(method, &path, Some(key("read")), None)).await;
        assert_eq!(status, expected, "{method} {path}: {body}");
    }
    let (stream_status, _) = send(
        &app,
        request(
            "GET",
            &format!("/v1/jobs/{job_id}/stream"),
            Some(key("read")),
            None,
        ),
    )
    .await;
    assert_ne!(stream_status, StatusCode::FORBIDDEN);

    for path in [
        format!("/v1/jobs/{job_id}"),
        format!("/v1/jobs/{job_id}/replay"),
        format!("/v1/jobs/{job_id}/result?wait_seconds=0"),
        format!("/v1/jobs/{job_id}/stream-ticket"),
    ] {
        let method = if path.ends_with("stream-ticket") {
            "POST"
        } else {
            "GET"
        };
        let (status, _) = send(&app, request(method, &path, Some(key("other-read")), None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "foreign {method} {path}");
    }
    let (foreign_cancel, _) = send(
        &app,
        request(
            "DELETE",
            &format!("/v1/jobs/{job_id}"),
            Some(key("other-cancel")),
            None,
        ),
    )
    .await;
    assert_eq!(foreign_cancel, StatusCode::NOT_FOUND);

    for (method, path, credential, required) in [
        ("GET", "/v1/jobs", "submit", "jobs:read"),
        ("DELETE", "/v1/jobs/unknown", "read", "jobs:cancel"),
        ("GET", "/v1/status", "read", "service:read"),
        ("GET", "/v1/capabilities", "read", "service:read"),
        ("GET", "/v1/whoami", "read", "service:read"),
        ("GET", "/v1/metrics", "read", "metrics:read"),
        ("GET", "/v1/status", "metrics", "service:read"),
        ("GET", "/v1/metrics", "service", "metrics:read"),
    ] {
        let response = app
            .clone()
            .oneshot(request(method, path, Some(key(credential)), None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(challenge.contains(required), "{challenge}");
    }

    let (status, whoami) = send(
        &app,
        request("GET", "/v1/whoami", Some(key("service")), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{whoami}");
    assert_eq!(whoami["tenant"], "tenant-a");
    assert_eq!(whoami["principal_id"], "principal-service");
    assert_eq!(whoami["credential_id"], "service");
    assert_eq!(whoami["auth_method"], "api_key");
    assert_eq!(whoami["scopes"], serde_json::json!(["service:read"]));

    let (metrics, _) = send(
        &app,
        request("GET", "/v1/metrics", Some(key("metrics")), None),
    )
    .await;
    assert_eq!(metrics, StatusCode::OK);
    let (cancelled, _) = send(
        &app,
        request(
            "DELETE",
            &format!("/v1/jobs/{job_id}"),
            Some(key("cancel")),
            None,
        ),
    )
    .await;
    assert_eq!(cancelled, StatusCode::OK);
}

#[tokio::test]
async fn malformed_json_returns_structured_error() {
    let app = spawn_app().await;
    let (status, body) = send(
        &app,
        request(
            "POST",
            "/v1/jobs",
            Some("test-key"),
            Some("{not-json".to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_json", "{body}");
    assert!(body["error"]["request_id"].is_string(), "{body}");
}

#[tokio::test]
async fn full_decoded_code_and_stdin_fit_even_with_worst_case_json_escaping() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let cfg = test_config(&db);
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (app, _state, _queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .expect("build app");
    let escaped = "\u{1}".repeat(1_048_576);
    let payload = serde_json::json!({
        "language": "python",
        "code": escaped,
        "stdin": escaped,
    })
    .to_string();
    assert!(
        payload.len() > 12_000_000,
        "test must exercise JSON expansion"
    );

    let (status, body) = send(
        &app,
        request("POST", "/v1/jobs", Some("test-key"), Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn submit_preserves_unsupported_media_type_semantics() {
    let app = spawn_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/jobs")
        .header(header::AUTHORIZATION, "Bearer test-key")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(r#"{"language":"python","code":"print(1)"}"#))
        .unwrap();
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{body}");
    assert_eq!(body["error"]["code"], "unsupported_media_type", "{body}");
}

#[tokio::test]
async fn queued_detail_exposes_unknown_effective_policy_without_fabrication() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let cfg = test_config(&db);
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (app, _state, _queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .expect("build app");
    let (status, accepted) = send(
        &app,
        request(
            "POST",
            "/v1/jobs",
            Some("test-key"),
            Some(r#"{"language":"python","code":"print(1)"}"#.to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{accepted}");
    let id = accepted["job_id"].as_str().unwrap();
    let (status, detail) = send(
        &app,
        request("GET", &format!("/v1/jobs/{id}"), Some("test-key"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert!(detail["effective_spec"].is_null(), "{detail}");
    for field in [
        "sandbox",
        "seccomp",
        "network_allowed",
        "networking",
        "private_rootfs",
        "dedicated_bootstrap",
    ] {
        assert!(
            detail["execution_policy"][field].is_null(),
            "{field}: {detail}"
        );
    }
}

#[tokio::test]
async fn unavailable_development_runtime_is_not_advertised_or_admitted() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let mut cfg = test_config(&db);
    cfg.python_bin = Some(
        std::env::temp_dir()
            .join(format!("missing-coop-python-{}", uuid::Uuid::now_v7()))
            .to_string_lossy()
            .into_owned(),
    );
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (app, _state, _queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .expect("build app");

    let (capabilities_status, capabilities) = send(
        &app,
        request("GET", "/v1/capabilities", Some("test-key"), None),
    )
    .await;
    assert_eq!(capabilities_status, StatusCode::OK, "{capabilities}");
    assert!(
        !capabilities["languages"]
            .as_array()
            .expect("languages")
            .iter()
            .any(|language| language == "python"),
        "{capabilities}"
    );
    assert_eq!(
        capabilities["execution"]["limit_enforcement"],
        serde_json::json!({
            "wall_seconds": true,
            "cpu_seconds": false,
            "mem_mb": false,
            "max_pids": false,
            "max_file_mb": false,
        }),
        "development capabilities must not advertise controls the subprocess backend does not enforce: {capabilities}"
    );
    let languages = capabilities["languages"]
        .as_array()
        .expect("capability languages");
    let language_rank = |language: &serde_json::Value| {
        coop_types::SUPPORTED_LANGUAGES
            .iter()
            .position(|candidate| Some(*candidate) == language.as_str())
            .expect("advertised language is supported")
    };
    assert!(
        languages
            .windows(2)
            .all(|pair| language_rank(&pair[0]) < language_rank(&pair[1])),
        "concurrent preflight completion must not reorder capabilities: {capabilities}"
    );

    let (submit_status, submit) = send(
        &app,
        request(
            "POST",
            "/v1/jobs",
            Some("test-key"),
            Some(serde_json::json!({"language":"python","code":"print(1)"}).to_string()),
        ),
    )
    .await;
    assert_eq!(submit_status, StatusCode::UNPROCESSABLE_ENTITY, "{submit}");
    assert_eq!(submit["error"]["code"], "runtime_unavailable", "{submit}");
}

#[tokio::test]
async fn saturated_admission_is_nonblocking_and_retryable() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let cfg = test_config(&db);
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (app, state, _queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .expect("build app");
    for n in 0..coop_server::QUEUE_CAPACITY {
        state
            .admission
            .try_reserve(&format!("synthetic-tenant-{n}"), 256)
            .expect("reserve admission")
            .send(format!("synthetic-{n}"));
    }

    let started = std::time::Instant::now();
    let response = app
        .oneshot(request(
            "POST",
            "/v1/jobs",
            Some("test-key"),
            Some(r#"{"language":"python","code":"print(1)"}"#.to_string()),
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json error");
    assert_eq!(body["error"]["code"], "queue_saturated", "{body}");
    assert_eq!(body["error"]["retryable"], true, "{body}");
}

#[tokio::test]
async fn tenant_queue_capacity_returns_429_without_blocking_another_tenant() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let mut cfg = test_config(&db);
    cfg.tenant_queue_capacity = 2;
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (app, _state, _queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .expect("build app");
    let body = r#"{"language":"python","code":"print(1)"}"#;
    for _ in 0..2 {
        let (status, value) = send(
            &app,
            request("POST", "/v1/jobs", Some("test-key"), Some(body.into())),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{value}");
    }
    let (status, value) = send(
        &app,
        request("POST", "/v1/jobs", Some("test-key"), Some(body.into())),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{value}");
    assert_eq!(value["error"]["code"], "tenant_queue_saturated");

    let (status, value) = send(
        &app,
        request("POST", "/v1/jobs", Some("other-key"), Some(body.into())),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
}

#[tokio::test]
async fn retained_storage_quota_maps_tenant_capacity_without_charging_other_tenants() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let mut cfg = test_config(&db);
    cfg.storage_tenant_mb = 64;
    cfg.storage_global_mb = 128;
    let store = Arc::new(
        Store::open_with_limits(&db, cfg.storage_limits())
            .await
            .expect("open limited store"),
    );
    let (app, _state, _queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .expect("build app");
    let body = r#"{"language":"python","code":"print(1)"}"#;
    let (status, first) = send(
        &app,
        request("POST", "/v1/jobs", Some("test-key"), Some(body.into())),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let (status, rejected) = send(
        &app,
        request("POST", "/v1/jobs", Some("test-key"), Some(body.into())),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{rejected}");
    assert_eq!(rejected["error"]["code"], "tenant_storage_quota");

    let (status, other) = send(
        &app,
        request("POST", "/v1/jobs", Some("other-key"), Some(body.into())),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{other}");
}

#[tokio::test]
async fn idempotency_replays_original_job_and_rejects_fingerprint_reuse() {
    let app = spawn_app().await;
    let make = |body: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/jobs")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", "sdk-retry-1")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let first = app.clone().oneshot(make(
        r#"{"language":"python","code":"print(42)","limits":{"mem_mb":128}}"#,
    ));
    let first = first.await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    assert_eq!(first.headers()["idempotency-replayed"], "false");
    let first_location = first.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let first_body = axum::body::to_bytes(first.into_body(), 1 << 20)
        .await
        .unwrap();
    let first_json: serde_json::Value = serde_json::from_slice(&first_body).unwrap();

    // Reordered object members canonicalize to the same parsed JobSpec.
    let second = app
        .clone()
        .oneshot(make(
            r#"{"limits":{"mem_mb":128},"code":"print(42)","language":"python"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CREATED);
    assert_eq!(second.headers()["idempotency-replayed"], "true");
    assert_eq!(second.headers()[header::LOCATION], first_location);
    let second_body = axum::body::to_bytes(second.into_body(), 1 << 20)
        .await
        .unwrap();
    let second_json: serde_json::Value = serde_json::from_slice(&second_body).unwrap();
    assert_eq!(second_json["job_id"], first_json["job_id"]);

    let (status, conflict) = send(
        &app,
        make(r#"{"language":"python","code":"print(43)","limits":{"mem_mb":128}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{conflict}");
    assert_eq!(conflict["error"]["code"], "idempotency_key_reused");
}

#[tokio::test]
async fn concurrent_same_key_requests_have_one_acceptance_and_fingerprint_conflicts() {
    let app = spawn_app().await;
    let body = r#"{"language":"python","code":"print(7)"}"#;
    let (left, right) = tokio::join!(
        send_idempotent(&app, "concurrent-same", body),
        send_idempotent(&app, "concurrent-same", body),
    );
    assert_eq!(left.0, StatusCode::CREATED, "{}", left.2);
    assert_eq!(right.0, StatusCode::CREATED, "{}", right.2);
    assert_eq!(left.2["job_id"], right.2["job_id"]);
    let replay_flags = [left.1.as_deref(), right.1.as_deref()];
    assert!(replay_flags.contains(&Some("false")));
    assert!(replay_flags.contains(&Some("true")));

    let (left, right) = tokio::join!(
        send_idempotent(
            &app,
            "concurrent-conflict",
            r#"{"language":"python","code":"print('left')"}"#,
        ),
        send_idempotent(
            &app,
            "concurrent-conflict",
            r#"{"language":"python","code":"print('right')"}"#,
        ),
    );
    let statuses = [left.0, right.0];
    assert!(statuses.contains(&StatusCode::CREATED));
    assert!(statuses.contains(&StatusCode::UNPROCESSABLE_ENTITY));
    let conflict = if left.0 == StatusCode::UNPROCESSABLE_ENTITY {
        left.2
    } else {
        right.2
    };
    assert_eq!(conflict["error"]["code"], "idempotency_key_reused");
}

#[tokio::test]
async fn shutdown_is_sticky_and_queued_work_does_not_start_after_it() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let cfg = test_config(&db);
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (_app, state, queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .expect("build app");
    state
        .store
        .create_job_with_event(
            "shutdown-queued",
            "t1",
            "python",
            r#"{"language":"python","code":"print(1)"}"#,
        )
        .await
        .unwrap();
    state
        .admission
        .try_reserve("t1", 256)
        .unwrap()
        .send("shutdown-queued".to_string());

    // No watch receiver existed when this was published. A late subscriber
    // must still observe shutdown, and newly spawned workers must not start.
    state.begin_shutdown();
    assert!(*state.shutdown.subscribe().borrow());
    let workers = scheduler::spawn_workers(state.clone(), queue_rx);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let row = state
        .store
        .get_job("shutdown-queued")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "queued");
    let _ = workers.shutdown(&state, Duration::from_millis(250)).await;
}

#[tokio::test]
async fn readiness_monitor_exits_when_shutdown_was_already_sticky() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let cfg = test_config(&db);
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (_app, state, _queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .expect("build app");
    state.begin_shutdown();

    let monitor = coop_server::readiness::spawn_monitor(state);
    tokio::time::timeout(Duration::from_millis(100), monitor)
        .await
        .expect("sticky shutdown stops monitor before its first tick")
        .expect("monitor joins cleanly");
}

#[tokio::test]
async fn long_result_wait_returns_promptly_when_shutdown_begins() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let cfg = test_config(&db);
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (app, state, _queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .expect("build app");
    let (status, accepted) = send(
        &app,
        request(
            "POST",
            "/v1/jobs",
            Some("test-key"),
            Some(r#"{"language":"python","code":"print(1)"}"#.to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{accepted}");
    let id = accepted["job_id"].as_str().unwrap().to_string();
    let wait_app = app.clone();
    let waiter = tokio::spawn(async move {
        send(
            &wait_app,
            request(
                "GET",
                &format!("/v1/jobs/{id}/result?wait_seconds=300"),
                Some("test-key"),
                None,
            ),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    state.begin_shutdown();
    let (status, body) = tokio::time::timeout(Duration::from_millis(500), waiter)
        .await
        .expect("result wait stopped on shutdown")
        .expect("wait task joined");
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], "shutting_down");
}

#[tokio::test]
async fn result_wait_honors_budget_before_recovery_registers_completion_watch() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let cfg = test_config(&db);
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (_unused_app, mut state, _queue_rx) =
        coop_server::build_app(cfg, Arc::clone(&store), loopback_addr())
            .await
            .expect("build app");
    state.result_wait_admission = coop_server::LifetimeAdmission::new(1, 1);
    let app = coop_server::router_for_bound_state(state.clone(), loopback_addr()).unwrap();
    let job_id = "recovery-row-before-completion-watch";
    store
        .create_job_with_event(job_id, "t1", "bash", r#"{"language":"bash","code":":"}"#)
        .await
        .expect("create queued recovery fixture");
    assert!(
        state.bus.completion(job_id).is_none(),
        "fixture deliberately predates recovery watch registration"
    );

    let wait_app = app.clone();
    let waiter = tokio::spawn(async move {
        send(
            &wait_app,
            request(
                "GET",
                &format!("/v1/jobs/{job_id}/result?wait_seconds=2"),
                Some("test-key"),
                None,
            ),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while let Ok(probe) = state.result_wait_admission.try_acquire("t1") {
            drop(probe);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("result handler entered its requested wait");
    store
        .finalize_with_event(job_id, "cancelled", None, 0, None)
        .await
        .expect("finalize recovery fixture");

    let (status, body) = tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("durable terminal polling woke the result request")
        .expect("result task joined");
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "cancelled", "{body}");
}

#[tokio::test]
async fn cancelled_envelope_reclaims_capacity_only_after_scheduler_dequeues_it() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let mut cfg = test_config(&db);
    cfg.workers = 1;
    cfg.tenant_concurrency = 1;
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (_app, state, queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .expect("build app");
    state
        .store
        .create_job_with_event(
            "cancelled-envelope",
            "t1",
            "python",
            r#"{"language":"python","code":"print(1)"}"#,
        )
        .await
        .unwrap();
    state
        .store
        .cancel_queued_with_event("cancelled-envelope", "t1", None)
        .await
        .unwrap();
    state
        .admission
        .try_reserve("t1", 256)
        .unwrap()
        .send("cancelled-envelope".to_string());
    assert_eq!(state.admission.depth(), 1);
    let workers = scheduler::spawn_workers(state.clone(), queue_rx);
    for _ in 0..100 {
        if state.admission.depth() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        state.admission.depth(),
        0,
        "cancelled envelope leaked its slot"
    );
    let _ = workers.shutdown(&state, Duration::from_millis(250)).await;
}

#[tokio::test]
async fn rate_limit_errors_include_retry_after_and_request_id() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let mut cfg = test_config(&db);
    cfg.rate_per_min = 1;
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (app, _state, _queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .expect("build app");

    let first = app
        .clone()
        .oneshot(request("GET", "/v1/whoami", Some("test-key"), None))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = app
        .oneshot(request("GET", "/v1/whoami", Some("test-key"), None))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(second.headers().contains_key("retry-after"));
    assert!(second.headers().contains_key("x-request-id"));
    let body = axum::body::to_bytes(second.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "rate_limit_exceeded");
    assert_eq!(body["error"]["retryable"], true);
}

#[tokio::test]
async fn rejects_unknown_language() {
    let app = spawn_app().await;
    let (status, _) = send(
        &app,
        request(
            "POST",
            "/v1/jobs",
            Some("test-key"),
            Some(r#"{"language":"fortran","code":"PRINT *, 1"}"#.into()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn minimum_isolation_is_checked_atomically_before_persistence() {
    let app = spawn_app().await;
    let payload = serde_json::json!({
        "language": "python",
        "code": "print('must not queue')",
        "requirements": {"minimum_isolation": "gvisor-application-kernel"}
    })
    .to_string();
    let (status, body) = send(
        &app,
        request("POST", "/v1/jobs", Some("test-key"), Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "minimum_isolation_unsatisfied");

    let (status, jobs) = send(
        &app,
        request("GET", "/v1/jobs?limit=100", Some("test-key"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(jobs["items"].as_array().unwrap().is_empty(), "{jobs}");
}

#[tokio::test]
async fn cross_tenant_reads_are_rejected() {
    let app = spawn_app().await;
    let payload = r#"{"language":"python","code":"print(1)"}"#.to_string();
    let (status, body) = send(
        &app,
        request("POST", "/v1/jobs", Some("test-key"), Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let job_id = body["job_id"].as_str().expect("job_id");

    let (owner_status, _) = send(
        &app,
        request("GET", &format!("/v1/jobs/{job_id}"), Some("test-key"), None),
    )
    .await;
    assert_eq!(owner_status, StatusCode::OK);

    for path in [
        format!("/v1/jobs/{job_id}"),
        format!("/v1/jobs/{job_id}/replay"),
    ] {
        let (status, _) = send(&app, request("GET", &path, Some("other-key"), None)).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-tenant read of {path} must look like a missing job"
        );
    }

    let (_, other_jobs) = send(
        &app,
        request("GET", "/v1/jobs?limit=100", Some("other-key"), None),
    )
    .await;
    let leaked = other_jobs["items"]
        .as_array()
        .map(|a| a.iter().any(|j| j["job_id"] == *job_id))
        .unwrap_or(false);
    assert!(!leaked, "tenant t2 must not see tenant t1 jobs in listings");
}

#[tokio::test]
async fn list_jobs_supports_language_filters_and_stable_cursors() {
    let app = spawn_app().await;
    for (language, code) in [
        ("python", "print('one')"),
        ("python", "print('middle')"),
        ("python", "print('two')"),
    ] {
        let payload = serde_json::json!({ "language": language, "code": code }).to_string();
        let (status, body) = send(
            &app,
            request("POST", "/v1/jobs", Some("test-key"), Some(payload)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    let (status, excluded) = send(
        &app,
        request(
            "GET",
            "/v1/jobs?language=node&limit=10",
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{excluded}");
    assert!(excluded["items"].as_array().is_some_and(Vec::is_empty));

    let (status, first) = send(
        &app,
        request(
            "GET",
            "/v1/jobs?language=python&limit=1",
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let first_items = first["items"].as_array().expect("items");
    assert_eq!(first_items.len(), 1, "{first}");
    assert_eq!(first_items[0]["language"], "python");
    for blob_field in ["requested_spec", "effective_spec", "receipt"] {
        assert!(
            first_items[0].get(blob_field).is_none(),
            "list projection must not load/expose {blob_field}: {first}"
        );
    }
    let first_id = first_items[0]["job_id"].as_str().unwrap().to_string();
    let cursor = first["next_cursor"].as_str().expect("next cursor");

    let (status, second) = send(
        &app,
        request(
            "GET",
            &format!("/v1/jobs?language=python&limit=1&cursor={cursor}"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let second_items = second["items"].as_array().expect("items");
    assert_eq!(second_items.len(), 1, "{second}");
    assert_eq!(second_items[0]["language"], "python");
    assert_ne!(second_items[0]["job_id"], first_id);
}

#[tokio::test]
async fn identity_capabilities_status_and_readiness_are_truthful() {
    let app = spawn_app().await;
    let (status, ready) = send(&app, request("GET", "/readyz", None, None)).await;
    assert_eq!(status, StatusCode::OK, "{ready}");
    assert_eq!(ready["ok"], true);

    let (status, who) = send(&app, request("GET", "/v1/whoami", Some("test-key"), None)).await;
    assert_eq!(status, StatusCode::OK, "{who}");
    assert_eq!(who["tenant"], "t1");

    let (status, capabilities) = send(
        &app,
        request("GET", "/v1/capabilities", Some("test-key"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{capabilities}");
    assert_eq!(capabilities["execution"]["isolated"], false);
    assert_eq!(capabilities["execution"]["seccomp"], false);
    assert_eq!(capabilities["execution"]["networking"], "host");
    assert_eq!(capabilities["features"]["stream_tickets"], true);
    assert_eq!(capabilities["limits"]["mem_mb_max"], 1024);
    assert_eq!(capabilities["limits"]["concurrent_mem_mb_max"], 4096);

    let (status, service) = send(&app, request("GET", "/v1/status", Some("test-key"), None)).await;
    assert_eq!(status, StatusCode::OK, "{service}");
    assert_eq!(service["environment"], "development");
    assert_eq!(service["scheduler"]["queue_capacity"], 64);
    assert_eq!(service["scheduler"]["queue_depth"], 0);
}

#[tokio::test]
async fn status_queue_depth_is_tenant_scoped() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let cfg = test_config(&db);
    let store = Arc::new(Store::open(&db).await.unwrap());
    let (app, state, _queue_rx) = coop_server::build_app(cfg, store, loopback_addr())
        .await
        .unwrap();
    state
        .admission
        .try_reserve("t2", 256)
        .unwrap()
        .send("status-t2".to_string());
    let (_, t1) = send(&app, request("GET", "/v1/status", Some("test-key"), None)).await;
    let (_, t2) = send(&app, request("GET", "/v1/status", Some("other-key"), None)).await;
    assert_eq!(t1["scheduler"]["queue_depth"], 0);
    assert_eq!(t2["scheduler"]["queue_depth"], 1);
}

#[tokio::test]
async fn queued_job_keeps_acceptance_memory_ceiling_when_server_limit_increases() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let mut low = test_config(&db);
    low.max_job_mem_mb = 512;
    let store = Arc::new(Store::open(&db).await.unwrap());
    let (first_app, first_state, first_queue) =
        coop_server::build_app(low, Arc::clone(&store), loopback_addr())
            .await
            .unwrap();
    let (status, submitted) = send(
        &first_app,
        request(
            "POST",
            "/v1/jobs",
            Some("test-key"),
            Some(
                r#"{"language":"python","code":"print('memory-policy')","limits":{"mem_mb":1024}}"#
                    .into(),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{submitted}");
    let job_id = submitted["job_id"].as_str().unwrap().to_string();
    drop((first_app, first_state, first_queue));
    drop(store);

    let mut high = test_config(&db);
    high.max_job_mem_mb = 1024;
    let store = Arc::new(Store::open(&db).await.unwrap());
    let (app, state, queue_rx) = coop_server::build_app(high, Arc::clone(&store), loopback_addr())
        .await
        .unwrap();
    let queued = store.queued_jobs_page(None, 10).await.unwrap();
    let row = queued.iter().find(|row| row.job_id == job_id).unwrap();
    assert_eq!(row.requested_mem_mb, 512);
    state.bus.register(&job_id);
    state
        .admission
        .reserve_recovery(&row.tenant, state.cfg.clamp_mem_mb(row.requested_mem_mb))
        .await
        .unwrap()
        .send(job_id.clone());
    scheduler::spawn_workers(state, queue_rx);
    let detail = wait_terminal(&app, &job_id).await;
    assert_eq!(detail["status"], "succeeded", "{detail}");
    assert_eq!(
        store.job_requested_mem_mb(&job_id).await.unwrap(),
        Some(512)
    );
}

#[tokio::test]
async fn stream_tickets_are_job_bound_and_one_use() {
    let app = spawn_app().await;
    let first = submit_python(&app, "print('first')").await;
    let second = submit_python(&app, "print('second')").await;
    let (status, ticket) = send(
        &app,
        request(
            "POST",
            &format!("/v1/jobs/{first}/stream-ticket"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{ticket}");
    let stream_url = ticket["stream_url"].as_str().expect("stream_url");
    let query = stream_url.split_once('?').expect("ticket query").1;

    // A wrong job path cannot consume or use the grant.
    let (wrong_status, wrong) = send(
        &app,
        request(
            "GET",
            &format!("/v1/jobs/{second}/stream?{query}"),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(wrong_status, StatusCode::UNAUTHORIZED, "{wrong}");
    assert_eq!(wrong["error"]["code"], "invalid_stream_ticket");

    // The correct path passes authentication (and then fails only because
    // this test request is not a WebSocket upgrade), consuming the ticket.
    let (first_use, _) = send(&app, request("GET", stream_url, None, None)).await;
    assert_ne!(first_use, StatusCode::UNAUTHORIZED);
    let (second_use, body) = send(&app, request("GET", stream_url, None, None)).await;
    assert_eq!(second_use, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "invalid_stream_ticket");
}

#[tokio::test]
async fn stream_ticket_is_rejected_after_shutdown_becomes_sticky() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let cfg = test_config(&db);
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (_unused_app, state, _queue_rx) =
        coop_server::build_app(cfg, Arc::clone(&store), loopback_addr())
            .await
            .expect("build app");
    let job_id = "ticket-after-shutdown";
    store
        .create_job_with_event(job_id, "t1", "bash", r#"{"language":"bash","code":":"}"#)
        .await
        .expect("create ticket fixture");
    state.begin_shutdown();
    let app = coop_server::router_for_bound_state(state, loopback_addr()).unwrap();

    let (status, body) = send(
        &app,
        request(
            "POST",
            &format!("/v1/jobs/{job_id}/stream-ticket"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], "shutting_down", "{body}");
}

#[tokio::test]
async fn production_never_accepts_api_keys_in_stream_query_strings() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let cfg = test_config(&db);
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (_app, mut state, _queue_rx) = coop_server::build_app(cfg.clone(), store, loopback_addr())
        .await
        .expect("build app");
    let mut production_cfg = cfg;
    production_cfg.production = true;
    production_cfg.unsafe_allow_naive = true;
    state.cfg = Arc::new(production_cfg);
    let app = coop_server::router_for_bound_state(state, loopback_addr()).unwrap();
    let (status, body) = send(
        &app,
        request("GET", "/v1/jobs/unknown/stream?key=test-key", None, None),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "missing_api_key", "{body}");
}

#[tokio::test]
async fn runs_python_hello_world_end_to_end() {
    if !python_available() {
        eprintln!("skipping: no python interpreter on PATH");
        return;
    }
    let app = spawn_app().await;
    let code = "print('hello from coop')".to_string();
    let payload = serde_json::json!({ "language": "python", "code": code }).to_string();

    let (status, body) = send(
        &app,
        request("POST", "/v1/jobs", Some("test-key"), Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "submit failed: {body}");
    let job_id = body["job_id"].as_str().expect("job_id").to_string();

    let final_view = wait_terminal(&app, &job_id).await;
    assert_eq!(
        final_view["status"], "succeeded",
        "final view: {final_view}"
    );
    assert_eq!(final_view["exit_code"], 0);
    assert_eq!(final_view["requested_spec"]["language"], "python");
    assert_eq!(
        final_view["effective_spec"]["limits"]["allow_network"],
        true
    );
    assert_eq!(final_view["effective_spec"]["limits"]["wall_seconds"], 15);
    for unenforced in ["cpu_seconds", "mem_mb", "max_pids", "max_file_mb"] {
        assert!(
            final_view["effective_spec"]["limits"][unenforced].is_null(),
            "development backend must not claim {unenforced}: {final_view}"
        );
    }
    assert_eq!(final_view["execution_policy"]["bootstrap_ready"], true);
    assert_eq!(final_view["execution_policy"]["isolated"], false);
    assert_eq!(
        final_view["execution_policy"]["limit_enforcement"],
        serde_json::json!({
            "wall_seconds": true,
            "cpu_seconds": false,
            "mem_mb": false,
            "max_pids": false,
            "max_file_mb": false,
        })
    );
    assert_eq!(final_view["execution_policy"]["network_allowed"], true);
    assert_eq!(final_view["execution_policy"]["networking"], "host");
    assert_eq!(final_view["execution_policy"]["private_rootfs"], false);
    assert_eq!(final_view["execution_policy"]["dedicated_bootstrap"], false);
    assert_eq!(final_view["receipt"]["network_allowed"], true);
    assert_eq!(final_view["receipt"]["networking"], "host");
    assert_eq!(final_view["receipt"]["private_rootfs"], false);
    assert_eq!(final_view["receipt"]["dedicated_bootstrap"], false);
    assert_eq!(final_view["receipt"]["bootstrap_ready"], true);
    assert_eq!(final_view["receipt"]["isolated"], false);
    assert_eq!(
        final_view["receipt"]["effective_limits"]["wall_seconds"],
        15
    );
    assert!(final_view["receipt"]["effective_limits"]["cpu_seconds"].is_null());
    assert!(final_view["receipt"].is_object(), "{final_view}");
    assert!(final_view["receipt_sha256"].is_string(), "{final_view}");
    assert_eq!(
        final_view["receipt_sha256"], final_view["receipt"]["receipt_sha256"],
        "{final_view}"
    );
    assert_eq!(final_view["receipt"]["event_chain"]["version"], 1);

    let (_, replay) = send(
        &app,
        request(
            "GET",
            &format!("/v1/jobs/{job_id}/replay"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    let stdout: String = replay["events"]
        .as_array()
        .expect("replay array")
        .iter()
        .filter(|e| e["kind"] == "stdout")
        .filter_map(|e| e["data"]["line"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(stdout.contains("hello from coop"), "stdout was: {stdout}");

    let kinds: Vec<&str> = replay["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"started"));
    assert!(kinds.contains(&"finished"));
    assert!(replay["next_cursor"].is_i64(), "{replay}");
    assert!(replay["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|event| event["hash_version"] == 1 && event["event_hash"].is_string()));

    let first_seq = replay["events"][0]["seq"].as_i64().unwrap();
    let (_, after) = send(
        &app,
        request(
            "GET",
            &format!("/v1/jobs/{job_id}/replay?after={first_seq}"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert!(after["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|event| event["seq"].as_i64().unwrap() > first_seq));
}

// ---------------------------------------------------------------------------
// Cancellation (DELETE /v1/jobs/{id})
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancel_queued_job_finalizes_without_execution() {
    let app = spawn_app().await;

    // Deterministic queuing: fill the 2-worker pool with long-running
    // blockers so the victim below cannot start before its DELETE lands.
    // (A bare `echo` victim completes in milliseconds and raced this test
    // on CI: sometimes already terminal, making the expected 200 a 409.)
    let mut blockers = Vec::new();
    for _ in 0..2 {
        let (status, body) = send(
            &app,
            request(
                "POST",
                "/v1/jobs",
                Some("test-key"),
                Some(
                    r#"{"language":"python","code":"import time; time.sleep(30)","limits":{"wall_seconds":30}}"#.into(),
                ),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        blockers.push(body["job_id"].as_str().expect("job_id").to_string());
    }

    let (status, body) = send(
        &app,
        request(
            "POST",
            "/v1/jobs",
            Some("test-key"),
            Some(r#"{"language":"python","code":"print('should-never-run')","limits":{"wall_seconds":30}}"#.into()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let job_id = body["job_id"].as_str().expect("job_id").to_string();

    let (status, cancellation) = send(
        &app,
        request(
            "DELETE",
            &format!("/v1/jobs/{job_id}"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cancellation["cancellation_requested"], true);
    assert_eq!(cancellation["already_terminal"], false);
    assert_eq!(cancellation["job"]["job_id"], job_id);

    // The job must reach a terminal `cancelled` state without running.
    let view = wait_terminal(&app, &job_id).await;
    assert_eq!(view["status"], "cancelled", "{view}");

    // Cancelling again is a typed idempotent observation and emits no second
    // terminal transition.
    let (status, cancellation) = send(
        &app,
        request(
            "DELETE",
            &format!("/v1/jobs/{job_id}"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cancellation["cancellation_requested"], false);
    assert_eq!(cancellation["already_terminal"], true);
    assert_eq!(cancellation["job"]["status"], "cancelled");

    // Cleanup: cancel the blockers so the pool drains before the app drops.
    for id in &blockers {
        let _ = send(
            &app,
            request("DELETE", &format!("/v1/jobs/{id}"), Some("test-key"), None),
        )
        .await;
    }
}

#[tokio::test]
async fn cancel_running_job_kills_it_before_wall_clock() {
    let app = spawn_app().await;
    let (status, body) = send(
        &app,
        request(
            "POST",
            "/v1/jobs",
            Some("test-key"),
            Some(r#"{"language":"python","code":"import time; time.sleep(60)","limits":{"wall_seconds":60}}"#.into()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let job_id = body["job_id"].as_str().expect("job_id").to_string();

    // Wait until it is actually running so we exercise the kill path, not
    // the queued-skip path.
    for _ in 0..100 {
        let (_, v) = send(
            &app,
            request("GET", &format!("/v1/jobs/{job_id}"), Some("test-key"), None),
        )
        .await;
        if v["status"] == "running" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let started = std::time::Instant::now();
    let (status, _) = send(
        &app,
        request(
            "DELETE",
            &format!("/v1/jobs/{job_id}"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let view = wait_terminal(&app, &job_id).await;
    assert_eq!(view["status"], "cancelled", "{view}");
    // Must be cancelled far before the 60s wall clock.
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "cancel took too long: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn cancel_is_tenant_scoped() {
    let app = spawn_app().await;
    let (_, body) = send(
        &app,
        request(
            "POST",
            "/v1/jobs",
            Some("test-key"),
            Some(
                r#"{"language":"python","code":"print('t1')","limits":{"wall_seconds":15}}"#.into(),
            ),
        ),
    )
    .await;
    let job_id = body["job_id"].as_str().expect("job_id").to_string();

    // Tenant t2 cannot see or cancel tenant t1's job.
    let (status, _) = send(
        &app,
        request(
            "DELETE",
            &format!("/v1/jobs/{job_id}"),
            Some("other-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tenant_waiters_do_not_occupy_workers_and_starve_other_tenants() {
    if !python_available() {
        eprintln!("skipping: no python interpreter on PATH");
        return;
    }
    let app = spawn_app_with_limits(2, 1).await;

    let first = submit_python(&app, "import time; time.sleep(5)").await;
    for _ in 0..100 {
        let (_, view) = send(
            &app,
            request("GET", &format!("/v1/jobs/{first}"), Some("test-key"), None),
        )
        .await;
        if view["status"] == "running" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // A second t1 job cannot acquire t1's permit. It must remain in the fair
    // dispatcher, not consume worker 2 while waiting.
    let second = submit_python(&app, "import time; time.sleep(5)").await;
    let (status, other) = send(
        &app,
        request(
            "POST",
            "/v1/jobs",
            Some("other-key"),
            Some(r#"{"language":"python","code":"print('other-tenant')"}"#.to_string()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{other}");
    let other_id = other["job_id"].as_str().unwrap().to_string();

    let started = std::time::Instant::now();
    let other_view = wait_terminal_with_key(&app, &other_id, "other-key").await;
    assert_eq!(other_view["status"], "succeeded", "{other_view}");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "other tenant was starved behind a tenant semaphore waiter"
    );

    for id in [first, second] {
        let _ = send(
            &app,
            request("DELETE", &format!("/v1/jobs/{id}"), Some("test-key"), None),
        )
        .await;
    }
}

#[tokio::test]
async fn metrics_endpoint_reports_job_counts() {
    let app = spawn_app().await;
    send(
        &app,
        request(
            "POST",
            "/v1/jobs",
            Some("test-key"),
            Some(
                r#"{"language":"python","code":"print('hi')","limits":{"wall_seconds":15}}"#.into(),
            ),
        ),
    )
    .await;

    let res = app
        .clone()
        .oneshot(request("GET", "/v1/metrics", Some("test-key"), None))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
    let ct = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.starts_with("text/plain"), "content-type was {ct}");
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .expect("body");
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("coop_jobs_current"), "{text}");
    assert!(text.contains("coop_job_lifecycle_owners_current"), "{text}");
    assert!(!text.contains("coop_running_jobs"), "{text}");

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .header(header::AUTHORIZATION, "Bearer test-metrics-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("global metrics");
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("global metrics body");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains(
            "coop_http_server_requests_total{method=\"GET\",route=\"/v1/metrics\",status_class=\"2xx\"} 1"
        ),
        "{text}"
    );
    assert!(
        text.contains("coop_jobs_submitted_total{language=\"python\"} 1"),
        "{text}"
    );
}

#[tokio::test]
async fn global_metrics_are_separately_authorized_bounded_and_negotiated() {
    let app = spawn_app().await;

    for key in [None, Some("test-key")] {
        let response = app
            .clone()
            .oneshot(request("GET", "/metrics", key, None))
            .await
            .expect("metrics response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key("x-request-id"));
        assert_eq!(
            response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer realm=\"rookhold-metrics\"")
        );
    }

    let openmetrics = Request::builder()
        .method("GET")
        .uri("/metrics")
        .header(header::AUTHORIZATION, "Bearer test-metrics-token")
        .header(header::ACCEPT, "application/openmetrics-text;version=1.0.0")
        .body(Body::empty())
        .unwrap();
    let response = app
        .clone()
        .oneshot(openmetrics)
        .await
        .expect("OpenMetrics response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/openmetrics-text; version=1.0.0; charset=utf-8")
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("metrics body");
    let text = String::from_utf8(bytes.to_vec()).expect("UTF-8 metrics");
    assert!(text.ends_with("# EOF\n"), "{text}");
    for family in [
        "coop_http_server_request_duration_seconds",
        "coop_admission_rejections_total",
        "coop_queue_depth",
        "coop_executions_active",
        "coop_storage_errors_total",
        "coop_output_truncations_total",
        "coop_recovered_jobs_total",
        "coop_retention_runs_total",
        "coop_capacity_used",
        "coop_build_info",
    ] {
        assert!(text.contains(family), "missing {family}");
    }
    for forbidden in ["tenant=", "job_id=", "request_id=", "trace_id="] {
        assert!(!text.contains(forbidden), "leaked {forbidden}");
    }

    let legacy = Request::builder()
        .method("GET")
        .uri("/metrics")
        .header(header::AUTHORIZATION, "Bearer test-metrics-token")
        .header(header::ACCEPT, "text/plain;version=0.0.4")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(legacy).await.expect("legacy metrics response");
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("legacy body");
    assert!(!bytes.ends_with(b"# EOF\n"));
}

#[tokio::test]
async fn ingress_request_id_covers_success_early_error_and_ignores_caller_value() {
    let app = spawn_app().await;
    let success = app
        .clone()
        .oneshot(request("GET", "/healthz", None, None))
        .await
        .expect("health response");
    let success_id = success
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("success request ID");
    assert_eq!(
        uuid::Uuid::parse_str(success_id)
            .expect("UUID request ID")
            .get_version_num(),
        7
    );

    let unauthorized = Request::builder()
        .method("GET")
        .uri("/v1/whoami")
        .header("x-request-id", "caller-controlled")
        .header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .header("baggage", "secret=must-not-propagate")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(unauthorized).await.expect("auth response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let header_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("error request ID")
        .to_string();
    assert_ne!(header_id, "caller-controlled");
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("error body");
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["request_id"], header_id);
    assert!(!body.to_string().contains("must-not-propagate"));
    assert!(!body
        .to_string()
        .contains("4bf92f3577b34da6a3ce929d0e0e4736"));
}

// ---------------------------------------------------------------------------
// GET /v1/jobs/{id}/result
// ---------------------------------------------------------------------------

async fn submit_python(app: &Router, code: &str) -> String {
    let payload =
        serde_json::json!({ "language": "python", "code": code, "limits": { "wall_seconds": 15 } })
            .to_string();
    let (status, body) = send(
        app,
        request("POST", "/v1/jobs", Some("test-key"), Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["job_id"].as_str().expect("job_id").to_string()
}

#[tokio::test]
async fn result_endpoint_folds_output_into_one_response() {
    if !python_available() {
        eprintln!("skipping: no python interpreter on PATH");
        return;
    }
    let app = spawn_app().await;
    let payload = serde_json::json!({
        "language": "python",
        "code": "print('out-line'); import sys; print('err-line', file=sys.stderr)",
    })
    .to_string();
    let (status, body) = send(
        &app,
        request("POST", "/v1/jobs", Some("test-key"), Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let job_id = body["job_id"].as_str().expect("job_id").to_string();

    // Server-side wait: a single call must block until terminal and return
    // the folded result.
    let (status, body) = send(
        &app,
        request(
            "GET",
            &format!("/v1/jobs/{job_id}/result?wait_seconds=30"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["job_id"], job_id);
    assert_eq!(body["status"], "succeeded", "{body}");
    assert_eq!(body["exit_code"], 0);
    assert_eq!(body["stdout"], "out-line");
    assert_eq!(body["stderr"], "err-line");
    assert_eq!(body["truncated"], false);
    assert!(body["violations"]
        .as_array()
        .expect("violations")
        .is_empty());
    assert!(body["duration_ms"].is_i64(), "{body}");
}

#[tokio::test]
async fn bounded_files_are_materialized_collected_and_hashed_in_the_receipt() {
    if !python_available() {
        eprintln!("skipping: no python interpreter on PATH");
        return;
    }
    let app = spawn_app().await;
    let payload = serde_json::json!({
        "language": "python",
        "code": "from pathlib import Path\nvalue=Path('input/data.txt').read_text()\nPath('output/result.txt').write_text(value.upper())\nprint('done')",
        "files": [{
            "path": "input/data.txt",
            "content_base64": BASE64_STANDARD.encode(b"hello"),
        }],
        "outputs": ["output/result.txt"],
    })
    .to_string();
    let (status, body) = send(
        &app,
        request("POST", "/v1/jobs", Some("test-key"), Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let job_id = body["job_id"].as_str().unwrap();
    let (status, result) = send(
        &app,
        request(
            "GET",
            &format!("/v1/jobs/{job_id}/result?wait_seconds=30"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["status"], "succeeded", "{result}");
    assert_eq!(result["artifacts"][0]["path"], "output/result.txt");
    assert_eq!(result["artifacts"][0]["content_base64"], "SEVMTE8=");
    assert_eq!(result["artifacts"][0]["size_bytes"], 5);
    assert_eq!(
        result["artifacts"][0]["sha256"],
        "3733cd977ff8eb18b987357e22ced99f46097f31ecb239e878ae63760e83e4d5"
    );
    let (status, detail) = send(
        &app,
        request("GET", &format!("/v1/jobs/{job_id}"), Some("test-key"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{detail}");
    assert_eq!(
        detail["receipt"]["input_files"][0]["path"],
        "input/data.txt"
    );
    assert_eq!(
        detail["receipt"]["artifacts"][0]["path"],
        "output/result.txt"
    );
    assert!(detail["receipt"]["artifacts"][0]["content_base64"].is_null());
}

#[tokio::test]
async fn bounded_file_paths_reject_traversal_before_acceptance() {
    let app = spawn_app().await;
    let payload = serde_json::json!({
        "language": "python",
        "code": "print('never runs')",
        "files": [{"path": "input/../secret", "content_base64": "eA=="}],
    })
    .to_string();
    let (status, body) = send(
        &app,
        request("POST", "/v1/jobs", Some("test-key"), Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "invalid_input_path");
}

#[tokio::test]
async fn missing_requested_output_cannot_leave_a_successful_job() {
    if !python_available() {
        eprintln!("skipping: no python interpreter on PATH");
        return;
    }
    let app = spawn_app().await;
    let payload = serde_json::json!({
        "language": "python",
        "code": "print('forgot the file')",
        "outputs": ["output/result.txt"],
    })
    .to_string();
    let (status, submitted) = send(
        &app,
        request("POST", "/v1/jobs", Some("test-key"), Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{submitted}");
    let job_id = submitted["job_id"].as_str().unwrap();
    let (status, result) = send(
        &app,
        request(
            "GET",
            &format!("/v1/jobs/{job_id}/result?wait_seconds=30"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["status"], "error", "{result}");
    assert!(result["violations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value["rule"] == "artifact_collection_failed"));
}

#[tokio::test]
async fn result_is_tenant_scoped_and_404_for_unknown_jobs() {
    let app = spawn_app().await;
    let job_id = submit_python(&app, "print('scoped')").await;

    // Another tenant must see a missing job, not someone else's result.
    let (status, _) = send(
        &app,
        request(
            "GET",
            &format!("/v1/jobs/{job_id}/result"),
            Some("other-key"),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-tenant result read must look like a missing job"
    );

    // Unknown ids look the same way.
    let (status, _) = send(
        &app,
        request(
            "GET",
            "/v1/jobs/01a00000-0000-7000-8000-000000000000/result",
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn result_with_zero_wait_returns_202_while_running() {
    let app = spawn_app().await;
    if !python_available() {
        eprintln!("skipping: no python interpreter on PATH");
        return;
    }
    let job_id = submit_python(&app, "import time; time.sleep(5)").await;

    // A zero wait budget must return immediately with a partial view while
    // the job is still running.
    let started = std::time::Instant::now();
    let (status, body) = send(
        &app,
        request(
            "GET",
            &format!("/v1/jobs/{job_id}/result?wait_seconds=0"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    // Not terminal yet; whether the worker has already picked it up
    // (`queued` vs `running`) is a scheduling race the test must not
    // depend on.
    assert!(
        matches!(body["status"].as_str(), Some("queued" | "running")),
        "{body}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "wait_seconds=0 must not block"
    );
}

#[tokio::test]
async fn result_wait_capacity_is_tenant_global_and_only_for_actual_waits() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let mut cfg = test_config(&db);
    cfg.api_keys
        .insert("third-key".to_string(), "t3".to_string());
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (_unused_app, mut state, _queue_rx) =
        coop_server::build_app(cfg, Arc::clone(&store), loopback_addr())
            .await
            .expect("build app");
    state.result_wait_admission = coop_server::LifetimeAdmission::new(2, 1);
    let app = coop_server::router_for_bound_state(state.clone(), loopback_addr()).unwrap();

    for (id, tenant) in [
        ("result-cap-t1", "t1"),
        ("result-cap-t2", "t2"),
        ("result-cap-t3", "t3"),
        ("result-cap-terminal", "t1"),
    ] {
        store
            .create_job_with_event(id, tenant, "bash", r#"{"language":"bash","code":":"}"#)
            .await
            .expect("create queued job");
        state.bus.register(id);
    }
    store
        .finalize_with_event("result-cap-terminal", "cancelled", None, 0, None)
        .await
        .expect("finalize terminal fixture");

    let held_t1 = state
        .result_wait_admission
        .try_acquire("t1")
        .expect("hold t1 wait slot");
    let (status, body) = send(
        &app,
        request(
            "GET",
            "/v1/jobs/result-cap-t1/result?wait_seconds=300",
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"]["code"], "tenant_result_wait_capacity");

    let held_t2 = state
        .result_wait_admission
        .try_acquire("t2")
        .expect("hold t2 wait slot");
    let (status, body) = send(
        &app,
        request(
            "GET",
            "/v1/jobs/result-cap-t3/result?wait_seconds=300",
            Some("third-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], "result_wait_capacity");

    let (status, body) = send(
        &app,
        request(
            "GET",
            "/v1/jobs/result-cap-t1/result?wait_seconds=0",
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    let (status, body) = send(
        &app,
        request(
            "GET",
            "/v1/jobs/result-cap-terminal/result?wait_seconds=300",
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    drop((held_t1, held_t2));
    let _reclaimed = state
        .result_wait_admission
        .try_acquire("t1")
        .expect("dropping waits reclaims capacity");
}

#[tokio::test]
async fn large_response_capacity_guards_all_blob_endpoints_and_reclaims() {
    let db = std::env::temp_dir().join(format!("coop-test-{}.db", uuid::Uuid::now_v7()));
    let mut cfg = test_config(&db);
    cfg.api_keys
        .insert("third-key".to_string(), "t3".to_string());
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (_unused_app, mut state, _queue_rx) =
        coop_server::build_app(cfg, Arc::clone(&store), loopback_addr())
            .await
            .expect("build app");
    state.large_response_admission = coop_server::LifetimeAdmission::new(2, 1);
    let app = coop_server::router_for_bound_state(state.clone(), loopback_addr()).unwrap();

    for (id, tenant) in [
        ("response-cap-t1", "t1"),
        ("response-cap-t2", "t2"),
        ("response-cap-t3", "t3"),
    ] {
        store
            .create_job_with_event(id, tenant, "bash", r#"{"language":"bash","code":":"}"#)
            .await
            .expect("create queued job");
    }

    let held_t1 = state
        .large_response_admission
        .try_acquire("t1")
        .expect("hold t1 response slot");
    for path in [
        "/v1/jobs/response-cap-t1",
        "/v1/jobs/response-cap-t1/replay",
        "/v1/jobs/response-cap-t1/result?wait_seconds=0",
    ] {
        let (status, body) = send(&app, request("GET", path, Some("test-key"), None)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{path}: {body}");
        assert_eq!(body["error"]["code"], "tenant_response_capacity");
    }

    let held_t2 = state
        .large_response_admission
        .try_acquire("t2")
        .expect("hold t2 response slot");
    let (status, body) = send(
        &app,
        request("GET", "/v1/jobs/response-cap-t3", Some("third-key"), None),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], "response_capacity");

    drop((held_t1, held_t2));
    for (path, expected) in [
        ("/v1/jobs/response-cap-t1", StatusCode::OK),
        ("/v1/jobs/response-cap-t1/replay", StatusCode::OK),
        (
            "/v1/jobs/response-cap-t1/result?wait_seconds=0",
            StatusCode::ACCEPTED,
        ),
    ] {
        let (status, body) = send(&app, request("GET", path, Some("test-key"), None)).await;
        assert_eq!(status, expected, "{path}: {body}");
    }
}

#[tokio::test]
async fn result_waits_for_terminal_within_budget() {
    if !python_available() {
        eprintln!("skipping: no python interpreter on PATH");
        return;
    }
    let app = spawn_app().await;
    let payload = serde_json::json!({
        "language": "python",
        "code": "import time; time.sleep(1.5); print('late but done')",
    })
    .to_string();
    let (status, body) = send(
        &app,
        request("POST", "/v1/jobs", Some("test-key"), Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let job_id = body["job_id"].as_str().expect("job_id").to_string();

    let (status, body) = send(
        &app,
        request(
            "GET",
            &format!("/v1/jobs/{job_id}/result?wait_seconds=30"),
            Some("test-key"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "succeeded", "{body}");
    assert_eq!(body["stdout"], "late but done");
}
