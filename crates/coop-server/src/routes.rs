use crate::auth::AuthContext;
use crate::bus::WireEvent;
use crate::AppState;
use axum::extract::rejection::JsonRejection;
use axum::extract::ws::{close_code, CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, FromRequest, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Version};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use base64::Engine as _;
use coop_attestation::bytes_to_hex;
use coop_store::{AttestationMetadata, JobCursor, JobRow, JobSummary, ListJobsQuery};
use coop_types::{
    EffectiveJobSpec, IsolationClass, JobSpec, JobStatus, LimitEnforcement, CPU_MAX_SECONDS,
    FILE_MAX_MB, MAX_INPUT_BYTES, MAX_INPUT_FILES, MAX_INPUT_FILE_BYTES, MAX_OUTPUT_BYTES,
    MAX_OUTPUT_FILES, MAX_OUTPUT_FILE_BYTES, PIDS_MAX, RUNTIME_PACKS, SUPPORTED_LANGUAGES,
    WALL_MAX_SECONDS,
};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
#[cfg(test)]
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tracing::Instrument as _;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    pub request_id: String,
    pub retryable: bool,
}

pub(crate) fn api_error(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
    retryable: bool,
) -> Response {
    api_error_with_retry(status, code, message, retryable, None)
}

pub(crate) fn api_error_with_retry(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
    retryable: bool,
    retry_after_secs: Option<u64>,
) -> Response {
    let request_id =
        crate::request_context::current_request_id().unwrap_or_else(|| Uuid::now_v7().to_string());
    let mut response = (
        status,
        Json(ErrorEnvelope {
            error: ErrorBody {
                code: code.into(),
                message: message.into(),
                request_id: request_id.clone(),
                retryable,
            },
        }),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    if let Some(seconds) = retry_after_secs {
        if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
            response.headers_mut().insert("retry-after", value);
        }
    }
    response
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SubmitResponse {
    pub job_id: String,
    pub status: String,
    pub stream_url: String,
    pub replay_url: String,
    pub stream_ticket_url: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct JobDetail {
    #[serde(flatten)]
    pub job: JobView,
    pub requested_spec: JobSpec,
    pub effective_spec: Option<EffectiveJobSpec>,
    pub execution_policy: ExecutionPolicy,
    #[schema(value_type = Option<Object>)]
    pub receipt: Option<serde_json::Value>,
    pub receipt_sha256: Option<String>,
    pub attestation: JobAttestationStatus,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct JobAttestationStatus {
    pub available: bool,
    pub tenant: Option<String>,
    pub key_id: Option<String>,
    pub receipt_sha256: Option<String>,
    pub result_media_type: Option<String>,
    pub result_sha256: Option<String>,
    pub result_size_bytes: Option<u64>,
    pub envelope_sha256: Option<String>,
    pub envelope_size_bytes: Option<u64>,
    pub envelope_url: Option<String>,
    pub result_artifact_url: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExecutionPolicy {
    pub sandbox: Option<String>,
    pub isolation_class: Option<IsolationClass>,
    pub bootstrap_ready: Option<bool>,
    pub isolated: Option<bool>,
    pub seccomp: Option<bool>,
    pub network_allowed: Option<bool>,
    pub networking: Option<String>,
    pub private_rootfs: Option<bool>,
    pub dedicated_bootstrap: Option<bool>,
    pub limit_enforcement: Option<LimitEnforcement>,
    pub runtime_version: Option<String>,
    pub runtime_sha256: Option<String>,
    pub rootfs_sha256: Option<String>,
    pub config_sha256: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListJobsResponse {
    pub items: Vec<JobView>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReplayResponse {
    pub events: Vec<WireEvent>,
    pub next_cursor: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StreamTicketResponse {
    pub ticket: String,
    pub stream_url: String,
    pub expires_at_ms: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WhoAmIResponse {
    pub tenant: String,
    pub principal_id: String,
    pub credential_id: Option<String>,
    pub auth_method: String,
    pub scopes: Vec<String>,
    pub expires_at_ms: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CapabilitiesResponse {
    pub version: String,
    pub languages: Vec<String>,
    pub execution: ExecutionCapabilities,
    pub limits: LimitCapabilities,
    pub features: FeatureCapabilities,
    pub attestations: AttestationCapabilities,
    pub runtime_packs: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AttestationCapabilities {
    pub enabled: bool,
    pub algorithm: Option<String>,
    pub envelope_format: Option<String>,
    pub key_id: Option<String>,
    pub public_key_url: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AttestationPublicKeyResponse {
    pub algorithm: String,
    pub key_id: String,
    pub public_key_pem: String,
    pub trust_notice: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExecutionCapabilities {
    pub backend: String,
    pub isolation_class: IsolationClass,
    pub isolated: bool,
    pub private_rootfs: bool,
    pub dedicated_bootstrap: bool,
    pub seccomp: bool,
    pub networking: String,
    pub limit_enforcement: LimitEnforcement,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LimitCapabilities {
    pub wall_seconds_max: u32,
    pub cpu_seconds_max: u32,
    pub mem_mb_max: u32,
    pub concurrent_mem_mb_max: u32,
    pub pids_max: u32,
    pub file_mb_max: u32,
    pub output_lines_max: usize,
    pub output_bytes_per_stream_max: usize,
    pub output_record_bytes_max: usize,
    pub code_bytes_max: usize,
    pub stdin_bytes_max: usize,
    pub input_files_max: usize,
    pub input_file_bytes_max: usize,
    pub input_bytes_max: usize,
    pub output_files_max: usize,
    pub output_file_bytes_max: usize,
    pub output_bytes_max: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FeatureCapabilities {
    pub result_wait: bool,
    pub cancellation: bool,
    pub event_cursors: bool,
    pub stream_tickets: bool,
    pub receipts: bool,
    pub signed_attestations: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StatusResponse {
    pub version: String,
    /// Compatibility alias for `execution.backend`.
    pub sandbox: String,
    pub uptime_seconds: u64,
    pub environment: String,
    pub execution: ExecutionCapabilities,
    pub scheduler: SchedulerStatus,
    pub storage_ready: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SchedulerStatus {
    pub workers: usize,
    pub queue_capacity: usize,
    pub queue_depth: usize,
    pub running: usize,
    pub shutting_down: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct JobView {
    pub job_id: String,
    pub tenant: String,
    pub language: String,
    pub status: String,
    pub created_at_ms: i64,
    pub started_at_ms: Option<i64>,
    pub finished_at_ms: Option<i64>,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CancellationResponse {
    pub job: JobView,
    pub cancellation_requested: bool,
    pub already_terminal: bool,
}

fn cancellation_response(
    row: &JobSummary,
    cancellation_requested: bool,
    already_terminal: bool,
) -> Response {
    Json(CancellationResponse {
        job: JobView::from_summary(row),
        cancellation_requested,
        already_terminal,
    })
    .into_response()
}

impl JobView {
    fn from_row(row: &JobRow) -> Self {
        Self {
            job_id: row.job_id.clone(),
            tenant: row.tenant.clone(),
            language: row.language.clone(),
            status: row.status.clone(),
            created_at_ms: row.created_at_ms,
            started_at_ms: row.started_at_ms,
            finished_at_ms: row.finished_at_ms,
            exit_code: row.exit_code,
        }
    }

    fn from_summary(row: &JobSummary) -> Self {
        Self {
            job_id: row.job_id.clone(),
            tenant: row.tenant.clone(),
            language: row.language.clone(),
            status: row.status.clone(),
            created_at_ms: row.created_at_ms,
            started_at_ms: row.started_at_ms,
            finished_at_ms: row.finished_at_ms,
            exit_code: row.exit_code,
        }
    }
}

/// One-call job outcome for agent tool loops: the terminal view plus stdout /
/// stderr folded out of the retained, hash-chained event log server-side, so clients get
/// a ready-to-use string instead of replaying raw events themselves.
#[derive(Debug, Serialize, ToSchema)]
pub struct ResultView {
    pub job_id: String,
    pub status: String,
    pub exit_code: Option<i32>,
    #[schema(value_type = Option<i64>)]
    pub duration_ms: Option<i64>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    #[schema(value_type = Vec<Object>)]
    pub violations: Vec<serde_json::Value>,
    pub artifacts: Vec<ArtifactView>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactView {
    pub path: String,
    pub content_base64: String,
    pub size_bytes: usize,
    pub sha256: String,
}

/// True when the job exists AND belongs to `tenant`. Foreign jobs are
/// indistinguishable from missing ones (same IDOR posture as F-001).
async fn owns_job(state: &AppState, id: &str, tenant: &str) -> coop_store::StoreResult<bool> {
    Ok(state
        .store
        .get_job_summary(id)
        .await?
        .is_some_and(|row| row.tenant == tenant))
}

/// Server-side wait policy for GET /v1/jobs/{id}/result.
const RESULT_DEFAULT_WAIT_SECONDS: u64 = 60;
const RESULT_MAX_WAIT_SECONDS: u64 = 300;
const MAX_CODE_BYTES: usize = 1_048_576;
const MAX_STDIN_BYTES: usize = 1_048_576;
// JSON escaping can expand code and stdin bytes to six-byte `\uXXXX`
// sequences. Base64 adds four bytes for each three decoded input-file bytes.
// Keep the encoded request bounded while allowing every decoded field to reach
// its independent limit in one valid request plus envelope overhead.
const MAX_REQUEST_BODY_BYTES: usize = 24 * 1_048_576;
const SUBMIT_BODY_READ_DEADLINE: Duration = Duration::from_secs(30);
const MAX_INBOUND_STREAM_MESSAGE_BYTES: usize = 1_024;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const STREAM_SEND_DEADLINE: Duration = Duration::from_secs(5);
const STREAM_CLOSE_DEADLINE: Duration = Duration::from_millis(250);
const LARGE_RESPONSE_CHUNK_BYTES: usize = 64 * 1_024;
fn idempotency_request(
    headers: &HeaderMap,
    spec: &JobSpec,
) -> Result<Option<coop_store::IdempotencyRequest>, Box<Response>> {
    let mut values = headers.get_all("idempotency-key").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Box::new(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            "Idempotency-Key must appear exactly once",
            false,
        )));
    }
    let key = value.to_str().map_err(|_| {
        Box::new(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            "Idempotency-Key must contain visible ASCII",
            false,
        ))
    })?;
    if key.is_empty()
        || key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        || !key.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(Box::new(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            format!("Idempotency-Key must be 1-{MAX_IDEMPOTENCY_KEY_BYTES} visible ASCII bytes"),
            false,
        )));
    }
    let value = serde_json::to_value(spec)
        .map_err(|error| Box::new(internal_error("canonicalize idempotent job spec", error)))?;
    let canonical = coop_store::canonical_json(&value);
    Ok(Some(coop_store::IdempotencyRequest {
        key: key.to_string(),
        request_sha256: bytes_to_hex(Sha256::digest(canonical.as_bytes()).as_slice()),
    }))
}

fn idempotency_conflict() -> Response {
    api_error(
        StatusCode::UNPROCESSABLE_ENTITY,
        "idempotency_key_reused",
        "Idempotency-Key was already used for a different canonical job specification",
        false,
    )
}

fn submission_response(job_id: String, replayed: bool) -> Response {
    let location = format!("/v1/jobs/{job_id}");
    let mut response = (
        StatusCode::CREATED,
        Json(SubmitResponse {
            stream_url: format!("/v1/jobs/{job_id}/stream"),
            replay_url: format!("/v1/jobs/{job_id}/replay"),
            stream_ticket_url: format!("/v1/jobs/{job_id}/stream-ticket"),
            job_id,
            status: "queued".to_string(),
        }),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response.headers_mut().insert(
        "idempotency-replayed",
        HeaderValue::from_static(if replayed { "true" } else { "false" }),
    );
    response
}

pub struct SubmitPayload {
    spec: JobSpec,
    _permit: crate::LifetimePermit,
}

#[derive(Clone, Default)]
struct SubmitBodyReadState(Arc<std::sync::atomic::AtomicBool>);

impl SubmitBodyReadState {
    fn mark_complete(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }

    fn is_complete(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

fn http1_submit_has_framed_body(req: &Request) -> bool {
    matches!(
        req.version(),
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11
    ) && req.method() == axum::http::Method::POST
        && req.uri().path() == "/v1/jobs"
        && (req.headers().contains_key(header::TRANSFER_ENCODING)
            || req
                .headers()
                .get_all(header::CONTENT_LENGTH)
                .iter()
                .any(|value| value.as_bytes() != b"0"))
}

/// HTTP/1 has one ordered request stream per connection. If auth, scope,
/// rate limiting, or extraction rejects a submission before its advertised
/// body reaches EOF, dropping the body can otherwise leave Hyper draining an
/// attacker-paced body after the submit-body permit has been released (or
/// before one was acquired). Close only that HTTP/1 connection; HTTP/2 stream
/// cancellation remains session-local and must not receive hop-by-hop
/// `Connection` headers.
async fn close_early_http1_submit_body(mut req: Request, next: axum::middleware::Next) -> Response {
    let state = http1_submit_has_framed_body(&req).then(SubmitBodyReadState::default);
    if let Some(state) = state.as_ref() {
        req.extensions_mut().insert(state.clone());
    }
    let mut response = next.run(req).await;
    if state.as_ref().is_some_and(|state| !state.is_complete()) {
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

#[allow(clippy::result_large_err)]
impl FromRequest<AppState> for SubmitPayload {
    type Rejection = Response;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let tenant = req
            .extensions()
            .get::<AuthContext>()
            .map(|auth| auth.tenant_id.clone())
            .unwrap_or_else(|| "unauthenticated".to_string());
        extract_submit_payload(
            req,
            &state.submit_body_admission,
            Some(state.metrics.as_ref()),
            &tenant,
            SUBMIT_BODY_READ_DEADLINE,
        )
        .await
    }
}

#[allow(clippy::result_large_err)]
async fn extract_submit_payload(
    req: Request,
    admission: &crate::LifetimeAdmission,
    metrics: Option<&crate::metrics::Metrics>,
    tenant: &str,
    deadline: Duration,
) -> Result<SubmitPayload, Response> {
    let request_version = req.version();
    let body_read_state = req.extensions().get::<SubmitBodyReadState>().cloned();
    let permit = match admission.try_acquire(tenant) {
        Ok(permit) => permit,
        Err(crate::TryLifetimeError::Closed) => {
            if let Some(metrics) = metrics {
                record_lifetime_rejection(
                    metrics,
                    crate::metrics::AdmissionScope::SubmitBody,
                    crate::TryLifetimeError::Closed,
                );
            }
            return Err(api_error_with_retry(
                StatusCode::SERVICE_UNAVAILABLE,
                "shutting_down",
                "server is shutting down",
                true,
                Some(1),
            ));
        }
        Err(crate::TryLifetimeError::GlobalFull) => {
            if let Some(metrics) = metrics {
                record_lifetime_rejection(
                    metrics,
                    crate::metrics::AdmissionScope::SubmitBody,
                    crate::TryLifetimeError::GlobalFull,
                );
            }
            return Err(api_error_with_retry(
                StatusCode::SERVICE_UNAVAILABLE,
                "submit_body_capacity",
                "too many request bodies are currently being read",
                true,
                Some(1),
            ));
        }
        Err(crate::TryLifetimeError::TenantFull) => {
            if let Some(metrics) = metrics {
                record_lifetime_rejection(
                    metrics,
                    crate::metrics::AdmissionScope::SubmitBody,
                    crate::TryLifetimeError::TenantFull,
                );
            }
            return Err(api_error_with_retry(
                StatusCode::TOO_MANY_REQUESTS,
                "tenant_submit_body_capacity",
                "this tenant has too many request bodies currently being read",
                true,
                Some(1),
            ));
        }
    };

    match tokio::time::timeout(deadline, Json::<JobSpec>::from_request(req, &())).await {
        Ok(Ok(Json(spec))) => {
            if let Some(state) = body_read_state.as_ref() {
                state.mark_complete();
            }
            Ok(SubmitPayload {
                spec,
                _permit: permit,
            })
        }
        Ok(Err(rejection)) => {
            // Axum buffers the complete body before deserializing JSON.
            // Syntax/data failures therefore reached EOF, while content-type
            // and byte-buffer failures may still leave attacker-paced bytes.
            if matches!(
                &rejection,
                JsonRejection::JsonDataError(_) | JsonRejection::JsonSyntaxError(_)
            ) {
                if let Some(state) = body_read_state.as_ref() {
                    state.mark_complete();
                }
            }
            Err(json_rejection_response(rejection))
        }
        Err(_) => {
            let mut response = api_error_with_retry(
                StatusCode::REQUEST_TIMEOUT,
                "request_body_timeout",
                "request body was not received before the read deadline",
                true,
                Some(1),
            );
            // Dropping an incomplete HTTP/1 request body can otherwise leave
            // the connection task draining attacker-controlled bytes after
            // this request's memory permit has been reclaimed. HTTP/2 drops
            // reset only the affected stream and must not close the session.
            if matches!(
                request_version,
                Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11
            ) {
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
            }
            Err(response)
        }
    }
}

fn json_rejection_response(rejection: JsonRejection) -> Response {
    let rejection_status = rejection.status();
    let (status, code) = match rejection_status {
        StatusCode::PAYLOAD_TOO_LARGE => (StatusCode::PAYLOAD_TOO_LARGE, "request_body_too_large"),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => {
            (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
        }
        _ => (StatusCode::BAD_REQUEST, "invalid_json"),
    };
    api_error(status, code, rejection.body_text(), false)
}

fn acquire_large_response(
    state: &AppState,
    tenant: &str,
) -> Result<crate::LifetimePermit, crate::TryLifetimeError> {
    state.large_response_admission.try_acquire(tenant)
}

fn large_response_error(error: crate::TryLifetimeError) -> Response {
    match error {
        crate::TryLifetimeError::Closed => api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "server is shutting down",
            true,
            Some(1),
        ),
        crate::TryLifetimeError::GlobalFull => api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "response_capacity",
            "too many large responses are currently being transferred",
            true,
            Some(1),
        ),
        crate::TryLifetimeError::TenantFull => api_error_with_retry(
            StatusCode::TOO_MANY_REQUESTS,
            "tenant_response_capacity",
            "this tenant has a large response transfer in progress",
            true,
            Some(1),
        ),
    }
}

fn result_wait_error(error: crate::TryLifetimeError) -> Response {
    match error {
        crate::TryLifetimeError::Closed => api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "server is shutting down",
            true,
            Some(1),
        ),
        crate::TryLifetimeError::GlobalFull => api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "result_wait_capacity",
            "too many long result waits are active",
            true,
            Some(1),
        ),
        crate::TryLifetimeError::TenantFull => api_error_with_retry(
            StatusCode::TOO_MANY_REQUESTS,
            "tenant_result_wait_capacity",
            "this tenant has too many active result waits",
            true,
            Some(1),
        ),
    }
}

fn stream_admission_error(error: crate::TryLifetimeError) -> Response {
    match error {
        crate::TryLifetimeError::Closed => api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "server is shutting down",
            true,
            Some(1),
        ),
        crate::TryLifetimeError::GlobalFull => api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "stream_capacity",
            "too many WebSocket streams are active",
            true,
            Some(1),
        ),
        crate::TryLifetimeError::TenantFull => api_error_with_retry(
            StatusCode::TOO_MANY_REQUESTS,
            "tenant_stream_capacity",
            "this tenant has too many active WebSocket streams",
            true,
            Some(1),
        ),
    }
}

fn record_lifetime_rejection(
    metrics: &crate::metrics::Metrics,
    scope: crate::metrics::AdmissionScope,
    error: crate::TryLifetimeError,
) {
    let reason = match error {
        crate::TryLifetimeError::Closed => crate::metrics::AdmissionReason::Closed,
        crate::TryLifetimeError::GlobalFull => crate::metrics::AdmissionReason::GlobalFull,
        crate::TryLifetimeError::TenantFull => crate::metrics::AdmissionReason::TenantFull,
    };
    metrics.reject(scope, reason);
}

fn guarded_json_response<T: Serialize>(
    status: StatusCode,
    value: &T,
    permit: crate::LifetimePermit,
) -> Response {
    let encoded = match serde_json::to_vec(value) {
        Ok(encoded) => encoded,
        Err(error) => return internal_error("serialize JSON response", error),
    };
    guarded_bytes_response(
        status,
        encoded,
        permit,
        HeaderValue::from_static("application/json"),
        None,
    )
}

fn guarded_bytes_response(
    status: StatusCode,
    encoded: Vec<u8>,
    permit: crate::LifetimePermit,
    content_type: HeaderValue,
    sha256: Option<&str>,
) -> Response {
    let encoded_len = encoded.len();
    let (chunk_tx, chunk_rx) = tokio::sync::mpsc::channel::<axum::body::Bytes>(1);
    tokio::spawn(async move {
        let mut offset = 0;
        while offset < encoded.len() {
            let end = (offset + LARGE_RESPONSE_CHUNK_BYTES).min(encoded.len());
            // Reserve channel space before copying so the application owns
            // at most one detached 64 KiB chunk. The response lifetime permit
            // bounds the full encoded buffer while transport-level write
            // progress and absolute connection deadlines close slow peers.
            match chunk_tx.reserve().await {
                Ok(slot) => {
                    slot.send(axum::body::Bytes::copy_from_slice(&encoded[offset..end]));
                    offset = end;
                }
                Err(_) => break,
            }
        }
    });
    // The non-cloneable permit lives in Body state. The encoded buffer, an
    // unread connection, and its one queued chunk remain covered by the hard
    // global/tenant cap until Hyper observes EOF or drops the body.
    let stream =
        futures_util::stream::unfold((chunk_rx, permit), |(mut receiver, permit)| async move {
            receiver
                .recv()
                .await
                .map(|chunk| (Ok::<_, std::convert::Infallible>(chunk), (receiver, permit)))
        });
    let mut response = Response::new(axum::body::Body::from_stream(stream));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    if let Ok(value) = HeaderValue::from_str(&encoded_len.to_string()) {
        response.headers_mut().insert(header::CONTENT_LENGTH, value);
    }
    if let Some(sha256) = sha256.and_then(|value| HeaderValue::from_str(value).ok()) {
        response.headers_mut().insert("x-content-sha256", sha256);
    }
    response
}

/// Complete the durable-acceptance linearization while owning both capacity
/// leases. The caller runs this future in a detached Tokio task before its
/// next await, so dropping the HTTP request cannot cancel an in-flight SQLite
/// COMMIT and strand a queued row without its scheduler envelope.
#[cfg(test)]
struct ReservedSubmissionCommit {
    reservation: crate::scheduler::AdmissionReservation,
    job_id: String,
    event: Option<coop_store::EventRow>,
}

#[cfg(test)]
impl ReservedSubmissionCommit {
    fn publish_and_handoff(self, publish: impl FnOnce(Option<coop_store::EventRow>)) {
        // Publishing the accepted event and committing the already-reserved
        // channel permit are synchronous. No cancellation point can split a
        // durable acceptance from its scheduler envelope.
        publish(self.event);
        self.reservation.send(self.job_id);
    }
}

#[cfg(test)]
async fn commit_reserved_submission<P, PF, R, RF, E>(
    reservation: crate::scheduler::AdmissionReservation,
    job_id: String,
    persist: P,
    mut reconcile: R,
) -> Result<ReservedSubmissionCommit, E>
where
    P: FnOnce() -> PF,
    PF: Future<Output = Result<coop_store::EventRow, E>>,
    R: FnMut() -> RF,
    RF: Future<Output = Result<bool, E>>,
    E: std::fmt::Display,
{
    match persist().await {
        Ok(event) => Ok(ReservedSubmissionCommit {
            reservation,
            job_id,
            event: Some(event),
        }),
        Err(commit_error) => {
            // A local SQLite COMMIT error is normally definitive, but retain
            // the lease while proving that no durable row exists. This also
            // covers an ambiguous acknowledgement boundary without ever
            // admitting a second job into the same global slot.
            let mut delay = Duration::from_millis(10);
            loop {
                match reconcile().await {
                    Ok(true) => {
                        return Ok(ReservedSubmissionCommit {
                            reservation,
                            job_id,
                            event: None,
                        });
                    }
                    Ok(false) => return Err(commit_error),
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            %job_id,
                            "could not reconcile an ambiguous job acceptance; retaining admission and retrying"
                        );
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(1));
                    }
                }
            }
        }
    }
}

struct SubmissionAcceptance {
    job_id: String,
    replayed: bool,
}

struct PendingSubmission {
    job_id: String,
    tenant: String,
    language: String,
    spec_json: String,
    requested_mem_mb: u32,
    idempotency: Option<coop_store::IdempotencyRequest>,
    job_trace: crate::request_context::JobTraceContext,
}

#[cfg(test)]
#[derive(Clone)]
struct SubmissionCommitPause {
    key: String,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[cfg(test)]
static SUBMISSION_COMMIT_PAUSE: std::sync::Mutex<Option<SubmissionCommitPause>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
async fn pause_after_submission_commit(idempotency: Option<&coop_store::IdempotencyRequest>) {
    let pause = SUBMISSION_COMMIT_PAUSE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .filter(|pause| idempotency.is_some_and(|request| request.key == pause.key))
        .cloned();
    if let Some(pause) = pause {
        pause.entered.notify_one();
        pause.release.notified().await;
    }
}

fn spawn_submission_commit(
    state: AppState,
    reservation: crate::scheduler::AdmissionReservation,
    body_permit: crate::LifetimePermit,
    pending: PendingSubmission,
) -> tokio::task::JoinHandle<coop_store::StoreResult<SubmissionAcceptance>> {
    let accept_span = pending.job_trace.accept_span(&pending.job_id);
    let future = async move {
        let PendingSubmission {
            job_id,
            tenant,
            language,
            spec_json,
            requested_mem_mb,
            idempotency,
            job_trace,
        } = pending;
        let started_at = std::time::Instant::now();
        // Establish process-local observation and retain the composite queue
        // reservation before COMMIT can publish the durable idempotency row.
        // A racing replay may therefore return only after both ownership
        // structures already exist; this registration is never repeated
        // after COMMIT, so a racing cancellation cannot be overwritten by a
        // fresh nonterminal channel.
        state.bus.register(&job_id);
        let persisted = state
            .store
            .create_job_with_event_idempotent(
                &job_id,
                &tenant,
                &language,
                &spec_json,
                requested_mem_mb,
                idempotency.as_ref(),
            )
            .await;
        state.metrics.observe_storage(
            crate::metrics::StorageOperation::Accept,
            started_at.elapsed(),
            persisted.is_ok(),
        );
        #[cfg(test)]
        pause_after_submission_commit(idempotency.as_ref()).await;
        let result = match persisted {
            Ok(coop_store::CreateJobOutcome::Created(event)) => {
                state.bus.send(&job_id, wire_event(event));
                reservation.send(job_id.clone());
                state.job_traces.insert(job_id.clone(), job_trace);
                state
                    .metrics
                    .submitted(crate::metrics::Language::classify(&language));
                Ok(SubmissionAcceptance {
                    job_id: job_id.clone(),
                    replayed: false,
                })
            }
            Ok(coop_store::CreateJobOutcome::Replayed {
                job_id: replayed_job_id,
            }) => {
                state.bus.remove(&job_id);
                drop(reservation);
                Ok(SubmissionAcceptance {
                    job_id: replayed_job_id,
                    replayed: true,
                })
            }
            Err(commit_error) => {
                // Distinguish a definitive capacity/validation rejection from
                // a commit acknowledgement lost after the row became durable.
                let mut delay = Duration::from_millis(10);
                loop {
                    let read_started_at = std::time::Instant::now();
                    let summary = state.store.get_job_summary(&job_id).await;
                    state.metrics.observe_storage(
                        crate::metrics::StorageOperation::Read,
                        read_started_at.elapsed(),
                        summary.is_ok(),
                    );
                    match summary {
                        Ok(Some(row))
                            if row.tenant == tenant
                                && row.language == language
                                && row.status == "queued" =>
                        {
                            tracing::warn!(%job_id, "reconciled an ambiguously acknowledged durable job acceptance");
                            reservation.send(job_id.clone());
                            state.job_traces.insert(job_id.clone(), job_trace);
                            state
                                .metrics
                                .submitted(crate::metrics::Language::classify(&language));
                            break Ok(SubmissionAcceptance {
                                job_id: job_id.clone(),
                                replayed: false,
                            });
                        }
                        Ok(_) => {
                            let Some(request) = idempotency.as_ref() else {
                                state.bus.remove(&job_id);
                                drop(reservation);
                                break Err(commit_error);
                            };
                            let read_started_at = std::time::Instant::now();
                            let lookup = state.store.lookup_idempotency(&tenant, request).await;
                            state.metrics.observe_storage(
                                crate::metrics::StorageOperation::Read,
                                read_started_at.elapsed(),
                                lookup.is_ok(),
                            );
                            match lookup {
                                Ok(coop_store::IdempotencyLookup::Replay {
                                    job_id: replayed_job_id,
                                }) => {
                                    state.bus.remove(&job_id);
                                    drop(reservation);
                                    break Ok(SubmissionAcceptance {
                                        job_id: replayed_job_id,
                                        replayed: true,
                                    });
                                }
                                Ok(coop_store::IdempotencyLookup::Conflict)
                                    if coop_store::is_idempotency_conflict(&commit_error) =>
                                {
                                    state.bus.remove(&job_id);
                                    drop(reservation);
                                    break Err(commit_error);
                                }
                                Ok(_) => {
                                    state.bus.remove(&job_id);
                                    drop(reservation);
                                    break Err(commit_error);
                                }
                                Err(error) => {
                                    tracing::warn!(error = %error, job_id = %job_id, "could not reconcile idempotent job acceptance; retaining leases")
                                }
                            }
                        }
                        Err(error) => {
                            tracing::warn!(error = %error, job_id = %job_id, "could not reconcile job acceptance; retaining leases")
                        }
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(1));
                }
            }
        };
        if result.is_err() {
            state.bus.remove(&job_id);
            state.job_traces.remove(&job_id);
        }
        // Keep parsed request memory and both submission capacity budgets
        // alive until durable commit/reconciliation and scheduler handoff.
        drop(body_permit);
        result
    };
    tokio::spawn(future.instrument(accept_span))
}

pub(crate) fn router(state: AppState) -> Router {
    let api = Router::new()
        .route(
            "/v1/jobs",
            post(submit).route_layer(axum::middleware::from_fn(crate::auth::require_jobs_submit)),
        )
        .route(
            "/v1/jobs",
            get(list_jobs).route_layer(axum::middleware::from_fn(crate::auth::require_jobs_read)),
        )
        .route(
            "/v1/jobs/{id}",
            get(get_job).route_layer(axum::middleware::from_fn(crate::auth::require_jobs_read)),
        )
        .route(
            "/v1/jobs/{id}",
            delete(cancel_job)
                .route_layer(axum::middleware::from_fn(crate::auth::require_jobs_cancel)),
        )
        .route(
            "/v1/jobs/{id}/replay",
            get(replay).route_layer(axum::middleware::from_fn(crate::auth::require_jobs_read)),
        )
        .route(
            "/v1/jobs/{id}/result",
            get(job_result).route_layer(axum::middleware::from_fn(crate::auth::require_jobs_read)),
        )
        .route(
            "/v1/jobs/{id}/attestation",
            get(job_attestation)
                .route_layer(axum::middleware::from_fn(crate::auth::require_jobs_read)),
        )
        .route(
            "/v1/jobs/{id}/result-artifact",
            get(job_result_artifact)
                .route_layer(axum::middleware::from_fn(crate::auth::require_jobs_read)),
        )
        .route(
            "/v1/jobs/{id}/stream",
            get(stream).route_layer(axum::middleware::from_fn(crate::auth::require_jobs_read)),
        )
        .route(
            "/v1/jobs/{id}/stream-ticket",
            post(stream_ticket)
                .route_layer(axum::middleware::from_fn(crate::auth::require_jobs_read)),
        )
        .route(
            "/v1/metrics",
            get(metrics).route_layer(axum::middleware::from_fn(crate::auth::require_metrics_read)),
        )
        .route(
            "/v1/status",
            get(status).route_layer(axum::middleware::from_fn(crate::auth::require_service_read)),
        )
        .route(
            "/v1/capabilities",
            get(capabilities)
                .route_layer(axum::middleware::from_fn(crate::auth::require_service_read)),
        )
        .route(
            "/v1/attestation/public-key",
            get(attestation_public_key)
                .route_layer(axum::middleware::from_fn(crate::auth::require_service_read)),
        )
        .route(
            "/v1/whoami",
            get(whoami).route_layer(axum::middleware::from_fn(crate::auth::require_service_read)),
        )
        .route(
            "/whoami",
            get(whoami).route_layer(axum::middleware::from_fn(crate::auth::require_service_read)),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::ratelimit::middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::middleware,
        ))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(axum::middleware::from_fn(crate::auth::no_store))
        .layer(axum::middleware::from_fn(close_early_http1_submit_body));

    Router::new()
        .route("/", get(dashboard))
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(operator_metrics))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource_metadata),
        )
        .route("/openapi.json", get(crate::openapi::serve))
        .merge(api)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::request_context::middleware,
        ))
        .with_state(state)
}

async fn not_found() -> Response {
    api_error(
        StatusCode::NOT_FOUND,
        "not_found",
        "the requested resource does not exist",
        false,
    )
}

async fn method_not_allowed() -> Response {
    api_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "the HTTP method is not allowed for this resource",
        false,
    )
}

fn internal_error(context: &str, e: impl std::fmt::Display) -> Response {
    let response = api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "an internal server error occurred",
        true,
    );
    let request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    tracing::error!(context, error = %e, request_id, "internal error");
    response
}

#[utoipa::path(
    post,
    path = "/v1/jobs",
    params(
        ("Idempotency-Key" = Option<String>, Header, description = "Optional 1-128 byte visible-ASCII opaque key. Scoped to the authenticated tenant; replaying the same canonical request returns the original job, while reuse with a different request returns 422.")
    ),
    request_body = JobSpec,
    responses(
        (status = 201, description = "Job accepted or replayed", body = SubmitResponse,
            headers(
                ("Location" = String, description = "Canonical /v1/jobs/{job_id} resource"),
                ("Idempotency-Replayed" = String, description = "true when this response replays an existing idempotent acceptance; false for a new acceptance")
            )
        ),
        (status = 400, description = "Invalid job spec", body = ErrorEnvelope),
        (status = 401, description = "Missing or invalid API key", body = ErrorEnvelope),
        (status = 408, description = "Request body read deadline exceeded", body = ErrorEnvelope),
        (status = 413, description = "Code or stdin too large", body = ErrorEnvelope),
        (status = 415, description = "JSON content type required", body = ErrorEnvelope),
        (status = 422, description = "Configured runtime is unavailable or an idempotency key conflicts with a different canonical request", body = ErrorEnvelope),
        (status = 429, description = "Rate or per-tenant body capacity exceeded", body = ErrorEnvelope),
        (status = 503, description = "Queue, global body, startup, shutdown, or logical storage capacity unavailable", body = ErrorEnvelope),
        (status = 507, description = "Filesystem free-space reserve prevents admission", body = ErrorEnvelope)
    )
)]
pub async fn submit(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    SubmitPayload {
        spec,
        _permit: body_permit,
    }: SubmitPayload,
) -> Response {
    let idempotency = match idempotency_request(&headers, &spec) {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if let Some(request) = idempotency.as_ref() {
        match state
            .store
            .lookup_idempotency(&auth.tenant_id, request)
            .await
        {
            Ok(coop_store::IdempotencyLookup::Replay { job_id }) => {
                return submission_response(job_id, true)
            }
            Ok(coop_store::IdempotencyLookup::Conflict) => return idempotency_conflict(),
            Ok(coop_store::IdempotencyLookup::Miss) => {}
            Err(error) => return internal_error("lookup idempotent submission", error),
        }
    }
    if *state.shutdown.borrow() {
        state.metrics.reject(
            crate::metrics::AdmissionScope::Scheduler,
            crate::metrics::AdmissionReason::Shutdown,
        );
        return api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "server is shutting down",
            true,
            Some(1),
        );
    }
    if !state
        .startup_ready
        .load(std::sync::atomic::Ordering::Acquire)
    {
        state.metrics.reject(
            crate::metrics::AdmissionScope::Scheduler,
            crate::metrics::AdmissionReason::Startup,
        );
        return api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "startup_recovery",
            "durable startup recovery is still in progress",
            true,
            Some(1),
        );
    }
    if !state
        .execution_provider
        .isolation_class()
        .satisfies(spec.requirements.minimum_isolation)
    {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "minimum_isolation_unsatisfied",
            format!(
                "the configured provider {} cannot satisfy requested minimum isolation {}",
                state.execution_provider.isolation_class(),
                spec.requirements.minimum_isolation
            ),
            false,
        );
    }
    if !coop_types::is_supported_language(&spec.language) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "unsupported_language",
            format!("unsupported language; expected one of {SUPPORTED_LANGUAGES:?}"),
            false,
        );
    }
    if !state
        .available_languages
        .iter()
        .any(|language| language == &spec.language)
    {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "runtime_unavailable",
            "the requested language runtime is not available in this server configuration",
            false,
        );
    }
    if spec.code.trim().is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "empty_code",
            "code must not be empty",
            false,
        );
    }
    if spec.code.len() > MAX_CODE_BYTES {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "code_too_large",
            format!("code exceeds the {MAX_CODE_BYTES} byte limit"),
            false,
        );
    }
    if spec
        .stdin
        .as_ref()
        .is_some_and(|stdin| stdin.len() > MAX_STDIN_BYTES)
    {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "stdin_too_large",
            format!("stdin exceeds the {MAX_STDIN_BYTES} byte limit"),
            false,
        );
    }
    if spec.files.len() > MAX_INPUT_FILES {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_many_input_files",
            format!("files exceeds the {MAX_INPUT_FILES} file limit"),
            false,
        );
    }
    let mut input_paths = HashSet::with_capacity(spec.files.len());
    let mut input_bytes = 0_usize;
    for file in &spec.files {
        if !coop_types::validate_artifact_path(&file.path, "input") {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_input_path",
                "input file paths must be safe relative paths under input/",
                false,
            );
        }
        if !input_paths.insert(file.path.as_str()) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "duplicate_input_path",
                "input file paths must be unique",
                false,
            );
        }
        let decoded = match base64::engine::general_purpose::STANDARD.decode(&file.content_base64) {
            Ok(decoded) => decoded,
            Err(_) => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_input_base64",
                    "input file content_base64 must be valid standard base64",
                    false,
                )
            }
        };
        if decoded.len() > MAX_INPUT_FILE_BYTES {
            return api_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "input_file_too_large",
                format!("one input file exceeds {MAX_INPUT_FILE_BYTES} bytes"),
                false,
            );
        }
        input_bytes = input_bytes.saturating_add(decoded.len());
        if input_bytes > MAX_INPUT_BYTES {
            return api_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "input_files_too_large",
                format!("decoded input files exceed {MAX_INPUT_BYTES} total bytes"),
                false,
            );
        }
    }
    if spec.outputs.len() > MAX_OUTPUT_FILES {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_many_output_files",
            format!("outputs exceeds the {MAX_OUTPUT_FILES} file limit"),
            false,
        );
    }
    let mut output_paths = HashSet::with_capacity(spec.outputs.len());
    for path in &spec.outputs {
        if !coop_types::validate_artifact_path(path, "output") {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_output_path",
                "output file paths must be safe relative paths under output/",
                false,
            );
        }
        if !output_paths.insert(path.as_str()) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "duplicate_output_path",
                "output file paths must be unique",
                false,
            );
        }
    }
    if !coop_types::validate_runtime_pack(&spec.language, spec.runtime.as_deref()) {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "runtime_pack_unavailable",
            "the requested runtime pack is not available for this language",
            false,
        );
    }
    if spec.runtime.is_some() && state.execution_provider.isolation_class() == IsolationClass::None
    {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "runtime_pack_requires_isolation",
            "named runtime packs require a Linux isolated execution provider",
            false,
        );
    }
    if spec.limits.allow_network {
        return api_error(
            StatusCode::BAD_REQUEST,
            "network_opt_in_unsupported",
            "limits.allow_network is not an opt-in: namespace mode denies egress, while unsafe subprocess mode retains host networking regardless of this flag",
            false,
        );
    }

    // Reserve capacity before creating durable state. This is non-blocking:
    // saturated admission returns 503 immediately and cannot leave a zombie
    // queued row behind.
    let mem_mb = state.cfg.clamp_limits(spec.limits.clone()).mem_mb;
    let permit = match state.admission.try_reserve(&auth.tenant_id, mem_mb) {
        Ok(permit) => permit,
        Err(crate::scheduler::TryAdmissionError::GlobalFull) => {
            state.metrics.reject(
                crate::metrics::AdmissionScope::Queue,
                crate::metrics::AdmissionReason::GlobalFull,
            );
            return api_error_with_retry(
                StatusCode::SERVICE_UNAVAILABLE,
                "queue_saturated",
                "job queue is saturated; retry later",
                true,
                Some(1),
            );
        }
        Err(crate::scheduler::TryAdmissionError::TenantFull) => {
            state.metrics.reject(
                crate::metrics::AdmissionScope::Queue,
                crate::metrics::AdmissionReason::TenantFull,
            );
            return api_error_with_retry(
                StatusCode::TOO_MANY_REQUESTS,
                "tenant_queue_saturated",
                "this tenant has reached its queued-job capacity",
                true,
                Some(1),
            );
        }
        Err(crate::scheduler::TryAdmissionError::Closed) => {
            state.metrics.reject(
                crate::metrics::AdmissionScope::Scheduler,
                crate::metrics::AdmissionReason::Closed,
            );
            return api_error_with_retry(
                StatusCode::SERVICE_UNAVAILABLE,
                "scheduler_unavailable",
                "job scheduler is unavailable",
                true,
                Some(1),
            );
        }
    };

    let job_id = Uuid::now_v7().to_string();
    let spec_json = match serde_json::to_string(&spec) {
        Ok(s) => s,
        Err(e) => return internal_error("serialize job spec", e),
    };

    // Spawn before the next await. If the client disconnects while SQLite is
    // committing, dropping this handler only detaches the JoinHandle; the
    // continuation still owns the body, channel, and global queue permits
    // through reconciliation and the synchronous scheduler handoff.
    let commit = spawn_submission_commit(
        state.clone(),
        permit,
        body_permit,
        PendingSubmission {
            job_id: job_id.clone(),
            tenant: auth.tenant_id.clone(),
            language: spec.language.clone(),
            spec_json,
            requested_mem_mb: mem_mb,
            idempotency,
            job_trace: crate::request_context::current_job_context(),
        },
    );
    let accepted = match commit.await {
        Ok(Ok(accepted)) => accepted,
        Ok(Err(e)) if coop_store::is_idempotency_conflict(&e) => return idempotency_conflict(),
        Ok(Err(e)) => match coop_store::capacity_error_kind(&e) {
            Some(coop_store::CapacityErrorKind::Tenant) => {
                return api_error_with_retry(
                    StatusCode::TOO_MANY_REQUESTS,
                    "tenant_storage_quota",
                    "this tenant has reached its retained storage quota",
                    true,
                    Some(1),
                )
            }
            Some(coop_store::CapacityErrorKind::Global) => {
                return api_error_with_retry(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_capacity",
                    "global retained storage capacity is exhausted",
                    true,
                    Some(1),
                )
            }
            Some(coop_store::CapacityErrorKind::Filesystem) => {
                return api_error_with_retry(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "storage_reserve",
                    "filesystem free-space reserve prevents accepting another job",
                    true,
                    Some(1),
                )
            }
            None => return internal_error("persist job", e),
        },
        Err(e) => {
            state.bus.remove(&job_id);
            return internal_error("join durable job acceptance", e);
        }
    };

    let accepted_job_id = &accepted.job_id;
    tracing::info!(
        job_id = %accepted_job_id,
        replayed = accepted.replayed,
        tenant = %auth.tenant_id,
        principal = %auth.principal_id,
        language = %spec.language,
        "job submitted"
    );

    submission_response(accepted.job_id, accepted.replayed)
}

#[utoipa::path(
    get,
    path = "/v1/jobs",
    params(
        ("limit" = Option<i64>, Query, description = "Max rows (1-500), default 50"),
        ("cursor" = Option<String>, Query, description = "Opaque cursor from next_cursor"),
        ("status" = Option<String>, Query, description = "Exact job status filter"),
        ("language" = Option<String>, Query, description = "Exact language filter")
    ),
    responses(
        (status = 200, body = ListJobsResponse),
        (status = 400, body = ErrorEnvelope),
        (status = 401, body = ErrorEnvelope)
    )
)]
pub async fn list_jobs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(unknown) = params
        .keys()
        .find(|key| !matches!(key.as_str(), "limit" | "cursor" | "status" | "language"))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "unknown_query_parameter",
            format!("unknown query parameter {unknown:?}"),
            false,
        );
    }
    let limit = match params.get("limit") {
        Some(raw) => match raw.parse::<i64>() {
            Ok(value @ 1..=500) => value,
            _ => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_limit",
                    "limit must be an integer between 1 and 500",
                    false,
                )
            }
        },
        None => 50,
    };
    let before = match params.get("cursor") {
        Some(raw) => match decode_job_cursor(raw) {
            Ok(cursor) => Some(cursor),
            Err(message) => {
                return api_error(StatusCode::BAD_REQUEST, "invalid_cursor", message, false)
            }
        },
        None => None,
    };
    let status = params.get("status").cloned();
    if status
        .as_deref()
        .is_some_and(|value| JobStatus::parse(value).is_none())
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_status",
            "status is not a recognized job state",
            false,
        );
    }
    let language = params.get("language").cloned();
    if language
        .as_deref()
        .is_some_and(|value| !coop_types::is_supported_language(value))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "unsupported_language",
            format!("language must be one of {SUPPORTED_LANGUAGES:?}"),
            false,
        );
    }

    match state
        .store
        .list_job_summaries_page(ListJobsQuery {
            tenant: Some(auth.tenant_id),
            status,
            language,
            before,
            limit: limit + 1,
        })
        .await
    {
        Ok(mut rows) => {
            let has_more = rows.len() > limit as usize;
            rows.truncate(limit as usize);
            let next_cursor = has_more && !rows.is_empty();
            let cursor = next_cursor.then(|| encode_job_cursor(rows.last().expect("non-empty")));
            Json(ListJobsResponse {
                items: rows.iter().map(JobView::from_summary).collect(),
                next_cursor: cursor,
            })
            .into_response()
        }
        Err(e) => internal_error("list jobs", e),
    }
}

fn encode_job_cursor(row: &JobSummary) -> String {
    format!("{}:{}", row.created_at_ms, row.job_id)
}

fn decode_job_cursor(raw: &str) -> Result<JobCursor, String> {
    let (created, job_id) = raw
        .split_once(':')
        .ok_or_else(|| "cursor is malformed".to_string())?;
    let created_at_ms = created
        .parse::<i64>()
        .map_err(|_| "cursor timestamp is malformed".to_string())?;
    if created_at_ms < 0 || job_id.is_empty() || job_id.len() > 128 {
        return Err("cursor is malformed".to_string());
    }
    Ok(JobCursor {
        created_at_ms,
        job_id: job_id.to_string(),
    })
}

#[utoipa::path(
    get,
    path = "/v1/jobs/{id}",
    params(("id" = String, Path, description = "Job id")),
    responses(
        (status = 200, body = JobDetail),
        (status = 429, body = ErrorEnvelope),
        (status = 503, body = ErrorEnvelope),
        (status = 404, body = ErrorEnvelope),
        (status = 401, body = ErrorEnvelope)
    )
)]
pub async fn get_job(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    match state.store.get_job_summary(&id).await {
        Ok(Some(row)) if row.tenant == auth.tenant_id => {}
        Ok(_) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "job_not_found",
                "job not found",
                false,
            )
        }
        Err(e) => return internal_error("get job summary", e),
    }
    // Acquire before selecting the multi-megabyte spec/receipt columns.
    let permit = match acquire_large_response(&state, &auth.tenant_id) {
        Ok(permit) => permit,
        Err(error) => {
            record_lifetime_rejection(
                state.metrics.as_ref(),
                crate::metrics::AdmissionScope::LargeResponse,
                error,
            );
            return large_response_error(error);
        }
    };
    match state.store.get_job(&id).await {
        Ok(Some(row)) if row.tenant == auth.tenant_id => {
            let metadata = match state.store.attestation_metadata(&id).await {
                Ok(metadata) => metadata,
                Err(error) => return internal_error("load job attestation metadata", error),
            };
            match job_detail(&state, &row, metadata.as_ref()) {
                Ok(detail) => guarded_json_response(StatusCode::OK, &detail, permit),
                Err(e) => internal_error("decode stored job detail", e),
            }
        }
        Ok(_) => api_error(
            StatusCode::NOT_FOUND,
            "job_not_found",
            "job not found",
            false,
        ),
        Err(e) => internal_error("get job", e),
    }
}

fn job_detail(
    _state: &AppState,
    row: &JobRow,
    attestation: Option<&AttestationMetadata>,
) -> Result<JobDetail, serde_json::Error> {
    let requested_spec: JobSpec = serde_json::from_str(&row.spec_json)?;
    let receipt: Option<serde_json::Value> = row
        .receipt_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?;
    let stored_effective: Option<EffectiveJobSpec> = row
        .effective_spec_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?
        .map(|value: serde_json::Value| {
            if value
                .get("storage_version")
                .and_then(serde_json::Value::as_u64)
                == Some(2)
            {
                let limits = serde_json::from_value(
                    value
                        .get("limits")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                )?;
                let requirements = value
                    .get("requirements")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?
                    .unwrap_or_else(|| requested_spec.requirements.clone());
                let isolation_class = value
                    .get("isolation_class")
                    .cloned()
                    .map(serde_json::from_value::<Option<IsolationClass>>)
                    .transpose()?
                    .flatten();
                let files = value
                    .get("files")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?
                    .unwrap_or_else(|| requested_spec.files.clone());
                let outputs = value
                    .get("outputs")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?
                    .unwrap_or_else(|| requested_spec.outputs.clone());
                let runtime = value
                    .get("runtime")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?
                    .unwrap_or_else(|| requested_spec.runtime.clone());
                Ok(EffectiveJobSpec {
                    language: requested_spec.language.clone(),
                    code: requested_spec.code.clone(),
                    stdin: requested_spec.stdin.clone(),
                    limits,
                    requirements,
                    isolation_class,
                    files,
                    outputs,
                    runtime,
                })
            } else {
                serde_json::from_value(value)
            }
        })
        .transpose()?;
    // Only receipts carrying the executor-observed readiness marker are
    // trusted as execution posture. Older receipts and in-flight rows cannot
    // be reconstructed from the server's current configuration without
    // risking a false containment claim.
    let observed = receipt
        .as_ref()
        .and_then(|value| value.get("bootstrap_ready"))
        .and_then(serde_json::Value::as_bool);
    let observed_receipt = observed.is_some().then_some(receipt.as_ref()).flatten();
    let sandbox = observed_receipt
        .and_then(|value| value.get("backend"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let isolated = observed_receipt
        .and_then(|value| value.get("isolated"))
        .and_then(serde_json::Value::as_bool);
    let isolation_class = observed_receipt
        .and_then(|value| value.get("isolation_class"))
        .cloned()
        .map(serde_json::from_value)
        .transpose()?;
    let network_allowed = observed_receipt
        .and_then(|value| value.get("network_allowed"))
        .and_then(serde_json::Value::as_bool);
    let networking = observed_receipt
        .and_then(|value| value.get("networking"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let seccomp = observed_receipt
        .and_then(|value| value.get("seccomp"))
        .and_then(serde_json::Value::as_bool);
    let private_rootfs = observed_receipt
        .and_then(|value| value.get("private_rootfs"))
        .and_then(serde_json::Value::as_bool);
    let dedicated_bootstrap = observed_receipt
        .and_then(|value| value.get("dedicated_bootstrap"))
        .and_then(serde_json::Value::as_bool);
    let limit_enforcement = observed_receipt
        .and_then(|value| value.get("limit_enforcement"))
        .cloned()
        .map(serde_json::from_value)
        .transpose()?;
    let receipt_string = |name: &str| {
        observed_receipt
            .and_then(|value| value.get(name))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    let effective_limits = observed_receipt
        .and_then(|value| value.get("effective_limits"))
        .cloned()
        .map(serde_json::from_value)
        .transpose()?;
    let effective_spec = match (
        stored_effective,
        effective_limits,
        limit_enforcement.as_ref(),
    ) {
        (Some(mut spec), Some(limits), Some(_)) => {
            spec.limits = limits;
            Some(spec)
        }
        _ => None,
    };
    let receipt_sha256 = receipt.as_ref().map(|value| {
        value
            .get("receipt_sha256")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| coop_store::compute_receipt_sha256(value))
    });
    Ok(JobDetail {
        job: JobView::from_row(row),
        requested_spec,
        effective_spec,
        execution_policy: ExecutionPolicy {
            sandbox,
            isolation_class,
            bootstrap_ready: observed,
            isolated,
            seccomp,
            network_allowed,
            networking,
            private_rootfs,
            dedicated_bootstrap,
            limit_enforcement,
            runtime_version: receipt_string("runtime_version"),
            runtime_sha256: receipt_string("runtime_sha256"),
            rootfs_sha256: receipt_string("rootfs_sha256"),
            config_sha256: receipt_string("config_sha256"),
        },
        receipt,
        receipt_sha256,
        attestation: match attestation {
            Some(attestation) => JobAttestationStatus {
                available: true,
                tenant: Some(row.tenant.clone()),
                key_id: Some(attestation.key_id.clone()),
                receipt_sha256: Some(attestation.receipt_sha256.clone()),
                result_media_type: Some(attestation.result_media_type.clone()),
                result_sha256: Some(attestation.result_sha256.clone()),
                result_size_bytes: Some(attestation.result_size_bytes),
                envelope_sha256: Some(attestation.envelope_sha256.clone()),
                envelope_size_bytes: Some(attestation.envelope_size_bytes),
                envelope_url: Some(format!("/v1/jobs/{}/attestation", row.job_id)),
                result_artifact_url: Some(format!("/v1/jobs/{}/result-artifact", row.job_id)),
            },
            None => JobAttestationStatus {
                available: false,
                tenant: None,
                key_id: None,
                receipt_sha256: None,
                result_media_type: None,
                result_sha256: None,
                result_size_bytes: None,
                envelope_sha256: None,
                envelope_size_bytes: None,
                envelope_url: None,
                result_artifact_url: None,
            },
        },
    })
}

#[utoipa::path(
    get,
    path = "/v1/jobs/{id}/attestation",
    params(("id" = String, Path, description = "Job id")),
    responses(
        (status = 200, description = "Exact persisted DSSE envelope bytes"),
        (status = 404, body = ErrorEnvelope),
        (status = 429, body = ErrorEnvelope),
        (status = 503, body = ErrorEnvelope),
        (status = 401, body = ErrorEnvelope)
    )
)]
pub async fn job_attestation(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    match owns_job(&state, &id, &auth.tenant_id).await {
        Ok(true) => {}
        Ok(false) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "job_not_found",
                "job not found",
                false,
            )
        }
        Err(error) => return internal_error("authorize job attestation", error),
    }
    let permit = match acquire_large_response(&state, &auth.tenant_id) {
        Ok(permit) => permit,
        Err(error) => {
            record_lifetime_rejection(
                state.metrics.as_ref(),
                crate::metrics::AdmissionScope::LargeResponse,
                error,
            );
            return large_response_error(error);
        }
    };
    match state.store.attestation_envelope(&id).await {
        Ok(Some((metadata, bytes))) => guarded_bytes_response(
            StatusCode::OK,
            bytes,
            permit,
            HeaderValue::from_static(crate::attestation::DSSE_ENVELOPE_MEDIA_TYPE),
            Some(&metadata.envelope_sha256),
        ),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "attestation_unavailable",
            "this job does not have a persisted signed attestation",
            false,
        ),
        Err(error) => internal_error("load job attestation", error),
    }
}

#[utoipa::path(
    get,
    path = "/v1/jobs/{id}/result-artifact",
    params(("id" = String, Path, description = "Job id")),
    responses(
        (status = 200, description = "Exact result artifact bytes authenticated by the DSSE envelope"),
        (status = 404, body = ErrorEnvelope),
        (status = 429, body = ErrorEnvelope),
        (status = 503, body = ErrorEnvelope),
        (status = 401, body = ErrorEnvelope)
    )
)]
pub async fn job_result_artifact(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    match owns_job(&state, &id, &auth.tenant_id).await {
        Ok(true) => {}
        Ok(false) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "job_not_found",
                "job not found",
                false,
            )
        }
        Err(error) => return internal_error("authorize job result artifact", error),
    }
    let permit = match acquire_large_response(&state, &auth.tenant_id) {
        Ok(permit) => permit,
        Err(error) => {
            record_lifetime_rejection(
                state.metrics.as_ref(),
                crate::metrics::AdmissionScope::LargeResponse,
                error,
            );
            return large_response_error(error);
        }
    };
    match state.store.attestation_result_artifact(&id).await {
        Ok(Some((metadata, bytes))) => {
            let content_type = HeaderValue::from_str(&metadata.result_media_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
            guarded_bytes_response(
                StatusCode::OK,
                bytes,
                permit,
                content_type,
                Some(&metadata.result_sha256),
            )
        }
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "result_artifact_unavailable",
            "this job does not have a persisted attested result artifact",
            false,
        ),
        Err(error) => internal_error("load job result artifact", error),
    }
}

/// Cancel a job. Running jobs are terminated by the executor's containment
/// boundary (cgroup-wide in namespace mode) and finish as `cancelled`; queued jobs are marked
/// `cancelled` immediately so the scheduler skips them. Idempotent: an
/// already-terminal job returns 200 with `already_terminal=true` and its current status.
#[utoipa::path(
    delete,
    path = "/v1/jobs/{id}",
    params(("id" = String, Path, description = "Job id")),
    responses(
        (status = 200, description = "Cancellation state", body = CancellationResponse),
        (status = 404, description = "Unknown or foreign job", body = ErrorEnvelope),
        (status = 401, description = "Missing or invalid API key", body = ErrorEnvelope)
    )
)]
#[allow(clippy::needless_return)]
pub async fn cancel_job(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    let row = match state.store.get_job_summary(&id).await {
        Ok(Some(row)) if row.tenant == auth.tenant_id => row,
        Ok(_) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "job_not_found",
                "job not found",
                false,
            )
        }
        Err(e) => return internal_error("load job for cancel", e),
    };

    match JobStatus::parse(&row.status) {
        Some(status) if status.is_terminal() => {
            return cancellation_response(&row, false, true);
        }
        _ => {}
    }

    if let Some(flag) = state.cancels.get(&id) {
        flag.cancel.cancel();
        tracing::info!(
            job_id = %id,
            tenant = %auth.tenant_id,
            principal = %auth.principal_id,
            "job cancellation requested (running)"
        );
        return cancellation_response(&row, true, false);
    }

    // Queued (or just-started) path: conditional DB cancel. On success the
    // worker's conditional start (`set_started_if_queued`) will see the row
    // no longer queued and bail before executing. On failure the job
    // started between our load and now but before its cancel flag existed —
    // install a flag ourselves so the executor's next tick kills it.
    let queued_receipt = crate::scheduler::build_queued_cancel_receipt(&state, &id).await;
    match state
        .store
        .cancel_queued_with_event(&id, &auth.tenant_id, queued_receipt.as_ref())
        .await
    {
        Ok(Some(event)) => {
            state.bus.send(&id, wire_event(event));
            state.bus.complete(&id);
            tracing::info!(
                job_id = %id,
                tenant = %auth.tenant_id,
                principal = %auth.principal_id,
                "queued job cancelled"
            );
            return match state.store.get_job_summary(&id).await {
                Ok(Some(current)) if current.tenant == auth.tenant_id => {
                    cancellation_response(&current, true, false)
                }
                Ok(_) => api_error(
                    StatusCode::NOT_FOUND,
                    "job_not_found",
                    "job not found",
                    false,
                ),
                Err(error) => internal_error("reload cancelled job", error),
            };
        }
        Ok(None) => {
            let running = state
                .cancels
                .entry(id.clone())
                .or_insert_with(|| crate::RunningJob {
                    tenant: auth.tenant_id.clone(),
                    cancel: Arc::new(coop_exec::ExecutionCancellation::default()),
                })
                .clone();
            // Recheck durable state before installing a long-lived flag. The
            // finalizer may have won the race after our initial read.
            match state.store.get_job_summary(&id).await {
                Ok(Some(current))
                    if JobStatus::parse(&current.status).is_some_and(|s| s.is_terminal()) =>
                {
                    state.cancels.remove(&id);
                    return cancellation_response(&current, false, true);
                }
                Ok(Some(current)) => {
                    running.cancel.cancel();
                    tracing::info!(
                        job_id = %id,
                        tenant = %auth.tenant_id,
                        principal = %auth.principal_id,
                        "job cancellation requested (race — flag installed)"
                    );
                    return cancellation_response(&current, true, false);
                }
                Ok(None) => {
                    state.cancels.remove(&id);
                    return api_error(
                        StatusCode::NOT_FOUND,
                        "job_not_found",
                        "job not found",
                        false,
                    );
                }
                Err(e) => {
                    state.cancels.remove(&id);
                    return internal_error("recheck job for cancel", e);
                }
            }
        }
        Err(e) => return internal_error("cancel queued job", e),
    }
}

fn wire_event(event: coop_store::EventRow) -> WireEvent {
    WireEvent {
        seq: event.seq,
        ts_ms: event.ts_ms,
        kind: event.kind,
        data: event.data,
        prev_hash: event.prev_hash,
        event_hash: event.event_hash,
        hash_version: event.hash_version,
    }
}

/// Prometheus text-format metrics scoped to the authenticated tenant. Tenant
/// names are deliberately absent from labels to avoid accidental disclosure.
#[utoipa::path(
    get,
    path = "/v1/metrics",
    responses(
        (status = 200, description = "Prometheus text format"),
        (status = 401, body = ErrorEnvelope)
    )
)]
pub async fn metrics(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let mut body = String::with_capacity(512);
    body.push_str("# HELP coop_jobs_current Current tenant jobs by status.\n");
    body.push_str("# TYPE coop_jobs_current gauge\n");
    match state
        .store
        .count_by_status_for_tenant(&auth.tenant_id)
        .await
    {
        Ok(rows) => {
            for (status, n) in rows {
                body.push_str(&format!("coop_jobs_current{{status=\"{status}\"}} {n}\n"));
            }
        }
        Err(e) => return internal_error("count jobs for metrics", e),
    }
    body.push_str(&format!(
        "# HELP coop_job_lifecycle_owners_current Tenant jobs currently owned by the scheduler across pre-start, execution, and finalization.\n# TYPE coop_job_lifecycle_owners_current gauge\ncoop_job_lifecycle_owners_current {}\n",
        state
            .cancels
            .iter()
            .filter(|entry| entry.tenant == auth.tenant_id)
            .count()
    ));
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

/// Global process metrics. This surface has a credential separate from tenant
/// API keys, never emits tenant/job/request/trace labels, and performs no store
/// I/O while serving a scrape.
pub async fn operator_metrics(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(expected) = state.metrics_token_digest.as_ref() else {
        return no_store(api_error(
            StatusCode::NOT_FOUND,
            "metrics_disabled",
            "global operator metrics are not configured",
            false,
        ));
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, credential)| {
            scheme.eq_ignore_ascii_case("bearer") && !credential.is_empty()
        })
        .map(|(_, credential)| credential);
    if !presented.is_some_and(|token| crate::metrics::token_matches(expected, token)) {
        let mut response = api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_metrics_token",
            "a valid operator metrics bearer token is required",
            false,
        );
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"rookhold-metrics\""),
        );
        return no_store(response);
    }

    let format = crate::metrics::negotiate(headers.get(header::ACCEPT));
    let startup = state
        .startup_ready
        .load(std::sync::atomic::Ordering::Acquire);
    let storage = state.readiness.storage_ready();
    let scheduler = !*state.shutdown.borrow();
    let accepting = startup && storage && scheduler;
    let snapshot = crate::metrics::RuntimeSnapshot {
        capacity: crate::metrics::CapacitySnapshot {
            queue_used: state.admission.depth(),
            queue_limit: state.admission.capacity(),
            submit_bodies_used: state.submit_body_admission.depth(),
            submit_bodies_limit: state.submit_body_admission.capacity(),
            streams_used: state.stream_admission.depth(),
            streams_limit: state.stream_admission.capacity(),
            result_waits_used: state.result_wait_admission.depth(),
            result_waits_limit: state.result_wait_admission.capacity(),
            large_responses_used: state.large_response_admission.depth(),
            large_responses_limit: state.large_response_admission.capacity(),
        },
        readiness: crate::metrics::ReadinessSnapshot {
            ready: accepting,
            startup,
            storage,
            // Scheduler supervision publishes shutdown after retaining a fatal
            // diagnosis, so this remains a cached, O(1) component.
            scheduler,
            accepting,
        },
    };
    let body = state.metrics.render(format, snapshot);
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(format.content_type()),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (header::VARY, HeaderValue::from_static("accept")),
        ],
        body,
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/v1/jobs/{id}/replay",
    params(
        ("id" = String, Path, description = "Job id"),
        ("after" = Option<i64>, Query, description = "Exclusive event sequence cursor"),
        ("limit" = Option<i64>, Query, description = "Maximum events (1-5000)")
    ),
    responses(
        (status = 200, body = ReplayResponse),
        (status = 400, body = ErrorEnvelope),
        (status = 429, body = ErrorEnvelope),
        (status = 503, body = ErrorEnvelope),
        (status = 404, body = ErrorEnvelope),
        (status = 401, body = ErrorEnvelope)
    )
)]
pub async fn replay(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    match owns_job(&state, &id, &auth.tenant_id).await {
        Ok(true) => {}
        Ok(false) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "job_not_found",
                "job not found",
                false,
            )
        }
        Err(error) => return internal_error("authorize job replay", error),
    }
    if let Some(unknown) = params
        .keys()
        .find(|key| !matches!(key.as_str(), "after" | "limit"))
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "unknown_query_parameter",
            format!("unknown query parameter {unknown:?}"),
            false,
        );
    }
    let after = match params.get("after") {
        Some(raw) => match raw.parse::<i64>() {
            Ok(value) if value >= 0 => value,
            _ => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_event_cursor",
                    "after must be a non-negative event sequence",
                    false,
                )
            }
        },
        None => 0,
    };
    let limit = match params.get("limit") {
        Some(raw) => match raw.parse::<i64>() {
            Ok(value @ 1..=5_000) => value,
            _ => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_limit",
                    "limit must be an integer between 1 and 5000",
                    false,
                )
            }
        },
        None => 1_000,
    };
    // Bound both event materialization and the subsequent transfer.
    let permit = match acquire_large_response(&state, &auth.tenant_id) {
        Ok(permit) => permit,
        Err(error) => {
            record_lifetime_rejection(
                state.metrics.as_ref(),
                crate::metrics::AdmissionScope::LargeResponse,
                error,
            );
            return large_response_error(error);
        }
    };
    match state.store.events_after(&id, after, limit).await {
        Ok(events) => {
            let next_cursor = events.last().map(|event| event.seq);
            let replay = ReplayResponse {
                events: events.into_iter().map(wire_event).collect(),
                next_cursor,
            };
            guarded_json_response(StatusCode::OK, &replay, permit)
        }
        Err(e) => internal_error("load events", e),
    }
}

/// One-call outcome for agent tool loops: waits (server-side) for a terminal
/// state and returns the view plus stdout/stderr folded out of the event log.
/// `?wait_seconds=` caps the in-request wait (0 = return current state
/// immediately); when the wait budget expires with the job still running the
/// response is 202 with whatever has been produced so far.
#[utoipa::path(
    get,
    path = "/v1/jobs/{id}/result",
    params(
        ("id" = String, Path, description = "Job id"),
        ("wait_seconds" = Option<u64>, Query, description = "Max seconds to wait for a terminal state (0-300, default 60)")
    ),
    responses(
        (status = 200, description = "Job reached a terminal state", body = ResultView),
        (status = 202, description = "Still running when the wait budget expired; partial output included", body = ResultView),
        (status = 400, body = ErrorEnvelope),
        (status = 429, body = ErrorEnvelope),
        (status = 503, body = ErrorEnvelope),
        (status = 404, body = ErrorEnvelope),
        (status = 401, body = ErrorEnvelope)
    )
)]
pub async fn job_result(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let wait_seconds = match params.get("wait_seconds") {
        Some(raw) => match raw.parse::<u64>() {
            Ok(value) if value <= RESULT_MAX_WAIT_SECONDS => value,
            _ => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_wait_seconds",
                    format!("wait_seconds must be between 0 and {RESULT_MAX_WAIT_SECONDS}"),
                    false,
                )
            }
        },
        None => RESULT_DEFAULT_WAIT_SECONDS,
    };

    let mut row = match state.store.get_job_summary(&id).await {
        Ok(Some(row)) if row.tenant == auth.tenant_id => row,
        Ok(_) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "job_not_found",
                "job not found",
                false,
            )
        }
        Err(e) => return internal_error("load job summary for result", e),
    };
    let terminal = JobStatus::parse(&row.status).is_some_and(|status| status.is_terminal());
    let mut _wait_permit = None;
    if !terminal && wait_seconds > 0 {
        let mut shutdown = state.shutdown.subscribe();
        if !*shutdown.borrow() {
            _wait_permit = Some(
                match state.result_wait_admission.try_acquire(&auth.tenant_id) {
                    Ok(permit) => permit,
                    Err(error) => {
                        record_lifetime_rejection(
                            state.metrics.as_ref(),
                            crate::metrics::AdmissionScope::ResultWait,
                            error,
                        );
                        return result_wait_error(error);
                    }
                },
            );
            // During readiness-gated startup recovery, durable queued rows
            // can briefly predate their in-process completion watch. Poll the
            // indexed summary until recovery registers the watch, then switch
            // to notifications without resetting the caller's wait budget.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_seconds);
            let mut completion = state.bus.completion(&id);
            loop {
                if completion
                    .as_ref()
                    .is_some_and(|receiver| *receiver.borrow())
                {
                    break;
                }
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    break;
                }
                let mut completion_closed = false;
                if let Some(receiver) = completion.as_mut() {
                    tokio::select! {
                        _ = tokio::time::sleep_until(deadline) => break,
                        changed = receiver.changed() => {
                            completion_closed = changed.is_err();
                        }
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                break;
                            }
                        }
                    }
                } else {
                    let interval = (deadline - now).min(Duration::from_millis(250));
                    tokio::select! {
                        _ = tokio::time::sleep(interval) => {}
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                break;
                            }
                        }
                    }
                }
                if completion_closed {
                    completion = None;
                }
                row = match state.store.get_job_summary(&id).await {
                    Ok(Some(row)) if row.tenant == auth.tenant_id => row,
                    Ok(_) => {
                        return api_error(
                            StatusCode::NOT_FOUND,
                            "job_not_found",
                            "job not found",
                            false,
                        )
                    }
                    Err(e) => return internal_error("poll job summary for result", e),
                };
                if JobStatus::parse(&row.status).is_some_and(|status| status.is_terminal()) {
                    break;
                }
                if completion.is_none() {
                    completion = state.bus.completion(&id);
                }
            }
        }
        // One post-notification read is enough. If completion raced with the
        // durable transition, this read observes the committed state.
        row = match state.store.get_job_summary(&id).await {
            Ok(Some(row)) if row.tenant == auth.tenant_id => row,
            Ok(_) => {
                return api_error(
                    StatusCode::NOT_FOUND,
                    "job_not_found",
                    "job not found",
                    false,
                )
            }
            Err(e) => return internal_error("reload job summary for result", e),
        };
    }

    // Only completed/non-waiting callers compete for response memory; a
    // completion burst cannot materialize more than the response cap.
    let permit = match acquire_large_response(&state, &auth.tenant_id) {
        Ok(permit) => permit,
        Err(error) => {
            record_lifetime_rejection(
                state.metrics.as_ref(),
                crate::metrics::AdmissionScope::LargeResponse,
                error,
            );
            return large_response_error(error);
        }
    };
    match state.store.events_for(&id).await {
        Ok(events) => {
            let view = fold_result(&row, &events);
            let code = if JobStatus::parse(&row.status).is_some_and(|s| s.is_terminal()) {
                StatusCode::OK
            } else {
                StatusCode::ACCEPTED
            };
            guarded_json_response(code, &view, permit)
        }
        Err(e) => internal_error("load events for result", e),
    }
}

/// Fold an ordered event list into a flat result: stdout/stderr joined
/// line-wise, truncation flag, and every sandbox violation raised during the
/// run. Deterministic over the replayable log — no live state involved.
fn fold_result(row: &JobSummary, events: &[coop_store::EventRow]) -> ResultView {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut truncated = false;
    let mut violations = Vec::new();
    let mut artifacts = Vec::new();
    for event in events {
        match event.kind.as_str() {
            "stdout" | "stderr" => {
                if let Some(line) = event.data.get("line").and_then(serde_json::Value::as_str) {
                    if event.kind == "stdout" {
                        stdout.push(line);
                    } else {
                        stderr.push(line);
                    }
                }
            }
            "truncated" => truncated = true,
            "violation" => violations.push(event.data.clone()),
            "artifact" => {
                if let (Some(path), Some(content_base64), Some(size_bytes), Some(sha256)) = (
                    event.data.get("path").and_then(Value::as_str),
                    event.data.get("content_base64").and_then(Value::as_str),
                    event.data.get("size_bytes").and_then(Value::as_u64),
                    event.data.get("sha256").and_then(Value::as_str),
                ) {
                    if let Ok(size_bytes) = usize::try_from(size_bytes) {
                        artifacts.push(ArtifactView {
                            path: path.to_string(),
                            content_base64: content_base64.to_string(),
                            size_bytes,
                            sha256: sha256.to_string(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    ResultView {
        job_id: row.job_id.clone(),
        status: row.status.clone(),
        exit_code: row.exit_code,
        duration_ms: match (row.started_at_ms, row.finished_at_ms) {
            (Some(started), Some(finished)) => Some(finished - started),
            _ => None,
        },
        stdout: stdout.join("\n"),
        stderr: stderr.join("\n"),
        truncated,
        violations,
        artifacts,
    }
}

#[utoipa::path(
    get,
    path = "/v1/jobs/{id}/stream",
    params(
        ("id" = String, Path, description = "Job id"),
        ("ticket" = Option<String>, Query, description = "One-use stream ticket"),
        ("after" = Option<i64>, Query, description = "Exclusive event sequence cursor")
    ),
    responses(
        (status = 101, description = "WebSocket upgrade accepted"),
        (status = 400, body = ErrorEnvelope),
        (status = 429, body = ErrorEnvelope),
        (status = 503, body = ErrorEnvelope),
        (status = 401, body = ErrorEnvelope),
        (status = 404, body = ErrorEnvelope)
    )
)]
pub async fn stream(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Response {
    if *state.shutdown.borrow() {
        return api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "server is shutting down",
            true,
            Some(1),
        );
    }
    match owns_job(&state, &id, &auth.tenant_id).await {
        Ok(true) => {}
        Ok(false) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "job_not_found",
                "job not found",
                false,
            )
        }
        Err(error) => return internal_error("authorize job stream", error),
    }
    let after = match params.get("after") {
        Some(raw) => match raw.parse::<i64>() {
            Ok(value) if value >= 0 => value,
            _ => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_event_cursor",
                    "after must be a non-negative event sequence",
                    false,
                )
            }
        },
        None => 0,
    };
    let stream_permit = match state.stream_admission.try_acquire(&auth.tenant_id) {
        Ok(permit) => permit,
        Err(error) => {
            record_lifetime_rejection(
                state.metrics.as_ref(),
                crate::metrics::AdmissionScope::Stream,
                error,
            );
            return stream_admission_error(error);
        }
    };
    ws.max_message_size(MAX_INBOUND_STREAM_MESSAGE_BYTES)
        .max_frame_size(MAX_INBOUND_STREAM_MESSAGE_BYTES)
        .on_upgrade(move |socket| stream_socket(state, id, after, socket, stream_permit))
}

#[utoipa::path(
    post,
    path = "/v1/jobs/{id}/stream-ticket",
    params(("id" = String, Path, description = "Job id")),
    responses(
        (status = 200, body = StreamTicketResponse),
        (status = 503, body = ErrorEnvelope),
        (status = 404, body = ErrorEnvelope),
        (status = 401, body = ErrorEnvelope)
    )
)]
pub async fn stream_ticket(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    if *state.shutdown.borrow() {
        return api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "server is shutting down",
            true,
            Some(1),
        );
    }
    match owns_job(&state, &id, &auth.tenant_id).await {
        Ok(true) => {}
        Ok(false) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "job_not_found",
                "job not found",
                false,
            )
        }
        Err(error) => return internal_error("authorize stream ticket", error),
    }
    // Ownership requires an async storage read. Recheck the sticky bit after
    // that cancellation point so shutdown cannot linearize between the first
    // check and minting a new credential.
    if *state.shutdown.borrow() {
        return api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "server is shutting down",
            true,
            Some(1),
        );
    }
    let (ticket, expires_at_ms) = crate::auth::issue_stream_ticket(&state, &id, &auth);
    if *state.shutdown.borrow() {
        state.stream_tickets.remove(&ticket);
        return api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "server is shutting down",
            true,
            Some(1),
        );
    }
    Json(StreamTicketResponse {
        stream_url: format!("/v1/jobs/{id}/stream?ticket={ticket}"),
        ticket,
        expires_at_ms,
    })
    .into_response()
}

async fn stream_socket(
    state: AppState,
    job_id: String,
    after: i64,
    socket: WebSocket,
    _stream_permit: crate::LifetimePermit,
) {
    let (mut tx, mut rx) = socket.split();
    let mut live = state.bus.subscribe(&job_id);
    let mut sent_max = after;
    let mut shutdown = state.shutdown.subscribe();

    if !send_history(state.store.as_ref(), &job_id, &mut tx, &mut sent_max).await {
        return;
    }
    match drain_terminal_history(state.store.as_ref(), &job_id, &mut tx, &mut sent_max).await {
        TerminalDrain::Running => {}
        TerminalDrain::Terminal => {
            close_stream_bounded(&mut tx, STREAM_CLOSE_DEADLINE).await;
            return;
        }
        TerminalDrain::SinkClosed => return,
    }

    loop {
        if *shutdown.borrow() {
            break;
        }
        // `live.is_none()` means the per-job broadcast channel has been
        // removed (job finished and `pump_events` called `bus.remove`) or
        // never existed for a finished job. In that state `next_live` parks
        // forever and the old code waited on client traffic only, pinning
        // the task indefinitely for finished jobs. Wake periodically to
        // check terminal state and (re-)drain persisted history.
        let is_idle = live.is_none();
        let idle_wake = async {
            if is_idle {
                tokio::time::sleep(Duration::from_millis(250)).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            incoming = rx.next() => match incoming {
                Some(Ok(message @ (Message::Text(_) | Message::Binary(_)))) => {
                    // The server protocol is output-only except for the
                    // literal text keepalive. Close rather than retaining or
                    // silently accepting attacker-controlled payloads.
                    if is_stream_keepalive(&message) {
                        if !send_stream_message_bounded(
                            &mut tx,
                            Message::text("pong"),
                            STREAM_SEND_DEADLINE,
                        )
                        .await
                        {
                            break;
                        }
                    } else {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            tx.send(Message::Close(Some(CloseFrame {
                                code: close_code::POLICY,
                                reason: "only the text keepalive ping is accepted".into(),
                            }))),
                        )
                        .await;
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            },

            event = next_live(&mut live) => match event {
                // `None` is unreachable (`next_live` parks forever when
                // `live` is `None`) — kept for type completeness.
                None => {
                    match drain_terminal_history(state.store.as_ref(), &job_id, &mut tx, &mut sent_max).await {
                        TerminalDrain::Running => {}
                        TerminalDrain::Terminal | TerminalDrain::SinkClosed => break,
                    }
                }
                Some(Err(RecvError::Lagged(_))) => {
                    if !send_history(state.store.as_ref(), &job_id, &mut tx, &mut sent_max).await {
                        break;
                    }
                    match drain_terminal_history(state.store.as_ref(), &job_id, &mut tx, &mut sent_max).await {
                        TerminalDrain::Running => {}
                        TerminalDrain::Terminal | TerminalDrain::SinkClosed => break,
                    }
                }
                Some(Err(RecvError::Closed)) => {
                    match drain_terminal_history(state.store.as_ref(), &job_id, &mut tx, &mut sent_max).await {
                        TerminalDrain::Running => live = None,
                        TerminalDrain::Terminal | TerminalDrain::SinkClosed => break,
                    }
                }
                Some(Ok(ev)) => {
                    if ev.seq > sent_max {
                        sent_max = ev.seq;
                        let payload = serde_json::to_string(ev.as_ref()).unwrap_or_default();
                        if !send_stream_message_bounded(
                            &mut tx,
                            Message::text(payload),
                            STREAM_SEND_DEADLINE,
                        )
                        .await
                        {
                            break;
                        }
                        if ev.kind == "finished" {
                            break;
                        }
                    }
                }
            },

            _ = idle_wake => {
                match drain_terminal_history(state.store.as_ref(), &job_id, &mut tx, &mut sent_max).await {
                    TerminalDrain::Running => {}
                    TerminalDrain::Terminal | TerminalDrain::SinkClosed => break,
                }
                if live.is_none() {
                    live = state.bus.subscribe(&job_id);
                    if !send_history(state.store.as_ref(), &job_id, &mut tx, &mut sent_max).await {
                        break;
                    }
                    match drain_terminal_history(state.store.as_ref(), &job_id, &mut tx, &mut sent_max).await {
                        TerminalDrain::Running => {}
                        TerminalDrain::Terminal | TerminalDrain::SinkClosed => break,
                    }
                }
            }
        }
    }

    close_stream_bounded(&mut tx, STREAM_CLOSE_DEADLINE).await;
}

/// A close control frame is best effort. A peer that stopped reading must not
/// keep the upgraded socket (and its global connection/stream permits) alive
/// beyond the server's bounded shutdown path.
async fn close_stream_bounded<S>(tx: &mut S, deadline: Duration)
where
    S: futures_util::Sink<Message> + Unpin,
{
    let _ = tokio::time::timeout(deadline, tx.send(Message::Close(None))).await;
}

async fn send_stream_message_bounded<S>(tx: &mut S, message: Message, deadline: Duration) -> bool
where
    S: futures_util::Sink<Message> + Unpin,
{
    matches!(
        tokio::time::timeout(deadline, tx.send(message)).await,
        Ok(Ok(()))
    )
}

fn is_stream_keepalive(message: &Message) -> bool {
    matches!(message, Message::Text(text) if text.as_str() == "ping")
}

async fn next_live(
    live: &mut Option<tokio::sync::broadcast::Receiver<Arc<WireEvent>>>,
) -> Option<Result<Arc<WireEvent>, RecvError>> {
    match live.as_mut() {
        Some(receiver) => Some(receiver.recv().await),
        None => {
            std::future::pending::<()>().await;
            None
        }
    }
}

async fn send_history<S>(
    store: &coop_store::Store,
    job_id: &str,
    tx: &mut S,
    sent_max: &mut i64,
) -> bool
where
    S: futures_util::Sink<Message> + Unpin,
{
    loop {
        match store.events_after(job_id, *sent_max, 5_000).await {
            Ok(events) => {
                let count = events.len();
                for event in events {
                    *sent_max = event.seq;
                    let payload = serde_json::to_string(&wire_event(event)).unwrap_or_default();
                    if !send_stream_message_bounded(
                        tx,
                        Message::text(payload),
                        STREAM_SEND_DEADLINE,
                    )
                    .await
                    {
                        return false;
                    }
                }
                if count < 5_000 {
                    return true;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, job_id, "failed to replay stream history");
                return false;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalDrain {
    Running,
    Terminal,
    SinkClosed,
}

/// Once durable state is terminal, the transaction containing the terminal
/// row also contains the final hash-chain event. Always replay once more after
/// observing that state: the commit may have landed after the preceding
/// history SELECT but before this status read.
async fn drain_terminal_history<S>(
    store: &coop_store::Store,
    job_id: &str,
    tx: &mut S,
    sent_max: &mut i64,
) -> TerminalDrain
where
    S: futures_util::Sink<Message> + Unpin,
{
    match job_terminal(store, job_id).await {
        Ok(false) => return TerminalDrain::Running,
        Ok(true) => {}
        Err(error) => {
            tracing::warn!(%error, job_id, "failed to read durable stream terminal state");
            return TerminalDrain::SinkClosed;
        }
    }
    if send_history(store, job_id, tx, sent_max).await {
        TerminalDrain::Terminal
    } else {
        TerminalDrain::SinkClosed
    }
}

async fn job_terminal(store: &coop_store::Store, job_id: &str) -> coop_store::StoreResult<bool> {
    let Some(row) = store.get_job_summary(job_id).await? else {
        // A row removed by retention cannot produce another event. Closing
        // avoids retaining a stream forever after a tombstone race.
        return Ok(true);
    };
    let Some(status) = JobStatus::parse(&row.status) else {
        tracing::error!(job_id, status = %row.status, "invalid durable job status");
        return Ok(true);
    };
    Ok(status.is_terminal())
}

#[utoipa::path(
    get,
    path = "/healthz",
    security(),
    responses((status = 200, description = "Process liveness"))
)]
pub async fn health() -> Response {
    let mut response = Json(serde_json::json!({ "ok": true })).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[utoipa::path(
    get,
    path = "/.well-known/oauth-protected-resource",
    responses(
        (status = 200, description = "RFC 9728 OAuth protected-resource metadata"),
        (status = 404, body = ErrorEnvelope)
    ),
    security()
)]
pub async fn oauth_protected_resource_metadata(State(state): State<AppState>) -> Response {
    match &state.cfg.jwt {
        Some(jwt) => Json(jwt.protected_resource_metadata()).into_response(),
        None => api_error(
            StatusCode::NOT_FOUND,
            "oauth_not_configured",
            "OAuth protected-resource metadata is unavailable",
            false,
        ),
    }
}

#[utoipa::path(
    get,
    path = "/readyz",
    security(),
    responses(
        (status = 200, description = "Ready to accept traffic"),
        (status = 503, body = ErrorEnvelope)
    )
)]
pub async fn ready(State(state): State<AppState>) -> Response {
    if !state
        .startup_ready
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return no_store(api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "startup_recovery",
            "durable startup recovery is still in progress",
            true,
            Some(1),
        ));
    }
    if *state.shutdown.borrow() {
        return no_store(api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "server is shutting down",
            true,
            Some(1),
        ));
    }
    if !state.readiness.storage_ready() {
        return no_store(api_error_with_retry(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
            "the cached event-store readiness probe is unhealthy or stale",
            true,
            Some(1),
        ));
    }
    no_store(Json(serde_json::json!({ "ok": true })).into_response())
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn execution_capabilities(state: &AppState) -> ExecutionCapabilities {
    let isolation_class = state.execution_provider.isolation_class();
    let isolated = isolation_class != IsolationClass::None;
    ExecutionCapabilities {
        backend: state.sandbox_mode.as_str().to_string(),
        isolation_class,
        isolated,
        private_rootfs: isolated && state.cfg.rootfs.is_some(),
        dedicated_bootstrap: isolated
            && (state.cfg.sandbox_helper.is_some()
                || matches!(state.sandbox_mode, coop_exec::SandboxMode::Gvisor)),
        seccomp: matches!(state.sandbox_mode, coop_exec::SandboxMode::Namespaces) && state.seccomp,
        networking: if isolated { "disabled" } else { "host" }.to_string(),
        limit_enforcement: if isolated {
            LimitEnforcement::NAMESPACE_SANDBOX
        } else {
            LimitEnforcement::DEVELOPMENT_SUBPROCESS
        },
    }
}

#[utoipa::path(
    get,
    path = "/v1/capabilities",
    responses((status = 200, body = CapabilitiesResponse), (status = 401, body = ErrorEnvelope))
)]
pub async fn capabilities(State(state): State<AppState>) -> Response {
    Json(CapabilitiesResponse {
        version: crate::VERSION.to_string(),
        languages: state.available_languages.as_ref().clone(),
        execution: execution_capabilities(&state),
        limits: LimitCapabilities {
            wall_seconds_max: WALL_MAX_SECONDS,
            cpu_seconds_max: CPU_MAX_SECONDS,
            mem_mb_max: state.cfg.max_job_mem_mb,
            concurrent_mem_mb_max: state.cfg.memory_budget_mb,
            pids_max: PIDS_MAX,
            file_mb_max: FILE_MAX_MB,
            output_lines_max: coop_types::MAX_OUTPUT_LINES,
            output_bytes_per_stream_max: coop_types::MAX_OUTPUT_BYTES_PER_STREAM,
            output_record_bytes_max: coop_types::MAX_OUTPUT_RECORD_BYTES,
            code_bytes_max: MAX_CODE_BYTES,
            stdin_bytes_max: MAX_STDIN_BYTES,
            input_files_max: MAX_INPUT_FILES,
            input_file_bytes_max: MAX_INPUT_FILE_BYTES,
            input_bytes_max: MAX_INPUT_BYTES,
            output_files_max: MAX_OUTPUT_FILES,
            output_file_bytes_max: MAX_OUTPUT_FILE_BYTES,
            output_bytes_max: MAX_OUTPUT_BYTES,
        },
        features: FeatureCapabilities {
            result_wait: true,
            cancellation: true,
            event_cursors: true,
            stream_tickets: true,
            receipts: true,
            signed_attestations: state.attestations.enabled(),
        },
        attestations: AttestationCapabilities {
            enabled: state.attestations.enabled(),
            algorithm: state.attestations.enabled().then(|| "Ed25519".to_string()),
            envelope_format: state
                .attestations
                .enabled()
                .then(|| "DSSE/in-toto Statement v1".to_string()),
            key_id: state.attestations.key_id().map(str::to_string),
            public_key_url: state
                .attestations
                .enabled()
                .then(|| "/v1/attestation/public-key".to_string()),
        },
        runtime_packs: if state.execution_provider.isolation_class() == IsolationClass::None {
            Vec::new()
        } else {
            RUNTIME_PACKS
                .iter()
                .filter(|(language, _)| {
                    state
                        .available_languages
                        .iter()
                        .any(|available| available == language)
                })
                .map(|(_, pack)| (*pack).to_string())
                .collect()
        },
    })
    .into_response()
}

#[utoipa::path(
    get,
    path = "/v1/attestation/public-key",
    responses(
        (status = 200, body = AttestationPublicKeyResponse),
        (status = 404, body = ErrorEnvelope),
        (status = 401, body = ErrorEnvelope)
    )
)]
pub async fn attestation_public_key(State(state): State<AppState>) -> Response {
    let (Some(key_id), Some(public_key_pem)) = (
        state.attestations.key_id(),
        state.attestations.public_key_pem(),
    ) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "attestations_disabled",
            "this server has no attestation signing key",
            false,
        );
    };
    Json(AttestationPublicKeyResponse {
        algorithm: "Ed25519".to_string(),
        key_id: key_id.to_string(),
        public_key_pem: public_key_pem.to_string(),
        trust_notice: "The key id identifies this key but is not a trust anchor. Pin or distribute the public key through an authenticated out-of-band channel before relying on signatures."
            .to_string(),
    })
    .into_response()
}

#[utoipa::path(
    get,
    path = "/v1/whoami",
    responses((status = 200, body = WhoAmIResponse), (status = 401, body = ErrorEnvelope))
)]
pub async fn whoami(Extension(auth): Extension<AuthContext>) -> Response {
    Json(WhoAmIResponse {
        tenant: auth.tenant_id,
        principal_id: auth.principal_id,
        credential_id: auth.credential_id,
        auth_method: auth.method.as_str().to_string(),
        scopes: auth
            .scopes
            .names()
            .into_iter()
            .map(str::to_string)
            .collect(),
        expires_at_ms: auth.expires_at_ms,
    })
    .into_response()
}

/// Version + sandbox mode detail, behind the authenticated API surface
/// (the unauthenticated /healthz stays status-only so it leaks nothing).
#[utoipa::path(
    get,
    path = "/v1/status",
    responses(
        (status = 200, body = StatusResponse),
        (status = 401, description = "Missing or invalid API key", body = ErrorEnvelope)
    )
)]
pub async fn status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let storage_ready = state.readiness.storage_ready();
    Json(StatusResponse {
        version: crate::VERSION.to_string(),
        sandbox: state.sandbox_mode.as_str().to_string(),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        environment: if state.cfg.production {
            "production".to_string()
        } else {
            "development".to_string()
        },
        execution: execution_capabilities(&state),
        scheduler: SchedulerStatus {
            workers: state.cfg.workers,
            queue_capacity: state.admission.tenant_capacity(),
            queue_depth: state.admission.tenant_depth(&auth.tenant_id),
            running: state
                .cancels
                .iter()
                .filter(|entry| entry.tenant == auth.tenant_id)
                .count(),
            shutting_down: *state.shutdown.borrow(),
        },
        storage_ready,
    })
    .into_response()
}

const DASHBOARD_CSP: &str = "default-src 'none'; script-src 'sha256-F4Jfbts5NGULA30jcXFv7DX593iVAzPCeJK0gL+oi1w='; style-src 'sha256-2yKveexTlgndN9h8kvvqXY/1uu7pjXw5etsx29BP1fM='; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
#[cfg(test)]
const DASHBOARD_MAX_BYTES: usize = 192 * 1024;

async fn dashboard() -> Response {
    let mut response = Html(include_str!("dashboard.html")).into_response();
    let headers = response.headers_mut();
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(DASHBOARD_CSP),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use coop_store::EventRow;
    use sha2::{Digest, Sha256};
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tower::ServiceExt;

    #[derive(Default)]
    struct MessageSink {
        messages: Vec<Message>,
    }

    struct BackpressuredMessageSink;

    #[test]
    fn dashboard_disables_submission_when_capabilities_have_no_runtimes() {
        let source = include_str!("dashboard.html");
        assert!(source.contains("No runtimes available"));
        assert!(source.contains("dom.jobLanguage.disabled = true"));
        assert!(source.contains("dom.submitRun.disabled = Boolean(reason)"));
        assert!(source
            .contains("dom.languageFilter.replaceChildren(new Option(\"All languages\", \"\"))"));
    }

    #[test]
    fn dashboard_submits_the_six_class_isolation_contract_atomically() {
        let source = include_str!("dashboard.html");
        for isolation in [
            "none",
            "linux-shared-kernel",
            "gvisor-application-kernel",
            "wasm-capability",
            "hardware-vm",
            "confidential-vm",
        ] {
            assert!(
                source.contains(&format!("value=\"{isolation}\"")),
                "dashboard isolation selector is missing {isolation}"
            );
        }
        assert!(source.contains("requirements: { minimum_isolation: minimumIsolation }"));
        assert!(source.contains("execution.isolation_class"));
        assert!(source.contains("state.identity.scopes.includes(scope)"));
        assert!(source.contains("gVisor does not claim the namespace guest seccomp filter"));
        assert!(source.contains("job.attestation"));
        assert!(source.contains("attestation.envelope_url"));
        assert!(source.contains("attestation.result_artifact_url"));
        assert!(source.contains("url.origin !== window.location.origin"));
        assert!(source.contains("not a trust anchor"));
    }

    #[test]
    fn dashboard_execution_desk_keeps_view_and_cancel_state_scoped() {
        let source = include_str!("dashboard.html");
        for anchor in [
            "data-dock-tab=\"compose\"",
            "data-dock-tab=\"history\"",
            "dockView: \"compose\"",
            "sheetOpen: true",
            "primaryView: \"dock\"",
            "state.cancelArmedId !== id",
            "state.cancelArmedId = null",
            "Requested policy",
            "not a guarantee",
            "Server-reported portable evidence",
        ] {
            assert!(
                source.contains(anchor),
                "dashboard contract is missing {anchor}"
            );
        }
    }

    fn base64_standard(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let bits = u32::from(chunk[0]) << 16
                | u32::from(chunk.get(1).copied().unwrap_or(0)) << 8
                | u32::from(chunk.get(2).copied().unwrap_or(0));
            encoded.push(ALPHABET[((bits >> 18) & 0x3f) as usize] as char);
            encoded.push(ALPHABET[((bits >> 12) & 0x3f) as usize] as char);
            encoded.push(if chunk.len() > 1 {
                ALPHABET[((bits >> 6) & 0x3f) as usize] as char
            } else {
                '='
            });
            encoded.push(if chunk.len() > 2 {
                ALPHABET[(bits & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        encoded
    }

    fn inline_block<'a>(html: &'a str, open: &str, close: &str) -> &'a str {
        let (_, after_open) = html.split_once(open).expect("inline block opens");
        let (block, after_close) = after_open.split_once(close).expect("inline block closes");
        assert!(
            !after_close.contains(open),
            "dashboard must contain exactly one {open} block"
        );
        block
    }

    #[tokio::test]
    async fn dashboard_http_security_headers_hash_exact_inline_blocks() {
        let response = dashboard().await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            headers
                .get("referrer-policy")
                .and_then(|value| value.to_str().ok()),
            Some("no-referrer")
        );
        assert_eq!(
            headers
                .get("x-frame-options")
                .and_then(|value| value.to_str().ok()),
            Some("DENY")
        );
        let csp = headers
            .get("content-security-policy")
            .expect("dashboard CSP")
            .to_str()
            .expect("ASCII CSP")
            .to_string();
        assert_eq!(csp, DASHBOARD_CSP);
        assert!(!csp.contains("'unsafe-inline'"));
        assert!(!csp.contains("ws:"));
        assert!(!csp.contains("wss:"));

        let body = axum::body::to_bytes(response.into_body(), DASHBOARD_MAX_BYTES)
            .await
            .expect("dashboard body");
        assert!(
            body.len() <= DASHBOARD_MAX_BYTES,
            "dashboard exceeds its bounded HTML budget"
        );
        let html = std::str::from_utf8(&body).expect("UTF-8 dashboard");
        assert!(html.contains("localStorage.removeItem(\"coop_api_key\")"));
        assert!(html.contains("localStorage.removeItem(\"coop_key\")"));
        assert!(html.contains("sessionStorage.removeItem(\"coop_api_key\")"));
        assert!(html.contains("sessionStorage.removeItem(\"coop_key\")"));
        assert!(!html.contains(".getItem("));
        assert!(!html.contains("storageGet"));
        assert!(!html.contains("rememberKey"));
        let style = inline_block(html, "<style>", "</style>");
        let script = inline_block(html, "<script>", "</script>");
        let style_digest = Sha256::digest(style.as_bytes());
        let script_digest = Sha256::digest(script.as_bytes());
        let style_source = format!("'sha256-{}'", base64_standard(&style_digest));
        let script_source = format!("'sha256-{}'", base64_standard(&script_digest));
        assert!(csp.contains(&format!("style-src {style_source}")));
        assert!(csp.contains(&format!("script-src {script_source}")));
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("connect-src 'self'"));
        assert!(csp.contains("base-uri 'none'"));
        assert!(csp.contains("form-action 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    impl futures_util::Sink<Message> for MessageSink {
        type Error = Infallible;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.get_mut().messages.push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl futures_util::Sink<Message> for BackpressuredMessageSink {
        type Error = Infallible;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn start_send(self: Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
            unreachable!("a permanently backpressured sink is never ready")
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn websocket_close_is_bounded_when_peer_stops_reading() {
        let mut sink = BackpressuredMessageSink;
        tokio::time::timeout(
            Duration::from_millis(100),
            close_stream_bounded(&mut sink, Duration::from_millis(10)),
        )
        .await
        .expect("bounded close returns even while the peer is backpressured");
    }

    #[tokio::test]
    async fn websocket_data_send_is_bounded_when_peer_stops_reading() {
        let mut sink = BackpressuredMessageSink;
        let sent = tokio::time::timeout(
            Duration::from_millis(100),
            send_stream_message_bounded(
                &mut sink,
                Message::text("event"),
                Duration::from_millis(10),
            ),
        )
        .await
        .expect("bounded data send returns while the peer is backpressured");
        assert!(!sent);
    }

    fn event(seq: i64, kind: &str, data: serde_json::Value) -> EventRow {
        EventRow {
            seq,
            ts_ms: seq * 10,
            kind: kind.to_string(),
            data,
            prev_hash: String::new(),
            event_hash: String::new(),
            hash_version: 0,
        }
    }

    fn line(n: i64, stream: &str, text: &str) -> EventRow {
        event(n, stream, serde_json::json!({ "line": text }))
    }

    fn row(
        status: &str,
        started: Option<i64>,
        finished: Option<i64>,
        exit_code: Option<i32>,
    ) -> JobSummary {
        JobSummary {
            job_id: "job-1".into(),
            tenant: "t1".into(),
            language: "python".into(),
            status: status.into(),
            created_at_ms: 1,
            started_at_ms: started,
            finished_at_ms: finished,
            exit_code,
        }
    }

    #[test]
    fn fold_result_joins_streams_flags_and_violations() {
        let r = row("succeeded", Some(10), Some(45), Some(0));
        let events = vec![
            event(1, "started", serde_json::json!({})),
            line(2, "stdout", "one"),
            line(3, "stderr", "boom"),
            line(4, "stdout", "two"),
            event(5, "truncated", serde_json::json!({"stream": "stdout"})),
            event(
                6,
                "violation",
                serde_json::json!({"rule": "wall_clock_exceeded"}),
            ),
            event(7, "finished", serde_json::json!({"status": "succeeded"})),
        ];
        let v = fold_result(&r, &events);
        assert_eq!(v.status, "succeeded");
        assert_eq!(v.exit_code, Some(0));
        assert_eq!(v.duration_ms, Some(35));
        assert_eq!(v.stdout, "one\ntwo");
        assert_eq!(v.stderr, "boom");
        assert!(v.truncated);
        assert_eq!(v.violations.len(), 1);
        assert_eq!(v.violations[0]["rule"], "wall_clock_exceeded");
    }

    #[test]
    fn fold_result_empty_log_yields_empty_fields_and_no_duration() {
        let v = fold_result(&row("running", None, None, None), &[]);
        assert_eq!(v.stdout, "");
        assert_eq!(v.stderr, "");
        assert!(!v.truncated);
        assert!(v.violations.is_empty());
        assert_eq!(v.duration_ms, None);
    }

    #[tokio::test]
    async fn healthz_payload_is_status_only() {
        let resp = health().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), br#"{"ok":true}"#);
    }

    #[tokio::test]
    async fn terminal_observation_finally_drains_commit_after_prior_replay() {
        let db = std::env::temp_dir().join(format!(
            "coop-stream-terminal-race-{}.db",
            uuid::Uuid::now_v7()
        ));
        let store = coop_store::Store::open(&db).await.expect("open store");
        let job_id = "job-stream-terminal-race";
        store
            .create_job(
                job_id,
                "tenant",
                "bash",
                r#"{"language":"bash","code":":"}"#,
            )
            .await
            .expect("create queued job");

        let mut sink = MessageSink::default();
        let mut sent_max = 0;
        assert!(send_history(&store, job_id, &mut sink, &mut sent_max).await);
        assert_eq!(sink.messages.len(), 1, "initial replay sent accepted");

        // Deterministically place the terminal transaction in the old race
        // window: after the final replay SELECT but before the status read.
        let finished = store
            .finalize_with_event(job_id, "cancelled", None, 0, None)
            .await
            .expect("finalize")
            .expect("terminal transition");
        assert_eq!(
            drain_terminal_history(&store, job_id, &mut sink, &mut sent_max).await,
            TerminalDrain::Terminal
        );
        assert_eq!(sent_max, finished.seq);
        let last = sink.messages.last().expect("terminal message");
        let Message::Text(payload) = last else {
            panic!("expected terminal text frame")
        };
        let event: serde_json::Value =
            serde_json::from_str(payload.as_str()).expect("terminal event JSON");
        assert_eq!(event["kind"], "finished");
    }

    #[tokio::test]
    async fn stream_and_result_lifetimes_map_caps_and_reclaim() {
        for map_error in [
            stream_admission_error as fn(crate::TryLifetimeError) -> Response,
            result_wait_error,
        ] {
            let admission = crate::LifetimeAdmission::new(2, 1);
            let tenant_a = admission.try_acquire("tenant-a").expect("tenant a slot");
            let tenant_error = admission.try_acquire("tenant-a").err().expect("tenant cap");
            assert_eq!(
                map_error(tenant_error).status(),
                StatusCode::TOO_MANY_REQUESTS
            );

            let tenant_b = admission.try_acquire("tenant-b").expect("tenant b slot");
            let global_error = admission.try_acquire("tenant-c").err().expect("global cap");
            assert_eq!(
                map_error(global_error).status(),
                StatusCode::SERVICE_UNAVAILABLE
            );

            drop(tenant_a);
            let reclaimed = admission
                .try_acquire("tenant-a")
                .expect("disconnect reclaims both slots");
            drop((tenant_b, reclaimed));
        }
    }

    #[test]
    fn stream_inbound_protocol_accepts_only_tiny_text_keepalive() {
        assert_eq!(MAX_INBOUND_STREAM_MESSAGE_BYTES, 1_024);
        assert!(is_stream_keepalive(&Message::text("ping")));
        assert!(!is_stream_keepalive(&Message::text("PING")));
        assert!(!is_stream_keepalive(&Message::text("x".repeat(1_024))));
        assert!(!is_stream_keepalive(&Message::Binary(vec![0].into())));
    }

    fn submit_request(body: axum::body::Body) -> Request {
        Request::builder()
            .method("POST")
            .uri("/v1/jobs")
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(body)
            .expect("request")
    }

    #[tokio::test]
    async fn submit_body_read_is_tenant_bounded_timed_and_reclaimable() {
        let admission = crate::LifetimeAdmission::new(2, 1);
        let (polled_tx, polled_rx) = tokio::sync::oneshot::channel();
        let mut polled_tx = Some(polled_tx);
        let stalled = futures_util::stream::poll_fn(move |_cx| {
            if let Some(sender) = polled_tx.take() {
                let _ = sender.send(());
            }
            Poll::Pending::<Option<Result<axum::body::Bytes, Infallible>>>
        });
        let held_admission = admission.clone();
        let held = tokio::spawn(async move {
            extract_submit_payload(
                submit_request(axum::body::Body::from_stream(stalled)),
                &held_admission,
                None,
                "tenant-a",
                Duration::from_secs(5),
            )
            .await
        });
        polled_rx.await.expect("stalled body was polled");

        let tenant_error = extract_submit_payload(
            submit_request(axum::body::Body::from(r#"{"language":"bash","code":":"}"#)),
            &admission,
            None,
            "tenant-a",
            Duration::from_secs(1),
        )
        .await
        .err()
        .expect("same tenant is bounded");
        assert_eq!(tenant_error.status(), StatusCode::TOO_MANY_REQUESTS);

        let other = extract_submit_payload(
            submit_request(axum::body::Body::from(r#"{"language":"bash","code":":"}"#)),
            &admission,
            None,
            "tenant-b",
            Duration::from_secs(1),
        )
        .await;
        assert!(other.is_ok(), "another tenant retains its slot");
        held.abort();
        let _ = held.await;

        let timeout_admission = crate::LifetimeAdmission::new(1, 1);
        let never = futures_util::stream::pending::<Result<axum::body::Bytes, Infallible>>();
        let timeout = extract_submit_payload(
            submit_request(axum::body::Body::from_stream(never)),
            &timeout_admission,
            None,
            "tenant-a",
            Duration::from_millis(10),
        )
        .await
        .err()
        .expect("stalled body times out");
        assert_eq!(timeout.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(
            timeout.headers().get(header::CONNECTION),
            Some(&HeaderValue::from_static("close")),
            "an incomplete HTTP/1 body must not outlive its admission permit"
        );

        assert!(
            extract_submit_payload(
                submit_request(axum::body::Body::from(r#"{"language":"bash","code":":"}"#,)),
                &timeout_admission,
                None,
                "tenant-a",
                Duration::from_secs(1),
            )
            .await
            .is_ok(),
            "timeout releases both permits"
        );
    }

    #[tokio::test]
    async fn submit_admission_rejects_before_polling_body() {
        let admission = crate::LifetimeAdmission::new(1, 1);
        let _held = admission.try_acquire("tenant-a").expect("hold capacity");
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let body_polls = Arc::clone(&polls);
        let body = futures_util::stream::poll_fn(move |_cx| {
            body_polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Poll::Pending::<Option<Result<axum::body::Bytes, Infallible>>>
        });
        let response = extract_submit_payload(
            submit_request(axum::body::Body::from_stream(body)),
            &admission,
            None,
            "tenant-b",
            Duration::from_secs(1),
        )
        .await
        .err()
        .expect("global capacity is full");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            polls.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a rejected request body must never be polled"
        );
    }

    #[tokio::test]
    async fn submit_body_rejections_record_closed_global_and_tenant_reasons() {
        let metrics = crate::metrics::Metrics::new();
        let admission = crate::LifetimeAdmission::new(2, 1);
        let _tenant_a = admission.try_acquire("tenant-a").unwrap();
        let tenant = extract_submit_payload(
            submit_request(axum::body::Body::empty()),
            &admission,
            Some(&metrics),
            "tenant-a",
            Duration::from_secs(1),
        )
        .await
        .err()
        .expect("tenant body capacity rejects");
        assert_eq!(tenant.status(), StatusCode::TOO_MANY_REQUESTS);

        let _tenant_b = admission.try_acquire("tenant-b").unwrap();
        let global = extract_submit_payload(
            submit_request(axum::body::Body::empty()),
            &admission,
            Some(&metrics),
            "tenant-c",
            Duration::from_secs(1),
        )
        .await
        .err()
        .expect("global body capacity rejects");
        assert_eq!(global.status(), StatusCode::SERVICE_UNAVAILABLE);

        let closed_admission = crate::LifetimeAdmission::new(1, 1);
        closed_admission.close();
        let closed = extract_submit_payload(
            submit_request(axum::body::Body::empty()),
            &closed_admission,
            Some(&metrics),
            "tenant-a",
            Duration::from_secs(1),
        )
        .await
        .err()
        .expect("closed body admission rejects");
        assert_eq!(closed.status(), StatusCode::SERVICE_UNAVAILABLE);

        for (reason, expected) in [
            (crate::metrics::AdmissionReason::TenantFull, 1),
            (crate::metrics::AdmissionReason::GlobalFull, 1),
            (crate::metrics::AdmissionReason::Closed, 1),
        ] {
            assert_eq!(
                metrics.rejection_count(crate::metrics::AdmissionScope::SubmitBody, reason),
                expected
            );
        }
    }

    #[tokio::test]
    async fn aborted_submit_waiter_cannot_cancel_ambiguous_commit_or_release_lease() {
        let (admission, mut queued_rx) = crate::scheduler::Admission::channel(1, 1);
        let reservation = admission
            .try_reserve("tenant-a", 256)
            .expect("queue reservation");
        let body_admission = crate::LifetimeAdmission::new(1, 1);
        let body_permit = body_admission
            .try_acquire("tenant-a")
            .expect("body reservation");
        let (commit_entered_tx, commit_entered_rx) = tokio::sync::oneshot::channel();
        let (commit_release_tx, commit_release_rx) = tokio::sync::oneshot::channel();
        let durable = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let durable_after_commit = Arc::clone(&durable);
        let durable_for_reconcile = Arc::clone(&durable);
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let detached_metrics = Arc::clone(&metrics);

        // This is the exact ownership pattern used by submit(): the HTTP
        // waiter owns only a JoinHandle, while the detached continuation owns
        // both permits through an in-flight, ambiguously acknowledged COMMIT.
        let continuation = tokio::spawn(async move {
            let result = commit_reserved_submission(
                reservation,
                "committed-job".to_string(),
                move || async move {
                    let _ = commit_entered_tx.send(());
                    let _ = commit_release_rx.await;
                    durable_after_commit.store(true, std::sync::atomic::Ordering::Release);
                    Err::<coop_store::EventRow, &'static str>("commit acknowledgement lost")
                },
                move || {
                    let durable = Arc::clone(&durable_for_reconcile);
                    async move {
                        Ok::<bool, &'static str>(durable.load(std::sync::atomic::Ordering::Acquire))
                    }
                },
            )
            .await
            .map(|committed| {
                committed.publish_and_handoff(|_| {});
                detached_metrics.submitted(crate::metrics::Language::Python);
            });
            drop(body_permit);
            result
        });
        let waiter = tokio::spawn(continuation);

        commit_entered_rx.await.expect("COMMIT is in flight");
        waiter.abort();
        let _ = waiter.await;
        assert_eq!(admission.depth(), 1, "queue lease survives handler abort");
        assert_eq!(
            metrics.submitted_count(crate::metrics::Language::Python),
            0,
            "an uncommitted attempt is not submitted"
        );
        assert_eq!(
            body_admission.try_acquire("tenant-a").err(),
            Some(crate::TryLifetimeError::GlobalFull),
            "parsed request memory remains bounded through COMMIT"
        );

        commit_release_tx.send(()).expect("finish ambiguous COMMIT");
        let queued = tokio::time::timeout(Duration::from_secs(1), queued_rx.recv())
            .await
            .expect("continuation handed off promptly")
            .expect("scheduler envelope");
        assert!(durable.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(queued.job_id, "committed-job");
        assert_eq!(queued.tenant, "tenant-a");
        assert_eq!(
            metrics.submitted_count(crate::metrics::Language::Python),
            1,
            "detached durable success counts exactly once"
        );
        assert_eq!(
            admission.depth(),
            1,
            "durable queued row remains represented by exactly one live lease"
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(reclaimed) = body_admission.try_acquire("tenant-a") {
                    drop(reclaimed);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("acceptance completion reclaims parsed-body capacity");
        drop(queued);
        assert_eq!(admission.depth(), 0);
    }

    #[tokio::test]
    async fn submit_extractor_preserves_body_limit_and_content_type_errors() {
        let admission = crate::LifetimeAdmission::new(1, 1);
        let mut too_large =
            submit_request(axum::body::Body::from(r#"{"language":"bash","code":":"}"#));
        DefaultBodyLimit::max(8).apply(&mut too_large);
        let response = extract_submit_payload(
            too_large,
            &admission,
            None,
            "tenant-a",
            Duration::from_secs(1),
        )
        .await
        .err()
        .expect("tiny encoded limit rejects the body");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let mut wrong_type =
            submit_request(axum::body::Body::from(r#"{"language":"bash","code":":"}"#));
        wrong_type.headers_mut().remove(header::CONTENT_TYPE);
        let response = extract_submit_payload(
            wrong_type,
            &admission,
            None,
            "tenant-a",
            Duration::from_secs(1),
        )
        .await
        .err()
        .expect("JSON extractor requires JSON content type");
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn submit_http2_timeout_does_not_close_the_connection() {
        let admission = crate::LifetimeAdmission::new(1, 1);
        let never = futures_util::stream::pending::<Result<axum::body::Bytes, Infallible>>();
        let mut request = submit_request(axum::body::Body::from_stream(never));
        *request.version_mut() = Version::HTTP_2;
        let response = extract_submit_payload(
            request,
            &admission,
            None,
            "tenant-a",
            Duration::from_millis(10),
        )
        .await
        .err()
        .expect("stalled HTTP/2 stream times out");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(!response.headers().contains_key(header::CONNECTION));
    }

    #[tokio::test]
    async fn guarded_response_is_chunked_complete_and_reclaimable() {
        let admission = crate::LifetimeAdmission::new(1, 1);
        let permit = admission.try_acquire("tenant-a").expect("response slot");
        let payload = serde_json::json!({
            "data": "x".repeat(LARGE_RESPONSE_CHUNK_BYTES * 3)
        });
        let response = guarded_json_response(StatusCode::OK, &payload, permit);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );

        // Do not poll the response. Its encoded buffer, unread Body, and one
        // queued chunk must remain covered by admission; transport owns the
        // write-progress and absolute connection deadlines.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            admission.try_acquire("tenant-a").err(),
            Some(crate::TryLifetimeError::GlobalFull)
        );
        drop(response);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(reclaimed) = admission.try_acquire("tenant-a") {
                    drop(reclaimed);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping a stalled body reclaims response admission");

        let permit = admission
            .try_acquire("tenant-a")
            .expect("normal response slot");
        let expected = serde_json::to_vec(&payload).expect("serialize expected response");
        let response = guarded_json_response(StatusCode::OK, &payload, permit);
        assert_eq!(
            response.headers().get(header::CONTENT_LENGTH),
            Some(&HeaderValue::from_str(&expected.len().to_string()).unwrap())
        );
        let actual = axum::body::to_bytes(response.into_body(), expected.len() + 1)
            .await
            .expect("consume guarded body");
        assert_eq!(actual.as_ref(), expected.as_slice());
        let _reclaimed = admission
            .try_acquire("tenant-a")
            .expect("EOF reclaims response admission");
    }

    #[tokio::test]
    async fn committed_idempotent_replay_and_cancel_cannot_leave_bus_or_queue_leases() {
        let base = std::env::temp_dir().join(format!("coop-handoff-race-{}", uuid::Uuid::now_v7()));
        let db = base.join("coop.db");
        let jobs = base.join("jobs");
        let source = |key: &str| match key {
            "ROOKHOLD_API_KEYS" => Some("tenant:test-key-with-enough-entropy".to_string()),
            "ROOKHOLD_SANDBOX" => Some("off".to_string()),
            "ROOKHOLD_STORAGE_FREE_RESERVE_MB" => Some("0".to_string()),
            "ROOKHOLD_JOBS_ROOT" => Some(jobs.to_string_lossy().into_owned()),
            _ => None,
        };
        let cfg = crate::config::Config::from_sources(&source, false).unwrap();
        let store = Arc::new(
            coop_store::Store::open_with_limits(&db, cfg.storage_limits())
                .await
                .unwrap(),
        );
        let (app, state, mut queue_rx) =
            crate::build_app(cfg, Arc::clone(&store), "127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();

        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        *SUBMISSION_COMMIT_PAUSE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(SubmissionCommitPause {
            key: "race-key".to_string(),
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });

        let submit_request = || {
            Request::builder()
                .method("POST")
                .uri("/v1/jobs")
                .header(header::AUTHORIZATION, "Bearer test-key-with-enough-entropy")
                .header(header::CONTENT_TYPE, "application/json")
                .header("idempotency-key", "race-key")
                .body(axum::body::Body::from(
                    r#"{"language":"python","code":"print(1)"}"#,
                ))
                .unwrap()
        };
        let first_app = app.clone();
        let first = tokio::spawn(async move { first_app.oneshot(submit_request()).await.unwrap() });
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .expect("first submit committed before handoff pause");

        // The replay can observe the durable mapping while the original task
        // is paused only because bus registration and the composite queue
        // reservation were established before COMMIT.
        let replay = tokio::time::timeout(
            Duration::from_secs(2),
            app.clone().oneshot(submit_request()),
        )
        .await
        .expect("replay did not wait on missing process-local ownership")
        .unwrap();
        assert_eq!(replay.status(), StatusCode::CREATED);
        assert_eq!(replay.headers()["idempotency-replayed"], "true");
        let replay_body = axum::body::to_bytes(replay.into_body(), 1 << 20)
            .await
            .unwrap();
        let replay_body: serde_json::Value = serde_json::from_slice(&replay_body).unwrap();
        let job_id = replay_body["job_id"].as_str().unwrap().to_string();
        assert!(state.bus.subscribe(&job_id).is_some());

        let cancel = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/jobs/{job_id}"))
                    .header(header::AUTHORIZATION, "Bearer test-key-with-enough-entropy")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cancel.status(), StatusCode::OK);
        assert!(state.bus.subscribe(&job_id).is_none());

        release.notify_one();
        let first = first.await.unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let envelope = tokio::time::timeout(Duration::from_secs(2), queue_rx.recv())
            .await
            .expect("scheduler envelope missing")
            .expect("queue closed");
        assert_eq!(envelope.job_id, job_id);
        drop(envelope);
        assert_eq!(state.admission.depth(), 0);
        assert_eq!(state.admission.tenant_depth("tenant"), 0);
        assert!(state.bus.subscribe(&job_id).is_none());
        *SUBMISSION_COMMIT_PAUSE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let _ = std::fs::remove_dir_all(base);
    }
}
