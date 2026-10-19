//! Domain models, quota constants, and public projections for `coop-store`.
//!
//! # Architectural Note: Two-Phase Logical Storage Reserve
//!
//! Admitting a job reserves `JOB_COMPLETION_RESERVE_BYTES` (32 MiB) against both
//! the tenant and global logical byte budgets before the job runs. When the job
//! reaches a terminal state and commits its `receipt_json`, the reservation
//! steps down to `ATTESTATION_RESERVE_BYTES` (20 MiB)—enough to cover the
//! worst-case 16 MiB deterministic result artifact (`MAX_RESULT_ARTIFACT_BYTES`)
//! plus the 2 MiB DSSE envelope (`MAX_ATTESTATION_ENVELOPE_BYTES`) and row
//! overhead while the job sits in `attestation_outbox`. Only after the Ed25519
//! signer persists the immutable `job_attestations` row (or an operator with
//! signing disabled explicitly waives the outbox item) is the remaining reserve
//! released. This prevents concurrent jobs from exhausting disk or tenant quota
//! between execution completion and asynchronous signature convergence.

use serde_json::Value;
use std::path::PathBuf;

pub type StoreResult<T> = Result<T, sqlx::Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageLimits {
    pub global_bytes: u64,
    pub tenant_bytes: u64,
    pub free_reserve_bytes: u64,
}

impl StorageLimits {
    pub const fn new(global_bytes: u64, tenant_bytes: u64, free_reserve_bytes: u64) -> Self {
        Self {
            global_bytes,
            tenant_bytes,
            free_reserve_bytes,
        }
    }

    pub const fn unlimited() -> Self {
        Self::new(i64::MAX as u64, i64::MAX as u64, 0)
    }

    pub const fn local_default() -> Self {
        Self::new(16 * 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024, 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityErrorKind {
    Tenant,
    Global,
    Filesystem,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyRequest {
    pub key: String,
    pub request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyLookup {
    Miss,
    Replay { job_id: String },
    Conflict,
}

pub const JOB_COMPLETION_RESERVE_BYTES: u64 = 32 * 1024 * 1024;
/// Portion of a job's admission-time completion reserve retained after its
/// receipt commits and until its durable attestation outbox item is either
/// signed or explicitly waived by a server running with attestations off.
pub const ATTESTATION_RESERVE_BYTES: u64 = 20 * 1024 * 1024;
/// Exact persisted result artifacts are bounded independently of SQLite and
/// HTTP response limits. Two 1 MiB output streams can expand under JSON
/// escaping; 16 MiB leaves a deterministic fail-closed ceiling.
pub const MAX_RESULT_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ATTESTATION_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

pub(crate) const LOGICAL_ROW_OVERHEAD_BYTES: u64 = 64;
pub(crate) const TERMINAL_RESERVE_BYTES: u64 = ATTESTATION_RESERVE_BYTES;
pub(crate) const TENANT_QUOTA_MARKER: &str = "coop-capacity:tenant-logical-bytes";
pub(crate) const GLOBAL_QUOTA_MARKER: &str = "coop-capacity:global-logical-bytes";
pub(crate) const FREE_SPACE_MARKER: &str = "coop-capacity:filesystem-reserve";
pub(crate) const IDEMPOTENCY_CONFLICT_MARKER: &str = "coop-idempotency:fingerprint-conflict";
pub(crate) const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub(crate) const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
// Immutable predicate-v1 wire identity retained across the repository rename.
pub(crate) const COOP_EXECUTION_PREDICATE_TYPE: &str =
    "https://github.com/sambai-dev/coop/blob/main/crates/coop-attestation/FORMAT.md#predicate-v1";

pub fn capacity_error_kind(error: &sqlx::Error) -> Option<CapacityErrorKind> {
    let text = error.to_string();
    if text.contains(TENANT_QUOTA_MARKER) {
        Some(CapacityErrorKind::Tenant)
    } else if text.contains(GLOBAL_QUOTA_MARKER) {
        Some(CapacityErrorKind::Global)
    } else if text.contains(FREE_SPACE_MARKER)
        || text.contains("database or disk is full")
        || text.contains("SQLITE_FULL")
    {
        Some(CapacityErrorKind::Filesystem)
    } else {
        None
    }
}

pub fn is_idempotency_conflict(error: &sqlx::Error) -> bool {
    error.to_string().contains(IDEMPOTENCY_CONFLICT_MARKER)
}

pub(crate) const DEFAULT_RETENTION_BATCH: i64 = 32;
pub(crate) const MAX_RETENTION_BATCH: i64 = 64;
/// Hard event-row budget for one retention transaction. Oversized legacy jobs
/// are drained newest-first over multiple sweeps before their row is deleted.
pub const MAX_RETENTION_EVENTS_PER_BATCH: u64 = 4_096;
pub(crate) const MAX_EVENT_PAGE: i64 = 5_000;
pub(crate) const MAX_JOB_PAGE: i64 = 500;
pub(crate) const MAX_JOB_LOOKAHEAD_PAGE: i64 = MAX_JOB_PAGE + 1;
pub(crate) const MAX_RECOVERY_PAGE: i64 = 1_024;
pub(crate) const MAX_RUNNING_RECOVERY_ID_PAGE: i64 = 32;
/// Upper bound for one atomic event append. This keeps a single writer from
/// holding SQLite's write lock indefinitely while still amortizing the FULL
/// synchronous commit cost over output bursts.
pub const MAX_EVENT_BATCH_SIZE: usize = 256;
pub(crate) const TERMINAL_STATUSES_SQL: &str =
    "'succeeded','failed','timed_out','oom_killed','cancelled','error'";
pub(crate) const JOB_ROW_PROJECTION: &str =
    "job_id, tenant, language, status, spec_json, effective_spec_json, receipt_json, \
     created_at_ms, started_at_ms, finished_at_ms, exit_code";
pub(crate) const JOB_SUMMARY_PROJECTION: &str =
    "job_id, tenant, language, status, created_at_ms, started_at_ms, finished_at_ms, exit_code";

#[derive(Debug, Clone)]
pub struct JobRow {
    pub job_id: String,
    pub tenant: String,
    pub language: String,
    pub status: String,
    pub created_at_ms: i64,
    pub started_at_ms: Option<i64>,
    pub finished_at_ms: Option<i64>,
    pub exit_code: Option<i32>,
    pub spec_json: String,
    pub effective_spec_json: Option<String>,
    pub receipt_json: Option<String>,
}

/// Small retrieval projection for an immutable signed execution attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationMetadata {
    pub job_id: String,
    pub receipt_sha256: String,
    pub result_media_type: String,
    pub result_sha256: String,
    pub result_size_bytes: u64,
    pub envelope_sha256: String,
    pub envelope_size_bytes: u64,
    pub key_id: String,
    pub created_at_ms: i64,
}

/// Exact bytes returned by the artifact and DSSE download endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAttestation {
    pub metadata: AttestationMetadata,
    pub result_artifact: Vec<u8>,
    pub envelope_json: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationSourceJob {
    pub job_id: String,
    pub tenant: String,
    pub status: String,
    pub created_at_ms: i64,
    pub started_at_ms: Option<i64>,
    pub finished_at_ms: i64,
    pub exit_code: Option<i32>,
    pub receipt_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistAttestationOutcome {
    Created,
    Existing,
    StaleReceipt,
}

/// Lightweight projection for job-list surfaces. Deliberately excludes the
/// potentially multi-megabyte requested/effective specs and receipt payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSummary {
    pub job_id: String,
    pub tenant: String,
    pub language: String,
    pub status: String,
    pub created_at_ms: i64,
    pub started_at_ms: Option<i64>,
    pub finished_at_ms: Option<i64>,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EventRow {
    pub seq: i64,
    pub ts_ms: i64,
    pub kind: String,
    pub data: Value,
    /// SHA-256 of the preceding verified event in this job's chain. Empty for
    /// the first verified event and for migrated legacy events.
    pub prev_hash: String,
    /// SHA-256 of this event's versioned canonical payload. Empty only for
    /// migrated legacy events.
    pub event_hash: String,
    /// Zero denotes a legacy/unverified event; one is Rookhold's canonical v1
    /// event-chain format.
    pub hash_version: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CreateJobOutcome {
    Created(EventRow),
    Replayed { job_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobCursor {
    pub created_at_ms: i64,
    pub job_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedJobRow {
    pub job_id: String,
    pub tenant: String,
    pub created_at_ms: i64,
    pub requested_mem_mb: u32,
}

impl From<&QueuedJobRow> for JobCursor {
    fn from(row: &QueuedJobRow) -> Self {
        Self {
            created_at_ms: row.created_at_ms,
            job_id: row.job_id.clone(),
        }
    }
}

impl From<&JobSummary> for JobCursor {
    fn from(row: &JobSummary) -> Self {
        Self {
            created_at_ms: row.created_at_ms,
            job_id: row.job_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ListJobsQuery {
    /// `None` is an explicitly privileged all-tenant query. `Some("")` is
    /// never treated as a wildcard.
    pub tenant: Option<String>,
    pub status: Option<String>,
    pub language: Option<String>,
    pub before: Option<JobCursor>,
    pub limit: i64,
}

impl Default for ListJobsQuery {
    fn default() -> Self {
        Self {
            tenant: None,
            status: None,
            language: None,
            before: None,
            limit: 50,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventChainHead {
    pub event_count: i64,
    pub verified_event_count: i64,
    pub legacy_event_count: i64,
    pub head_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventChainVerification {
    pub head: EventChainHead,
    pub valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionReport {
    pub jobs_deleted: u64,
    pub events_deleted: u64,
    pub more_remaining: bool,
}

pub struct Store {
    pub(crate) pool: sqlx::SqlitePool,
    pub(crate) db_path: PathBuf,
    pub(crate) limits: StorageLimits,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Store").finish_non_exhaustive()
    }
}
