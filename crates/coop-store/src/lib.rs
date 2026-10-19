//! SQLite persistence engine, transactional byte-quota accounting, event-chain
//! integrity, and schema-v4 attestation outbox for Rookhold (`coop-store`).
//!
//! # Systems Architecture & Scaling Trade-offs
//!
//! - **Concurrency Model (SQLite WAL + `BEGIN IMMEDIATE`):** Connections run in
//!   Write-Ahead Logging (`WAL`) mode with `synchronous = FULL` and a bounded
//!   `busy_timeout`. Read queries (job status, paginated event streams, result
//!   views, and keyset-indexed history) execute concurrently over consistent
//!   WAL snapshots without blocking on writer transactions. Mutating operations
//!   acquire SQLite's single writer lock upfront via `BEGIN IMMEDIATE` so quota
//!   checks, event-chain sequence assignment, and transaction-local integrity
//!   sentinels are strictly serialized without mid-transaction `SQLITE_BUSY`
//!   deadlocks.
//! - **Event Batching (`MAX_EVENT_BATCH_SIZE = 256`):** Because `synchronous = FULL`
//!   requires a WAL `fsync` on commit, flushing stdout/stderr chunks line-by-line
//!   would bottleneck on disk IOPS. `append_events` amortizes a single `fsync`
//!   and hash-chain update across up to 256 events while bounding writer-lock
//!   hold time so cancellation and new job submissions remain responsive.
//! - **100x Scaling Bottleneck & Evolution Path:** On a single node, the primary
//!   throughput ceiling (~500–1,500 short jobs/sec depending on NVMe fsync
//!   latency) is SQLite's single-writer serialization across job creation,
//!   event flushing, terminal receipt commit, and outbox completion. Scaling
//!   beyond one node requires: (1) group-commit batching across concurrent
//!   job submissions, or (2) partitioning execution workers across independent
//!   per-shard SQLite WAL stores / migrating the state machine to PostgreSQL
//!   with `SKIP LOCKED` outbox workers.

mod filesystem;
pub mod models;
pub mod receipts;
mod triggers;

pub use models::*;
pub use receipts::{canonical_json, compute_receipt_sha256};

use filesystem::*;
use futures_util::TryStreamExt;
use receipts::*;
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{QueryBuilder, Row, Sqlite, SqliteConnection, SqlitePool};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use triggers::*;

const CURRENT_SCHEMA_VERSION: i64 = 4;
const ROW_VALIDATION_REVISION: i64 = 3;
// Transaction-local durable sentinel used to distinguish Rookhold-owned writes
// from offline/raw SQL changes in the validation-dirty triggers. SQLite's
// immediate writer lock prevents another connection from observing or using
// the sentinel until the transaction commits (which Rookhold never does).
const OWNED_ROW_WRITE_REVISION: i64 = ROW_VALIDATION_REVISION + 1;
// Revision 2 proves the exact terminal-pending attestation reserve. Revision 1
// omitted durable idempotency-row bytes and accepted the historical zero-reserve
// restart rebuild. It is repaired once under intact guards during upgrade.
const ACCOUNTING_VALIDATION_REVISION: i64 = 2;
const REPAIRABLE_ACCOUNTING_VALIDATION_REVISION: i64 = 1;
const OWNED_ACCOUNTING_WRITE_REVISION: i64 = ACCOUNTING_VALIDATION_REVISION + 1;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn validate_storage_limits(limits: StorageLimits) -> StoreResult<()> {
    if limits.global_bytes == 0
        || limits.tenant_bytes == 0
        || limits.tenant_bytes > limits.global_bytes
        || limits.global_bytes > i64::MAX as u64
        || limits.tenant_bytes > i64::MAX as u64
    {
        return Err(sqlx::Error::InvalidArgument(
            "logical storage limits must be positive, fit i64, and keep tenant <= global"
                .to_string(),
        ));
    }
    Ok(())
}

fn requested_mem_mb_from_json(spec_json: &str) -> StoreResult<u32> {
    let value: Value = serde_json::from_str(spec_json)
        .map_err(|error| sqlx::Error::InvalidArgument(error.to_string()))?;
    let raw = value
        .get("limits")
        .and_then(|limits| limits.get("mem_mb"))
        .and_then(Value::as_u64)
        .unwrap_or(256)
        .clamp(16, 4096);
    Ok(raw as u32)
}

fn logical_job_base_bytes(
    job_id: &str,
    tenant: &str,
    language: &str,
    status: &str,
    spec_json: &str,
) -> u64 {
    LOGICAL_ROW_OVERHEAD_BYTES
        .saturating_add(job_id.len() as u64)
        .saturating_add(tenant.len() as u64)
        .saturating_add(language.len() as u64)
        .saturating_add(status.len() as u64)
        .saturating_add(spec_json.len() as u64)
}

fn logical_event_bytes(event: &EventRow) -> u64 {
    LOGICAL_ROW_OVERHEAD_BYTES
        .saturating_add(event.kind.len() as u64)
        .saturating_add(canonical_json(&event.data).len() as u64)
        .saturating_add(event.prev_hash.len() as u64)
        .saturating_add(event.event_hash.len() as u64)
}

fn logical_idempotency_bytes(tenant: &str, job_id: &str, request: &IdempotencyRequest) -> u64 {
    LOGICAL_ROW_OVERHEAD_BYTES
        .saturating_add(tenant.len() as u64)
        .saturating_add(request.key.len() as u64)
        .saturating_add(request.request_sha256.len() as u64)
        .saturating_add(job_id.len() as u64)
}

fn to_i64_bytes(value: u64) -> StoreResult<i64> {
    i64::try_from(value)
        .map_err(|_| sqlx::Error::Protocol("logical byte count exceeded i64".to_string()))
}

async fn ensure_storage_quota_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant: &str,
    additional: u64,
    limits: StorageLimits,
) -> StoreResult<()> {
    if additional == 0 {
        return Ok(());
    }
    let global: i64 =
        sqlx::query("SELECT charged_bytes FROM storage_usage_total WHERE singleton = 1")
            .fetch_one(&mut **tx)
            .await?
            .try_get("charged_bytes")?;
    let tenant_used: i64 = sqlx::query(
        "SELECT COALESCE((
             SELECT charged_bytes FROM tenant_storage_usage WHERE tenant = ?1
         ), 0) AS charged_bytes",
    )
    .bind(tenant)
    .fetch_one(&mut **tx)
    .await?
    .try_get("charged_bytes")?;
    let additional = to_i64_bytes(additional)?;
    if tenant_used.saturating_add(additional) > limits.tenant_bytes as i64 {
        return Err(sqlx::Error::Protocol(TENANT_QUOTA_MARKER.to_string()));
    }
    if global.saturating_add(additional) > limits.global_bytes as i64 {
        return Err(sqlx::Error::Protocol(GLOBAL_QUOTA_MARKER.to_string()));
    }
    Ok(())
}

async fn actual_job_logical_bytes_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    job_id: &str,
) -> StoreResult<Option<(String, u64)>> {
    let row = sqlx::query(
        "SELECT job.tenant,
                64
                  + length(CAST(job.job_id AS BLOB))
                  + length(CAST(job.tenant AS BLOB))
                  + length(CAST(job.language AS BLOB))
                  + length(CAST(job.status AS BLOB))
                  + length(CAST(job.spec_json AS BLOB))
                  + COALESCE(length(CAST(job.effective_spec_json AS BLOB)), 0)
                  + COALESCE(length(CAST(job.receipt_json AS BLOB)), 0)
                  + COALESCE((
                      SELECT SUM(
                          64
                          + length(CAST(event.kind AS BLOB))
                          + length(CAST(event.data_json AS BLOB))
                          + length(CAST(event.prev_hash AS BLOB))
                          + length(CAST(event.event_hash AS BLOB))
                      ) FROM events AS event WHERE event.job_id = job.job_id
                    ), 0)
                  + COALESCE((
                      SELECT 64
                          + length(CAST(attestation.job_id AS BLOB))
                          + length(CAST(attestation.receipt_sha256 AS BLOB))
                          + length(CAST(attestation.result_media_type AS BLOB))
                          + length(attestation.result_artifact)
                          + length(CAST(attestation.result_sha256 AS BLOB))
                          + length(attestation.envelope_json)
                          + length(CAST(attestation.envelope_sha256 AS BLOB))
                          + length(CAST(attestation.key_id AS BLOB))
                      FROM job_attestations AS attestation
                      WHERE attestation.job_id = job.job_id
                    ), 0)
                   + COALESCE((
                       SELECT 64 + length(CAST(outbox.job_id AS BLOB))
                       FROM attestation_outbox AS outbox
                       WHERE outbox.job_id = job.job_id
                    ), 0)
                  + COALESCE((
                      SELECT SUM(
                          64
                          + length(CAST(mapping.tenant AS BLOB))
                          + length(CAST(mapping.idempotency_key AS BLOB))
                          + length(CAST(mapping.request_sha256 AS BLOB))
                          + length(CAST(mapping.job_id AS BLOB))
                      )
                      FROM idempotency_keys AS mapping
                      WHERE mapping.tenant = job.tenant
                        AND mapping.job_id = job.job_id
                    ), 0) AS retained_bytes
         FROM jobs AS job WHERE job.job_id = ?1",
    )
    .bind(job_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        let retained: i64 = row.try_get("retained_bytes")?;
        Ok((
            row.try_get("tenant")?,
            u64::try_from(retained).map_err(|_| {
                sqlx::Error::Protocol("logical retained bytes became negative".to_string())
            })?,
        ))
    })
    .transpose()
}

async fn reconcile_job_storage_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    job_id: &str,
    release_reservation: bool,
    db_path: &Path,
    limits: StorageLimits,
) -> StoreResult<()> {
    let Some((tenant, actual)) = actual_job_logical_bytes_tx(tx, job_id).await? else {
        return Ok(());
    };
    let row = sqlx::query(
        "SELECT retained_bytes, reserved_bytes FROM job_storage_usage WHERE job_id = ?1",
    )
    .bind(job_id)
    .fetch_one(&mut **tx)
    .await?;
    let old_retained = u64::try_from(row.try_get::<i64, _>("retained_bytes")?)
        .map_err(|_| sqlx::Error::Protocol("logical retained bytes became negative".to_string()))?;
    let old_reserved = u64::try_from(row.try_get::<i64, _>("reserved_bytes")?)
        .map_err(|_| sqlx::Error::Protocol("logical reserved bytes became negative".to_string()))?;
    let mut new_reserved = old_reserved;
    if actual > old_retained {
        let growth = actual - old_retained;
        let protected = if release_reservation {
            0
        } else {
            old_reserved.min(TERMINAL_RESERVE_BYTES)
        };
        let consumable = old_reserved.saturating_sub(protected);
        let consumed = growth.min(consumable);
        new_reserved = old_reserved - consumed;
        let overage = growth - consumed;
        if overage != 0 {
            ensure_storage_quota_tx(tx, &tenant, overage, limits).await?;
            ensure_filesystem_reserve_tx(tx, db_path, limits.free_reserve_bytes, overage).await?;
        }
    }
    if release_reservation {
        let attestation_pending: i64 = sqlx::query(
            "SELECT EXISTS(
                 SELECT 1 FROM attestation_outbox WHERE job_id = ?1
             ) AS pending",
        )
        .bind(job_id)
        .fetch_one(&mut **tx)
        .await?
        .try_get("pending")?;
        new_reserved = if attestation_pending != 0 {
            new_reserved.min(ATTESTATION_RESERVE_BYTES)
        } else {
            0
        };
    }
    sqlx::query(
        "UPDATE job_storage_usage
         SET retained_bytes = ?2, reserved_bytes = ?3
         WHERE job_id = ?1",
    )
    .bind(job_id)
    .bind(to_i64_bytes(actual)?)
    .bind(to_i64_bytes(new_reserved)?)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn lookup_idempotency_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    tenant: &str,
    request: &IdempotencyRequest,
) -> StoreResult<IdempotencyLookup> {
    let row = sqlx::query(
        "SELECT mapping.request_sha256, mapping.job_id
         FROM idempotency_keys AS mapping
         INNER JOIN jobs AS job
           ON job.tenant = mapping.tenant AND job.job_id = mapping.job_id
         WHERE mapping.tenant = ?1 AND mapping.idempotency_key = ?2",
    )
    .bind(tenant)
    .bind(&request.key)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(match row {
        None => IdempotencyLookup::Miss,
        Some(row) if row.get::<String, _>("request_sha256") == request.request_sha256 => {
            IdempotencyLookup::Replay {
                job_id: row.get("job_id"),
            }
        }
        Some(_) => IdempotencyLookup::Conflict,
    })
}

fn build_job_list_query<'args>(
    prefix: &'static str,
    projection: &'static str,
    query: &'args ListJobsQuery,
) -> QueryBuilder<'args, Sqlite> {
    let mut statement = QueryBuilder::<Sqlite>::new(prefix);
    statement.push("SELECT ").push(projection).push(
        " FROM jobs
              WHERE NOT EXISTS (
                  SELECT 1 FROM retention_tombstones
                  WHERE retention_tombstones.job_id = jobs.job_id
              )",
    );
    if let Some(tenant) = query.tenant.as_deref() {
        statement.push(" AND jobs.tenant = ").push_bind(tenant);
    }
    if let Some(status) = query.status.as_deref() {
        statement.push(" AND jobs.status = ").push_bind(status);
    }
    if let Some(language) = query.language.as_deref() {
        statement.push(" AND jobs.language = ").push_bind(language);
    }
    if let Some(before) = query.before.as_ref() {
        statement
            .push(" AND (jobs.created_at_ms, jobs.job_id) < (")
            .push_bind(before.created_at_ms)
            .push(", ")
            .push_bind(before.job_id.as_str())
            .push(")");
    }
    statement
        .push(" ORDER BY jobs.created_at_ms DESC, jobs.job_id DESC LIMIT ")
        .push_bind(query.limit.clamp(1, MAX_JOB_LOOKAHEAD_PAGE));
    statement
}

fn build_queued_jobs_query<'args>(
    prefix: &'static str,
    after: Option<&'args JobCursor>,
    limit: i64,
) -> QueryBuilder<'args, Sqlite> {
    let mut statement = QueryBuilder::<Sqlite>::new(prefix);
    statement.push(
        "SELECT jobs.job_id, jobs.tenant, jobs.created_at_ms,
                jobs.admitted_mem_mb AS requested_mem_mb
         FROM jobs INDEXED BY idx_jobs_status_created_recovery_v3
         WHERE jobs.status = 'queued'
           AND NOT EXISTS (
                SELECT 1 FROM retention_tombstones
                WHERE retention_tombstones.job_id = jobs.job_id
           )",
    );
    if let Some(after) = after {
        statement
            .push(" AND (jobs.created_at_ms, jobs.job_id) > (")
            .push_bind(after.created_at_ms)
            .push(", ")
            .push_bind(after.job_id.as_str())
            .push(")");
    }
    statement
        .push(" ORDER BY jobs.created_at_ms ASC, jobs.job_id ASC LIMIT ")
        .push_bind(limit.clamp(1, MAX_RECOVERY_PAGE));
    statement
}

impl Store {
    pub async fn open(path: &Path) -> StoreResult<Self> {
        Self::open_with_limits(path, StorageLimits::local_default()).await
    }

    pub async fn open_with_limits(path: &Path, limits: StorageLimits) -> StoreResult<Self> {
        validate_storage_limits(limits)?;
        prepare_storage_path(path)?;

        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            // UTF-8 physical validation streams potentially large JSON rows.
            // Apply backpressure after one pending row so a valid database
            // cannot queue dozens of maximum-sized specs in process memory.
            .row_buffer_size(1)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .pragma("secure_delete", "FAST")
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;
        let store = Self {
            pool,
            db_path: path.to_path_buf(),
            limits,
        };

        if let Err(error) = store.migrate().await {
            store.pool.close().await;
            return Err(error);
        }

        // SQLite derives sidecar permissions from the database mode. Enforce
        // them explicitly too, both as defense in depth and for pre-existing
        // WAL/SHM files created by an older Rookhold version.
        harden_storage_files(path)?;
        Ok(store)
    }

    pub fn storage_limits(&self) -> StorageLimits {
        self.limits
    }

    async fn migrate(&self) -> StoreResult<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::migrate_locked(&mut tx).await?;
        tx.commit().await
    }

    async fn migrate_locked(conn: &mut SqliteConnection) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY CHECK (typeof(version) = 'integer' AND version > 0),
                applied_at_ms INTEGER NOT NULL
                    CHECK (typeof(applied_at_ms) = 'integer' AND applied_at_ms >= 0)
            )",
        )
        .execute(&mut *conn)
        .await?;

        validate_required_columns(
            conn,
            "schema_migrations",
            &[
                RequiredColumn::primary_key("version", "INTEGER"),
                RequiredColumn::not_null("applied_at_ms", "INTEGER"),
            ],
        )
        .await?;
        validate_migration_history_rows(conn).await?;

        let row = sqlx::query("SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations")
            .fetch_one(&mut *conn)
            .await?;
        let history_version: i64 = row.get("version");
        let user_version: i64 = sqlx::query("PRAGMA user_version")
            .fetch_one(&mut *conn)
            .await?
            .get("user_version");
        if user_version < 0 {
            return Err(sqlx::Error::Protocol(format!(
                "database has an invalid negative user_version ({user_version})"
            )));
        }
        if history_version > CURRENT_SCHEMA_VERSION || user_version > CURRENT_SCHEMA_VERSION {
            return Err(sqlx::Error::Protocol(format!(
                "database schema is newer than supported version {CURRENT_SCHEMA_VERSION} (history={history_version}, user_version={user_version})"
            )));
        }
        if history_version != 0 && user_version != 0 && history_version != user_version {
            return Err(sqlx::Error::Protocol(format!(
                "database schema version markers disagree (history={history_version}, user_version={user_version})"
            )));
        }
        let version = history_version.max(user_version);
        let schema_markers_current =
            history_version == CURRENT_SCHEMA_VERSION && user_version == CURRENT_SCHEMA_VERSION;

        let has_jobs = table_exists(conn, "jobs").await?;
        let v3_table_count = physical_v3_table_count(conn).await?;
        let has_admitted_memory =
            has_jobs && column_exists(conn, "jobs", "admitted_mem_mb").await?;
        let has_accounting_revision = table_exists(conn, "store_integrity").await?
            && column_exists(conn, "store_integrity", "accounting_validation_revision").await?;
        let physical_v3_signature =
            v3_table_count != 0 || has_admitted_memory || has_accounting_revision;
        if physical_v3_signature && v3_table_count != 4 {
            return Err(sqlx::Error::Protocol(format!(
                "database has a partial v3 physical schema ({v3_table_count}/4 required tables)"
            )));
        }
        if version >= 3 && v3_table_count != 4 {
            return Err(sqlx::Error::Protocol(
                "v3-or-newer database markers require the complete physical v3 schema".to_string(),
            ));
        }
        let physical_v3 = physical_v3_signature;
        if physical_v3 && !matches!((history_version, user_version), (3, 3) | (4, 4)) {
            return Err(sqlx::Error::Protocol(format!(
                "physical v3 schema has downgraded or missing version markers (history={history_version}, user_version={user_version})"
            )));
        }
        if has_jobs && schema_has_v2_extensions(conn).await? {
            ensure_admitted_memory_column(conn, physical_v3).await?;
        }
        match (version, has_jobs) {
            (0, false) => {
                Self::create_current_schema(conn).await?;
                record_migration(conn, 1).await?;
                record_migration(conn, 2).await?;
                record_migration(conn, 3).await?;
                record_migration(conn, CURRENT_SCHEMA_VERSION).await?;
            }
            (0, true) | (1, true) => {
                if schema_has_v2_extensions(conn).await? {
                    // Lost or stale markers must not project a current table
                    // through the v1 migration, which would discard receipt
                    // and event-hash evidence. Validate and reconcile it in
                    // place; a partial v2 shape fails closed below.
                    Self::validate_current_schema(conn).await?;
                } else {
                    Self::migrate_legacy_schema(conn).await?;
                    if history_version == 0 {
                        record_migration(conn, 1).await?;
                    }
                    record_migration(conn, 2).await?;
                    record_migration(conn, 3).await?;
                    record_migration(conn, CURRENT_SCHEMA_VERSION).await?;
                }
            }
            (1, false) => {
                return Err(sqlx::Error::Protocol(
                    "schema migration history exists but the jobs table is missing".to_string(),
                ));
            }
            (2, true) | (3, true) | (CURRENT_SCHEMA_VERSION, true) => {}
            (CURRENT_SCHEMA_VERSION, false) => {
                return Err(sqlx::Error::Protocol(
                    "current schema migration is recorded but the jobs table is missing"
                        .to_string(),
                ));
            }
            _ => {
                return Err(sqlx::Error::Protocol(format!(
                    "unsupported schema migration state: version={version}, jobs_table={has_jobs}"
                )));
            }
        }

        if !table_exists(conn, "events").await? {
            return Err(sqlx::Error::Protocol(
                "events table is missing after schema migration".to_string(),
            ));
        }

        // A marker alone is not evidence that the physical schema is usable.
        // Validate the columns and cascade that all current read/write paths
        // rely on before reconciling either version marker.
        Self::validate_current_schema(conn).await?;
        // sqlite_sequence is writable outside Rookhold and cannot be guarded by a
        // table trigger. This indexed high-watermark check is cheap enough for
        // every open and prevents cursor reuse/exhaustion on the fast path.
        validated_event_sequence_counter(conn, "events").await?;
        Self::ensure_integrity_state(conn).await?;
        // v4 tables must exist before row validation and logical accounting
        // can inspect or charge them. Creating them is permitted only while
        // migrating a legitimately marked pre-v4 database; current v4
        // markers with missing tables fail closed inside this helper.
        Self::ensure_retention_tombstones(conn).await?;
        Self::ensure_attestation_tables(conn).await?;
        let row_validation_current = Self::row_validation_current(conn).await?;
        let storage_guards_were_current = storage_guards_current(conn).await?;
        // Current guards turn every committed raw jobs/events mutation into a
        // durable dirty revision. There is no legitimate crash state with a
        // committed dirty sentinel (owned writes either commit the validated
        // revision atomically or roll back), so silently rescanning and
        // blessing such edits would launder immutable identity/evidence.
        if schema_markers_current && storage_guards_were_current && !row_validation_current {
            return Err(sqlx::Error::Protocol(
                "jobs/events/attestations were modified outside an owned write".to_string(),
            ));
        }
        let accounting_validation_revision = Self::accounting_validation_revision(conn).await?;
        let accounting_guard_generation = accounting_guard_generation(conn).await?;
        let repair_accounting_generation = matches!(
            (accounting_validation_revision, accounting_guard_generation),
            (
                Some(REPAIRABLE_ACCOUNTING_VALIDATION_REVISION),
                AccountingGuardGeneration::RepairableRevisionOne
            ) | (
                Some(ACCOUNTING_VALIDATION_REVISION),
                AccountingGuardGeneration::StorageOnlyRevisionTwo
            )
        );
        let unbound_attestations_requeued = if repair_accounting_generation {
            Self::requeue_unbound_revision_one_attestations(conn).await?
        } else {
            false
        };
        let attestation_outbox_seeded = Self::seed_missing_attestation_outbox(conn).await?;
        let requires_full_validation = !schema_markers_current
            || !row_validation_current
            || !storage_guards_were_current
            || unbound_attestations_requeued
            || attestation_outbox_seeded;
        if requires_full_validation {
            Self::validate_current_rows(conn).await?;
            validate_foreign_keys(conn).await?;
        }
        // Existing v2 tables predate the storage-class CHECKs. Idempotent
        // guards preserve compatibility while enforcing the same invariants
        // for all future inserts and updates.
        Self::create_indexes(conn, repair_accounting_generation).await?;
        if requires_full_validation {
            Self::record_row_validation(conn).await?;
        }
        record_migration(conn, 1).await?;
        record_migration(conn, 2).await?;
        record_migration(conn, 3).await?;
        record_migration(conn, CURRENT_SCHEMA_VERSION).await?;

        sqlx::query(&format!("PRAGMA user_version = {CURRENT_SCHEMA_VERSION}"))
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    async fn create_current_schema(conn: &mut SqliteConnection) -> StoreResult<()> {
        create_jobs_table(conn, "jobs").await?;
        create_events_table(conn, "events", "jobs").await?;
        Self::create_indexes(conn, false).await
    }

    async fn ensure_integrity_state(conn: &mut SqliteConnection) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS store_integrity (
                 singleton INTEGER PRIMARY KEY
                     CHECK (typeof(singleton) = 'integer' AND singleton = 1),
                 row_validation_revision INTEGER NOT NULL
                     CHECK (typeof(row_validation_revision) = 'integer'
                            AND row_validation_revision >= 0),
                 accounting_validation_revision INTEGER NOT NULL
                     CHECK (typeof(accounting_validation_revision) = 'integer'
                            AND accounting_validation_revision >= 0),
                 validated_at_ms INTEGER NOT NULL
                     CHECK (typeof(validated_at_ms) = 'integer' AND validated_at_ms >= 0),
                 full_scan_count INTEGER NOT NULL
                     CHECK (typeof(full_scan_count) = 'integer' AND full_scan_count > 0)
             )",
        )
        .execute(&mut *conn)
        .await?;
        if !column_exists(conn, "store_integrity", "accounting_validation_revision").await? {
            sqlx::query(
                "ALTER TABLE store_integrity
                 ADD COLUMN accounting_validation_revision INTEGER NOT NULL DEFAULT 0
                 CHECK (typeof(accounting_validation_revision) = 'integer'
                        AND accounting_validation_revision >= 0)",
            )
            .execute(&mut *conn)
            .await?;
        }
        validate_required_columns(
            conn,
            "store_integrity",
            &[
                RequiredColumn::primary_key("singleton", "INTEGER"),
                RequiredColumn::not_null("row_validation_revision", "INTEGER"),
                RequiredColumn::not_null("accounting_validation_revision", "INTEGER"),
                RequiredColumn::not_null("validated_at_ms", "INTEGER"),
                RequiredColumn::not_null("full_scan_count", "INTEGER"),
            ],
        )
        .await?;
        let invalid: i64 = sqlx::query(
            "SELECT EXISTS(
                 SELECT 1 FROM store_integrity
                 WHERE typeof(singleton) != 'integer' OR singleton != 1
                    OR typeof(row_validation_revision) != 'integer'
                    OR row_validation_revision < 0
                    OR typeof(accounting_validation_revision) != 'integer'
                    OR accounting_validation_revision < 0
                    OR typeof(validated_at_ms) != 'integer' OR validated_at_ms < 0
                    OR typeof(full_scan_count) != 'integer' OR full_scan_count <= 0
             ) AS invalid",
        )
        .fetch_one(&mut *conn)
        .await?
        .try_get("invalid")?;
        if invalid != 0 {
            return Err(sqlx::Error::Protocol(
                "store_integrity contains invalid values".to_string(),
            ));
        }
        Ok(())
    }

    async fn row_validation_current(conn: &mut SqliteConnection) -> StoreResult<bool> {
        let revision =
            sqlx::query("SELECT row_validation_revision FROM store_integrity WHERE singleton = 1")
                .fetch_optional(&mut *conn)
                .await?
                .map(|row| row.try_get::<i64, _>("row_validation_revision"))
                .transpose()?;
        if revision.is_some_and(|value| value > ROW_VALIDATION_REVISION) {
            return Err(sqlx::Error::Protocol(format!(
                "database row-validation revision is newer than supported revision {ROW_VALIDATION_REVISION}"
            )));
        }
        Ok(revision == Some(ROW_VALIDATION_REVISION))
    }

    async fn accounting_validation_revision(
        conn: &mut SqliteConnection,
    ) -> StoreResult<Option<i64>> {
        let revision = sqlx::query(
            "SELECT accounting_validation_revision
             FROM store_integrity WHERE singleton = 1",
        )
        .fetch_optional(&mut *conn)
        .await?
        .map(|row| row.try_get::<i64, _>("accounting_validation_revision"))
        .transpose()?;
        if revision.is_some_and(|value| value > ACCOUNTING_VALIDATION_REVISION) {
            return Err(sqlx::Error::Protocol(format!(
                "database accounting-validation revision is newer than supported revision {ACCOUNTING_VALIDATION_REVISION}"
            )));
        }
        Ok(revision)
    }

    async fn record_row_validation(conn: &mut SqliteConnection) -> StoreResult<()> {
        sqlx::query(
            "INSERT INTO store_integrity(
                 singleton, row_validation_revision, accounting_validation_revision,
                 validated_at_ms, full_scan_count
             ) VALUES (1, ?1, ?2, ?3, 1)
             ON CONFLICT(singleton) DO UPDATE SET
                 row_validation_revision = excluded.row_validation_revision,
                 accounting_validation_revision = excluded.accounting_validation_revision,
                 validated_at_ms = excluded.validated_at_ms,
                 full_scan_count = store_integrity.full_scan_count + 1",
        )
        .bind(ROW_VALIDATION_REVISION)
        .bind(ACCOUNTING_VALIDATION_REVISION)
        .bind(now_ms())
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    async fn begin_row_writes(conn: &mut SqliteConnection) -> StoreResult<()> {
        let updated = sqlx::query(
            "UPDATE store_integrity
             SET row_validation_revision = ?2,
                 accounting_validation_revision = ?4
             WHERE singleton = 1 AND row_validation_revision = ?1
               AND accounting_validation_revision = ?3",
        )
        .bind(ROW_VALIDATION_REVISION)
        .bind(OWNED_ROW_WRITE_REVISION)
        .bind(ACCOUNTING_VALIDATION_REVISION)
        .bind(OWNED_ACCOUNTING_WRITE_REVISION)
        .execute(&mut *conn)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(sqlx::Error::Protocol(
                "row validation is stale during a Rookhold write; run validate_integrity before retrying"
                    .to_string(),
            ));
        }
        Ok(())
    }

    async fn mark_row_writes_validated(conn: &mut SqliteConnection) -> StoreResult<()> {
        let updated = sqlx::query(
            "UPDATE store_integrity
             SET row_validation_revision = ?1,
                 accounting_validation_revision = ?4,
                 validated_at_ms = ?2
             WHERE singleton = 1 AND row_validation_revision = ?3
               AND accounting_validation_revision = ?5",
        )
        .bind(ROW_VALIDATION_REVISION)
        .bind(now_ms())
        .bind(OWNED_ROW_WRITE_REVISION)
        .bind(ACCOUNTING_VALIDATION_REVISION)
        .bind(OWNED_ACCOUNTING_WRITE_REVISION)
        .execute(&mut *conn)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(sqlx::Error::Protocol(
                "row-validation ownership was lost during a Rookhold write".to_string(),
            ));
        }
        Ok(())
    }

    async fn create_indexes(
        conn: &mut SqliteConnection,
        repair_accounting_generation: bool,
    ) -> StoreResult<()> {
        Self::ensure_integrity_state(conn).await?;
        Self::ensure_retention_tombstones(conn).await?;
        Self::ensure_attestation_tables(conn).await?;
        ensure_admitted_memory_column(conn, false).await?;
        let accounting_guard_generation = accounting_guard_generation(conn).await?;
        let accounting_guards_were_current =
            accounting_guard_generation == AccountingGuardGeneration::CurrentRevisionTwo;
        drop_accounting_guard_triggers(conn).await?;
        Self::ensure_idempotency_keys(conn).await?;
        Self::ensure_storage_accounting(
            conn,
            accounting_guards_were_current,
            repair_accounting_generation,
        )
        .await?;
        // These non-covering v2-development indexes can force SQLite to walk
        // large table-record overflow chains for lifecycle columns stored
        // after the JSON payloads. Replace them transactionally with indexes
        // that contain only the lightweight summary/recovery projection.
        for stale_index in [
            "idx_jobs_tenant_created",
            "idx_jobs_tenant_status_created",
            "idx_jobs_tenant_language_created",
            "idx_jobs_status",
            "idx_jobs_status_created_recovery",
        ] {
            sqlx::query(&format!("DROP INDEX IF EXISTS {stale_index}"))
                .execute(&mut *conn)
                .await?;
        }
        for statement in [
            "CREATE INDEX IF NOT EXISTS idx_events_job_seq ON events(job_id, seq)",
            "CREATE INDEX IF NOT EXISTS idx_jobs_tenant_created_summary ON jobs(
                 tenant, created_at_ms DESC, job_id DESC, language, status,
                 started_at_ms, finished_at_ms, exit_code
             )",
            "CREATE INDEX IF NOT EXISTS idx_jobs_tenant_status_created_summary ON jobs(
                 tenant, status, created_at_ms DESC, job_id DESC, language,
                 started_at_ms, finished_at_ms, exit_code
             )",
            "CREATE INDEX IF NOT EXISTS idx_jobs_tenant_language_created_summary ON jobs(
                 tenant, language, created_at_ms DESC, job_id DESC, status,
                 started_at_ms, finished_at_ms, exit_code
             )",
            "CREATE INDEX IF NOT EXISTS idx_jobs_tenant_status_language_created_summary ON jobs(
                 tenant, status, language, created_at_ms DESC, job_id DESC,
                 started_at_ms, finished_at_ms, exit_code
             )",
            "CREATE INDEX IF NOT EXISTS idx_jobs_id_summary ON jobs(
                 job_id, tenant, language, status, created_at_ms,
                 started_at_ms, finished_at_ms, exit_code
             )",
            "CREATE INDEX IF NOT EXISTS idx_jobs_status_created_recovery_v3 ON jobs(
                 status, created_at_ms ASC, job_id ASC, tenant, admitted_mem_mb
             )",
            "CREATE INDEX IF NOT EXISTS idx_jobs_retention ON jobs(finished_at_ms, job_id) WHERE finished_at_ms IS NOT NULL",
        ] {
            sqlx::query(statement).execute(&mut *conn).await?;
        }
        create_storage_guard_triggers(conn).await?;
        Ok(())
    }

    async fn ensure_attestation_tables(conn: &mut SqliteConnection) -> StoreResult<()> {
        let attestations_exist = table_exists(conn, "job_attestations").await?;
        let outbox_exists = table_exists(conn, "attestation_outbox").await?;
        let history_version: i64 =
            sqlx::query("SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations")
                .fetch_one(&mut *conn)
                .await?
                .try_get("version")?;
        let user_version: i64 = sqlx::query("PRAGMA user_version")
            .fetch_one(&mut *conn)
            .await?
            .try_get("user_version")?;
        if attestations_exist != outbox_exists {
            return Err(sqlx::Error::Protocol(
                "attestation schema is partially present".to_string(),
            ));
        }
        if !attestations_exist && (history_version >= 4 || user_version >= 4) {
            return Err(sqlx::Error::Protocol(
                "v4 database is missing durable attestation tables".to_string(),
            ));
        }

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS job_attestations (
                 job_id TEXT PRIMARY KEY NOT NULL
                     REFERENCES jobs(job_id) ON DELETE CASCADE
                     CHECK (typeof(job_id) = 'text' AND length(trim(job_id)) > 0),
                 receipt_sha256 TEXT NOT NULL
                     CHECK (typeof(receipt_sha256) = 'text'
                            AND length(receipt_sha256) = 64
                            AND receipt_sha256 NOT GLOB '*[^0-9a-f]*'),
                 result_media_type TEXT NOT NULL
                     CHECK (typeof(result_media_type) = 'text'
                            AND length(trim(result_media_type)) BETWEEN 1 AND 255),
                 result_artifact BLOB NOT NULL
                     CHECK (typeof(result_artifact) = 'blob'
                            AND length(result_artifact) BETWEEN 1 AND 16777216
                            AND json_valid(CAST(result_artifact AS TEXT))),
                 result_sha256 TEXT NOT NULL
                     CHECK (typeof(result_sha256) = 'text'
                            AND length(result_sha256) = 64
                            AND result_sha256 NOT GLOB '*[^0-9a-f]*'),
                 envelope_json BLOB NOT NULL
                     CHECK (typeof(envelope_json) = 'blob'
                            AND length(envelope_json) BETWEEN 1 AND 2097152
                            AND json_valid(CAST(envelope_json AS TEXT))),
                 envelope_sha256 TEXT NOT NULL
                     CHECK (typeof(envelope_sha256) = 'text'
                            AND length(envelope_sha256) = 64
                            AND envelope_sha256 NOT GLOB '*[^0-9a-f]*'),
                 key_id TEXT NOT NULL
                     CHECK (typeof(key_id) = 'text'
                            AND length(trim(key_id)) BETWEEN 1 AND 256),
                 created_at_ms INTEGER NOT NULL
                     CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0)
             )",
        )
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS attestation_outbox (
                 job_id TEXT PRIMARY KEY NOT NULL
                     REFERENCES jobs(job_id) ON DELETE CASCADE
                     CHECK (typeof(job_id) = 'text' AND length(trim(job_id)) > 0),
                 pending_since_ms INTEGER NOT NULL
                     CHECK (typeof(pending_since_ms) = 'integer' AND pending_since_ms >= 0),
                 attempt_count INTEGER NOT NULL DEFAULT 0
                     CHECK (typeof(attempt_count) = 'integer'
                            AND attempt_count BETWEEN 0 AND 2147483647),
                 next_attempt_ms INTEGER NOT NULL
                     CHECK (typeof(next_attempt_ms) = 'integer' AND next_attempt_ms >= 0)
             )",
        )
        .execute(&mut *conn)
        .await?;
        validate_required_columns(
            conn,
            "job_attestations",
            &[
                RequiredColumn::primary_key("job_id", "TEXT"),
                RequiredColumn::not_null("receipt_sha256", "TEXT"),
                RequiredColumn::not_null("result_media_type", "TEXT"),
                RequiredColumn::not_null("result_artifact", "BLOB"),
                RequiredColumn::not_null("result_sha256", "TEXT"),
                RequiredColumn::not_null("envelope_json", "BLOB"),
                RequiredColumn::not_null("envelope_sha256", "TEXT"),
                RequiredColumn::not_null("key_id", "TEXT"),
                RequiredColumn::not_null("created_at_ms", "INTEGER"),
            ],
        )
        .await?;
        validate_required_columns(
            conn,
            "attestation_outbox",
            &[
                RequiredColumn::primary_key("job_id", "TEXT"),
                RequiredColumn::not_null("pending_since_ms", "INTEGER"),
                RequiredColumn::not_null("attempt_count", "INTEGER"),
                RequiredColumn::not_null("next_attempt_ms", "INTEGER"),
            ],
        )
        .await?;
        for table in ["job_attestations", "attestation_outbox"] {
            let foreign_keys = sqlx::query(&format!("PRAGMA foreign_key_list({table})"))
                .fetch_all(&mut *conn)
                .await?;
            let has_job_cascade = foreign_keys.iter().any(|row| {
                row.get::<String, _>("table") == "jobs"
                    && row.get::<String, _>("from") == "job_id"
                    && row.get::<String, _>("to") == "job_id"
                    && row
                        .get::<String, _>("on_delete")
                        .eq_ignore_ascii_case("CASCADE")
            });
            if !has_job_cascade {
                return Err(sqlx::Error::Protocol(format!(
                    "{table}.job_id is missing its cascading jobs foreign key"
                )));
            }
        }
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_attestation_outbox_pending
             ON attestation_outbox(next_attempt_ms ASC, pending_since_ms ASC, job_id ASC)",
        )
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Re-establish crash-convergent signing work only after the caller has
    /// checked whether durable row validation was already dirty. Keeping this
    /// separate from schema creation prevents startup backfill from masking an
    /// unrelated raw mutation before the fail-closed check runs.
    async fn seed_missing_attestation_outbox(conn: &mut SqliteConnection) -> StoreResult<bool> {
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO attestation_outbox(
                 job_id, pending_since_ms, attempt_count, next_attempt_ms
             )
             SELECT jobs.job_id,
                    COALESCE(jobs.finished_at_ms, jobs.created_at_ms),
                    0,
                    COALESCE(jobs.finished_at_ms, jobs.created_at_ms)
             FROM jobs
             LEFT JOIN job_attestations ON job_attestations.job_id = jobs.job_id
             WHERE jobs.status IN ('succeeded','failed','timed_out','oom_killed','cancelled','error')
               AND jobs.receipt_json IS NOT NULL
               AND job_attestations.job_id IS NULL
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )",
        )
        .execute(&mut *conn)
        .await?;
        Ok(inserted.rows_affected() != 0)
    }

    /// Remove pre-fix attestation rows whose exact files do not bind the
    /// authoritative job tenant. The following outbox seed recreates signing
    /// work. This runs only while upgrading the clean revision-1 accounting
    /// generation, so ordinary opens do not rescan large immutable blobs.
    async fn requeue_unbound_revision_one_attestations(
        conn: &mut SqliteConnection,
    ) -> StoreResult<bool> {
        let mut stale_job_ids = Vec::new();
        let mut rows = sqlx::query(
            "SELECT job.job_id, job.tenant,
                    attestation.receipt_sha256,
                    attestation.result_media_type,
                    attestation.result_artifact,
                    attestation.result_sha256,
                    attestation.envelope_json
             FROM job_attestations AS attestation
             INNER JOIN jobs AS job ON job.job_id = attestation.job_id
             ORDER BY job.job_id ASC",
        )
        .fetch(&mut *conn);
        while let Some(row) = rows.try_next().await? {
            let job_id: String = row.try_get("job_id")?;
            let tenant: String = row.try_get("tenant")?;
            let receipt_sha256: String = row.try_get("receipt_sha256")?;
            let result_media_type: String = row.try_get("result_media_type")?;
            let result_artifact: Vec<u8> = row.try_get("result_artifact")?;
            let result_sha256: String = row.try_get("result_sha256")?;
            let envelope_json: Vec<u8> = row.try_get("envelope_json")?;
            if !portable_attestation_binding_matches(
                &job_id,
                &tenant,
                &receipt_sha256,
                &result_media_type,
                &result_artifact,
                &result_sha256,
                &envelope_json,
            ) {
                stale_job_ids.push(job_id);
            }
        }
        drop(rows);
        for job_id in &stale_job_ids {
            sqlx::query("DELETE FROM job_attestations WHERE job_id = ?1")
                .bind(job_id)
                .execute(&mut *conn)
                .await?;
        }
        Ok(!stale_job_ids.is_empty())
    }

    async fn ensure_storage_accounting(
        conn: &mut SqliteConnection,
        guards_were_current: bool,
        repair_accounting_generation: bool,
    ) -> StoreResult<()> {
        let existed = table_exists(conn, "job_storage_usage").await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS job_storage_usage (
                 job_id TEXT PRIMARY KEY NOT NULL,
                 tenant TEXT NOT NULL
                     CHECK (typeof(tenant) = 'text' AND length(trim(tenant)) > 0),
                 retained_bytes INTEGER NOT NULL
                     CHECK (typeof(retained_bytes) = 'integer' AND retained_bytes >= 0),
                 reserved_bytes INTEGER NOT NULL
                     CHECK (typeof(reserved_bytes) = 'integer' AND reserved_bytes >= 0),
                 requested_mem_mb INTEGER NOT NULL
                     CHECK (typeof(requested_mem_mb) = 'integer'
                            AND requested_mem_mb BETWEEN 16 AND 4096),
                 FOREIGN KEY(tenant, job_id)
                     REFERENCES jobs(tenant, job_id) ON DELETE CASCADE
             )",
        )
        .execute(&mut *conn)
        .await?;
        upgrade_job_storage_fk_if_needed(conn).await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS storage_usage_total (
                 singleton INTEGER PRIMARY KEY
                     CHECK (typeof(singleton) = 'integer' AND singleton = 1),
                 charged_bytes INTEGER NOT NULL
                     CHECK (typeof(charged_bytes) = 'integer' AND charged_bytes >= 0)
             )",
        )
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS tenant_storage_usage (
                 tenant TEXT PRIMARY KEY NOT NULL
                     CHECK (typeof(tenant) = 'text' AND length(trim(tenant)) > 0),
                 charged_bytes INTEGER NOT NULL
                     CHECK (typeof(charged_bytes) = 'integer' AND charged_bytes >= 0)
             )",
        )
        .execute(&mut *conn)
        .await?;
        validate_required_columns(
            conn,
            "job_storage_usage",
            &[
                RequiredColumn::primary_key("job_id", "TEXT"),
                RequiredColumn::not_null("tenant", "TEXT"),
                RequiredColumn::not_null("retained_bytes", "INTEGER"),
                RequiredColumn::not_null("reserved_bytes", "INTEGER"),
                RequiredColumn::not_null("requested_mem_mb", "INTEGER"),
            ],
        )
        .await?;
        validate_required_columns(
            conn,
            "storage_usage_total",
            &[
                RequiredColumn::primary_key("singleton", "INTEGER"),
                RequiredColumn::not_null("charged_bytes", "INTEGER"),
            ],
        )
        .await?;
        validate_required_columns(
            conn,
            "tenant_storage_usage",
            &[
                RequiredColumn::primary_key("tenant", "TEXT"),
                RequiredColumn::not_null("charged_bytes", "INTEGER"),
            ],
        )
        .await?;

        let row_validation_current = Self::row_validation_current(conn).await?;
        let accounting_validation_revision = Self::accounting_validation_revision(conn).await?;
        let authoritative_rows_changed = !row_validation_current || repair_accounting_generation;
        if !existed || authoritative_rows_changed {
            sqlx::query("DELETE FROM job_storage_usage")
                .execute(&mut *conn)
                .await?;
            sqlx::query(
                "INSERT INTO job_storage_usage(
                     job_id, tenant, retained_bytes, reserved_bytes, requested_mem_mb
                 )
                 SELECT job.job_id,
                        job.tenant,
                        64
                          + length(CAST(job.job_id AS BLOB))
                          + length(CAST(job.tenant AS BLOB))
                          + length(CAST(job.language AS BLOB))
                          + length(CAST(job.status AS BLOB))
                          + length(CAST(job.spec_json AS BLOB))
                          + COALESCE(length(CAST(job.effective_spec_json AS BLOB)), 0)
                          + COALESCE(length(CAST(job.receipt_json AS BLOB)), 0)
                          + COALESCE((
                              SELECT SUM(
                                  64
                                  + length(CAST(event.kind AS BLOB))
                                  + length(CAST(event.data_json AS BLOB))
                                  + length(CAST(event.prev_hash AS BLOB))
                                  + length(CAST(event.event_hash AS BLOB))
                              )
                              FROM events AS event WHERE event.job_id = job.job_id
                            ), 0)
                          + COALESCE((
                              SELECT 64
                                  + length(CAST(attestation.job_id AS BLOB))
                                  + length(CAST(attestation.receipt_sha256 AS BLOB))
                                  + length(CAST(attestation.result_media_type AS BLOB))
                                  + length(attestation.result_artifact)
                                  + length(CAST(attestation.result_sha256 AS BLOB))
                                  + length(attestation.envelope_json)
                                  + length(CAST(attestation.envelope_sha256 AS BLOB))
                                  + length(CAST(attestation.key_id AS BLOB))
                              FROM job_attestations AS attestation
                              WHERE attestation.job_id = job.job_id
                            ), 0)
                           + COALESCE((
                               SELECT 64 + length(CAST(outbox.job_id AS BLOB))
                               FROM attestation_outbox AS outbox
                               WHERE outbox.job_id = job.job_id
                            ), 0)
                          + COALESCE((
                              SELECT SUM(
                                  64
                                  + length(CAST(mapping.tenant AS BLOB))
                                  + length(CAST(mapping.idempotency_key AS BLOB))
                                  + length(CAST(mapping.request_sha256 AS BLOB))
                                  + length(CAST(mapping.job_id AS BLOB))
                              )
                              FROM idempotency_keys AS mapping
                              WHERE mapping.tenant = job.tenant
                                AND mapping.job_id = job.job_id
                            ), 0),
                        CASE
                            WHEN job.status IN ('queued','running') THEN ?1
                            WHEN EXISTS (
                                SELECT 1 FROM attestation_outbox AS pending
                                WHERE pending.job_id = job.job_id
                            ) THEN ?2
                            ELSE 0
                        END,
                        job.admitted_mem_mb
                 FROM jobs AS job",
            )
            .bind(JOB_COMPLETION_RESERVE_BYTES as i64)
            .bind(ATTESTATION_RESERVE_BYTES as i64)
            .execute(&mut *conn)
            .await?;
            sqlx::query("DELETE FROM storage_usage_total")
                .execute(&mut *conn)
                .await?;
            sqlx::query(
                "INSERT INTO storage_usage_total(singleton, charged_bytes)
                 SELECT 1, COALESCE(SUM(retained_bytes + reserved_bytes), 0)
                 FROM job_storage_usage",
            )
            .execute(&mut *conn)
            .await?;
            sqlx::query("DELETE FROM tenant_storage_usage")
                .execute(&mut *conn)
                .await?;
            sqlx::query(
                "INSERT INTO tenant_storage_usage(tenant, charged_bytes)
                 SELECT tenant, SUM(retained_bytes + reserved_bytes)
                 FROM job_storage_usage GROUP BY tenant",
            )
            .execute(&mut *conn)
            .await?;
        }
        sqlx::query(
            "INSERT OR IGNORE INTO storage_usage_total(singleton, charged_bytes) VALUES (1, 0)",
        )
        .execute(&mut *conn)
        .await?;

        let accounting_validation_current = accounting_validation_revision
            == Some(ACCOUNTING_VALIDATION_REVISION)
            && guards_were_current;
        let rebuilt = !existed || authoritative_rows_changed;
        let requires_full_validation = rebuilt || !guards_were_current;
        if !accounting_validation_current && guards_were_current && !rebuilt {
            return Err(sqlx::Error::Protocol(
                "logical storage/idempotency accounting was modified outside an owned write"
                    .to_string(),
            ));
        }
        if requires_full_validation || !accounting_validation_current {
            Self::validate_storage_accounting_full(conn).await?;
        } else {
            Self::validate_storage_accounting_fast(conn).await?;
        }
        create_accounting_guard_triggers(conn).await?;
        if requires_full_validation || !accounting_validation_current {
            Self::record_accounting_validation(conn).await?;
        }
        Ok(())
    }

    async fn ensure_idempotency_keys(conn: &mut SqliteConnection) -> StoreResult<()> {
        let existed = table_exists(conn, "idempotency_keys").await?;
        let history_version: i64 =
            sqlx::query("SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations")
                .fetch_one(&mut *conn)
                .await?
                .try_get("version")?;
        let user_version: i64 = sqlx::query("PRAGMA user_version")
            .fetch_one(&mut *conn)
            .await?
            .try_get("user_version")?;
        if !existed && (history_version >= 3 || user_version >= 3) {
            return Err(sqlx::Error::Protocol(
                "v3 database is missing durable idempotency mappings".to_string(),
            ));
        }
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS idempotency_keys (
                 tenant TEXT NOT NULL
                     CHECK (typeof(tenant) = 'text' AND length(trim(tenant)) > 0),
                 idempotency_key TEXT NOT NULL
                     CHECK (typeof(idempotency_key) = 'text'
                            AND length(idempotency_key) BETWEEN 1 AND 128),
                 request_sha256 TEXT NOT NULL
                     CHECK (typeof(request_sha256) = 'text' AND length(request_sha256) = 64),
                 job_id TEXT NOT NULL,
                 created_at_ms INTEGER NOT NULL
                     CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
                 PRIMARY KEY(tenant, idempotency_key),
                 FOREIGN KEY(tenant, job_id)
                     REFERENCES jobs(tenant, job_id) ON DELETE CASCADE
             ) WITHOUT ROWID",
        )
        .execute(&mut *conn)
        .await?;
        upgrade_idempotency_fk_if_needed(conn).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_idempotency_job ON idempotency_keys(job_id)")
            .execute(&mut *conn)
            .await?;
        validate_required_columns(
            conn,
            "idempotency_keys",
            &[
                RequiredColumn::primary_key("tenant", "TEXT"),
                RequiredColumn::primary_key("idempotency_key", "TEXT"),
                RequiredColumn::not_null("request_sha256", "TEXT"),
                RequiredColumn::not_null("job_id", "TEXT"),
                RequiredColumn::not_null("created_at_ms", "INTEGER"),
            ],
        )
        .await?;
        Ok(())
    }

    async fn validate_storage_accounting_full(conn: &mut SqliteConnection) -> StoreResult<()> {
        let invalid: i64 = sqlx::query(
            "SELECT EXISTS(
                 SELECT 1
                 FROM jobs AS job
                 LEFT JOIN job_storage_usage AS usage ON usage.job_id = job.job_id
                 WHERE usage.job_id IS NULL OR usage.tenant != job.tenant
                    OR usage.requested_mem_mb != job.admitted_mem_mb
                    OR usage.retained_bytes != (
                        64
                        + length(CAST(job.job_id AS BLOB))
                        + length(CAST(job.tenant AS BLOB))
                        + length(CAST(job.language AS BLOB))
                        + length(CAST(job.status AS BLOB))
                        + length(CAST(job.spec_json AS BLOB))
                        + COALESCE(length(CAST(job.effective_spec_json AS BLOB)), 0)
                        + COALESCE(length(CAST(job.receipt_json AS BLOB)), 0)
                        + COALESCE((
                            SELECT SUM(
                                64
                                + length(CAST(event.kind AS BLOB))
                                + length(CAST(event.data_json AS BLOB))
                                + length(CAST(event.prev_hash AS BLOB))
                                + length(CAST(event.event_hash AS BLOB))
                            ) FROM events AS event WHERE event.job_id = job.job_id
                          ), 0)
                        + COALESCE((
                            SELECT 64
                                + length(CAST(attestation.job_id AS BLOB))
                                + length(CAST(attestation.receipt_sha256 AS BLOB))
                                + length(CAST(attestation.result_media_type AS BLOB))
                                + length(attestation.result_artifact)
                                + length(CAST(attestation.result_sha256 AS BLOB))
                                + length(attestation.envelope_json)
                                + length(CAST(attestation.envelope_sha256 AS BLOB))
                                + length(CAST(attestation.key_id AS BLOB))
                            FROM job_attestations AS attestation
                            WHERE attestation.job_id = job.job_id
                          ), 0)
                        + COALESCE((
                            SELECT 64 + length(CAST(outbox.job_id AS BLOB))
                            FROM attestation_outbox AS outbox
                            WHERE outbox.job_id = job.job_id
                          ), 0)
                        + COALESCE((
                            SELECT SUM(
                                64
                                + length(CAST(mapping.tenant AS BLOB))
                                + length(CAST(mapping.idempotency_key AS BLOB))
                                + length(CAST(mapping.request_sha256 AS BLOB))
                                + length(CAST(mapping.job_id AS BLOB))
                            )
                            FROM idempotency_keys AS mapping
                            WHERE mapping.tenant = job.tenant
                              AND mapping.job_id = job.job_id
                          ), 0)
                    )
                    OR (job.status NOT IN ('queued','running')
                        AND NOT EXISTS (
                            SELECT 1 FROM attestation_outbox AS pending
                            WHERE pending.job_id = job.job_id
                        )
                        AND usage.reserved_bytes != 0)
                    OR (job.status NOT IN ('queued','running')
                        AND EXISTS (
                            SELECT 1 FROM attestation_outbox AS pending
                            WHERE pending.job_id = job.job_id
                        )
                        AND usage.reserved_bytes != ?1)
             )
             OR EXISTS(
                 SELECT 1 FROM job_storage_usage AS usage
                 LEFT JOIN jobs AS job ON job.job_id = usage.job_id
                 WHERE job.job_id IS NULL
             ) AS invalid",
        )
        .bind(ATTESTATION_RESERVE_BYTES as i64)
        .fetch_one(&mut *conn)
        .await?
        .try_get("invalid")?;
        if invalid != 0 {
            return Err(sqlx::Error::Protocol(
                "logical storage accounting disagrees with retained rows".to_string(),
            ));
        }
        let global_valid: i64 = sqlx::query(
            "SELECT charged_bytes = (
                 SELECT COALESCE(SUM(retained_bytes + reserved_bytes), 0)
                 FROM job_storage_usage
             ) AS valid
             FROM storage_usage_total WHERE singleton = 1",
        )
        .fetch_one(&mut *conn)
        .await?
        .try_get("valid")?;
        let tenants_invalid: i64 = sqlx::query(
            "SELECT EXISTS(
                 SELECT tenant, charged_bytes FROM tenant_storage_usage
                 EXCEPT
                 SELECT tenant, SUM(retained_bytes + reserved_bytes)
                 FROM job_storage_usage GROUP BY tenant
             ) OR EXISTS(
                 SELECT tenant, SUM(retained_bytes + reserved_bytes)
                 FROM job_storage_usage GROUP BY tenant
                 EXCEPT
                 SELECT tenant, charged_bytes FROM tenant_storage_usage
             ) AS invalid",
        )
        .fetch_one(&mut *conn)
        .await?
        .try_get("invalid")?;
        if global_valid == 0 || tenants_invalid != 0 {
            return Err(sqlx::Error::Protocol(
                "logical storage aggregate counters are inconsistent".to_string(),
            ));
        }
        validate_v3_foreign_keys_and_tenants(conn).await?;
        validate_idempotency_fingerprints(conn).await?;
        Ok(())
    }

    async fn validate_storage_accounting_fast(conn: &mut SqliteConnection) -> StoreResult<()> {
        // Exact owned-trigger definitions plus the durable clean revision are
        // the healthy-open proof. Content joins/sums here would turn every
        // restart back into O(jobs), while events/spec scans are substantially
        // worse. The bounded schema checks still reject weakened FKs/indexes;
        // any content mutation under intact guards dirties the revision and is
        // rejected above or routed through the full validator.
        validate_v3_foreign_key_schema(conn).await
    }

    async fn record_accounting_validation(conn: &mut SqliteConnection) -> StoreResult<()> {
        let updated = sqlx::query(
            "UPDATE store_integrity
             SET accounting_validation_revision = ?1, validated_at_ms = ?2
             WHERE singleton = 1",
        )
        .bind(ACCOUNTING_VALIDATION_REVISION)
        .bind(now_ms())
        .execute(&mut *conn)
        .await?;
        // A brand-new database records the combined row/accounting revision
        // immediately after create_indexes. There is no singleton row yet in
        // that path, so zero affected rows deliberately defers to
        // record_row_validation's atomic upsert.
        if updated.rows_affected() > 1 {
            return Err(sqlx::Error::Protocol(
                "accounting validation updated multiple singleton rows".to_string(),
            ));
        }
        Ok(())
    }

    async fn ensure_retention_tombstones(conn: &mut SqliteConnection) -> StoreResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS retention_tombstones (
                 job_id TEXT PRIMARY KEY NOT NULL
                     REFERENCES jobs(job_id) ON DELETE CASCADE
                     CHECK (typeof(job_id) = 'text' AND length(trim(job_id)) > 0),
                 marked_at_ms INTEGER NOT NULL
                     CHECK (typeof(marked_at_ms) = 'integer' AND marked_at_ms >= 0)
             )",
        )
        .execute(&mut *conn)
        .await?;
        validate_required_columns(
            conn,
            "retention_tombstones",
            &[
                RequiredColumn::primary_key("job_id", "TEXT"),
                RequiredColumn::not_null("marked_at_ms", "INTEGER"),
            ],
        )
        .await?;
        let invalid_rows: i64 = sqlx::query(
            "SELECT EXISTS(
                 SELECT 1 FROM retention_tombstones
                 WHERE typeof(job_id) != 'text' OR length(trim(job_id)) = 0
                    OR typeof(marked_at_ms) != 'integer' OR marked_at_ms < 0
             ) AS invalid",
        )
        .fetch_one(&mut *conn)
        .await?
        .try_get("invalid")?;
        if invalid_rows != 0 {
            return Err(sqlx::Error::Protocol(
                "retention_tombstones contains invalid values".to_string(),
            ));
        }
        let tombstones = sqlx::query(
            "SELECT rowid AS storage_rowid, CAST(job_id AS BLOB) AS job_id_bytes
             FROM retention_tombstones",
        )
        .fetch_all(&mut *conn)
        .await?;
        for row in tombstones {
            validate_utf8_bytes(
                "retention_tombstones",
                row.try_get("storage_rowid")?,
                "job_id",
                &row.try_get::<Vec<u8>, _>("job_id_bytes")?,
            )?;
        }
        let foreign_keys = sqlx::query("PRAGMA foreign_key_list(retention_tombstones)")
            .fetch_all(&mut *conn)
            .await?;
        let has_job_cascade = foreign_keys.iter().any(|row| {
            row.get::<String, _>("table") == "jobs"
                && row.get::<String, _>("from") == "job_id"
                && row.get::<String, _>("to") == "job_id"
                && row
                    .get::<String, _>("on_delete")
                    .eq_ignore_ascii_case("CASCADE")
        });
        if !has_job_cascade {
            return Err(sqlx::Error::Protocol(
                "retention_tombstones.job_id is missing its cascading jobs foreign key".to_string(),
            ));
        }
        Ok(())
    }

    async fn validate_current_schema(conn: &mut SqliteConnection) -> StoreResult<()> {
        validate_required_columns(
            conn,
            "jobs",
            &[
                RequiredColumn::primary_key("job_id", "TEXT"),
                RequiredColumn::not_null("tenant", "TEXT"),
                RequiredColumn::not_null("language", "TEXT"),
                RequiredColumn::not_null("status", "TEXT"),
                RequiredColumn::not_null("spec_json", "TEXT"),
                RequiredColumn::not_null("admitted_mem_mb", "INTEGER"),
                RequiredColumn::nullable("effective_spec_json", "TEXT"),
                RequiredColumn::nullable("receipt_json", "TEXT"),
                RequiredColumn::not_null("created_at_ms", "INTEGER"),
                RequiredColumn::nullable("started_at_ms", "INTEGER"),
                RequiredColumn::nullable("finished_at_ms", "INTEGER"),
                RequiredColumn::nullable("exit_code", "INTEGER"),
            ],
        )
        .await?;
        validate_required_columns(
            conn,
            "events",
            &[
                RequiredColumn::primary_key("seq", "INTEGER"),
                RequiredColumn::not_null("job_id", "TEXT"),
                RequiredColumn::not_null("ts_ms", "INTEGER"),
                RequiredColumn::not_null("kind", "TEXT"),
                RequiredColumn::not_null("data_json", "TEXT"),
                RequiredColumn::not_null("prev_hash", "TEXT"),
                RequiredColumn::not_null("event_hash", "TEXT"),
                RequiredColumn::not_null("hash_version", "INTEGER"),
            ],
        )
        .await?;

        let foreign_keys = sqlx::query("PRAGMA foreign_key_list(events)")
            .fetch_all(&mut *conn)
            .await?;
        let has_job_cascade = foreign_keys.iter().any(|row| {
            row.get::<String, _>("table") == "jobs"
                && row.get::<String, _>("from") == "job_id"
                && row.get::<String, _>("to") == "job_id"
                && row
                    .get::<String, _>("on_delete")
                    .eq_ignore_ascii_case("CASCADE")
        });
        if !has_job_cascade {
            return Err(sqlx::Error::Protocol(
                "events.job_id is missing its jobs(job_id) ON DELETE CASCADE foreign key"
                    .to_string(),
            ));
        }

        let events_sql: String =
            sqlx::query("SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'events'")
                .fetch_one(&mut *conn)
                .await?
                .get("sql");
        if !events_sql.to_ascii_uppercase().contains("AUTOINCREMENT") {
            return Err(sqlx::Error::Protocol(
                "events.seq must use AUTOINCREMENT so replay cursors are never reused".to_string(),
            ));
        }
        Ok(())
    }

    async fn validate_current_rows(conn: &mut SqliteConnection) -> StoreResult<()> {
        let invalid_jobs: i64 = sqlx::query(
            "SELECT EXISTS(
                 SELECT 1 FROM jobs
                 WHERE typeof(job_id) != 'text' OR length(trim(job_id)) = 0
                    OR typeof(tenant) != 'text' OR length(trim(tenant)) = 0
                    OR typeof(language) != 'text' OR length(trim(language)) = 0
                    OR typeof(status) != 'text'
                    OR status NOT IN ('queued','running','succeeded','failed','timed_out','oom_killed','cancelled','error')
                    OR typeof(spec_json) != 'text' OR NOT json_valid(spec_json)
                    OR typeof(admitted_mem_mb) != 'integer'
                    OR admitted_mem_mb NOT BETWEEN 16 AND 4096
                    OR (effective_spec_json IS NOT NULL AND
                        (typeof(effective_spec_json) != 'text' OR NOT json_valid(effective_spec_json)))
                    OR (receipt_json IS NOT NULL AND
                        (typeof(receipt_json) != 'text' OR NOT json_valid(receipt_json)))
                    OR typeof(created_at_ms) != 'integer' OR created_at_ms < 0
                    OR (started_at_ms IS NOT NULL AND
                        (typeof(started_at_ms) != 'integer' OR started_at_ms < 0))
                    OR (finished_at_ms IS NOT NULL AND
                        (typeof(finished_at_ms) != 'integer' OR finished_at_ms < 0))
                    OR (exit_code IS NOT NULL AND
                        (typeof(exit_code) != 'integer' OR
                         exit_code < -2147483648 OR exit_code > 2147483647))
                    OR (status = 'queued' AND
                        (started_at_ms IS NOT NULL OR finished_at_ms IS NOT NULL))
                    OR (status = 'running' AND
                        (started_at_ms IS NULL OR finished_at_ms IS NOT NULL))
                    OR (status NOT IN ('queued','running') AND finished_at_ms IS NULL)
             ) AS invalid",
        )
        .fetch_one(&mut *conn)
        .await?
        .try_get("invalid")?;
        if invalid_jobs != 0 {
            return Err(sqlx::Error::Protocol(
                "jobs contains values incompatible with the current schema".to_string(),
            ));
        }

        let invalid_events: i64 = sqlx::query(
            "SELECT EXISTS(
                 SELECT 1 FROM events
                 WHERE typeof(seq) != 'integer'
                    OR seq <= 0 OR seq >= 9223372036854775806
                    OR typeof(job_id) != 'text'
                    OR typeof(ts_ms) != 'integer' OR ts_ms < 0
                    OR typeof(kind) != 'text' OR length(trim(kind)) = 0
                    OR typeof(data_json) != 'text' OR NOT json_valid(data_json)
                    OR typeof(prev_hash) != 'text'
                    OR typeof(event_hash) != 'text'
                    OR typeof(hash_version) != 'integer' OR hash_version NOT IN (0, 1)
                    OR (hash_version = 1 AND length(event_hash) != 64)
             ) AS invalid",
        )
        .fetch_one(&mut *conn)
        .await?
        .try_get("invalid")?;
        if invalid_events != 0 {
            return Err(sqlx::Error::Protocol(
                "events contains values incompatible with the current schema".to_string(),
            ));
        }

        let invalid_attestations: i64 = sqlx::query(
            "SELECT EXISTS(
                 SELECT 1
                 FROM job_attestations AS attestation
                 LEFT JOIN jobs AS job ON job.job_id = attestation.job_id
                 WHERE job.job_id IS NULL
                    OR job.status NOT IN ('succeeded','failed','timed_out','oom_killed','cancelled','error')
                    OR job.receipt_json IS NULL
                    OR COALESCE(json_type(job.receipt_json, '$.receipt_sha256'), '') != 'text'
                    OR COALESCE(json_extract(job.receipt_json, '$.receipt_sha256'), '') != attestation.receipt_sha256
                    OR typeof(attestation.job_id) != 'text'
                    OR length(trim(attestation.job_id)) = 0
                    OR typeof(attestation.receipt_sha256) != 'text'
                    OR length(attestation.receipt_sha256) != 64
                    OR attestation.receipt_sha256 GLOB '*[^0-9a-f]*'
                    OR typeof(attestation.result_media_type) != 'text'
                    OR length(trim(attestation.result_media_type)) NOT BETWEEN 1 AND 255
                    OR typeof(attestation.result_artifact) != 'blob'
                    OR length(attestation.result_artifact) NOT BETWEEN 1 AND 16777216
                    OR NOT json_valid(CAST(attestation.result_artifact AS TEXT))
                    OR typeof(attestation.result_sha256) != 'text'
                    OR length(attestation.result_sha256) != 64
                    OR attestation.result_sha256 GLOB '*[^0-9a-f]*'
                    OR typeof(attestation.envelope_json) != 'blob'
                    OR length(attestation.envelope_json) NOT BETWEEN 1 AND 2097152
                    OR NOT json_valid(CAST(attestation.envelope_json AS TEXT))
                    OR typeof(attestation.envelope_sha256) != 'text'
                    OR length(attestation.envelope_sha256) != 64
                    OR attestation.envelope_sha256 GLOB '*[^0-9a-f]*'
                    OR typeof(attestation.key_id) != 'text'
                    OR length(trim(attestation.key_id)) NOT BETWEEN 1 AND 256
                    OR typeof(attestation.created_at_ms) != 'integer'
                    OR attestation.created_at_ms < 0
             ) OR EXISTS(
                 SELECT 1
                 FROM attestation_outbox AS outbox
                 LEFT JOIN jobs AS job ON job.job_id = outbox.job_id
                 WHERE job.job_id IS NULL
                    OR job.status NOT IN ('succeeded','failed','timed_out','oom_killed','cancelled','error')
                    OR job.receipt_json IS NULL
                    OR COALESCE(json_type(job.receipt_json, '$.receipt_sha256'), '') != 'text'
                    OR length(COALESCE(json_extract(job.receipt_json, '$.receipt_sha256'), '')) != 64
                    OR COALESCE(json_extract(job.receipt_json, '$.receipt_sha256'), '') GLOB '*[^0-9a-f]*'
                    OR typeof(outbox.job_id) != 'text'
                    OR length(trim(outbox.job_id)) = 0
                    OR typeof(outbox.pending_since_ms) != 'integer'
                    OR outbox.pending_since_ms < 0
                    OR typeof(outbox.attempt_count) != 'integer'
                    OR outbox.attempt_count NOT BETWEEN 0 AND 2147483647
                    OR typeof(outbox.next_attempt_ms) != 'integer'
                    OR outbox.next_attempt_ms < 0
                    OR EXISTS (
                        SELECT 1 FROM job_attestations
                        WHERE job_attestations.job_id = outbox.job_id
                    )
             ) AS invalid",
        )
        .fetch_one(&mut *conn)
        .await?
        .try_get("invalid")?;
        if invalid_attestations != 0 {
            return Err(sqlx::Error::Protocol(
                "attestation rows are structurally invalid or disagree with terminal jobs"
                    .to_string(),
            ));
        }

        Self::validate_current_utf8(conn).await?;
        Self::validate_attestation_digests(conn).await?;
        Ok(())
    }

    async fn validate_attestation_digests(conn: &mut SqliteConnection) -> StoreResult<()> {
        let mut rows = sqlx::query(
            "SELECT rowid AS storage_rowid, result_artifact, result_sha256,
                    envelope_json, envelope_sha256
             FROM job_attestations ORDER BY rowid ASC",
        )
        .fetch(&mut *conn);
        while let Some(row) = rows.try_next().await? {
            let rowid: i64 = row.try_get("storage_rowid")?;
            let result: Vec<u8> = row.try_get("result_artifact")?;
            let expected_result: String = row.try_get("result_sha256")?;
            let envelope: Vec<u8> = row.try_get("envelope_json")?;
            let expected_envelope: String = row.try_get("envelope_sha256")?;
            if sha256_hex(&result) != expected_result || sha256_hex(&envelope) != expected_envelope
            {
                return Err(sqlx::Error::Protocol(format!(
                    "job_attestations rowid {rowid} has an exact-byte digest mismatch"
                )));
            }
        }
        Ok(())
    }

    async fn validate_current_utf8(conn: &mut SqliteConnection) -> StoreResult<()> {
        // `json_valid` verifies JSON syntax but SQLite can still accept invalid
        // UTF-8 bytes inside a JSON string. Read the raw bytes through a
        // backpressured stream: physical validation remains fail-closed while
        // retaining at most the current and one pending maximum-sized row.
        {
            let mut rows = sqlx::query(
                "SELECT rowid AS storage_rowid,
                        CAST(job_id AS BLOB) AS job_id_bytes,
                        CAST(tenant AS BLOB) AS tenant_bytes,
                        CAST(language AS BLOB) AS language_bytes,
                        CAST(status AS BLOB) AS status_bytes,
                        CAST(spec_json AS BLOB) AS spec_json_bytes,
                        CAST(effective_spec_json AS BLOB) AS effective_spec_json_bytes,
                        CAST(receipt_json AS BLOB) AS receipt_json_bytes
                 FROM jobs ORDER BY rowid ASC",
            )
            .fetch(&mut *conn);
            while let Some(row) = rows.try_next().await? {
                let rowid: i64 = row.try_get("storage_rowid")?;
                for (column, bytes) in [
                    ("job_id", row.try_get::<Vec<u8>, _>("job_id_bytes")?),
                    ("tenant", row.try_get::<Vec<u8>, _>("tenant_bytes")?),
                    ("language", row.try_get::<Vec<u8>, _>("language_bytes")?),
                    ("status", row.try_get::<Vec<u8>, _>("status_bytes")?),
                    ("spec_json", row.try_get::<Vec<u8>, _>("spec_json_bytes")?),
                ] {
                    validate_utf8_bytes("jobs", rowid, column, &bytes)?;
                }
                for (column, bytes) in [
                    (
                        "effective_spec_json",
                        row.try_get::<Option<Vec<u8>>, _>("effective_spec_json_bytes")?,
                    ),
                    (
                        "receipt_json",
                        row.try_get::<Option<Vec<u8>>, _>("receipt_json_bytes")?,
                    ),
                ] {
                    if let Some(bytes) = bytes {
                        validate_utf8_bytes("jobs", rowid, column, &bytes)?;
                    }
                }
            }
        }

        {
            let mut rows = sqlx::query(
                "SELECT seq,
                        CAST(job_id AS BLOB) AS job_id_bytes,
                        CAST(kind AS BLOB) AS kind_bytes,
                        CAST(data_json AS BLOB) AS data_json_bytes,
                        CAST(prev_hash AS BLOB) AS prev_hash_bytes,
                        CAST(event_hash AS BLOB) AS event_hash_bytes
                 FROM events ORDER BY seq ASC",
            )
            .fetch(&mut *conn);
            while let Some(row) = rows.try_next().await? {
                let seq: i64 = row.try_get("seq")?;
                for (column, bytes) in [
                    ("job_id", row.try_get::<Vec<u8>, _>("job_id_bytes")?),
                    ("kind", row.try_get::<Vec<u8>, _>("kind_bytes")?),
                    ("data_json", row.try_get::<Vec<u8>, _>("data_json_bytes")?),
                    ("prev_hash", row.try_get::<Vec<u8>, _>("prev_hash_bytes")?),
                    ("event_hash", row.try_get::<Vec<u8>, _>("event_hash_bytes")?),
                ] {
                    validate_utf8_bytes("events", seq, column, &bytes)?;
                }
            }
        }

        {
            let mut rows = sqlx::query(
                "SELECT rowid AS storage_rowid,
                        CAST(job_id AS BLOB) AS job_id_bytes,
                        CAST(receipt_sha256 AS BLOB) AS receipt_sha256_bytes,
                        CAST(result_media_type AS BLOB) AS result_media_type_bytes,
                        result_artifact,
                        CAST(result_sha256 AS BLOB) AS result_sha256_bytes,
                        envelope_json,
                        CAST(envelope_sha256 AS BLOB) AS envelope_sha256_bytes,
                        CAST(key_id AS BLOB) AS key_id_bytes
                 FROM job_attestations ORDER BY rowid ASC",
            )
            .fetch(&mut *conn);
            while let Some(row) = rows.try_next().await? {
                let rowid: i64 = row.try_get("storage_rowid")?;
                for (column, bytes) in [
                    ("job_id", row.try_get::<Vec<u8>, _>("job_id_bytes")?),
                    (
                        "receipt_sha256",
                        row.try_get::<Vec<u8>, _>("receipt_sha256_bytes")?,
                    ),
                    (
                        "result_media_type",
                        row.try_get::<Vec<u8>, _>("result_media_type_bytes")?,
                    ),
                    (
                        "result_artifact",
                        row.try_get::<Vec<u8>, _>("result_artifact")?,
                    ),
                    (
                        "result_sha256",
                        row.try_get::<Vec<u8>, _>("result_sha256_bytes")?,
                    ),
                    ("envelope_json", row.try_get::<Vec<u8>, _>("envelope_json")?),
                    (
                        "envelope_sha256",
                        row.try_get::<Vec<u8>, _>("envelope_sha256_bytes")?,
                    ),
                    ("key_id", row.try_get::<Vec<u8>, _>("key_id_bytes")?),
                ] {
                    validate_utf8_bytes("job_attestations", rowid, column, &bytes)?;
                }
            }
        }

        {
            let mut rows = sqlx::query(
                "SELECT rowid AS storage_rowid, CAST(job_id AS BLOB) AS job_id_bytes
                 FROM attestation_outbox ORDER BY rowid ASC",
            )
            .fetch(&mut *conn);
            while let Some(row) = rows.try_next().await? {
                validate_utf8_bytes(
                    "attestation_outbox",
                    row.try_get("storage_rowid")?,
                    "job_id",
                    &row.try_get::<Vec<u8>, _>("job_id_bytes")?,
                )?;
            }
        }
        Ok(())
    }

    async fn migrate_legacy_schema(conn: &mut SqliteConnection) -> StoreResult<()> {
        let has_events = table_exists(conn, "events").await?;
        let legacy_event_sequence = if has_events {
            validated_event_sequence_counter(conn, "events").await?
        } else {
            None
        };
        sqlx::query("ALTER TABLE jobs RENAME TO jobs_legacy_v1")
            .execute(&mut *conn)
            .await?;
        if has_events {
            sqlx::query("ALTER TABLE events RENAME TO events_legacy_v1")
                .execute(&mut *conn)
                .await?;
        }

        create_jobs_table(conn, "jobs").await?;
        create_events_table(conn, "events", "jobs").await?;

        let migration_time = now_ms();
        // Existing rows are preserved. Values which older schemas accepted
        // but the hardened schema cannot safely expose are quarantined or
        // normalized instead of being silently discarded.
        sqlx::query(
            "INSERT INTO jobs (
                job_id, tenant, language, status, spec_json,
                admitted_mem_mb, effective_spec_json, receipt_json, created_at_ms,
                started_at_ms, finished_at_ms, exit_code
             )
             SELECT
                job_id,
                CASE WHEN typeof(tenant) != 'text' OR trim(tenant) = ''
                     THEN '__legacy_invalid__:' || job_id ELSE tenant END,
                CASE WHEN typeof(language) != 'text' OR trim(language) = ''
                     THEN 'unknown' ELSE language END,
                CASE
                    WHEN status IN ('queued','running','succeeded','failed','timed_out','oom_killed','cancelled','error') THEN status
                    ELSE 'error'
                END,
                CASE WHEN typeof(spec_json) = 'text' AND json_valid(spec_json) THEN spec_json
                     ELSE json_object(
                         'legacy_invalid_spec_json',
                         CASE WHEN typeof(spec_json) = 'blob'
                              THEN 'blob:hex:' || hex(spec_json)
                              ELSE CAST(spec_json AS TEXT) END
                     ) END,
                CASE
                    WHEN typeof(spec_json) = 'text' AND json_valid(spec_json)
                         AND json_type(spec_json, '$.limits.mem_mb') = 'integer'
                    THEN MIN(MAX(CAST(json_extract(spec_json, '$.limits.mem_mb') AS INTEGER), 16), 4096)
                    ELSE 256
                END,
                NULL,
                NULL,
                CASE WHEN typeof(created_at_ms) = 'integer' AND created_at_ms >= 0
                     THEN created_at_ms ELSE 0 END,
                CASE
                    WHEN status = 'queued' THEN NULL
                    WHEN status = 'running' THEN
                        CASE
                            WHEN typeof(started_at_ms) = 'integer' AND started_at_ms >= 0
                                THEN started_at_ms
                            WHEN typeof(created_at_ms) = 'integer' AND created_at_ms >= 0
                                THEN created_at_ms
                            ELSE 0
                        END
                    WHEN started_at_ms IS NULL THEN NULL
                    WHEN typeof(started_at_ms) = 'integer' AND started_at_ms >= 0
                        THEN started_at_ms
                    ELSE NULL
                END,
                CASE
                    WHEN status IN ('queued','running') THEN NULL
                    WHEN typeof(finished_at_ms) = 'integer' AND finished_at_ms >= 0
                        THEN finished_at_ms
                    WHEN typeof(started_at_ms) = 'integer' AND started_at_ms >= 0
                        THEN started_at_ms
                    WHEN typeof(created_at_ms) = 'integer' AND created_at_ms >= 0
                        THEN created_at_ms
                    ELSE ?1
                END,
                CASE WHEN exit_code IS NULL OR
                               (typeof(exit_code) = 'integer' AND
                                exit_code BETWEEN -2147483648 AND 2147483647)
                     THEN exit_code ELSE NULL END
             FROM jobs_legacy_v1",
        )
        .bind(migration_time)
        .execute(&mut *conn)
        .await?;

        if has_events {
            let invalid_sequence_count: i64 = sqlx::query(
                "SELECT COUNT(*) AS n FROM events_legacy_v1
                 WHERE typeof(seq) != 'integer'
                    OR seq <= 0 OR seq >= 9223372036854775806",
            )
            .fetch_one(&mut *conn)
            .await?
            .try_get("n")?;
            if invalid_sequence_count != 0 {
                return Err(sqlx::Error::Protocol(format!(
                    "legacy database contains {invalid_sequence_count} non-positive event sequence values"
                )));
            }
            let orphan_count: i64 = sqlx::query(
                "SELECT COUNT(*) AS n
                 FROM events_legacy_v1 AS event
                 LEFT JOIN jobs AS job ON job.job_id = event.job_id
                 WHERE job.job_id IS NULL",
            )
            .fetch_one(&mut *conn)
            .await?
            .get("n");
            if orphan_count > 0 {
                return Err(sqlx::Error::Protocol(format!(
                    "legacy database contains {orphan_count} orphan event rows"
                )));
            }
            sqlx::query(
                "INSERT INTO events (
                    seq, job_id, ts_ms, kind, data_json,
                    prev_hash, event_hash, hash_version
                 )
                 SELECT
                    event.seq,
                    event.job_id,
                    CASE WHEN typeof(event.ts_ms) = 'integer' AND event.ts_ms >= 0
                         THEN event.ts_ms ELSE 0 END,
                    CASE WHEN typeof(event.kind) != 'text' OR trim(event.kind) = ''
                         THEN 'legacy_unknown' ELSE event.kind END,
                    CASE WHEN typeof(event.data_json) = 'text' AND json_valid(event.data_json)
                         THEN event.data_json
                         ELSE json_object(
                             'legacy_invalid_data_json',
                             CASE WHEN typeof(event.data_json) = 'blob'
                                  THEN 'blob:hex:' || hex(event.data_json)
                                  ELSE CAST(event.data_json AS TEXT) END
                         ) END,
                    '', '', 0
                 FROM events_legacy_v1 AS event
                 INNER JOIN jobs AS job ON job.job_id = event.job_id
                 ORDER BY event.seq ASC",
            )
            .execute(&mut *conn)
            .await?;
            if let Some(high_watermark) = legacy_event_sequence {
                raise_event_sequence_counter(conn, "events", high_watermark).await?;
            }
            sqlx::query("DROP TABLE events_legacy_v1")
                .execute(&mut *conn)
                .await?;
        }
        sqlx::query("DROP TABLE jobs_legacy_v1")
            .execute(&mut *conn)
            .await?;
        Self::create_indexes(conn, false).await
    }

    pub async fn schema_version(&self) -> StoreResult<i64> {
        let row = sqlx::query("SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get("version"))
    }

    /// Constant-work readiness probe for the exact schema this binary needs.
    /// Referencing both required data tables makes a missing/corrupt schema a
    /// failed probe without scanning tenant rows or maintaining probe data.
    pub async fn readiness_probe(&self) -> StoreResult<()> {
        let row = sqlx::query(
            "SELECT
                 COALESCE((SELECT MAX(version) FROM schema_migrations), 0) AS history_version,
                 (SELECT user_version FROM pragma_user_version) AS user_version,
                 EXISTS(SELECT 1 FROM jobs WHERE job_id = ?1) AS jobs_readable,
                 EXISTS(SELECT 1 FROM events WHERE job_id = ?1) AS events_readable",
        )
        .bind("__coop_readiness_schema_probe__")
        .fetch_one(&self.pool)
        .await?;
        let history_version: i64 = row.get("history_version");
        let user_version: i64 = row.get("user_version");
        // Read both values so SQLite must resolve and execute the required
        // table references even though the sentinel can never match a job ID.
        let _: i64 = row.get("jobs_readable");
        let _: i64 = row.get("events_readable");
        if history_version != CURRENT_SCHEMA_VERSION || user_version != CURRENT_SCHEMA_VERSION {
            return Err(sqlx::Error::Protocol(format!(
                "readiness schema mismatch: expected {CURRENT_SCHEMA_VERSION}, history={history_version}, user_version={user_version}"
            )));
        }
        Ok(())
    }

    /// Explicit, O(database-bytes) physical/value integrity check. Ordinary
    /// opens repeat this scan only when the durable validation revision or
    /// owned storage guards are absent/stale; callers can invoke this method
    /// during a maintenance window to detect offline byte-level corruption.
    pub async fn validate_integrity(&self) -> StoreResult<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::validate_current_schema(&mut tx).await?;
        Self::ensure_integrity_state(&mut tx).await?;
        let _ = Self::row_validation_current(&mut tx).await?;
        Self::validate_current_rows(&mut tx).await?;
        validate_foreign_keys(&mut tx).await?;
        Self::create_indexes(&mut tx, false).await?;
        Self::record_row_validation(&mut tx).await?;
        tx.commit().await
    }

    pub async fn create_job(
        &self,
        job_id: &str,
        tenant: &str,
        language: &str,
        spec_json: &str,
    ) -> StoreResult<()> {
        self.create_job_with_event(job_id, tenant, language, spec_json)
            .await
            .map(|_| ())
    }

    /// Atomically creates the queued row and the first, hashed `accepted`
    /// event. Callers that need to broadcast the event can use the returned
    /// row; the compatibility `create_job` wrapper deliberately discards it.
    pub async fn create_job_with_event(
        &self,
        job_id: &str,
        tenant: &str,
        language: &str,
        spec_json: &str,
    ) -> StoreResult<EventRow> {
        let requested_mem_mb = requested_mem_mb_from_json(spec_json)?;
        match self
            .create_job_with_event_idempotent(
                job_id,
                tenant,
                language,
                spec_json,
                requested_mem_mb,
                None,
            )
            .await?
        {
            CreateJobOutcome::Created(event) => Ok(event),
            CreateJobOutcome::Replayed { .. } => Err(sqlx::Error::Protocol(
                "non-idempotent job creation unexpectedly replayed".to_string(),
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_job_with_event_idempotent(
        &self,
        job_id: &str,
        tenant: &str,
        language: &str,
        spec_json: &str,
        requested_mem_mb: u32,
        idempotency: Option<&IdempotencyRequest>,
    ) -> StoreResult<CreateJobOutcome> {
        if job_id.trim().is_empty() || tenant.trim().is_empty() || language.trim().is_empty() {
            return Err(sqlx::Error::InvalidArgument(
                "job_id, tenant, and language must be non-empty".to_string(),
            ));
        }
        let requested_spec: Value = serde_json::from_str(spec_json)
            .map_err(|error| sqlx::Error::InvalidArgument(error.to_string()))?;
        let requested_spec_sha256 = sha256_hex(canonical_json(&requested_spec).as_bytes());
        let accepted_data = json!({
            "status": "queued",
            "tenant": tenant,
            "language": language,
            "requested_spec_sha256": requested_spec_sha256.clone(),
        });
        if !(16..=4096).contains(&requested_mem_mb) {
            return Err(sqlx::Error::InvalidArgument(
                "requested_mem_mb must be between 16 and 4096".to_string(),
            ));
        }
        if let Some(request) = idempotency {
            if request.key.is_empty()
                || request.key.len() > 128
                || !request
                    .key
                    .bytes()
                    .all(|byte| (0x21..=0x7e).contains(&byte))
                || request.request_sha256.len() != 64
                || !request
                    .request_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(sqlx::Error::InvalidArgument(
                    "invalid idempotency key or canonical request fingerprint".to_string(),
                ));
            }
            if request.request_sha256 != requested_spec_sha256 {
                return Err(sqlx::Error::InvalidArgument(
                    "idempotency fingerprint does not match canonical spec_json".to_string(),
                ));
            }
        }

        let idempotency_bytes = idempotency
            .map(|request| logical_idempotency_bytes(tenant, job_id, request))
            .unwrap_or(0);

        let initial_charge = logical_job_base_bytes(job_id, tenant, language, "queued", spec_json)
            .checked_add(JOB_COMPLETION_RESERVE_BYTES)
            .and_then(|value| {
                value.checked_add(
                    LOGICAL_ROW_OVERHEAD_BYTES
                        + job_id.len() as u64
                        + "accepted".len() as u64
                        + canonical_json(&accepted_data).len() as u64
                        + 64,
                )
            })
            .and_then(|value| value.checked_add(idempotency_bytes))
            .ok_or_else(|| sqlx::Error::Protocol("logical job charge overflowed".to_string()))?;
        let created_at = now_ms();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::begin_row_writes(&mut tx).await?;
        if let Some(idempotency) = idempotency {
            match lookup_idempotency_tx(&mut tx, tenant, idempotency).await? {
                IdempotencyLookup::Miss => {}
                IdempotencyLookup::Replay { job_id } => {
                    tx.rollback().await?;
                    return Ok(CreateJobOutcome::Replayed { job_id });
                }
                IdempotencyLookup::Conflict => {
                    tx.rollback().await?;
                    return Err(sqlx::Error::InvalidArgument(
                        IDEMPOTENCY_CONFLICT_MARKER.to_string(),
                    ));
                }
            }
        }
        ensure_filesystem_reserve_tx(
            &mut tx,
            &self.db_path,
            self.limits.free_reserve_bytes,
            initial_charge,
        )
        .await?;
        sqlx::query(
            "INSERT INTO jobs (
                job_id, tenant, language, status, spec_json,
                admitted_mem_mb, created_at_ms
             ) VALUES (?1, ?2, ?3, 'queued', ?4, ?5, ?6)",
        )
        .bind(job_id)
        .bind(tenant)
        .bind(language)
        .bind(spec_json)
        .bind(i64::from(requested_mem_mb))
        .bind(created_at)
        .execute(&mut *tx)
        .await?;
        let event =
            append_event_tx(&mut tx, job_id, "accepted", &accepted_data, created_at).await?;
        let retained_bytes = logical_job_base_bytes(job_id, tenant, language, "queued", spec_json)
            .checked_add(logical_event_bytes(&event))
            .and_then(|value| value.checked_add(idempotency_bytes))
            .ok_or_else(|| {
                sqlx::Error::Protocol("logical retained bytes overflowed".to_string())
            })?;
        let charged_bytes = retained_bytes
            .checked_add(JOB_COMPLETION_RESERVE_BYTES)
            .ok_or_else(|| sqlx::Error::Protocol("logical job charge overflowed".to_string()))?;
        ensure_storage_quota_tx(&mut tx, tenant, charged_bytes, self.limits).await?;
        sqlx::query(
            "INSERT INTO job_storage_usage(
                 job_id, tenant, retained_bytes, reserved_bytes, requested_mem_mb
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(job_id)
        .bind(tenant)
        .bind(to_i64_bytes(retained_bytes)?)
        .bind(JOB_COMPLETION_RESERVE_BYTES as i64)
        .bind(i64::from(requested_mem_mb))
        .execute(&mut *tx)
        .await?;
        if let Some(idempotency) = idempotency {
            sqlx::query(
                "INSERT INTO idempotency_keys(
                     tenant, idempotency_key, request_sha256, job_id, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(tenant)
            .bind(&idempotency.key)
            .bind(&idempotency.request_sha256)
            .bind(job_id)
            .bind(created_at)
            .execute(&mut *tx)
            .await?;
        }
        Self::mark_row_writes_validated(&mut tx).await?;
        tx.commit().await?;
        Ok(CreateJobOutcome::Created(event))
    }

    pub async fn lookup_idempotency(
        &self,
        tenant: &str,
        request: &IdempotencyRequest,
    ) -> StoreResult<IdempotencyLookup> {
        let mut tx = self.pool.begin().await?;
        let lookup = lookup_idempotency_tx(&mut tx, tenant, request).await?;
        tx.commit().await?;
        Ok(lookup)
    }

    /// Compatibility transition which does not append a `started` event.
    /// New scheduler code should prefer `start_with_event_if_queued` so the
    /// transition, effective spec, and evidence event commit atomically.
    pub async fn set_started_if_queued(&self, job_id: &str) -> StoreResult<bool> {
        self.set_started_inner(job_id, None).await
    }

    /// Persist the effective (post-policy/clamping) spec with the guarded
    /// queued-to-running transition. This compatibility form omits the event;
    /// `start_with_event_if_queued` is preferred for new code.
    pub async fn set_started_with_effective_if_queued(
        &self,
        job_id: &str,
        effective_spec: &Value,
    ) -> StoreResult<bool> {
        self.set_started_inner(job_id, Some(effective_spec)).await
    }

    async fn set_started_inner(
        &self,
        job_id: &str,
        effective_spec: Option<&Value>,
    ) -> StoreResult<bool> {
        let effective_json = effective_spec.map(canonical_json);
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::begin_row_writes(&mut tx).await?;
        let result = sqlx::query(
            "UPDATE jobs
             SET status = 'running', started_at_ms = ?2,
                 effective_spec_json = COALESCE(?3, effective_spec_json)
             WHERE job_id = ?1 AND status = 'queued'",
        )
        .bind(job_id)
        .bind(now_ms())
        .bind(effective_json)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }
        reconcile_job_storage_tx(&mut tx, job_id, false, &self.db_path, self.limits).await?;
        Self::mark_row_writes_validated(&mut tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Preferred guarded start: commits row state, effective spec, and the
    /// hashed `started` event as one transaction.
    pub async fn start_with_event_if_queued(
        &self,
        job_id: &str,
        effective_spec: &Value,
    ) -> StoreResult<Option<EventRow>> {
        let started_at = now_ms();
        let effective_json = canonical_json(effective_spec);
        let initial_effective_spec_sha256 = sha256_hex(effective_json.as_bytes());
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::begin_row_writes(&mut tx).await?;
        let result = sqlx::query(
            "UPDATE jobs
             SET status = 'running', started_at_ms = ?2, effective_spec_json = ?3
             WHERE job_id = ?1 AND status = 'queued'",
        )
        .bind(job_id)
        .bind(started_at)
        .bind(&effective_json)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(None);
        }

        let event = append_event_tx(
            &mut tx,
            job_id,
            "started",
            &json!({
                "status": "running",
                "initial_effective_spec_sha256": initial_effective_spec_sha256,
            }),
            started_at,
        )
        .await?;
        reconcile_job_storage_tx(&mut tx, job_id, false, &self.db_path, self.limits).await?;
        Self::mark_row_writes_validated(&mut tx).await?;
        tx.commit().await?;
        Ok(Some(event))
    }

    /// Compatibility terminal write. New code should pass a receipt and
    /// broadcast the event returned by `finalize_with_event`.
    pub async fn finish(
        &self,
        job_id: &str,
        status: &str,
        exit_code: Option<i32>,
    ) -> StoreResult<()> {
        self.finalize_with_event(job_id, status, exit_code, 0, None)
            .await
            .map(|_| ())
    }

    /// Finalize a queued or running job exactly once. The terminal row state,
    /// final hashed event, receipt JSON, and the receipt's chain head/count
    /// are committed atomically. `None` means the row was absent or already
    /// terminal.
    pub async fn finalize_with_event(
        &self,
        job_id: &str,
        status: &str,
        exit_code: Option<i32>,
        duration_ms: i64,
        receipt: Option<&Value>,
    ) -> StoreResult<Option<EventRow>> {
        self.finalize_with_event_and_effective_spec(
            job_id,
            status,
            exit_code,
            duration_ms,
            None,
            receipt,
        )
        .await
    }

    /// Finalize a job and, when supplied, atomically replace the initial
    /// effective-spec snapshot with controls observed by the executor. The
    /// terminal event binds that final canonical spec by SHA-256.
    pub async fn finalize_with_event_and_effective_spec(
        &self,
        job_id: &str,
        status: &str,
        exit_code: Option<i32>,
        duration_ms: i64,
        effective_spec: Option<&Value>,
        receipt: Option<&Value>,
    ) -> StoreResult<Option<EventRow>> {
        if !is_terminal_status(status) {
            return Err(sqlx::Error::InvalidArgument(format!(
                "cannot finalize a job with non-terminal status {status:?}"
            )));
        }
        self.finalize_inner(
            job_id,
            None,
            None,
            status,
            exit_code,
            duration_ms,
            effective_spec,
            receipt,
        )
        .await
    }

    /// Atomically cancel a job only if it is still queued and belongs to the
    /// supplied tenant. Blank tenants are rejected, never interpreted as a
    /// cross-tenant wildcard.
    pub async fn cancel_queued_with_event(
        &self,
        job_id: &str,
        tenant: &str,
        receipt: Option<&Value>,
    ) -> StoreResult<Option<EventRow>> {
        if tenant.trim().is_empty() {
            return Err(sqlx::Error::InvalidArgument(
                "tenant must be non-empty".to_string(),
            ));
        }
        self.finalize_inner(
            job_id,
            Some(tenant),
            Some("queued"),
            "cancelled",
            None,
            0,
            None,
            receipt,
        )
        .await
    }

    /// Compatibility wrapper for callers without a tenant in hand. It still
    /// emits the terminal event atomically, but API paths should use the
    /// tenant-scoped method above.
    pub async fn cancel_if_queued(&self, job_id: &str) -> StoreResult<bool> {
        self.finalize_inner(
            job_id,
            None,
            Some("queued"),
            "cancelled",
            None,
            0,
            None,
            None,
        )
        .await
        .map(|event| event.is_some())
    }

    #[allow(clippy::too_many_arguments)]
    async fn finalize_inner(
        &self,
        job_id: &str,
        tenant: Option<&str>,
        required_status: Option<&str>,
        status: &str,
        exit_code: Option<i32>,
        duration_ms: i64,
        effective_spec: Option<&Value>,
        receipt: Option<&Value>,
    ) -> StoreResult<Option<EventRow>> {
        let effective_json = effective_spec.map(canonical_json);
        let effective_spec_sha256 = effective_json
            .as_deref()
            .map(|value| sha256_hex(value.as_bytes()));
        let finished_at = now_ms();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::begin_row_writes(&mut tx).await?;

        let result = sqlx::query(
            "UPDATE jobs
             SET status = ?2, exit_code = ?3, finished_at_ms = ?4,
                 effective_spec_json = COALESCE(?7, effective_spec_json)
             WHERE job_id = ?1
               AND status IN ('queued','running')
               AND (?5 IS NULL OR tenant = ?5)
               AND (?6 IS NULL OR status = ?6)",
        )
        .bind(job_id)
        .bind(status)
        .bind(exit_code)
        .bind(finished_at)
        .bind(tenant)
        .bind(required_status)
        .bind(effective_json.as_deref())
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(None);
        }

        let lifecycle =
            sqlx::query("SELECT created_at_ms, started_at_ms FROM jobs WHERE job_id = ?1")
                .bind(job_id)
                .fetch_one(&mut *tx)
                .await?;
        let created_at_ms: i64 = lifecycle.get("created_at_ms");
        let started_at_ms: Option<i64> = lifecycle.get("started_at_ms");

        let mut finished_data = json!({
            "status": status,
            "exit_code": exit_code,
            "duration_ms": duration_ms.max(0),
        });
        if let Some(digest) = effective_spec_sha256 {
            finished_data
                .as_object_mut()
                .expect("finished event data is an object")
                .insert("effective_spec_sha256".to_string(), json!(digest));
        }
        let event =
            append_event_tx(&mut tx, job_id, "finished", &finished_data, finished_at).await?;
        let chain = event_chain_head_tx(&mut tx, job_id).await?;
        let receipt_json = receipt_with_chain(
            receipt,
            &chain,
            ReceiptCore {
                job_id,
                status,
                exit_code,
                created_at_ms,
                started_at_ms,
                finished_at_ms: finished_at,
                duration_ms: duration_ms.max(0),
            },
        );
        sqlx::query("UPDATE jobs SET receipt_json = ?2 WHERE job_id = ?1")
            .bind(job_id)
            .bind(receipt_json)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT OR IGNORE INTO attestation_outbox(
                 job_id, pending_since_ms, attempt_count, next_attempt_ms
             ) VALUES (?1, ?2, 0, ?2)",
        )
        .bind(job_id)
        .bind(finished_at)
        .execute(&mut *tx)
        .await?;
        reconcile_job_storage_tx(&mut tx, job_id, true, &self.db_path, self.limits).await?;
        Self::mark_row_writes_validated(&mut tx).await?;
        tx.commit().await?;
        Ok(Some(event))
    }

    pub async fn append_event(
        &self,
        job_id: &str,
        kind: &str,
        data: &Value,
    ) -> StoreResult<(i64, i64)> {
        self.append_event_row(job_id, kind, data)
            .await
            .map(|event| (event.seq, event.ts_ms))
    }

    pub async fn append_event_row(
        &self,
        job_id: &str,
        kind: &str,
        data: &Value,
    ) -> StoreResult<EventRow> {
        let pending = [(kind.to_string(), data.clone())];
        let mut appended = self.append_events_batch(job_id, &pending).await?;
        appended.pop().ok_or_else(|| {
            sqlx::Error::Protocol("single-event append returned no event".to_string())
        })
    }

    /// Append a bounded ordered batch using one SQLite transaction and one
    /// durable commit. Every returned row corresponds to the same-position
    /// input, and each hash links to the event immediately before it (whether
    /// that event predated this batch or was inserted earlier in the batch).
    ///
    /// An empty slice is a no-op. Oversized batches and invalid kinds fail
    /// before any transaction is opened. A database error at any position
    /// rolls back the complete batch.
    pub async fn append_events_batch(
        &self,
        job_id: &str,
        events: &[(String, Value)],
    ) -> StoreResult<Vec<EventRow>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        if events.len() > MAX_EVENT_BATCH_SIZE {
            return Err(sqlx::Error::InvalidArgument(format!(
                "event batch contains {} entries; maximum is {MAX_EVENT_BATCH_SIZE}",
                events.len()
            )));
        }
        if events.iter().any(|(kind, _)| kind.trim().is_empty()) {
            return Err(sqlx::Error::InvalidArgument(
                "event kind must be non-empty".to_string(),
            ));
        }

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::begin_row_writes(&mut tx).await?;
        let job = sqlx::query(
            "SELECT status FROM jobs
             WHERE job_id = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )",
        )
        .bind(job_id)
        .fetch_optional(&mut *tx)
        .await?;
        match job
            .map(|row| row.try_get::<String, _>("status"))
            .transpose()?
        {
            Some(status) if matches!(status.as_str(), "queued" | "running") => {}
            Some(_) => {
                tx.rollback().await?;
                return Err(sqlx::Error::InvalidArgument(
                    "cannot append an event after terminal finalization".to_string(),
                ));
            }
            None => {
                tx.rollback().await?;
                return Err(sqlx::Error::RowNotFound);
            }
        }

        let mut prev_hash = previous_event_hash_tx(&mut tx, job_id).await?;
        let batch_ts = now_ms();
        let mut appended = Vec::with_capacity(events.len());
        for (kind, data) in events {
            let event =
                match insert_hashed_event_tx(&mut tx, job_id, kind, data, batch_ts, &prev_hash)
                    .await
                {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = tx.rollback().await;
                        return Err(error);
                    }
                };
            prev_hash.clone_from(&event.event_hash);
            appended.push(event);
        }
        reconcile_job_storage_tx(&mut tx, job_id, false, &self.db_path, self.limits).await?;
        Self::mark_row_writes_validated(&mut tx).await?;
        tx.commit().await?;
        Ok(appended)
    }

    pub async fn last_seq(&self, job_id: &str) -> StoreResult<i64> {
        let row = sqlx::query(
            "SELECT COALESCE(MAX(seq), 0) AS max_seq FROM events
                 WHERE job_id = ?1
                   AND NOT EXISTS (
                       SELECT 1 FROM retention_tombstones
                       WHERE retention_tombstones.job_id = events.job_id
                   )",
        )
        .bind(job_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get("max_seq"))
    }

    pub async fn events_for(&self, job_id: &str) -> StoreResult<Vec<EventRow>> {
        let rows = sqlx::query(
            "SELECT seq, ts_ms, kind, data_json, prev_hash, event_hash, hash_version
             FROM events
             WHERE job_id = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = events.job_id
               )
             ORDER BY seq ASC",
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_event).collect()
    }

    /// Cursor page for replay and streaming catch-up. The cursor is exclusive
    /// and global event sequence numbers remain stable across retention.
    pub async fn events_after(
        &self,
        job_id: &str,
        after_seq: i64,
        limit: i64,
    ) -> StoreResult<Vec<EventRow>> {
        let rows = sqlx::query(
            "SELECT seq, ts_ms, kind, data_json, prev_hash, event_hash, hash_version
             FROM events
             WHERE job_id = ?1 AND seq > ?2
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = events.job_id
               )
             ORDER BY seq ASC
             LIMIT ?3",
        )
        .bind(job_id)
        .bind(after_seq.max(0))
        .bind(limit.clamp(1, MAX_EVENT_PAGE))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_event).collect()
    }

    pub async fn event_chain_head(&self, job_id: &str) -> StoreResult<EventChainHead> {
        let mut tx = self.pool.begin().await?;
        let head = event_chain_head_tx(&mut tx, job_id).await?;
        tx.commit().await?;
        Ok(head)
    }

    /// Recomputes every v1 digest and link. Legacy rows are reported, not
    /// treated as verified; a verified suffix after legacy history is valid
    /// only when it starts a new chain with an empty `prev_hash`.
    pub async fn verify_event_chain(&self, job_id: &str) -> StoreResult<EventChainVerification> {
        let events = self.events_for(job_id).await?;
        let mut valid = true;
        let mut expected_prev = String::new();
        let mut previous_was_legacy = false;
        let mut verified = 0_i64;
        let mut legacy = 0_i64;

        for event in &events {
            match event.hash_version {
                0 => {
                    legacy += 1;
                    expected_prev.clear();
                    previous_was_legacy = true;
                }
                1 => {
                    verified += 1;
                    if (previous_was_legacy && !event.prev_hash.is_empty())
                        || (!previous_was_legacy && event.prev_hash != expected_prev)
                        || event.event_hash
                            != compute_event_hash(
                                job_id,
                                &event.prev_hash,
                                event.seq,
                                event.ts_ms,
                                &event.kind,
                                &event.data,
                            )
                    {
                        valid = false;
                    }
                    expected_prev.clone_from(&event.event_hash);
                    previous_was_legacy = false;
                }
                _ => valid = false,
            }
        }

        let head = EventChainHead {
            event_count: events.len() as i64,
            verified_event_count: verified,
            legacy_event_count: legacy,
            head_hash: events
                .last()
                .filter(|event| event.hash_version == 1)
                .map(|event| event.event_hash.clone()),
        };
        Ok(EventChainVerification { head, valid })
    }

    /// Oldest durable attestation work first. The outbox row is committed in
    /// the terminal transaction, while signing and the immutable result row
    /// intentionally happen later and can be retried after any crash.
    pub async fn pending_attestation_job_ids(&self, limit: i64) -> StoreResult<Vec<String>> {
        let rows = sqlx::query(
            "SELECT attestation_outbox.job_id
             FROM attestation_outbox
             INNER JOIN jobs ON jobs.job_id = attestation_outbox.job_id
             WHERE jobs.status IN ('succeeded','failed','timed_out','oom_killed','cancelled','error')
               AND jobs.receipt_json IS NOT NULL
               AND attestation_outbox.next_attempt_ms <= ?2
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )
             ORDER BY attestation_outbox.next_attempt_ms ASC,
                      attestation_outbox.pending_since_ms ASC,
                      attestation_outbox.job_id ASC
             LIMIT ?1",
        )
        .bind(limit.clamp(1, 256))
        .bind(now_ms())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|row| row.try_get("job_id")).collect()
    }

    pub async fn attestation_source(
        &self,
        job_id: &str,
    ) -> StoreResult<Option<AttestationSourceJob>> {
        let row = sqlx::query(
            "SELECT jobs.job_id, jobs.tenant, jobs.status, jobs.created_at_ms,
                    jobs.started_at_ms, jobs.finished_at_ms, jobs.exit_code,
                    jobs.receipt_json
             FROM jobs
             INNER JOIN attestation_outbox ON attestation_outbox.job_id = jobs.job_id
             WHERE jobs.job_id = ?1
               AND jobs.status IN ('succeeded','failed','timed_out','oom_killed','cancelled','error')
               AND jobs.receipt_json IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )",
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let exit_code = row
                .try_get::<Option<i64>, _>("exit_code")?
                .map(i32::try_from)
                .transpose()
                .map_err(|_| {
                    sqlx::Error::Protocol("exit_code is outside the i32 range".to_string())
                })?;
            Ok(AttestationSourceJob {
                job_id: row.try_get("job_id")?,
                tenant: row.try_get("tenant")?,
                status: row.try_get("status")?,
                created_at_ms: row.try_get("created_at_ms")?,
                started_at_ms: row.try_get("started_at_ms")?,
                finished_at_ms: row.try_get("finished_at_ms")?,
                exit_code,
                receipt_json: row.try_get("receipt_json")?,
            })
        })
        .transpose()
    }

    /// Persist exact result and DSSE bytes iff the terminal receipt is still
    /// byte-for-byte identical to the one that was signed and both portable
    /// files structurally bind the authoritative job tenant. An existing
    /// exact row is an idempotent replay; any differing row fails closed.
    #[allow(clippy::too_many_arguments)]
    pub async fn persist_attestation(
        &self,
        job_id: &str,
        expected_receipt_json: &str,
        receipt_sha256: &str,
        result_media_type: &str,
        result_artifact: &[u8],
        result_sha256: &str,
        envelope_json: &[u8],
        envelope_sha256: &str,
        key_id: &str,
    ) -> StoreResult<PersistAttestationOutcome> {
        if job_id.trim().is_empty()
            || result_media_type.trim().is_empty()
            || result_media_type.len() > 255
            || key_id.trim().is_empty()
            || key_id.len() > 256
            || result_artifact.is_empty()
            || result_artifact.len() > MAX_RESULT_ARTIFACT_BYTES
            || envelope_json.is_empty()
            || envelope_json.len() > MAX_ATTESTATION_ENVELOPE_BYTES
            || !is_lower_sha256(receipt_sha256)
            || !is_lower_sha256(result_sha256)
            || !is_lower_sha256(envelope_sha256)
        {
            return Err(sqlx::Error::InvalidArgument(
                "attestation fields exceed the strict v4 storage profile".to_string(),
            ));
        }
        let receipt: Value = serde_json::from_str(expected_receipt_json)
            .map_err(|error| sqlx::Error::InvalidArgument(error.to_string()))?;
        if !receipt.is_object()
            || compute_receipt_sha256(&receipt) != receipt_sha256
            || receipt.get("receipt_sha256").and_then(Value::as_str) != Some(receipt_sha256)
            || sha256_hex(result_artifact) != result_sha256
            || sha256_hex(envelope_json) != envelope_sha256
        {
            return Err(sqlx::Error::InvalidArgument(
                "attestation digests do not match their exact bytes".to_string(),
            ));
        }
        let envelope: Value = serde_json::from_slice(envelope_json)
            .map_err(|error| sqlx::Error::InvalidArgument(error.to_string()))?;
        if !envelope.is_object() {
            return Err(sqlx::Error::InvalidArgument(
                "DSSE envelope must be a JSON object".to_string(),
            ));
        }

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::begin_row_writes(&mut tx).await?;
        let current = sqlx::query(
            "SELECT tenant, status, receipt_json FROM jobs
             WHERE job_id = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )",
        )
        .bind(job_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(current) = current else {
            tx.rollback().await?;
            return Ok(PersistAttestationOutcome::StaleReceipt);
        };
        let tenant: String = current.try_get("tenant")?;
        let status: String = current.try_get("status")?;
        let current_receipt: Option<String> = current.try_get("receipt_json")?;
        if !is_terminal_status(&status) || current_receipt.as_deref() != Some(expected_receipt_json)
        {
            tx.rollback().await?;
            return Ok(PersistAttestationOutcome::StaleReceipt);
        }

        if let Some(existing) = sqlx::query(
            "SELECT receipt_sha256, result_media_type, result_artifact,
                    result_sha256, envelope_json, envelope_sha256, key_id
             FROM job_attestations WHERE job_id = ?1",
        )
        .bind(job_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            let exact = existing.try_get::<String, _>("receipt_sha256")? == receipt_sha256
                && existing.try_get::<String, _>("result_media_type")? == result_media_type
                && existing.try_get::<Vec<u8>, _>("result_artifact")? == result_artifact
                && existing.try_get::<String, _>("result_sha256")? == result_sha256
                && existing.try_get::<Vec<u8>, _>("envelope_json")? == envelope_json
                && existing.try_get::<String, _>("envelope_sha256")? == envelope_sha256
                && existing.try_get::<String, _>("key_id")? == key_id;
            if !exact {
                tx.rollback().await?;
                return Err(sqlx::Error::Protocol(
                    "immutable job attestation already exists with different bytes".to_string(),
                ));
            }
            if !portable_attestation_binding_matches(
                job_id,
                &tenant,
                receipt_sha256,
                result_media_type,
                result_artifact,
                result_sha256,
                envelope_json,
            ) {
                tx.rollback().await?;
                return Err(sqlx::Error::Protocol(
                    "stored job attestation is not bound to its authoritative tenant".to_string(),
                ));
            }
            sqlx::query("DELETE FROM attestation_outbox WHERE job_id = ?1")
                .bind(job_id)
                .execute(&mut *tx)
                .await?;
            reconcile_job_storage_tx(&mut tx, job_id, true, &self.db_path, self.limits).await?;
            Self::mark_row_writes_validated(&mut tx).await?;
            tx.commit().await?;
            return Ok(PersistAttestationOutcome::Existing);
        }

        if !portable_attestation_binding_matches(
            job_id,
            &tenant,
            receipt_sha256,
            result_media_type,
            result_artifact,
            result_sha256,
            envelope_json,
        ) {
            tx.rollback().await?;
            return Err(sqlx::Error::InvalidArgument(
                "attestation bytes do not bind the authoritative job tenant".to_string(),
            ));
        }

        sqlx::query(
            "INSERT INTO job_attestations(
                 job_id, receipt_sha256, result_media_type, result_artifact,
                 result_sha256, envelope_json, envelope_sha256, key_id, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(job_id)
        .bind(receipt_sha256)
        .bind(result_media_type)
        .bind(result_artifact)
        .bind(result_sha256)
        .bind(envelope_json)
        .bind(envelope_sha256)
        .bind(key_id)
        .bind(now_ms())
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM attestation_outbox WHERE job_id = ?1")
            .bind(job_id)
            .execute(&mut *tx)
            .await?;
        reconcile_job_storage_tx(&mut tx, job_id, true, &self.db_path, self.limits).await?;
        Self::mark_row_writes_validated(&mut tx).await?;
        tx.commit().await?;
        Ok(PersistAttestationOutcome::Created)
    }

    /// Resolve one outbox item under an explicit server-wide off policy. The
    /// terminal row remains discoverable and will be re-seeded on a later
    /// startup if signing is enabled then.
    pub async fn waive_pending_attestation(&self, job_id: &str) -> StoreResult<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::begin_row_writes(&mut tx).await?;
        let deleted = sqlx::query("DELETE FROM attestation_outbox WHERE job_id = ?1")
            .bind(job_id)
            .execute(&mut *tx)
            .await?;
        if deleted.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }
        reconcile_job_storage_tx(&mut tx, job_id, true, &self.db_path, self.limits).await?;
        Self::mark_row_writes_validated(&mut tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Move a failed item behind currently eligible work and persist a short
    /// retry delay. A poison item therefore cannot starve every later
    /// terminal job in the bounded outbox page.
    pub async fn defer_pending_attestation(
        &self,
        job_id: &str,
        delay_ms: u64,
    ) -> StoreResult<bool> {
        let delay_ms = i64::try_from(delay_ms.clamp(100, 60_000)).unwrap_or(60_000);
        let next_attempt_ms = now_ms().saturating_add(delay_ms);
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::begin_row_writes(&mut tx).await?;
        let updated = sqlx::query(
            "UPDATE attestation_outbox
             SET attempt_count = MIN(attempt_count + 1, 2147483647),
                 next_attempt_ms = ?2
             WHERE job_id = ?1",
        )
        .bind(job_id)
        .bind(next_attempt_ms)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }
        Self::mark_row_writes_validated(&mut tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn attestation_metadata(
        &self,
        job_id: &str,
    ) -> StoreResult<Option<AttestationMetadata>> {
        let row = sqlx::query(
            "SELECT job_attestations.job_id, job_attestations.receipt_sha256,
                    job_attestations.result_media_type,
                    job_attestations.result_sha256,
                    length(job_attestations.result_artifact) AS result_size_bytes,
                    job_attestations.envelope_sha256,
                    length(job_attestations.envelope_json) AS envelope_size_bytes,
                    job_attestations.key_id, job_attestations.created_at_ms
             FROM job_attestations
             INNER JOIN jobs ON jobs.job_id = job_attestations.job_id
             WHERE job_attestations.job_id = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )",
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| row_to_attestation_metadata(&row)).transpose()
    }

    pub async fn get_attestation(&self, job_id: &str) -> StoreResult<Option<StoredAttestation>> {
        let row = sqlx::query(
            "SELECT job_attestations.job_id, job_attestations.receipt_sha256,
                    job_attestations.result_media_type,
                    job_attestations.result_sha256,
                    length(job_attestations.result_artifact) AS result_size_bytes,
                    job_attestations.envelope_sha256,
                    length(job_attestations.envelope_json) AS envelope_size_bytes,
                    job_attestations.key_id, job_attestations.created_at_ms,
                    job_attestations.result_artifact, job_attestations.envelope_json
             FROM job_attestations
             INNER JOIN jobs ON jobs.job_id = job_attestations.job_id
             WHERE job_attestations.job_id = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )",
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let metadata = row_to_attestation_metadata(&row)?;
            Ok(StoredAttestation {
                metadata,
                result_artifact: row.try_get("result_artifact")?,
                envelope_json: row.try_get("envelope_json")?,
            })
        })
        .transpose()
    }

    pub async fn attestation_envelope(
        &self,
        job_id: &str,
    ) -> StoreResult<Option<(AttestationMetadata, Vec<u8>)>> {
        let row = sqlx::query(
            "SELECT job_attestations.job_id, job_attestations.receipt_sha256,
                    job_attestations.result_media_type,
                    job_attestations.result_sha256,
                    length(job_attestations.result_artifact) AS result_size_bytes,
                    job_attestations.envelope_sha256,
                    length(job_attestations.envelope_json) AS envelope_size_bytes,
                    job_attestations.key_id, job_attestations.created_at_ms,
                    job_attestations.envelope_json
             FROM job_attestations
             INNER JOIN jobs ON jobs.job_id = job_attestations.job_id
             WHERE job_attestations.job_id = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )",
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let metadata = row_to_attestation_metadata(&row)?;
            Ok((metadata, row.try_get("envelope_json")?))
        })
        .transpose()
    }

    pub async fn attestation_result_artifact(
        &self,
        job_id: &str,
    ) -> StoreResult<Option<(AttestationMetadata, Vec<u8>)>> {
        let row = sqlx::query(
            "SELECT job_attestations.job_id, job_attestations.receipt_sha256,
                    job_attestations.result_media_type,
                    job_attestations.result_sha256,
                    length(job_attestations.result_artifact) AS result_size_bytes,
                    job_attestations.envelope_sha256,
                    length(job_attestations.envelope_json) AS envelope_size_bytes,
                    job_attestations.key_id, job_attestations.created_at_ms,
                    job_attestations.result_artifact
             FROM job_attestations
             INNER JOIN jobs ON jobs.job_id = job_attestations.job_id
             WHERE job_attestations.job_id = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )",
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let metadata = row_to_attestation_metadata(&row)?;
            Ok((metadata, row.try_get("result_artifact")?))
        })
        .transpose()
    }

    pub async fn get_job(&self, job_id: &str) -> StoreResult<Option<JobRow>> {
        let row = sqlx::query(
            "SELECT job_id, tenant, language, status, spec_json,
                    effective_spec_json, receipt_json, created_at_ms,
                    started_at_ms, finished_at_ms, exit_code
             FROM jobs
             WHERE job_id = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )",
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(Self::row_to_job).transpose()
    }

    /// Point lookup for status/ownership and other lifecycle-only paths. This
    /// intentionally avoids decoding the potentially multi-megabyte spec and
    /// receipt columns selected by `get_job`.
    pub async fn get_job_summary(&self, job_id: &str) -> StoreResult<Option<JobSummary>> {
        let row = sqlx::query(
            "SELECT job_id, tenant, language, status, created_at_ms,
                    started_at_ms, finished_at_ms, exit_code
             FROM jobs INDEXED BY idx_jobs_id_summary
             WHERE job_id = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )",
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(Self::row_to_job_summary).transpose()
    }

    pub async fn job_requested_mem_mb(&self, job_id: &str) -> StoreResult<Option<u32>> {
        let value =
            sqlx::query_scalar::<_, i64>("SELECT admitted_mem_mb FROM jobs WHERE job_id = ?1")
                .bind(job_id)
                .fetch_optional(&self.pool)
                .await?;
        value
            .map(|value| {
                u32::try_from(value).map_err(|_| {
                    sqlx::Error::Protocol(
                        "stored requested_mem_mb is outside the u32 range".to_string(),
                    )
                })
            })
            .transpose()
    }

    pub async fn list_jobs(&self, tenant: Option<&str>, limit: i64) -> StoreResult<Vec<JobRow>> {
        self.list_jobs_page(ListJobsQuery {
            tenant: tenant.map(ToOwned::to_owned),
            limit: limit.clamp(1, MAX_JOB_PAGE),
            ..ListJobsQuery::default()
        })
        .await
    }

    /// Stable keyset pagination over `(created_at_ms, job_id)` with optional
    /// strict filters. This deliberately avoids offset pagination, whose
    /// pages shift as new jobs arrive.
    pub async fn list_jobs_page(&self, query: ListJobsQuery) -> StoreResult<Vec<JobRow>> {
        if query.tenant.as_deref().is_some_and(str::is_empty) {
            return Ok(Vec::new());
        }
        // Only active predicates are emitted. Optional `? IS NULL OR ...`
        // clauses prevent SQLite from using the tenant/keyset indexes and
        // turn every authenticated page into a full-table scan and temp sort.
        let mut statement = build_job_list_query("", JOB_ROW_PROJECTION, &query);
        let rows = statement.build().fetch_all(&self.pool).await?;
        rows.into_iter().map(Self::row_to_job).collect()
    }

    /// Stable keyset pagination for list surfaces without loading the large
    /// spec and receipt columns. Like `list_jobs_page`, this accepts one row
    /// beyond the public page maximum so callers can determine `has_more`.
    pub async fn list_job_summaries_page(
        &self,
        query: ListJobsQuery,
    ) -> StoreResult<Vec<JobSummary>> {
        if query.tenant.as_deref().is_some_and(str::is_empty) {
            return Ok(Vec::new());
        }
        let mut statement = build_job_list_query("", JOB_SUMMARY_PROJECTION, &query);
        let rows = statement.build().fetch_all(&self.pool).await?;
        rows.into_iter().map(Self::row_to_job_summary).collect()
    }

    pub async fn count_by_status(&self) -> StoreResult<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT status, COUNT(*) AS n FROM jobs
             WHERE NOT EXISTS (
                 SELECT 1 FROM retention_tombstones
                 WHERE retention_tombstones.job_id = jobs.job_id
             )
             GROUP BY status ORDER BY status",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| Ok((row.try_get("status")?, row.try_get("n")?)))
            .collect()
    }

    pub async fn count_by_status_for_tenant(
        &self,
        tenant: &str,
    ) -> StoreResult<Vec<(String, i64)>> {
        if tenant.trim().is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(
            "SELECT status, COUNT(*) AS n
             FROM jobs WHERE tenant = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )
             GROUP BY status ORDER BY status",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| Ok((row.try_get("status")?, row.try_get("n")?)))
            .collect()
    }

    /// Return persisted queued jobs oldest first so startup recovery can
    /// re-enqueue accepted work rather than incorrectly failing it.
    pub async fn queued_job_ids(&self, limit: i64) -> StoreResult<Vec<String>> {
        let rows = sqlx::query(
            "SELECT job_id FROM jobs
             WHERE status = 'queued'
               AND NOT EXISTS (
                   SELECT 1 FROM retention_tombstones
                   WHERE retention_tombstones.job_id = jobs.job_id
               )
             ORDER BY created_at_ms ASC, job_id ASC
             LIMIT ?1",
        )
        .bind(limit.clamp(1, 100_000))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|row| row.try_get("job_id")).collect()
    }

    /// Stable ascending page for boot reconciliation. Advancing with a cursor
    /// derived from the final row does not skip later jobs when earlier rows
    /// concurrently transition out of `queued`.
    pub async fn queued_jobs_page(
        &self,
        after: Option<&JobCursor>,
        limit: i64,
    ) -> StoreResult<Vec<QueuedJobRow>> {
        let mut statement = build_queued_jobs_query("", after, limit);
        let rows = statement.build().fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|row| {
                Ok(QueuedJobRow {
                    job_id: row.try_get("job_id")?,
                    tenant: row.try_get("tenant")?,
                    created_at_ms: row.try_get("created_at_ms")?,
                    requested_mem_mb: u32::try_from(row.try_get::<i64, _>("requested_mem_mb")?)
                        .map_err(|_| {
                            sqlx::Error::Protocol(
                                "queued requested_mem_mb is outside the u32 range".to_string(),
                            )
                        })?,
                })
            })
            .collect()
    }

    /// Delete one bounded batch of terminal jobs according to their actual
    /// finish time. Both the candidate-job count and cumulative event count
    /// are hard-bounded so cascade deletion cannot monopolize SQLite's sole
    /// writer. An individually oversized legacy history is drained newest
    /// first over multiple sweeps; its stale receipt is cleared as soon as
    /// partial pruning begins. This is a logical retention operation; use
    /// `compact` during a maintenance window for physical reclaim.
    pub async fn prune_older_than_batch(
        &self,
        max_age_ms: i64,
        batch_size: i64,
    ) -> StoreResult<RetentionReport> {
        if max_age_ms < 0 {
            return Err(sqlx::Error::InvalidArgument(
                "max_age_ms must be non-negative".to_string(),
            ));
        }
        let cutoff = now_ms().saturating_sub(max_age_ms);
        let batch_size = batch_size.clamp(1, MAX_RETENTION_BATCH);
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::begin_row_writes(&mut tx).await?;
        let candidate_sql = format!(
            "SELECT job_id FROM jobs
             WHERE status IN ({TERMINAL_STATUSES_SQL})
               AND finished_at_ms < ?1
             ORDER BY finished_at_ms ASC, job_id ASC
             LIMIT ?2"
        );
        let candidates = sqlx::query(&candidate_sql)
            .bind(cutoff)
            .bind(batch_size)
            .fetch_all(&mut *tx)
            .await?;

        let mut jobs_deleted = 0_u64;
        let mut events_deleted = 0_u64;
        for candidate in candidates {
            let job_id: String = candidate.try_get("job_id")?;
            let event_count = sqlx::query("SELECT COUNT(*) AS n FROM events WHERE job_id = ?1")
                .bind(&job_id)
                .fetch_one(&mut *tx)
                .await?
                .try_get::<i64, _>("n")?
                .max(0) as u64;
            let event_budget = MAX_RETENTION_EVENTS_PER_BATCH.saturating_sub(events_deleted);

            if event_count <= event_budget {
                let deleted = sqlx::query("DELETE FROM jobs WHERE job_id = ?1")
                    .bind(&job_id)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                jobs_deleted = jobs_deleted.saturating_add(deleted);
                if deleted != 0 {
                    events_deleted = events_deleted.saturating_add(event_count);
                }
                if events_deleted >= MAX_RETENTION_EVENTS_PER_BATCH {
                    break;
                }
                continue;
            }

            // Do not begin partially draining another job after this sweep
            // has already made progress. It will be the oldest candidate on
            // the next sweep and receive the complete event budget then.
            if jobs_deleted != 0 || events_deleted != 0 {
                break;
            }

            // The tombstone and first chunk commit atomically. Every public
            // reader excludes tombstoned jobs/events, so no transaction can
            // observe a receipt beside a partially retained hash chain.
            sqlx::query(
                "INSERT OR IGNORE INTO retention_tombstones(job_id, marked_at_ms)
                 VALUES (?1, ?2)",
            )
            .bind(&job_id)
            .bind(now_ms())
            .execute(&mut *tx)
            .await?;
            // A key must expire no later than logical job retention. The
            // oversized job row can remain temporarily while its events are
            // drained, so remove the replay mapping at tombstone time.
            sqlx::query("DELETE FROM idempotency_keys WHERE job_id = ?1")
                .bind(&job_id)
                .execute(&mut *tx)
                .await?;
            let deleted = sqlx::query(
                "DELETE FROM events
                 WHERE seq IN (
                     SELECT seq FROM events
                     WHERE job_id = ?1
                     ORDER BY seq DESC
                     LIMIT ?2
                 )",
            )
            .bind(&job_id)
            .bind(MAX_RETENTION_EVENTS_PER_BATCH as i64)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            events_deleted = events_deleted.saturating_add(deleted);
            sqlx::query("UPDATE jobs SET receipt_json = NULL WHERE job_id = ?1")
                .bind(&job_id)
                .execute(&mut *tx)
                .await?;
            reconcile_job_storage_tx(&mut tx, &job_id, true, &self.db_path, self.limits).await?;
            break;
        }

        let remaining_sql = format!(
            "SELECT EXISTS(
                SELECT 1 FROM jobs
                WHERE status IN ({TERMINAL_STATUSES_SQL})
                  AND finished_at_ms < ?1
             ) AS more_remaining"
        );
        let more_remaining = sqlx::query(&remaining_sql)
            .bind(cutoff)
            .fetch_one(&mut *tx)
            .await?
            .get::<i64, _>("more_remaining")
            != 0;
        let report = RetentionReport {
            jobs_deleted,
            events_deleted,
            more_remaining,
        };
        Self::mark_row_writes_validated(&mut tx).await?;
        tx.commit().await?;
        Ok(report)
    }

    /// Compatibility wrapper: one bounded retention batch, never a
    /// variable-length `IN (?, ... ?)` query.
    pub async fn prune_older_than(&self, max_age_ms: i64) -> StoreResult<(u64, u64)> {
        let report = self
            .prune_older_than_batch(max_age_ms, DEFAULT_RETENTION_BATCH)
            .await?;
        Ok((report.jobs_deleted, report.events_deleted))
    }

    /// Run SQLite's physical space reclamation. This can take an exclusive
    /// lock and is intentionally separate from routine retention sweeps.
    pub async fn compact(&self) -> StoreResult<()> {
        checkpoint_wal(&self.pool).await?;
        sqlx::query("VACUUM").execute(&self.pool).await?;
        checkpoint_wal(&self.pool).await?;
        sqlx::query("PRAGMA optimize").execute(&self.pool).await?;
        harden_storage_files(&self.db_path)?;
        Ok(())
    }

    /// Boot recovery finalizes only work which had actually started. Accepted
    /// queued jobs remain queued and can be obtained with `queued_job_ids`.
    /// Every recovered running job receives a terminal hashed event in the
    /// same transaction as its row update. Only a small page of identifiers
    /// and one job's potentially large specs are resident at a time. Each job
    /// commits independently, so a later corrupt row or I/O failure leaves
    /// earlier recoveries durable and the failing row wholly running.
    pub async fn recover_stale_running(&self) -> StoreResult<u64> {
        let recovered_at = now_ms();
        let mut recovered = 0_u64;
        loop {
            let rows = sqlx::query(
                "SELECT job_id FROM jobs
                 WHERE status = 'running'
                 ORDER BY created_at_ms ASC, job_id ASC
                 LIMIT ?1",
            )
            .bind(MAX_RUNNING_RECOVERY_ID_PAGE)
            .fetch_all(&self.pool)
            .await?;
            if rows.is_empty() {
                return Ok(recovered);
            }
            let job_ids = rows
                .into_iter()
                .map(|row| row.try_get::<String, _>("job_id"))
                .collect::<StoreResult<Vec<_>>>()?;

            for job_id in job_ids {
                if self
                    .recover_one_stale_running(&job_id, recovered_at)
                    .await?
                {
                    recovered = recovered.saturating_add(1);
                }
            }
        }
    }

    async fn recover_one_stale_running(
        &self,
        job_id: &str,
        recovered_at: i64,
    ) -> StoreResult<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Self::begin_row_writes(&mut tx).await?;
        let row = sqlx::query(
            "SELECT created_at_ms, started_at_ms, spec_json, effective_spec_json
             FROM jobs
             WHERE job_id = ?1 AND status = 'running'",
        )
        .bind(job_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(false);
        };
        let created_at_ms: i64 = row.try_get("created_at_ms")?;
        let started_at: Option<i64> = row.try_get("started_at_ms")?;
        let requested_spec: String = row.try_get("spec_json")?;
        let effective_spec: Option<String> = row.try_get("effective_spec_json")?;
        drop(row);

        let duration_ms = started_at
            .map(|started| recovered_at.saturating_sub(started).max(0))
            .unwrap_or(0);
        let result = sqlx::query(
            "UPDATE jobs
             SET status = 'error', exit_code = NULL, finished_at_ms = ?2
             WHERE job_id = ?1 AND status = 'running'",
        )
        .bind(job_id)
        .bind(recovered_at)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }

        append_event_tx(
            &mut tx,
            job_id,
            "finished",
            &json!({
                "status": "error",
                "exit_code": Value::Null,
                "duration_ms": duration_ms,
                "reason": "server_restarted",
            }),
            recovered_at,
        )
        .await?;
        let chain = event_chain_head_tx(&mut tx, job_id).await?;
        let recovery_receipt = recovery_receipt_details(
            &requested_spec,
            effective_spec.as_deref(),
            created_at_ms,
            started_at,
        );
        let receipt = receipt_with_chain(
            Some(&recovery_receipt),
            &chain,
            ReceiptCore {
                job_id,
                status: "error",
                exit_code: None,
                created_at_ms,
                started_at_ms: started_at,
                finished_at_ms: recovered_at,
                duration_ms,
            },
        );
        sqlx::query("UPDATE jobs SET receipt_json = ?2 WHERE job_id = ?1")
            .bind(job_id)
            .bind(receipt)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT OR IGNORE INTO attestation_outbox(
                 job_id, pending_since_ms, attempt_count, next_attempt_ms
             ) VALUES (?1, ?2, 0, ?2)",
        )
        .bind(job_id)
        .bind(recovered_at)
        .execute(&mut *tx)
        .await?;
        reconcile_job_storage_tx(&mut tx, job_id, true, &self.db_path, self.limits).await?;
        Self::mark_row_writes_validated(&mut tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    fn row_to_job(row: sqlx::sqlite::SqliteRow) -> StoreResult<JobRow> {
        let exit_code = row
            .try_get::<Option<i64>, _>("exit_code")?
            .map(i32::try_from)
            .transpose()
            .map_err(|_| sqlx::Error::Protocol("exit_code is outside the i32 range".to_string()))?;
        Ok(JobRow {
            job_id: row.try_get("job_id")?,
            tenant: row.try_get("tenant")?,
            language: row.try_get("language")?,
            status: row.try_get("status")?,
            created_at_ms: row.try_get("created_at_ms")?,
            started_at_ms: row.try_get("started_at_ms")?,
            finished_at_ms: row.try_get("finished_at_ms")?,
            exit_code,
            spec_json: row.try_get("spec_json")?,
            effective_spec_json: row.try_get("effective_spec_json")?,
            receipt_json: row.try_get("receipt_json")?,
        })
    }

    fn row_to_job_summary(row: sqlx::sqlite::SqliteRow) -> StoreResult<JobSummary> {
        let exit_code = row
            .try_get::<Option<i64>, _>("exit_code")?
            .map(i32::try_from)
            .transpose()
            .map_err(|_| sqlx::Error::Protocol("exit_code is outside the i32 range".to_string()))?;
        Ok(JobSummary {
            job_id: row.try_get("job_id")?,
            tenant: row.try_get("tenant")?,
            language: row.try_get("language")?,
            status: row.try_get("status")?,
            created_at_ms: row.try_get("created_at_ms")?,
            started_at_ms: row.try_get("started_at_ms")?,
            finished_at_ms: row.try_get("finished_at_ms")?,
            exit_code,
        })
    }
}

#[derive(Clone, Copy)]
struct RequiredColumn {
    name: &'static str,
    declared_type: &'static str,
    require_not_null: bool,
    require_primary_key: bool,
}

impl RequiredColumn {
    const fn primary_key(name: &'static str, declared_type: &'static str) -> Self {
        Self {
            name,
            declared_type,
            require_not_null: false,
            require_primary_key: true,
        }
    }

    const fn not_null(name: &'static str, declared_type: &'static str) -> Self {
        Self {
            name,
            declared_type,
            require_not_null: true,
            require_primary_key: false,
        }
    }

    const fn nullable(name: &'static str, declared_type: &'static str) -> Self {
        Self {
            name,
            declared_type,
            require_not_null: false,
            require_primary_key: false,
        }
    }
}

fn validate_utf8_bytes(table: &str, row_key: i64, column: &str, bytes: &[u8]) -> StoreResult<()> {
    std::str::from_utf8(bytes).map_err(|_| {
        sqlx::Error::Protocol(format!(
            "{table}.{column} contains invalid UTF-8 at row {row_key}"
        ))
    })?;
    Ok(())
}

async fn validate_required_columns(
    conn: &mut SqliteConnection,
    table: &str,
    required: &[RequiredColumn],
) -> StoreResult<()> {
    let statement = format!("PRAGMA table_info({table})");
    let rows = sqlx::query(&statement).fetch_all(&mut *conn).await?;
    for expected in required {
        let Some(row) = rows
            .iter()
            .find(|row| row.get::<String, _>("name") == expected.name)
        else {
            return Err(sqlx::Error::Protocol(format!(
                "{table} table is missing required column {}",
                expected.name
            )));
        };
        let declared_type: String = row.get("type");
        if !declared_type
            .trim()
            .eq_ignore_ascii_case(expected.declared_type)
        {
            return Err(sqlx::Error::Protocol(format!(
                "{table}.{} has type {declared_type:?}; expected {}",
                expected.name, expected.declared_type
            )));
        }
        if expected.require_not_null && row.get::<i64, _>("notnull") == 0 {
            return Err(sqlx::Error::Protocol(format!(
                "{table}.{} must be NOT NULL",
                expected.name
            )));
        }
        if expected.require_primary_key && row.get::<i64, _>("pk") == 0 {
            return Err(sqlx::Error::Protocol(format!(
                "{table}.{} must be part of the primary key",
                expected.name
            )));
        }
    }
    Ok(())
}

async fn table_exists(conn: &mut SqliteConnection, name: &str) -> StoreResult<bool> {
    let row = sqlx::query(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
         ) AS present",
    )
    .bind(name)
    .fetch_one(&mut *conn)
    .await?;
    Ok(row.get::<i64, _>("present") != 0)
}

async fn column_exists(
    conn: &mut SqliteConnection,
    table: &str,
    column: &str,
) -> StoreResult<bool> {
    let statement = format!("PRAGMA table_info({table})");
    let rows = sqlx::query(&statement).fetch_all(&mut *conn).await?;
    Ok(rows
        .iter()
        .any(|row| row.get::<String, _>("name") == column))
}

async fn schema_has_v2_extensions(conn: &mut SqliteConnection) -> StoreResult<bool> {
    for (table, column) in [
        ("jobs", "effective_spec_json"),
        ("jobs", "receipt_json"),
        ("events", "prev_hash"),
        ("events", "event_hash"),
        ("events", "hash_version"),
    ] {
        if column_exists(conn, table, column).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn physical_v3_table_count(conn: &mut SqliteConnection) -> StoreResult<usize> {
    let mut count = 0_usize;
    for table in [
        "job_storage_usage",
        "storage_usage_total",
        "tenant_storage_usage",
        "idempotency_keys",
    ] {
        count += usize::from(table_exists(conn, table).await?);
    }
    Ok(count)
}

async fn ensure_admitted_memory_column(
    conn: &mut SqliteConnection,
    preserve_v3_value: bool,
) -> StoreResult<()> {
    if !column_exists(conn, "jobs", "admitted_mem_mb").await? {
        sqlx::query(
            "ALTER TABLE jobs
             ADD COLUMN admitted_mem_mb INTEGER NOT NULL DEFAULT 256
             CHECK (typeof(admitted_mem_mb) = 'integer'
                    AND admitted_mem_mb BETWEEN 16 AND 4096)",
        )
        .execute(&mut *conn)
        .await?;
        if preserve_v3_value {
            let missing: i64 = sqlx::query(
                "SELECT EXISTS(
                     SELECT 1 FROM jobs
                     WHERE NOT EXISTS (
                         SELECT 1 FROM job_storage_usage
                         WHERE job_storage_usage.job_id = jobs.job_id
                           AND job_storage_usage.tenant = jobs.tenant
                     )
                 ) AS missing",
            )
            .fetch_one(&mut *conn)
            .await?
            .try_get("missing")?;
            if missing != 0 {
                return Err(sqlx::Error::Protocol(
                    "v3 accounting is missing a durable admitted-memory value".to_string(),
                ));
            }
            sqlx::query(
                "UPDATE jobs
                 SET admitted_mem_mb = MIN(MAX((
                     SELECT requested_mem_mb FROM job_storage_usage
                     WHERE job_storage_usage.job_id = jobs.job_id
                       AND job_storage_usage.tenant = jobs.tenant
                 ), 16), 4096)",
            )
            .execute(&mut *conn)
            .await?;
            sqlx::query(
                "UPDATE job_storage_usage
                 SET requested_mem_mb = MIN(MAX(requested_mem_mb, 16), 4096)",
            )
            .execute(&mut *conn)
            .await?;
        } else {
            sqlx::query(
                "UPDATE jobs SET admitted_mem_mb = CASE
                     WHEN json_type(spec_json, '$.limits.mem_mb') = 'integer'
                     THEN MIN(MAX(CAST(json_extract(spec_json, '$.limits.mem_mb') AS INTEGER), 16), 4096)
                     ELSE 256
                 END",
            )
            .execute(&mut *conn)
            .await?;
        }
    }
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_tenant_id_unique
         ON jobs(tenant, job_id)",
    )
    .execute(&mut *conn)
    .await?;
    validate_jobs_tenant_unique_index(conn).await?;
    Ok(())
}

async fn validate_jobs_tenant_unique_index(conn: &mut SqliteConnection) -> StoreResult<()> {
    let indexes = sqlx::query("PRAGMA index_list(jobs)")
        .fetch_all(&mut *conn)
        .await?;
    let Some(index) = indexes
        .iter()
        .find(|row| row.get::<String, _>("name") == "idx_jobs_tenant_id_unique")
    else {
        return Err(sqlx::Error::Protocol(
            "jobs is missing the tenant/job unique parent key".to_string(),
        ));
    };
    if index.get::<i64, _>("unique") != 1 || index.get::<i64, _>("partial") != 0 {
        return Err(sqlx::Error::Protocol(
            "jobs tenant/job parent index must be unique and non-partial".to_string(),
        ));
    }
    let columns = sqlx::query("PRAGMA index_info(idx_jobs_tenant_id_unique)")
        .fetch_all(&mut *conn)
        .await?;
    let names = columns
        .iter()
        .map(|row| row.get::<String, _>("name"))
        .collect::<Vec<_>>();
    if names != ["tenant", "job_id"] {
        return Err(sqlx::Error::Protocol(
            "jobs tenant/job parent index has the wrong column order".to_string(),
        ));
    }
    Ok(())
}

async fn exact_composite_job_fk(conn: &mut SqliteConnection, table: &str) -> StoreResult<bool> {
    let rows = sqlx::query(&format!("PRAGMA foreign_key_list({table})"))
        .fetch_all(&mut *conn)
        .await?;
    if rows.len() != 2 {
        return Ok(false);
    }
    let id = rows[0].get::<i64, _>("id");
    Ok(rows.iter().all(|row| {
        row.get::<i64, _>("id") == id
            && row.get::<String, _>("table") == "jobs"
            && row
                .get::<String, _>("on_delete")
                .eq_ignore_ascii_case("CASCADE")
            && row
                .get::<String, _>("on_update")
                .eq_ignore_ascii_case("NO ACTION")
    }) && rows.iter().any(|row| {
        row.get::<String, _>("from") == "tenant" && row.get::<String, _>("to") == "tenant"
    }) && rows.iter().any(|row| {
        row.get::<String, _>("from") == "job_id" && row.get::<String, _>("to") == "job_id"
    }))
}

async fn exact_legacy_job_fk(conn: &mut SqliteConnection, table: &str) -> StoreResult<bool> {
    let rows = sqlx::query(&format!("PRAGMA foreign_key_list({table})"))
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows.len() == 1
        && rows[0].get::<String, _>("table") == "jobs"
        && rows[0].get::<String, _>("from") == "job_id"
        && rows[0].get::<String, _>("to") == "job_id"
        && rows[0]
            .get::<String, _>("on_delete")
            .eq_ignore_ascii_case("CASCADE"))
}

async fn upgrade_job_storage_fk_if_needed(conn: &mut SqliteConnection) -> StoreResult<()> {
    if exact_composite_job_fk(conn, "job_storage_usage").await? {
        return Ok(());
    }
    if !exact_legacy_job_fk(conn, "job_storage_usage").await? {
        return Err(sqlx::Error::Protocol(
            "job_storage_usage has an unexpected foreign-key definition".to_string(),
        ));
    }
    sqlx::query(
        "CREATE TABLE job_storage_usage_v3 (
             job_id TEXT PRIMARY KEY NOT NULL,
             tenant TEXT NOT NULL
                 CHECK (typeof(tenant) = 'text' AND length(trim(tenant)) > 0),
             retained_bytes INTEGER NOT NULL
                 CHECK (typeof(retained_bytes) = 'integer' AND retained_bytes >= 0),
             reserved_bytes INTEGER NOT NULL
                 CHECK (typeof(reserved_bytes) = 'integer' AND reserved_bytes >= 0),
             requested_mem_mb INTEGER NOT NULL
                 CHECK (typeof(requested_mem_mb) = 'integer'
                        AND requested_mem_mb BETWEEN 16 AND 4096),
             FOREIGN KEY(tenant, job_id)
                 REFERENCES jobs(tenant, job_id) ON DELETE CASCADE
         )",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO job_storage_usage_v3(
             job_id, tenant, retained_bytes, reserved_bytes, requested_mem_mb
         )
         SELECT job_id, tenant, retained_bytes, reserved_bytes,
                MIN(MAX(requested_mem_mb, 16), 4096)
         FROM job_storage_usage",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query("DROP TABLE job_storage_usage")
        .execute(&mut *conn)
        .await?;
    sqlx::query("ALTER TABLE job_storage_usage_v3 RENAME TO job_storage_usage")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn upgrade_idempotency_fk_if_needed(conn: &mut SqliteConnection) -> StoreResult<()> {
    if exact_composite_job_fk(conn, "idempotency_keys").await? {
        return Ok(());
    }
    if !exact_legacy_job_fk(conn, "idempotency_keys").await? {
        return Err(sqlx::Error::Protocol(
            "idempotency_keys has an unexpected foreign-key definition".to_string(),
        ));
    }
    sqlx::query(
        "CREATE TABLE idempotency_keys_v3 (
             tenant TEXT NOT NULL
                 CHECK (typeof(tenant) = 'text' AND length(trim(tenant)) > 0),
             idempotency_key TEXT NOT NULL
                 CHECK (typeof(idempotency_key) = 'text'
                        AND length(idempotency_key) BETWEEN 1 AND 128),
             request_sha256 TEXT NOT NULL
                 CHECK (typeof(request_sha256) = 'text' AND length(request_sha256) = 64),
             job_id TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL
                 CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
             PRIMARY KEY(tenant, idempotency_key),
             FOREIGN KEY(tenant, job_id)
                 REFERENCES jobs(tenant, job_id) ON DELETE CASCADE
         ) WITHOUT ROWID",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO idempotency_keys_v3(
             tenant, idempotency_key, request_sha256, job_id, created_at_ms
         )
         SELECT tenant, idempotency_key, request_sha256, job_id, created_at_ms
         FROM idempotency_keys",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query("DROP TABLE idempotency_keys")
        .execute(&mut *conn)
        .await?;
    sqlx::query("ALTER TABLE idempotency_keys_v3 RENAME TO idempotency_keys")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn validate_v3_foreign_keys_and_tenants(conn: &mut SqliteConnection) -> StoreResult<()> {
    validate_v3_foreign_key_schema(conn).await?;
    let inconsistent: i64 = sqlx::query(
        "SELECT EXISTS(
             SELECT 1 FROM job_storage_usage AS usage
             LEFT JOIN jobs AS job
               ON job.tenant = usage.tenant AND job.job_id = usage.job_id
             WHERE job.job_id IS NULL
         ) OR EXISTS(
             SELECT 1 FROM idempotency_keys AS mapping
             LEFT JOIN jobs AS job
               ON job.tenant = mapping.tenant AND job.job_id = mapping.job_id
             WHERE job.job_id IS NULL
         ) AS inconsistent",
    )
    .fetch_one(&mut *conn)
    .await?
    .try_get("inconsistent")?;
    if inconsistent != 0 {
        return Err(sqlx::Error::Protocol(
            "v3 accounting/idempotency tenant ownership is inconsistent".to_string(),
        ));
    }
    Ok(())
}

async fn validate_v3_foreign_key_schema(conn: &mut SqliteConnection) -> StoreResult<()> {
    validate_jobs_tenant_unique_index(conn).await?;
    if !exact_composite_job_fk(conn, "job_storage_usage").await?
        || !exact_composite_job_fk(conn, "idempotency_keys").await?
    {
        return Err(sqlx::Error::Protocol(
            "v3 accounting/idempotency tables require exact composite cascading job foreign keys"
                .to_string(),
        ));
    }
    Ok(())
}

async fn validate_idempotency_fingerprints(conn: &mut SqliteConnection) -> StoreResult<()> {
    let mut rows = sqlx::query(
        "SELECT mapping.idempotency_key, mapping.request_sha256,
                mapping.created_at_ms, job.spec_json
         FROM idempotency_keys AS mapping
         INNER JOIN jobs AS job
           ON job.tenant = mapping.tenant AND job.job_id = mapping.job_id",
    )
    .fetch(&mut *conn);
    while let Some(row) = rows.try_next().await? {
        let key: String = row.try_get("idempotency_key")?;
        let fingerprint: String = row.try_get("request_sha256")?;
        let created_at_ms: i64 = row.try_get("created_at_ms")?;
        let spec_json: String = row.try_get("spec_json")?;
        let spec: Value = serde_json::from_str(&spec_json)
            .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let expected = sha256_hex(canonical_json(&spec).as_bytes());
        if key.is_empty()
            || key.len() > 128
            || !key.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
            || fingerprint != expected
            || created_at_ms < 0
        {
            return Err(sqlx::Error::Protocol(
                "idempotency mapping is incompatible with its canonical job specification"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

async fn validated_event_sequence_counter(
    conn: &mut SqliteConnection,
    events_table: &str,
) -> StoreResult<Option<i64>> {
    if !matches!(events_table, "events" | "events_legacy_v1") {
        return Err(sqlx::Error::InvalidArgument(
            "unexpected events table for sequence validation".to_string(),
        ));
    }
    let max_sequence: i64 = sqlx::query(&format!(
        "SELECT COALESCE(MAX(seq), 0) AS max_sequence FROM {events_table}"
    ))
    .fetch_one(&mut *conn)
    .await?
    .try_get("max_sequence")?;
    let rows = sqlx::query(
        "SELECT seq, typeof(seq) AS storage_type
         FROM sqlite_sequence WHERE name = ?1",
    )
    .bind(events_table)
    .fetch_all(&mut *conn)
    .await?;
    if rows.len() > 1 {
        return Err(sqlx::Error::Protocol(format!(
            "{events_table} has duplicate sqlite_sequence rows"
        )));
    }
    let Some(row) = rows.first() else {
        if max_sequence != 0 {
            return Err(sqlx::Error::Protocol(format!(
                "{events_table} has events but no AUTOINCREMENT counter"
            )));
        }
        return Ok(None);
    };
    if row.try_get::<String, _>("storage_type")? != "integer" {
        return Err(sqlx::Error::Protocol(format!(
            "{events_table} AUTOINCREMENT counter is not an integer"
        )));
    }
    let counter: i64 = row.try_get("seq")?;
    if counter < max_sequence || !(0..9223372036854775806).contains(&counter) {
        return Err(sqlx::Error::Protocol(format!(
            "{events_table} AUTOINCREMENT counter is below retained events, invalid, or exhausted"
        )));
    }
    Ok(Some(counter))
}

async fn raise_event_sequence_counter(
    conn: &mut SqliteConnection,
    events_table: &str,
    floor: i64,
) -> StoreResult<()> {
    if floor <= 0 {
        return Ok(());
    }
    match validated_event_sequence_counter(conn, events_table).await? {
        Some(current) if current >= floor => {}
        Some(_) => {
            let updated = sqlx::query("UPDATE sqlite_sequence SET seq = ?2 WHERE name = ?1")
                .bind(events_table)
                .bind(floor)
                .execute(&mut *conn)
                .await?;
            if updated.rows_affected() != 1 {
                return Err(sqlx::Error::Protocol(format!(
                    "failed to advance {events_table} AUTOINCREMENT counter"
                )));
            }
        }
        None => {
            sqlx::query("INSERT INTO sqlite_sequence(name, seq) VALUES (?1, ?2)")
                .bind(events_table)
                .bind(floor)
                .execute(&mut *conn)
                .await?;
        }
    }
    validated_event_sequence_counter(conn, events_table).await?;
    Ok(())
}

async fn validate_migration_history_rows(conn: &mut SqliteConnection) -> StoreResult<()> {
    let invalid: i64 = sqlx::query(
        "SELECT EXISTS(
             SELECT 1 FROM schema_migrations
             WHERE typeof(version) != 'integer' OR version <= 0
                OR typeof(applied_at_ms) != 'integer' OR applied_at_ms < 0
         ) AS invalid",
    )
    .fetch_one(&mut *conn)
    .await?
    .try_get("invalid")?;
    if invalid != 0 {
        return Err(sqlx::Error::Protocol(
            "schema_migrations contains invalid storage classes".to_string(),
        ));
    }
    Ok(())
}

async fn storage_guards_current(conn: &mut SqliteConnection) -> StoreResult<bool> {
    let rows = sqlx::query(
        "SELECT name, sql FROM sqlite_schema
         WHERE type = 'trigger' AND name IN (
             'coop_schema_migrations_storage_guard_insert',
             'coop_schema_migrations_storage_guard_update',
             'coop_schema_migrations_storage_guard_delete',
             'coop_jobs_storage_guard_insert',
             'coop_jobs_storage_guard_update',
             'coop_events_storage_guard_insert',
             'coop_events_storage_guard_update',
             'coop_events_sequence_guard_insert',
             'coop_jobs_validation_dirty_insert',
             'coop_jobs_validation_dirty_update',
             'coop_jobs_validation_dirty_delete',
             'coop_events_validation_dirty_insert',
             'coop_events_validation_dirty_update',
             'coop_events_validation_dirty_delete',
             'coop_attestations_storage_guard_insert',
             'coop_attestations_storage_guard_update',
             'coop_attestations_validation_dirty_insert',
             'coop_attestations_validation_dirty_update',
             'coop_attestations_validation_dirty_delete',
             'coop_attestation_outbox_storage_guard_insert',
             'coop_attestation_outbox_storage_guard_update',
             'coop_attestation_outbox_validation_dirty_insert',
             'coop_attestation_outbox_validation_dirty_update',
             'coop_attestation_outbox_validation_dirty_delete'
         )",
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.len() == STORAGE_GUARD_NAMES.len()
        && rows.iter().all(|row| {
            let Ok(name) = row.try_get::<String, _>("name") else {
                return false;
            };
            let Ok(sql) = row.try_get::<String, _>("sql") else {
                return false;
            };
            sql.contains(STORAGE_GUARD_REVISION_MARKER)
                && match name.as_str() {
                    "coop_schema_migrations_storage_guard_update" => {
                        sql.contains("NEW.version != OLD.version")
                    }
                    "coop_schema_migrations_storage_guard_delete" => {
                        sql.contains("BEFORE DELETE ON schema_migrations")
                    }
                    "coop_jobs_storage_guard_update" => {
                        sql.contains("NEW.job_id != OLD.job_id")
                            && sql.contains("NEW.admitted_mem_mb != OLD.admitted_mem_mb")
                    }
                    "coop_events_storage_guard_update" => {
                        sql.contains("NEW.seq != OLD.seq") && sql.contains("OLD.hash_version = 1")
                    }
                    "coop_attestations_storage_guard_update" => {
                        sql.contains("NEW.receipt_sha256 != OLD.receipt_sha256")
                            && sql.contains("NEW.envelope_json != OLD.envelope_json")
                            && sql.contains("NEW.result_artifact != OLD.result_artifact")
                    }
                    "coop_attestation_outbox_storage_guard_update" => {
                        sql.contains("NEW.job_id != OLD.job_id")
                            && sql.contains("NEW.pending_since_ms != OLD.pending_since_ms")
                    }
                    name if name.contains("validation_dirty") => {
                        sql.contains("accounting_validation_revision = 0")
                    }
                    _ => true,
                }
        }))
}

async fn validate_foreign_keys(conn: &mut SqliteConnection) -> StoreResult<()> {
    if sqlx::query("PRAGMA foreign_key_check")
        .fetch_optional(&mut *conn)
        .await?
        .is_some()
    {
        return Err(sqlx::Error::Protocol(
            "foreign-key validation failed".to_string(),
        ));
    }
    Ok(())
}

async fn record_migration(conn: &mut SqliteConnection, version: i64) -> StoreResult<()> {
    sqlx::query("INSERT OR IGNORE INTO schema_migrations(version, applied_at_ms) VALUES (?1, ?2)")
        .bind(version)
        .bind(now_ms())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn checkpoint_wal(pool: &SqlitePool) -> StoreResult<()> {
    let row = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_one(pool)
        .await?;
    let busy: i64 = row.try_get(0)?;
    if busy != 0 {
        return Err(sqlx::Error::Protocol(
            "WAL checkpoint could not complete because the database is busy".to_string(),
        ));
    }
    Ok(())
}

async fn create_jobs_table(conn: &mut SqliteConnection, table: &str) -> StoreResult<()> {
    let statement = format!(
        "CREATE TABLE {table} (
            job_id TEXT PRIMARY KEY NOT NULL
                CHECK (typeof(job_id) = 'text' AND length(trim(job_id)) > 0),
            tenant TEXT NOT NULL
                CHECK (typeof(tenant) = 'text' AND length(trim(tenant)) > 0),
            language TEXT NOT NULL
                CHECK (typeof(language) = 'text' AND length(trim(language)) > 0),
            status TEXT NOT NULL DEFAULT 'queued'
                CHECK (typeof(status) = 'text' AND status IN ('queued','running','succeeded','failed','timed_out','oom_killed','cancelled','error')),
            spec_json TEXT NOT NULL
                CHECK (typeof(spec_json) = 'text' AND json_valid(spec_json)),
            admitted_mem_mb INTEGER NOT NULL
                CHECK (typeof(admitted_mem_mb) = 'integer'
                       AND admitted_mem_mb BETWEEN 16 AND 4096),
            effective_spec_json TEXT
                CHECK (effective_spec_json IS NULL OR (typeof(effective_spec_json) = 'text' AND json_valid(effective_spec_json))),
            receipt_json TEXT
                CHECK (receipt_json IS NULL OR (typeof(receipt_json) = 'text' AND json_valid(receipt_json))),
            created_at_ms INTEGER NOT NULL
                CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
            started_at_ms INTEGER
                CHECK (started_at_ms IS NULL OR (typeof(started_at_ms) = 'integer' AND started_at_ms >= 0)),
            finished_at_ms INTEGER
                CHECK (finished_at_ms IS NULL OR (typeof(finished_at_ms) = 'integer' AND finished_at_ms >= 0)),
            exit_code INTEGER CHECK (
                exit_code IS NULL OR
                (typeof(exit_code) = 'integer' AND
                 exit_code BETWEEN -2147483648 AND 2147483647)
            ),
            CHECK (status != 'queued' OR (started_at_ms IS NULL AND finished_at_ms IS NULL)),
            CHECK (status != 'running' OR (started_at_ms IS NOT NULL AND finished_at_ms IS NULL)),
            CHECK (status IN ('queued','running') OR finished_at_ms IS NOT NULL),
            UNIQUE(tenant, job_id)
        )"
    );
    sqlx::query(&statement).execute(&mut *conn).await?;
    Ok(())
}

async fn create_events_table(
    conn: &mut SqliteConnection,
    table: &str,
    jobs_table: &str,
) -> StoreResult<()> {
    let statement = format!(
        "CREATE TABLE {table} (
            seq INTEGER PRIMARY KEY AUTOINCREMENT
                CHECK (
                    typeof(seq) = 'integer' AND
                    seq > 0 AND seq < 9223372036854775807
                ),
            job_id TEXT NOT NULL REFERENCES {jobs_table}(job_id) ON DELETE CASCADE
                CHECK (typeof(job_id) = 'text'),
            ts_ms INTEGER NOT NULL
                CHECK (typeof(ts_ms) = 'integer' AND ts_ms >= 0),
            kind TEXT NOT NULL
                CHECK (typeof(kind) = 'text' AND length(trim(kind)) > 0),
            data_json TEXT NOT NULL
                CHECK (typeof(data_json) = 'text' AND json_valid(data_json)),
            prev_hash TEXT NOT NULL DEFAULT '' CHECK (typeof(prev_hash) = 'text'),
            event_hash TEXT NOT NULL DEFAULT '' CHECK (typeof(event_hash) = 'text'),
            hash_version INTEGER NOT NULL DEFAULT 0
                CHECK (typeof(hash_version) = 'integer' AND hash_version IN (0, 1)),
            CHECK (hash_version = 0 OR length(event_hash) = 64)
        )"
    );
    sqlx::query(&statement).execute(&mut *conn).await?;
    Ok(())
}

async fn append_event_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    job_id: &str,
    kind: &str,
    data: &Value,
    ts_ms: i64,
) -> StoreResult<EventRow> {
    let prev_hash = previous_event_hash_tx(tx, job_id).await?;
    insert_hashed_event_tx(tx, job_id, kind, data, ts_ms, &prev_hash).await
}

async fn previous_event_hash_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    job_id: &str,
) -> StoreResult<String> {
    let prior = sqlx::query(
        "SELECT event_hash, hash_version FROM events
         WHERE job_id = ?1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(job_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(match prior {
        Some(row) if row.get::<i64, _>("hash_version") == 1 => row.get("event_hash"),
        _ => String::new(),
    })
}

async fn insert_hashed_event_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    job_id: &str,
    kind: &str,
    data: &Value,
    ts_ms: i64,
    prev_hash: &str,
) -> StoreResult<EventRow> {
    let data_json = canonical_json(data);
    // Insert as version zero so the schema accepts the temporary empty hash;
    // the row cannot escape the transaction before it is upgraded to v1.
    let inserted = sqlx::query(
        "INSERT INTO events (
            job_id, ts_ms, kind, data_json, prev_hash, event_hash, hash_version
         ) VALUES (?1, ?2, ?3, ?4, ?5, '', 0)
         RETURNING seq",
    )
    .bind(job_id)
    .bind(ts_ms)
    .bind(kind)
    .bind(&data_json)
    .bind(prev_hash)
    .fetch_one(&mut **tx)
    .await?;
    let seq: i64 = inserted.get("seq");
    let event_hash = compute_event_hash(job_id, prev_hash, seq, ts_ms, kind, data);
    sqlx::query("UPDATE events SET event_hash = ?2, hash_version = 1 WHERE seq = ?1")
        .bind(seq)
        .bind(&event_hash)
        .execute(&mut **tx)
        .await?;

    Ok(EventRow {
        seq,
        ts_ms,
        kind: kind.to_string(),
        data: data.clone(),
        prev_hash: prev_hash.to_string(),
        event_hash,
        hash_version: 1,
    })
}

async fn event_chain_head_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    job_id: &str,
) -> StoreResult<EventChainHead> {
    let row = sqlx::query(
        "SELECT
            COUNT(*) AS event_count,
            COALESCE(SUM(CASE WHEN hash_version = 1 THEN 1 ELSE 0 END), 0) AS verified_count,
            COALESCE(SUM(CASE WHEN hash_version = 0 THEN 1 ELSE 0 END), 0) AS legacy_count,
            (
                SELECT CASE WHEN hash_version = 1 THEN event_hash ELSE NULL END
                FROM events AS latest
                WHERE latest.job_id = ?1
                  AND NOT EXISTS (
                      SELECT 1 FROM retention_tombstones
                      WHERE retention_tombstones.job_id = latest.job_id
                  )
                ORDER BY seq DESC LIMIT 1
            ) AS head_hash
         FROM events
         WHERE job_id = ?1
           AND NOT EXISTS (
               SELECT 1 FROM retention_tombstones
               WHERE retention_tombstones.job_id = events.job_id
           )",
    )
    .bind(job_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(EventChainHead {
        event_count: row.get("event_count"),
        verified_event_count: row.get("verified_count"),
        legacy_event_count: row.get("legacy_count"),
        head_hash: row.get("head_hash"),
    })
}

#[cfg(test)]
mod query_plan_tests {
    use super::*;

    #[test]
    fn tenant_list_variants_use_composite_keyset_indexes_without_temp_sort() {
        sqlx::test_block_on(async {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let db = std::env::temp_dir()
                .join(format!(
                    "coop-store-list-plan-{}-{nonce}",
                    std::process::id()
                ))
                .join("coop.db");
            let store = Store::open(&db).await.unwrap();
            sqlx::query(
                "WITH RECURSIVE sequence(n) AS (
                     VALUES(1) UNION ALL SELECT n + 1 FROM sequence WHERE n < 8192
                 )
                 INSERT INTO jobs(
                     job_id, tenant, language, status, spec_json,
                     created_at_ms, finished_at_ms, admitted_mem_mb
                 )
                 SELECT printf('plan-%05d', n),
                        CASE n % 2 WHEN 0 THEN 'tenant-a' ELSE 'tenant-b' END,
                        CASE (n / 2) % 2 WHEN 0 THEN 'python' ELSE 'node' END,
                        CASE (n / 4) % 2 WHEN 0 THEN 'queued' ELSE 'succeeded' END,
                        '{}', n,
                        CASE (n / 4) % 2 WHEN 0 THEN NULL ELSE n END,
                        16
                 FROM sequence",
            )
            .execute(&store.pool)
            .await
            .unwrap();
            sqlx::query("ANALYZE").execute(&store.pool).await.unwrap();

            let cases = [
                (
                    ListJobsQuery {
                        tenant: Some("tenant-a".to_string()),
                        before: Some(JobCursor {
                            created_at_ms: 7000,
                            job_id: "plan-99999".to_string(),
                        }),
                        ..ListJobsQuery::default()
                    },
                    "idx_jobs_tenant_created_summary",
                ),
                (
                    ListJobsQuery {
                        tenant: Some("tenant-a".to_string()),
                        status: Some("queued".to_string()),
                        before: Some(JobCursor {
                            created_at_ms: 7000,
                            job_id: "plan-99999".to_string(),
                        }),
                        ..ListJobsQuery::default()
                    },
                    "idx_jobs_tenant_status_created_summary",
                ),
                (
                    ListJobsQuery {
                        tenant: Some("tenant-a".to_string()),
                        language: Some("python".to_string()),
                        before: Some(JobCursor {
                            created_at_ms: 7000,
                            job_id: "plan-99999".to_string(),
                        }),
                        ..ListJobsQuery::default()
                    },
                    "idx_jobs_tenant_language_created_summary",
                ),
                (
                    ListJobsQuery {
                        tenant: Some("tenant-a".to_string()),
                        status: Some("queued".to_string()),
                        language: Some("python".to_string()),
                        before: Some(JobCursor {
                            created_at_ms: 7000,
                            job_id: "plan-99999".to_string(),
                        }),
                        ..ListJobsQuery::default()
                    },
                    "idx_jobs_tenant_status_language_created_summary",
                ),
            ];

            for (query, expected_index) in cases {
                let mut statement =
                    build_job_list_query("EXPLAIN QUERY PLAN ", JOB_SUMMARY_PROJECTION, &query);
                let plan = statement
                    .build()
                    .fetch_all(&store.pool)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|row| row.get::<String, _>("detail"))
                    .collect::<Vec<_>>();
                assert!(
                    plan.iter()
                        .any(|detail| detail
                            .contains(&format!("USING COVERING INDEX {expected_index}"))),
                    "expected covering {expected_index} in plan: {plan:?}"
                );
                assert!(
                    !plan.iter().any(|detail| detail.contains("SCAN jobs")),
                    "unexpected jobs scan: {plan:?}"
                );
                assert!(
                    !plan.iter().any(|detail| detail.contains("USE TEMP B-TREE")),
                    "unexpected temp sort: {plan:?}"
                );
            }

            let recovery_cursor = JobCursor {
                created_at_ms: 2000,
                job_id: "plan-02000".to_string(),
            };
            let mut statement = build_queued_jobs_query(
                "EXPLAIN QUERY PLAN ",
                Some(&recovery_cursor),
                MAX_RECOVERY_PAGE,
            );
            let plan = statement
                .build()
                .fetch_all(&store.pool)
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.get::<String, _>("detail"))
                .collect::<Vec<_>>();
            assert!(
                plan.iter().any(|detail| detail
                    .contains("USING COVERING INDEX idx_jobs_status_created_recovery")),
                "expected covering recovery index in plan: {plan:?}"
            );
            assert!(
                !plan.iter().any(
                    |detail| detail.contains("SCAN jobs") || detail.contains("USE TEMP B-TREE")
                ),
                "unexpected recovery scan/sort: {plan:?}"
            );

            let point_plan = sqlx::query(
                "EXPLAIN QUERY PLAN
                 SELECT job_id, tenant, language, status, created_at_ms,
                        started_at_ms, finished_at_ms, exit_code
                 FROM jobs INDEXED BY idx_jobs_id_summary
                 WHERE job_id = ?1
                   AND NOT EXISTS (
                       SELECT 1 FROM retention_tombstones
                       WHERE retention_tombstones.job_id = jobs.job_id
                   )",
            )
            .bind("plan-00001")
            .fetch_all(&store.pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.get::<String, _>("detail"))
            .collect::<Vec<_>>();
            assert!(
                point_plan
                    .iter()
                    .any(|detail| detail.contains("USING COVERING INDEX idx_jobs_id_summary")),
                "expected covering point-lookup index in plan: {point_plan:?}"
            );
            assert!(
                !point_plan.iter().any(
                    |detail| detail.contains("SCAN jobs") || detail.contains("USE TEMP B-TREE")
                ),
                "unexpected point-lookup scan/sort: {point_plan:?}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn storage_parent_policy_never_hardens_shared_or_system_roots() {
        use std::os::unix::fs::PermissionsExt;

        let canonical_temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert_eq!(
            storage_parent_policy(&canonical_temp, Some(&canonical_temp)),
            StorageParentPolicy::PreserveSharedTemp
        );
        let before = std::fs::metadata(&canonical_temp)
            .unwrap()
            .permissions()
            .mode();
        harden_storage_directory(&canonical_temp).unwrap();
        let after = std::fs::metadata(&canonical_temp)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(after, before, "shared temp directory mode changed");

        for forbidden in ["/var", "/var/lib", "/var/tmp", "/private"] {
            let forbidden = Path::new(forbidden);
            let Ok(canonical) = std::fs::canonicalize(forbidden) else {
                continue;
            };
            if canonical == canonical_temp {
                continue;
            }
            let before = std::fs::metadata(forbidden).unwrap().permissions().mode();
            assert!(harden_storage_directory(forbidden).is_err());
            let after = std::fs::metadata(forbidden).unwrap().permissions().mode();
            assert_eq!(
                after, before,
                "forbidden parent mode changed: {canonical:?}"
            );
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dedicated = canonical_temp.join(format!(
            "coop-store-parent-policy-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&dedicated).unwrap();
        std::fs::set_permissions(&dedicated, std::fs::Permissions::from_mode(0o755)).unwrap();
        harden_storage_directory(&dedicated).unwrap();
        assert_eq!(
            std::fs::metadata(&dedicated).unwrap().permissions().mode() & 0o777,
            0o700
        );
        std::fs::remove_dir(&dedicated).unwrap();

        for broad in [
            "/var",
            "/var/lib",
            "/var/tmp",
            "/private",
            "/private/var",
            "/private/var/lib",
            "/private/var/tmp",
            "/private/tmp",
            "/Applications",
            "/Library",
            "/Network",
            "/System",
            "/Users",
            "/Volumes",
        ] {
            let path = Path::new(broad);
            assert_eq!(
                storage_parent_policy(path, None),
                StorageParentPolicy::RejectBroad,
                "broad parent was not rejected: {broad}"
            );
        }

        let dedicated = canonical_temp.join("coop-store-dedicated-child");
        assert_eq!(
            storage_parent_policy(&dedicated, Some(&canonical_temp)),
            StorageParentPolicy::HardenDedicated
        );
    }

    #[test]
    fn relative_database_free_space_probe_uses_current_directory() {
        assert_eq!(
            filesystem_probe_path(Path::new("coop.db")).unwrap(),
            std::env::current_dir().unwrap()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_alias_allowlist_is_exact_and_target_verified() {
        for alias in ["/var", "/tmp", "/etc"] {
            assert!(is_trusted_macos_system_alias(Path::new(alias)), "{alias}");
        }
        for untrusted in ["/private", "/var/lib", "/Users", "/usr"] {
            assert!(
                !is_trusted_macos_system_alias(Path::new(untrusted)),
                "{untrusted}"
            );
        }
    }
}
