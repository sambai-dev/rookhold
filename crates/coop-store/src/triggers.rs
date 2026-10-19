//! SQLite schema-v4 trigger definitions for row-storage invariants,
//! logical byte accounting, and offline-tamper detection (`store_integrity`).
//!
//! # Architectural Note: Dirty-Bit Tamper Detection via SQLite Triggers
//!
//! Because SQLite is an embedded file database, an external process with file
//! access could mutate `jobs`, `events`, or `job_storage_usage` rows directly
//! via raw SQL, bypassing Rust's quota and event-chain invariants. To detect
//! this without scanning every row on every startup, `store_integrity` stores
//! `row_validation_revision` and `accounting_validation_revision`.
//!
//! Every `AFTER INSERT/UPDATE/DELETE` trigger resets those revisions to `0`
//! *unless* the active transaction first sets them to the transaction-local
//! sentinel (`OWNED_ROW_WRITE_REVISION = 4` / `OWNED_ACCOUNTING_WRITE_REVISION = 3`)
//! inside a `BEGIN IMMEDIATE` write lock and restores them before `COMMIT`.
//! Any out-of-band raw SQL mutation therefore trips the dirty bit (`0`) and
//! forces a full table + hash-chain + byte-ledger verification pass on next open.

use crate::models::StoreResult;
use sqlx::{Row, SqliteConnection};

pub(crate) const STORAGE_GUARD_REVISION_MARKER: &str = "coop-storage-guard-r3";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccountingGuardGeneration {
    CurrentRevisionTwo,
    RepairableRevisionOne,
    StorageOnlyRevisionTwo,
    Invalid,
}

pub(crate) const STORAGE_GUARD_NAMES: [&str; 24] = [
    "coop_schema_migrations_storage_guard_insert",
    "coop_schema_migrations_storage_guard_update",
    "coop_schema_migrations_storage_guard_delete",
    "coop_jobs_storage_guard_insert",
    "coop_jobs_storage_guard_update",
    "coop_events_storage_guard_insert",
    "coop_events_storage_guard_update",
    "coop_events_sequence_guard_insert",
    "coop_jobs_validation_dirty_insert",
    "coop_jobs_validation_dirty_update",
    "coop_jobs_validation_dirty_delete",
    "coop_events_validation_dirty_insert",
    "coop_events_validation_dirty_update",
    "coop_events_validation_dirty_delete",
    "coop_attestations_storage_guard_insert",
    "coop_attestations_storage_guard_update",
    "coop_attestations_validation_dirty_insert",
    "coop_attestations_validation_dirty_update",
    "coop_attestations_validation_dirty_delete",
    "coop_attestation_outbox_storage_guard_insert",
    "coop_attestation_outbox_storage_guard_update",
    "coop_attestation_outbox_validation_dirty_insert",
    "coop_attestation_outbox_validation_dirty_update",
    "coop_attestation_outbox_validation_dirty_delete",
];

pub(crate) const ACCOUNTING_GUARD_NAMES: [&str; 26] = [
    "coop_usage_aggregate_insert",
    "coop_usage_aggregate_update",
    "coop_usage_aggregate_delete",
    "coop_job_storage_guard_insert",
    "coop_job_storage_guard_update",
    "coop_job_storage_dirty_insert",
    "coop_job_storage_dirty_update",
    "coop_job_storage_dirty_delete",
    "coop_total_storage_guard_insert",
    "coop_total_storage_guard_update",
    "coop_total_storage_dirty_insert",
    "coop_total_storage_dirty_update",
    "coop_total_storage_dirty_delete",
    "coop_tenant_storage_guard_insert",
    "coop_tenant_storage_guard_update",
    "coop_tenant_storage_dirty_insert",
    "coop_tenant_storage_dirty_update",
    "coop_tenant_storage_dirty_delete",
    "coop_idempotency_storage_guard_insert",
    "coop_idempotency_storage_guard_update",
    "coop_idempotency_dirty_insert",
    "coop_idempotency_dirty_update",
    "coop_idempotency_dirty_delete",
    "coop_tombstone_dirty_insert",
    "coop_tombstone_dirty_update",
    "coop_tombstone_dirty_delete",
];

pub(crate) fn normalize_trigger_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

pub(crate) fn accounting_trigger_statements() -> [&'static str; 26] {
    [
        "CREATE TRIGGER coop_usage_aggregate_insert
         AFTER INSERT ON job_storage_usage
         WHEN 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2' BEGIN
             UPDATE storage_usage_total
             SET charged_bytes = charged_bytes + NEW.retained_bytes + NEW.reserved_bytes
             WHERE singleton = 1;
             INSERT INTO tenant_storage_usage(tenant, charged_bytes)
             VALUES (NEW.tenant, NEW.retained_bytes + NEW.reserved_bytes)
             ON CONFLICT(tenant) DO UPDATE SET
                 charged_bytes = charged_bytes + excluded.charged_bytes;
         END",
        "CREATE TRIGGER coop_usage_aggregate_update
         AFTER UPDATE OF retained_bytes, reserved_bytes ON job_storage_usage
         WHEN 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2' BEGIN
             UPDATE storage_usage_total
             SET charged_bytes = charged_bytes
                 + (NEW.retained_bytes + NEW.reserved_bytes)
                 - (OLD.retained_bytes + OLD.reserved_bytes)
             WHERE singleton = 1;
             UPDATE tenant_storage_usage
             SET charged_bytes = charged_bytes
                 + (NEW.retained_bytes + NEW.reserved_bytes)
                 - (OLD.retained_bytes + OLD.reserved_bytes)
             WHERE tenant = NEW.tenant;
         END",
        "CREATE TRIGGER coop_usage_aggregate_delete
         AFTER DELETE ON job_storage_usage
         WHEN 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2' BEGIN
             UPDATE storage_usage_total
             SET charged_bytes = charged_bytes - OLD.retained_bytes - OLD.reserved_bytes
             WHERE singleton = 1;
             UPDATE tenant_storage_usage
             SET charged_bytes = charged_bytes - OLD.retained_bytes - OLD.reserved_bytes
             WHERE tenant = OLD.tenant;
             DELETE FROM tenant_storage_usage
             WHERE tenant = OLD.tenant AND charged_bytes = 0;
         END",
        "CREATE TRIGGER coop_job_storage_guard_insert
         BEFORE INSERT ON job_storage_usage
         WHEN typeof(NEW.job_id) != 'text' OR length(trim(NEW.job_id)) = 0
           OR typeof(NEW.tenant) != 'text' OR length(trim(NEW.tenant)) = 0
           OR typeof(NEW.retained_bytes) != 'integer' OR NEW.retained_bytes < 0
           OR typeof(NEW.reserved_bytes) != 'integer' OR NEW.reserved_bytes < 0
           OR typeof(NEW.requested_mem_mb) != 'integer'
           OR NEW.requested_mem_mb NOT BETWEEN 16 AND 4096
         BEGIN
             SELECT RAISE(ABORT, 'invalid job_storage_usage [coop-accounting-guard-r2]');
         END",
        "CREATE TRIGGER coop_job_storage_guard_update
         BEFORE UPDATE ON job_storage_usage
         WHEN NEW.job_id != OLD.job_id OR NEW.tenant != OLD.tenant
           OR NEW.requested_mem_mb != OLD.requested_mem_mb
           OR typeof(NEW.retained_bytes) != 'integer' OR NEW.retained_bytes < 0
           OR typeof(NEW.reserved_bytes) != 'integer' OR NEW.reserved_bytes < 0
         BEGIN
             SELECT RAISE(ABORT, 'immutable or invalid job_storage_usage [coop-accounting-guard-r2]');
         END",
        "CREATE TRIGGER coop_job_storage_dirty_insert AFTER INSERT ON job_storage_usage BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_job_storage_dirty_update AFTER UPDATE ON job_storage_usage BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_job_storage_dirty_delete AFTER DELETE ON job_storage_usage BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_total_storage_guard_insert BEFORE INSERT ON storage_usage_total
         WHEN typeof(NEW.singleton) != 'integer' OR NEW.singleton != 1
           OR typeof(NEW.charged_bytes) != 'integer' OR NEW.charged_bytes < 0
         BEGIN
             SELECT RAISE(ABORT, 'invalid storage_usage_total [coop-accounting-guard-r2]');
         END",
        "CREATE TRIGGER coop_total_storage_guard_update BEFORE UPDATE ON storage_usage_total
         WHEN NEW.singleton != OLD.singleton
           OR typeof(NEW.charged_bytes) != 'integer' OR NEW.charged_bytes < 0
         BEGIN
             SELECT RAISE(ABORT, 'immutable or invalid storage_usage_total [coop-accounting-guard-r2]');
         END",
        "CREATE TRIGGER coop_total_storage_dirty_insert AFTER INSERT ON storage_usage_total BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_total_storage_dirty_update AFTER UPDATE ON storage_usage_total BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_total_storage_dirty_delete AFTER DELETE ON storage_usage_total BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_tenant_storage_guard_insert BEFORE INSERT ON tenant_storage_usage
         WHEN typeof(NEW.tenant) != 'text' OR length(trim(NEW.tenant)) = 0
           OR typeof(NEW.charged_bytes) != 'integer' OR NEW.charged_bytes < 0
         BEGIN
             SELECT RAISE(ABORT, 'invalid tenant_storage_usage [coop-accounting-guard-r2]');
         END",
        "CREATE TRIGGER coop_tenant_storage_guard_update BEFORE UPDATE ON tenant_storage_usage
         WHEN NEW.tenant != OLD.tenant
           OR typeof(NEW.charged_bytes) != 'integer' OR NEW.charged_bytes < 0
         BEGIN
             SELECT RAISE(ABORT, 'immutable or invalid tenant_storage_usage [coop-accounting-guard-r2]');
         END",
        "CREATE TRIGGER coop_tenant_storage_dirty_insert AFTER INSERT ON tenant_storage_usage BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_tenant_storage_dirty_update AFTER UPDATE ON tenant_storage_usage BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_tenant_storage_dirty_delete AFTER DELETE ON tenant_storage_usage BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_idempotency_storage_guard_insert BEFORE INSERT ON idempotency_keys
         WHEN typeof(NEW.tenant) != 'text' OR length(trim(NEW.tenant)) = 0
           OR typeof(NEW.idempotency_key) != 'text'
           OR length(NEW.idempotency_key) NOT BETWEEN 1 AND 128
           OR typeof(NEW.request_sha256) != 'text' OR length(NEW.request_sha256) != 64
           OR NEW.request_sha256 GLOB '*[^0-9a-f]*'
           OR typeof(NEW.job_id) != 'text' OR length(trim(NEW.job_id)) = 0
           OR typeof(NEW.created_at_ms) != 'integer' OR NEW.created_at_ms < 0
         BEGIN
             SELECT RAISE(ABORT, 'invalid idempotency_keys [coop-accounting-guard-r2]');
         END",
        "CREATE TRIGGER coop_idempotency_storage_guard_update BEFORE UPDATE ON idempotency_keys
         WHEN NEW.tenant != OLD.tenant OR NEW.idempotency_key != OLD.idempotency_key
           OR NEW.request_sha256 != OLD.request_sha256 OR NEW.job_id != OLD.job_id
           OR NEW.created_at_ms != OLD.created_at_ms
         BEGIN
             SELECT RAISE(ABORT, 'idempotency mapping is immutable [coop-accounting-guard-r2]');
         END",
        "CREATE TRIGGER coop_idempotency_dirty_insert AFTER INSERT ON idempotency_keys BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_idempotency_dirty_update AFTER UPDATE ON idempotency_keys BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_idempotency_dirty_delete AFTER DELETE ON idempotency_keys BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_tombstone_dirty_insert AFTER INSERT ON retention_tombstones BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_tombstone_dirty_update AFTER UPDATE ON retention_tombstones BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
        "CREATE TRIGGER coop_tombstone_dirty_delete AFTER DELETE ON retention_tombstones BEGIN
             UPDATE store_integrity SET accounting_validation_revision = 0
             WHERE singleton = 1 AND accounting_validation_revision != 3
               AND 'coop-accounting-guard-r2' = 'coop-accounting-guard-r2';
         END",
    ]
}

pub(crate) async fn accounting_guard_generation(
    conn: &mut SqliteConnection,
) -> StoreResult<AccountingGuardGeneration> {
    let rows = sqlx::query("SELECT name, sql FROM sqlite_schema WHERE type = 'trigger'")
        .fetch_all(&mut *conn)
        .await?;
    // The exact r1 set is a trusted predecessor, not an arbitrary stale
    // definition. Accept it only as a complete set so revision-1 ledgers can
    // be rebuilt once before these triggers are recreated as r2 below.
    let mut all_current = true;
    let mut all_repairable_revision_one = true;
    let mut all_storage_only_revision_two = true;
    for expected in accounting_trigger_statements() {
        let expected_name = expected
            .split_whitespace()
            .nth(2)
            .expect("CREATE TRIGGER name");
        let Some(row) = rows
            .iter()
            .find(|row| row.get::<String, _>("name") == expected_name)
        else {
            return Ok(AccountingGuardGeneration::Invalid);
        };
        let actual: String = row.try_get("sql")?;
        let normalized_actual = normalize_trigger_sql(&actual);
        all_current &= normalized_actual == normalize_trigger_sql(expected);
        let revision_one = expected
            .replace("coop-accounting-guard-r2", "coop-accounting-guard-r1")
            .replace(
                "accounting_validation_revision != 3",
                "accounting_validation_revision != 2",
            );
        all_repairable_revision_one &= normalized_actual == normalize_trigger_sql(&revision_one);
        let storage_only_revision_two =
            expected.replace("coop-accounting-guard-r2", "coop-accounting-guard-r1");
        all_storage_only_revision_two &=
            normalized_actual == normalize_trigger_sql(&storage_only_revision_two);
    }
    Ok(if all_current {
        AccountingGuardGeneration::CurrentRevisionTwo
    } else if all_repairable_revision_one {
        AccountingGuardGeneration::RepairableRevisionOne
    } else if all_storage_only_revision_two {
        AccountingGuardGeneration::StorageOnlyRevisionTwo
    } else {
        AccountingGuardGeneration::Invalid
    })
}

pub(crate) async fn drop_accounting_guard_triggers(conn: &mut SqliteConnection) -> StoreResult<()> {
    for trigger in ACCOUNTING_GUARD_NAMES {
        sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger}"))
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

pub(crate) async fn create_accounting_guard_triggers(
    conn: &mut SqliteConnection,
) -> StoreResult<()> {
    for statement in accounting_trigger_statements() {
        sqlx::query(statement).execute(&mut *conn).await?;
    }
    Ok(())
}

pub(crate) async fn create_storage_guard_triggers(conn: &mut SqliteConnection) -> StoreResult<()> {
    // These names are owned by Rookhold. Recreate them transactionally on every
    // open so a stale same-version definition cannot silently weaken newly
    // added invariants.
    for trigger in STORAGE_GUARD_NAMES {
        sqlx::query(&format!("DROP TRIGGER IF EXISTS {trigger}"))
            .execute(&mut *conn)
            .await?;
    }
    for statement in [
        "CREATE TRIGGER IF NOT EXISTS coop_schema_migrations_storage_guard_insert
         BEFORE INSERT ON schema_migrations
         WHEN typeof(NEW.version) != 'integer' OR NEW.version <= 0
           OR typeof(NEW.applied_at_ms) != 'integer' OR NEW.applied_at_ms < 0
         BEGIN
             SELECT RAISE(ABORT, 'invalid schema_migrations storage class [coop-storage-guard-r3]');
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_schema_migrations_storage_guard_update
         BEFORE UPDATE ON schema_migrations
         WHEN NEW.version != OLD.version OR NEW.applied_at_ms != OLD.applied_at_ms
           OR typeof(NEW.version) != 'integer' OR NEW.version <= 0
           OR typeof(NEW.applied_at_ms) != 'integer' OR NEW.applied_at_ms < 0
         BEGIN
             SELECT RAISE(ABORT, 'invalid schema_migrations storage class [coop-storage-guard-r3]');
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_schema_migrations_storage_guard_delete
         BEFORE DELETE ON schema_migrations BEGIN
             SELECT RAISE(ABORT, 'schema migration history is immutable [coop-storage-guard-r3]');
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_jobs_storage_guard_insert
         BEFORE INSERT ON jobs
         WHEN typeof(NEW.job_id) != 'text' OR length(trim(NEW.job_id)) = 0
           OR typeof(NEW.tenant) != 'text' OR length(trim(NEW.tenant)) = 0
           OR typeof(NEW.language) != 'text' OR length(trim(NEW.language)) = 0
           OR typeof(NEW.status) != 'text'
           OR NEW.status NOT IN ('queued','running','succeeded','failed','timed_out','oom_killed','cancelled','error')
           OR typeof(NEW.spec_json) != 'text' OR NOT json_valid(NEW.spec_json)
           OR typeof(NEW.admitted_mem_mb) != 'integer'
           OR NEW.admitted_mem_mb NOT BETWEEN 16 AND 4096
           OR (NEW.effective_spec_json IS NOT NULL AND
               (typeof(NEW.effective_spec_json) != 'text' OR NOT json_valid(NEW.effective_spec_json)))
           OR (NEW.receipt_json IS NOT NULL AND
               (typeof(NEW.receipt_json) != 'text' OR NOT json_valid(NEW.receipt_json)))
           OR typeof(NEW.created_at_ms) != 'integer' OR NEW.created_at_ms < 0
           OR (NEW.started_at_ms IS NOT NULL AND
               (typeof(NEW.started_at_ms) != 'integer' OR NEW.started_at_ms < 0))
           OR (NEW.finished_at_ms IS NOT NULL AND
               (typeof(NEW.finished_at_ms) != 'integer' OR NEW.finished_at_ms < 0))
           OR (NEW.exit_code IS NOT NULL AND
               (typeof(NEW.exit_code) != 'integer' OR
                NEW.exit_code < -2147483648 OR NEW.exit_code > 2147483647))
           OR (NEW.status = 'queued' AND
               (NEW.started_at_ms IS NOT NULL OR NEW.finished_at_ms IS NOT NULL))
           OR (NEW.status = 'running' AND
               (NEW.started_at_ms IS NULL OR NEW.finished_at_ms IS NOT NULL))
           OR (NEW.status NOT IN ('queued','running') AND NEW.finished_at_ms IS NULL)
         BEGIN
             SELECT RAISE(ABORT, 'invalid jobs storage class [coop-storage-guard-r3]');
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_jobs_storage_guard_update
         BEFORE UPDATE ON jobs
         WHEN NEW.job_id != OLD.job_id OR NEW.tenant != OLD.tenant
           OR NEW.language != OLD.language OR NEW.spec_json != OLD.spec_json
           OR NEW.created_at_ms != OLD.created_at_ms
           OR NEW.admitted_mem_mb != OLD.admitted_mem_mb
           OR typeof(NEW.job_id) != 'text' OR length(trim(NEW.job_id)) = 0
           OR typeof(NEW.tenant) != 'text' OR length(trim(NEW.tenant)) = 0
           OR typeof(NEW.language) != 'text' OR length(trim(NEW.language)) = 0
           OR typeof(NEW.status) != 'text'
           OR NEW.status NOT IN ('queued','running','succeeded','failed','timed_out','oom_killed','cancelled','error')
           OR typeof(NEW.spec_json) != 'text' OR NOT json_valid(NEW.spec_json)
           OR typeof(NEW.admitted_mem_mb) != 'integer'
           OR NEW.admitted_mem_mb NOT BETWEEN 16 AND 4096
           OR (NEW.effective_spec_json IS NOT NULL AND
               (typeof(NEW.effective_spec_json) != 'text' OR NOT json_valid(NEW.effective_spec_json)))
           OR (NEW.receipt_json IS NOT NULL AND
               (typeof(NEW.receipt_json) != 'text' OR NOT json_valid(NEW.receipt_json)))
           OR typeof(NEW.created_at_ms) != 'integer' OR NEW.created_at_ms < 0
           OR (NEW.started_at_ms IS NOT NULL AND
               (typeof(NEW.started_at_ms) != 'integer' OR NEW.started_at_ms < 0))
           OR (NEW.finished_at_ms IS NOT NULL AND
               (typeof(NEW.finished_at_ms) != 'integer' OR NEW.finished_at_ms < 0))
           OR (NEW.exit_code IS NOT NULL AND
               (typeof(NEW.exit_code) != 'integer' OR
                NEW.exit_code < -2147483648 OR NEW.exit_code > 2147483647))
           OR (NEW.status = 'queued' AND
               (NEW.started_at_ms IS NOT NULL OR NEW.finished_at_ms IS NOT NULL))
           OR (NEW.status = 'running' AND
               (NEW.started_at_ms IS NULL OR NEW.finished_at_ms IS NOT NULL))
           OR (NEW.status NOT IN ('queued','running') AND NEW.finished_at_ms IS NULL)
         BEGIN
             SELECT RAISE(ABORT, 'invalid jobs storage class [coop-storage-guard-r3]');
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_events_storage_guard_insert
         BEFORE INSERT ON events
         WHEN typeof(NEW.job_id) != 'text'
           OR typeof(NEW.ts_ms) != 'integer' OR NEW.ts_ms < 0
           OR typeof(NEW.kind) != 'text' OR length(trim(NEW.kind)) = 0
           OR typeof(NEW.data_json) != 'text' OR NOT json_valid(NEW.data_json)
           OR typeof(NEW.prev_hash) != 'text'
           OR typeof(NEW.event_hash) != 'text'
           OR typeof(NEW.hash_version) != 'integer' OR NEW.hash_version NOT IN (0, 1)
           OR (NEW.hash_version = 1 AND length(NEW.event_hash) != 64)
         BEGIN
             SELECT RAISE(ABORT, 'invalid events storage class [coop-storage-guard-r3]');
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_events_storage_guard_update
         BEFORE UPDATE ON events
         WHEN NEW.seq != OLD.seq OR NEW.job_id != OLD.job_id
           OR NEW.ts_ms != OLD.ts_ms OR NEW.kind != OLD.kind
           OR NEW.data_json != OLD.data_json OR NEW.prev_hash != OLD.prev_hash
           OR (OLD.hash_version = 1 AND
               (NEW.event_hash != OLD.event_hash OR NEW.hash_version != OLD.hash_version))
           OR typeof(NEW.seq) != 'integer'
           OR NEW.seq <= 0 OR NEW.seq >= 9223372036854775807
           OR typeof(NEW.job_id) != 'text'
           OR typeof(NEW.ts_ms) != 'integer' OR NEW.ts_ms < 0
           OR typeof(NEW.kind) != 'text' OR length(trim(NEW.kind)) = 0
           OR typeof(NEW.data_json) != 'text' OR NOT json_valid(NEW.data_json)
           OR typeof(NEW.prev_hash) != 'text'
           OR typeof(NEW.event_hash) != 'text'
           OR typeof(NEW.hash_version) != 'integer' OR NEW.hash_version NOT IN (0, 1)
           OR (NEW.hash_version = 1 AND length(NEW.event_hash) != 64)
         BEGIN
             SELECT RAISE(ABORT, 'invalid events storage class [coop-storage-guard-r3]');
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_events_sequence_guard_insert
         AFTER INSERT ON events
         WHEN typeof(NEW.seq) != 'integer'
           OR NEW.seq <= 0 OR NEW.seq >= 9223372036854775807
         BEGIN
             SELECT RAISE(ABORT, 'invalid event sequence [coop-storage-guard-r3]');
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_jobs_validation_dirty_insert
         AFTER INSERT ON jobs BEGIN
             UPDATE store_integrity
             SET row_validation_revision = 0, accounting_validation_revision = 0
             WHERE singleton = 1
               AND row_validation_revision != 4
               AND 'coop-storage-guard-r3' = 'coop-storage-guard-r3';
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_jobs_validation_dirty_update
         AFTER UPDATE ON jobs BEGIN
             UPDATE store_integrity
             SET row_validation_revision = 0, accounting_validation_revision = 0
             WHERE singleton = 1
               AND row_validation_revision != 4
               AND 'coop-storage-guard-r3' = 'coop-storage-guard-r3';
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_jobs_validation_dirty_delete
         AFTER DELETE ON jobs BEGIN
             UPDATE store_integrity
             SET row_validation_revision = 0, accounting_validation_revision = 0
             WHERE singleton = 1
               AND row_validation_revision != 4
               AND 'coop-storage-guard-r3' = 'coop-storage-guard-r3';
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_events_validation_dirty_insert
         AFTER INSERT ON events BEGIN
             UPDATE store_integrity
             SET row_validation_revision = 0, accounting_validation_revision = 0
             WHERE singleton = 1
               AND row_validation_revision != 4
               AND 'coop-storage-guard-r3' = 'coop-storage-guard-r3';
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_events_validation_dirty_update
         AFTER UPDATE ON events BEGIN
             UPDATE store_integrity
             SET row_validation_revision = 0, accounting_validation_revision = 0
             WHERE singleton = 1
               AND row_validation_revision != 4
               AND 'coop-storage-guard-r3' = 'coop-storage-guard-r3';
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_events_validation_dirty_delete
         AFTER DELETE ON events BEGIN
             UPDATE store_integrity
             SET row_validation_revision = 0, accounting_validation_revision = 0
             WHERE singleton = 1
               AND row_validation_revision != 4
               AND 'coop-storage-guard-r3' = 'coop-storage-guard-r3';
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_attestations_storage_guard_insert
         BEFORE INSERT ON job_attestations
         WHEN typeof(NEW.job_id) != 'text' OR length(trim(NEW.job_id)) = 0
           OR typeof(NEW.receipt_sha256) != 'text'
           OR length(NEW.receipt_sha256) != 64
           OR NEW.receipt_sha256 GLOB '*[^0-9a-f]*'
           OR typeof(NEW.result_media_type) != 'text'
           OR length(trim(NEW.result_media_type)) NOT BETWEEN 1 AND 255
           OR typeof(NEW.result_artifact) != 'blob'
           OR length(NEW.result_artifact) NOT BETWEEN 1 AND 16777216
           OR NOT json_valid(CAST(NEW.result_artifact AS TEXT))
           OR typeof(NEW.result_sha256) != 'text'
           OR length(NEW.result_sha256) != 64
           OR NEW.result_sha256 GLOB '*[^0-9a-f]*'
           OR typeof(NEW.envelope_json) != 'blob'
           OR length(NEW.envelope_json) NOT BETWEEN 1 AND 2097152
           OR NOT json_valid(CAST(NEW.envelope_json AS TEXT))
           OR typeof(NEW.envelope_sha256) != 'text'
           OR length(NEW.envelope_sha256) != 64
           OR NEW.envelope_sha256 GLOB '*[^0-9a-f]*'
           OR typeof(NEW.key_id) != 'text'
           OR length(trim(NEW.key_id)) NOT BETWEEN 1 AND 256
           OR typeof(NEW.created_at_ms) != 'integer' OR NEW.created_at_ms < 0
         BEGIN
             SELECT RAISE(ABORT, 'invalid job_attestations storage class [coop-storage-guard-r3]');
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_attestations_storage_guard_update
         BEFORE UPDATE ON job_attestations
         WHEN NEW.job_id != OLD.job_id
           OR NEW.receipt_sha256 != OLD.receipt_sha256
           OR NEW.result_media_type != OLD.result_media_type
           OR NEW.result_artifact != OLD.result_artifact
           OR NEW.result_sha256 != OLD.result_sha256
           OR NEW.envelope_json != OLD.envelope_json
           OR NEW.envelope_sha256 != OLD.envelope_sha256
           OR NEW.key_id != OLD.key_id
           OR NEW.created_at_ms != OLD.created_at_ms
           OR typeof(NEW.job_id) != 'text' OR length(trim(NEW.job_id)) = 0
           OR typeof(NEW.receipt_sha256) != 'text'
           OR length(NEW.receipt_sha256) != 64
           OR NEW.receipt_sha256 GLOB '*[^0-9a-f]*'
           OR typeof(NEW.result_media_type) != 'text'
           OR length(trim(NEW.result_media_type)) NOT BETWEEN 1 AND 255
           OR typeof(NEW.result_artifact) != 'blob'
           OR length(NEW.result_artifact) NOT BETWEEN 1 AND 16777216
           OR NOT json_valid(CAST(NEW.result_artifact AS TEXT))
           OR typeof(NEW.result_sha256) != 'text'
           OR length(NEW.result_sha256) != 64
           OR NEW.result_sha256 GLOB '*[^0-9a-f]*'
           OR typeof(NEW.envelope_json) != 'blob'
           OR length(NEW.envelope_json) NOT BETWEEN 1 AND 2097152
           OR NOT json_valid(CAST(NEW.envelope_json AS TEXT))
           OR typeof(NEW.envelope_sha256) != 'text'
           OR length(NEW.envelope_sha256) != 64
           OR NEW.envelope_sha256 GLOB '*[^0-9a-f]*'
           OR typeof(NEW.key_id) != 'text'
           OR length(trim(NEW.key_id)) NOT BETWEEN 1 AND 256
           OR typeof(NEW.created_at_ms) != 'integer' OR NEW.created_at_ms < 0
         BEGIN
             SELECT RAISE(ABORT, 'invalid job_attestations storage class [coop-storage-guard-r3]');
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_attestations_validation_dirty_insert
         AFTER INSERT ON job_attestations BEGIN
             UPDATE store_integrity
             SET row_validation_revision = 0, accounting_validation_revision = 0
             WHERE singleton = 1
               AND row_validation_revision != 4
               AND 'coop-storage-guard-r3' = 'coop-storage-guard-r3';
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_attestations_validation_dirty_update
         AFTER UPDATE ON job_attestations BEGIN
             UPDATE store_integrity
             SET row_validation_revision = 0, accounting_validation_revision = 0
             WHERE singleton = 1
               AND row_validation_revision != 4
               AND 'coop-storage-guard-r3' = 'coop-storage-guard-r3';
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_attestations_validation_dirty_delete
         AFTER DELETE ON job_attestations BEGIN
             UPDATE store_integrity
             SET row_validation_revision = 0, accounting_validation_revision = 0
             WHERE singleton = 1
               AND row_validation_revision != 4
               AND 'coop-storage-guard-r3' = 'coop-storage-guard-r3';
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_attestation_outbox_storage_guard_insert
         BEFORE INSERT ON attestation_outbox
         WHEN typeof(NEW.job_id) != 'text' OR length(trim(NEW.job_id)) = 0
           OR typeof(NEW.pending_since_ms) != 'integer' OR NEW.pending_since_ms < 0
           OR typeof(NEW.attempt_count) != 'integer'
           OR NEW.attempt_count NOT BETWEEN 0 AND 2147483647
           OR typeof(NEW.next_attempt_ms) != 'integer' OR NEW.next_attempt_ms < 0
         BEGIN
             SELECT RAISE(ABORT, 'invalid attestation_outbox storage class [coop-storage-guard-r3]');
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_attestation_outbox_storage_guard_update
         BEFORE UPDATE ON attestation_outbox
         WHEN NEW.job_id != OLD.job_id OR NEW.pending_since_ms != OLD.pending_since_ms
           OR typeof(NEW.job_id) != 'text' OR length(trim(NEW.job_id)) = 0
           OR typeof(NEW.pending_since_ms) != 'integer' OR NEW.pending_since_ms < 0
           OR typeof(NEW.attempt_count) != 'integer'
           OR NEW.attempt_count NOT BETWEEN 0 AND 2147483647
           OR typeof(NEW.next_attempt_ms) != 'integer' OR NEW.next_attempt_ms < 0
         BEGIN
             SELECT RAISE(ABORT, 'invalid attestation_outbox storage class [coop-storage-guard-r3]');
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_attestation_outbox_validation_dirty_insert
         AFTER INSERT ON attestation_outbox BEGIN
             UPDATE store_integrity
             SET row_validation_revision = 0, accounting_validation_revision = 0
             WHERE singleton = 1
               AND row_validation_revision != 4
               AND 'coop-storage-guard-r3' = 'coop-storage-guard-r3';
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_attestation_outbox_validation_dirty_update
         AFTER UPDATE ON attestation_outbox BEGIN
             UPDATE store_integrity
             SET row_validation_revision = 0, accounting_validation_revision = 0
             WHERE singleton = 1
               AND row_validation_revision != 4
               AND 'coop-storage-guard-r3' = 'coop-storage-guard-r3';
         END",
        "CREATE TRIGGER IF NOT EXISTS coop_attestation_outbox_validation_dirty_delete
         AFTER DELETE ON attestation_outbox BEGIN
             UPDATE store_integrity
             SET row_validation_revision = 0, accounting_validation_revision = 0
             WHERE singleton = 1
               AND row_validation_revision != 4
               AND 'coop-storage-guard-r3' = 'coop-storage-guard-r3';
         END",
    ] {
        sqlx::query(statement).execute(&mut *conn).await?;
    }
    Ok(())
}
