//! Canonical JSON serialization, tamper-evident event-chain hashing, and
//! portable attestation identity binding.
//!
//! # Architectural Note: Length-Prefixed Event Hash Chain
//!
//! Every job's operational event log forms a per-job hash chain (`prev_hash` ->
//! `event_hash`). To prevent canonicalization ambiguity or field-boundary
//! concatenation attacks (where `("ab", "c")` collides with `("a", "bc")`),
//! `compute_event_hash` prefixes every variable-length field with its 64-bit
//! big-endian byte length under the `coop:event-chain:v1\0` domain separator,
//! and serializes `data` using lexicographically sorted `canonical_json`.
//! The terminal receipt then binds the chain head (`event_chain.head`) into
//! `receipt_sha256`, which is in turn signed inside the DSSE/in-toto statement.

use crate::models::{
    AttestationMetadata, EventChainHead, EventRow, StoreResult, COOP_EXECUTION_PREDICATE_TYPE,
    DSSE_PAYLOAD_TYPE, IN_TOTO_STATEMENT_TYPE,
};
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE};
use base64::Engine as _;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::fmt::Write as _;

pub(crate) fn recovery_receipt_details(
    requested_spec_json: &str,
    _effective_spec_json: Option<&str>,
    created_at_ms: i64,
    started_at_ms: Option<i64>,
) -> Value {
    let requested = serde_json::from_str::<Value>(requested_spec_json).unwrap_or(Value::Null);
    let mut details = Map::from_iter([
        ("terminal_reason".to_string(), json!("server_restarted")),
        ("killed_by".to_string(), json!("server_restarted")),
        ("created_at_ms".to_string(), json!(created_at_ms)),
        ("started_at_ms".to_string(), json!(started_at_ms)),
        ("evidence_complete".to_string(), json!(false)),
    ]);

    // Static request evidence remains knowable after a restart. Only include
    // members whose stored value has the SDK's documented non-null type;
    // execution/output observations that were lost with the process are
    // omitted rather than fabricated as nulls or zeroes.
    if let Some(limits @ Value::Object(_)) = requested.get("limits") {
        details.insert("requested_limits".to_string(), limits.clone());
    }
    // The configured execution plan survived, but whether its controls ever
    // became active did not. Recovery therefore preserves requested policy
    // only and deliberately omits effective limits/enforcement provenance.
    if let Some(code) = requested.get("code").and_then(Value::as_str) {
        details.insert(
            "code_sha256".to_string(),
            json!(sha256_hex(code.as_bytes())),
        );
    }
    if let Some(object) = requested.as_object() {
        let stdin = object.get("stdin").and_then(Value::as_str).unwrap_or("");
        details.insert(
            "stdin_sha256".to_string(),
            json!(sha256_hex(stdin.as_bytes())),
        );
    }

    Value::Object(details)
}

pub(crate) struct ReceiptCore<'a> {
    pub(crate) job_id: &'a str,
    pub(crate) status: &'a str,
    pub(crate) exit_code: Option<i32>,
    pub(crate) created_at_ms: i64,
    pub(crate) started_at_ms: Option<i64>,
    pub(crate) finished_at_ms: i64,
    pub(crate) duration_ms: i64,
}

pub(crate) fn receipt_with_chain(
    receipt: Option<&Value>,
    chain: &EventChainHead,
    core: ReceiptCore<'_>,
) -> String {
    let mut object = match receipt {
        Some(Value::Object(object)) => object.clone(),
        Some(other) => {
            let mut object = Map::new();
            object.insert("details".to_string(), other.clone());
            object
        }
        None => Map::new(),
    };
    // Never incorporate a caller-supplied digest into the digest input.
    object.remove("receipt_sha256");
    // These values come from the same transaction as the job row and final
    // event. Overwrite caller estimates so an exported receipt always agrees
    // exactly with the durable evidence.
    object.insert("version".to_string(), json!(1));
    object.insert("job_id".to_string(), json!(core.job_id));
    object.insert("outcome".to_string(), json!(core.status));
    object.insert("exit_code".to_string(), json!(core.exit_code));
    object.insert("created_at_ms".to_string(), json!(core.created_at_ms));
    object.insert("started_at_ms".to_string(), json!(core.started_at_ms));
    object.insert("finished_at_ms".to_string(), json!(core.finished_at_ms));
    object.insert("duration_ms".to_string(), json!(core.duration_ms.max(0)));
    object.insert(
        "event_chain".to_string(),
        json!({
            "version": 1,
            "head": chain.head_hash,
            "events": chain.event_count,
            "event_count": chain.event_count,
            "verified_events": chain.verified_event_count,
            "legacy_events": chain.legacy_event_count,
            "complete": chain.legacy_event_count == 0
                && chain.verified_event_count == chain.event_count,
        }),
    );
    let digest = compute_receipt_sha256(&Value::Object(object.clone()));
    object.insert("receipt_sha256".to_string(), Value::String(digest));
    canonical_json(&Value::Object(object))
}

pub(crate) fn row_to_event(row: sqlx::sqlite::SqliteRow) -> StoreResult<EventRow> {
    let data_json: String = row.try_get("data_json")?;
    let data =
        serde_json::from_str(&data_json).map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
    Ok(EventRow {
        seq: row.try_get("seq")?,
        ts_ms: row.try_get("ts_ms")?,
        kind: row.try_get("kind")?,
        data,
        prev_hash: row.try_get("prev_hash")?,
        event_hash: row.try_get("event_hash")?,
        hash_version: row.try_get("hash_version")?,
    })
}

pub(crate) fn row_to_attestation_metadata(
    row: &sqlx::sqlite::SqliteRow,
) -> StoreResult<AttestationMetadata> {
    let result_size = row.try_get::<i64, _>("result_size_bytes")?;
    let envelope_size = row.try_get::<i64, _>("envelope_size_bytes")?;
    Ok(AttestationMetadata {
        job_id: row.try_get("job_id")?,
        receipt_sha256: row.try_get("receipt_sha256")?,
        result_media_type: row.try_get("result_media_type")?,
        result_sha256: row.try_get("result_sha256")?,
        result_size_bytes: u64::try_from(result_size).map_err(|_| {
            sqlx::Error::Protocol("result artifact length became negative".to_string())
        })?,
        envelope_sha256: row.try_get("envelope_sha256")?,
        envelope_size_bytes: u64::try_from(envelope_size).map_err(|_| {
            sqlx::Error::Protocol("attestation envelope length became negative".to_string())
        })?,
        key_id: row.try_get("key_id")?,
        created_at_ms: row.try_get("created_at_ms")?,
    })
}

pub(crate) fn is_terminal_status(status: &str) -> bool {
    matches!(
        status,
        "succeeded" | "failed" | "timed_out" | "oom_killed" | "cancelled" | "error"
    )
}

/// Canonical JSON used for receipt persistence and event hashing. Object keys
/// are sorted lexicographically regardless of serde_json's map backend.
pub fn canonical_json(value: &Value) -> String {
    let mut output = String::new();
    write_canonical_json(value, &mut output);
    output
}

/// Compute the receipt's portable integrity digest. The `receipt_sha256`
/// member itself is excluded, allowing callers to verify a stored receipt by
/// parsing it and comparing this result with the member. This is an integrity
/// checksum, not a signature or proof against a database administrator.
pub fn compute_receipt_sha256(receipt: &Value) -> String {
    let unsigned = match receipt {
        Value::Object(object) => {
            let mut object = object.clone();
            object.remove("receipt_sha256");
            Value::Object(object)
        }
        other => other.clone(),
    };
    let canonical = canonical_json(&unsigned);
    sha256_hex(canonical.as_bytes())
}

fn write_canonical_json(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => {
            output.push_str(&serde_json::to_string(value).expect("JSON strings always serialize"));
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json(value, output);
            }
            output.push(']');
        }
        Value::Object(object) => {
            output.push('{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key).expect("JSON object keys always serialize"),
                );
                output.push(':');
                write_canonical_json(&object[key], output);
            }
            output.push('}');
        }
    }
}

/// v1 digest input is length-delimited and architecture-independent:
/// domain separator, job id, previous hash, signed big-endian seq/time, event
/// kind, and canonical JSON data.
pub(crate) fn compute_event_hash(
    job_id: &str,
    prev_hash: &str,
    seq: i64,
    ts_ms: i64,
    kind: &str,
    data: &Value,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"coop:event-chain:v1\0");
    hash_field(&mut hasher, job_id.as_bytes());
    hash_field(&mut hasher, prev_hash.as_bytes());
    hasher.update(seq.to_be_bytes());
    hasher.update(ts_ms.to_be_bytes());
    hash_field(&mut hasher, kind.as_bytes());
    let data = canonical_json(data);
    hash_field(&mut hasher, data.as_bytes());
    digest_hex(hasher.finalize())
}

pub(crate) fn sha256_hex(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    digest_hex(hasher.finalize())
}

pub(crate) fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Check the portable identity/digest links needed before treating stored
/// bytes as a tenant-bound attestation. This is not signature verification;
/// the signing service performs that before persistence. The store uses this
/// structural check to reject direct unbound writes and quarantine evidence
/// emitted by the pre-fix revision so it can be re-signed.
pub(crate) fn portable_attestation_binding_matches(
    job_id: &str,
    tenant: &str,
    receipt_sha256: &str,
    result_media_type: &str,
    result_artifact: &[u8],
    result_sha256: &str,
    envelope_json: &[u8],
) -> bool {
    let Ok(artifact) = serde_json::from_slice::<Value>(result_artifact) else {
        return false;
    };
    let Some(artifact) = artifact.as_object() else {
        return false;
    };
    if artifact.get("schema_version").and_then(Value::as_u64) != Some(1)
        || artifact.get("job_id").and_then(Value::as_str) != Some(job_id)
        || artifact.get("tenant").and_then(Value::as_str) != Some(tenant)
        || artifact.get("receipt_sha256").and_then(Value::as_str) != Some(receipt_sha256)
    {
        return false;
    }

    let Ok(envelope) = serde_json::from_slice::<Value>(envelope_json) else {
        return false;
    };
    let Some(envelope) = envelope.as_object() else {
        return false;
    };
    if envelope.get("payloadType").and_then(Value::as_str) != Some(DSSE_PAYLOAD_TYPE)
        || !envelope
            .get("signatures")
            .and_then(Value::as_array)
            .is_some_and(|signatures| !signatures.is_empty())
    {
        return false;
    }
    let Some(payload) = envelope.get("payload").and_then(Value::as_str) else {
        return false;
    };
    let Ok(statement_bytes) = BASE64_STANDARD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
    else {
        return false;
    };
    let Ok(statement) = serde_json::from_slice::<Value>(&statement_bytes) else {
        return false;
    };
    let Some(statement) = statement.as_object() else {
        return false;
    };
    if statement.get("_type").and_then(Value::as_str) != Some(IN_TOTO_STATEMENT_TYPE)
        || statement.get("predicateType").and_then(Value::as_str)
            != Some(COOP_EXECUTION_PREDICATE_TYPE)
    {
        return false;
    }
    let Some(subject) = statement
        .get("subject")
        .and_then(Value::as_array)
        .filter(|subjects| subjects.len() == 1)
        .and_then(|subjects| subjects[0].as_object())
    else {
        return false;
    };
    if subject
        .get("digest")
        .and_then(Value::as_object)
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str)
        != Some(result_sha256)
        || subject.get("mediaType").and_then(Value::as_str) != Some(result_media_type)
    {
        return false;
    }
    let Some(predicate) = statement.get("predicate").and_then(Value::as_object) else {
        return false;
    };
    if predicate.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || predicate.get("executionId").and_then(Value::as_str) != Some(job_id)
        || predicate.get("tenant").and_then(Value::as_str) != Some(tenant)
    {
        return false;
    }
    let Some(result) = predicate.get("result").and_then(Value::as_object) else {
        return false;
    };
    if result.get("sha256").and_then(Value::as_str) != Some(result_sha256)
        || result.get("mediaType").and_then(Value::as_str) != Some(result_media_type)
        || result.get("sizeBytes").and_then(Value::as_u64) != Some(result_artifact.len() as u64)
        || result.get("name") != subject.get("name")
    {
        return false;
    }
    predicate
        .get("receipt")
        .and_then(Value::as_object)
        .is_some_and(|receipt| {
            receipt.get("job_id").and_then(Value::as_str) == Some(job_id)
                && receipt.get("receipt_sha256").and_then(Value::as_str) == Some(receipt_sha256)
                && receipt
                    .get("tenant")
                    .is_none_or(|value| value.as_str() == Some(tenant))
        })
}

pub(crate) fn digest_hex(digest: impl IntoIterator<Item = u8>) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

pub(crate) fn hash_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}
