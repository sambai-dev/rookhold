# Architecture

Rookhold is an execution gateway, scheduler, executor, and evidence store in one Rust process. It is optimized for short, stateless agent jobs on one node. SQLite is the persistence boundary; horizontal scheduling and persistent workspaces are outside the current contract.

```text
agent / SDK / dashboard
          │ HTTP + WebSocket
          ▼
┌──────────────────────────────┐
│ API boundary                │
│ scoped auth · validation    │
│ idempotency · tenant limits │
└──────────────┬───────────────┘
               │ bounded queue
               ▼
┌──────────────────────────────┐
│ Scheduler                    │
│ fair admission · memory      │
│ cancellation · finalization  │
└──────────────┬───────────────┘
               │ execution plan
               ▼
┌──────────────────────────────┐
│ Executor                     │
│ namespace or gVisor provider │
│ cgroup v2 · private rootfs   │
└──────────────┬───────────────┘
               │ ordered events
               ▼
┌──────────────────────────────┐
│ SQLite + live fan-out        │
│ jobs · events · attestations │
└──────────────────────────────┘
```

## Crate boundaries

- `coop-types` owns JSON-facing job types, lifecycle enums, and compiled limit ceilings.
- `coop-store` owns the SQLite schema and persistence operations.
- `coop-exec` owns interpreter staging and execution backends.
- `coop-attestation` owns the DSSE/in-toto profile, strict Ed25519 keys, exact-byte verification, schemas, vectors, and offline CLI.
- `coop-server` owns configuration, identity, routing, fair admission, scheduling, signing orchestration, observability, WebSockets, OpenAPI, and the embedded dashboard.

The executor interface is intentionally narrower than an OCI runtime API: one
job enters, an ordered stream of output/violation events leaves, and one
terminal outcome plus executor-observed provenance returns. The provenance
ready bit is set only at the backend's actual workload-ready boundary. A future
provider must preserve that contract. The integrated gVisor/OCI backend does
so while adding reviewed-runtime, rootfs-manifest, and OCI-config digests.

## Job state and events

The jobs table is the current-state projection. The events table is an ordered
operational history keyed by job and sequence number. The durable start
transaction stores an all-null, unobserved effective-policy snapshot because
it precedes executor readiness. The terminal transaction atomically replaces
that snapshot with executor-observed effective controls and binds its digest
into the finished event. If provenance is unavailable, the API leaves the
effective policy unknown rather than reconstructing it from configuration.
Clients must use job status as the authoritative current state and event
sequence for investigation.

Schema v4 adds immutable `job_attestations` plus a durable
`attestation_outbox`. Terminal state and its receipt commit first; the outbox
then converges to an exact deterministic result artifact and signed envelope.
This deliberately does not claim an impossible atomic signature across
SQLite and a signer. Restart reseeds retained terminal jobs that have no
attestation, while receipt-byte conditional persistence prevents signing one
record and attaching it to another. The signer sources tenant from the durable
job row and binds it into both portable files; migrated v0.3 receipt bytes are
not rewritten. Pending outbox work retains an exact 20 MiB logical reserve,
including after restart reconstruction, until signing or an explicit waiver
releases it. The revision-1 migration preserves exact tenant-bound
attestations and quarantines/requeues older unbound files before API
availability can expose them.

“Replay” means retrieving the stored event history. It does not mean executing the code again or reproducing nondeterministic effects.

Output is bounded by both record and byte policies. The executor records truncation and continues supervising the process so timeout, cancellation, cgroup cleanup, and final state cannot be starved by output flood.

## Data and trust boundaries

Each API key maps to one tenant. Tenant ownership is checked on job detail, result, cancel, event history, and stream access. Foreign job IDs should be indistinguishable from missing IDs.

The server process, local signing key, SQLite file, reviewed runtime/private
rootfs, and outer host remain trusted. Submitted source, stdin, bounded input
files, requested output files, interpreter
behavior, and descendants are untrusted. A gVisor job receives a separate
application-kernel workload; a namespace job remains shared-kernel. Neither
may receive the database, keys, sockets, sibling staging, or outer host root.
Isolated providers are supported only on Linux x86_64; other platforms use the
unisolated development executor.

See [security-boundary.md](security-boundary.md) for the complete trust-tier statement.

## Scale characteristics

v0.8 remains a single-node design:

- atomic global/per-tenant queued leases and fair tenant dispatch
- a configured worker pool
- per-tenant concurrency plus weighted aggregate memory permits
- transactional tenant/global retained-byte quotas and filesystem reserve
- SQLite WAL for concurrent readers and serialized writes
- an in-process live event fan-out, backed by persisted history for reconnects

Running multiple Rookhold servers against the same SQLite file is unsupported. A multi-node design requires a durable queue, distributed admission control, a network database, and an external stream bus.

## Non-goals in v0.8

- persistent or resumable sandboxes
- persistent file or artifact stores beyond bounded per-job input/output files
- arbitrary container images
- PTYs and interactive shells
- exposed ports and inbound networking
- snapshots, warm pools, or deterministic replay
- KMS/HSM custody, public-key history, transparency anchoring, or remote hardware attestation
- hardware/confidential-VM claims beyond the implemented gVisor application-kernel class
- multi-node scheduling

## Where things live

The crate boundaries above map to the workspace as follows: `coop-types`,
`coop-store`, `coop-attestation`, and `coop-exec` are independent libraries,
and `coop-server` composes them into the service process. For the per-crate
module map, the binary layout, and the naming rationale, see
[crates/README.md](https://github.com/sambai-dev/rookhold/blob/main/crates/README.md).
The adversarial payloads used to prove the executor boundary live in
[crates/coop-server/tests/fixtures/hostile-jobs](https://github.com/sambai-dev/rookhold/tree/main/crates/coop-server/tests/fixtures/hostile-jobs).
