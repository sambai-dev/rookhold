# Rookhold security review record

**Review date:** 2026-08-26

**Scope:** Rust workspace, execution boundary, API tenancy, scheduler, SQLite store, dashboard, SDKs, Docker/Compose, CI/release automation, and public documentation

**Status:** historical v0.2 record plus the v0.4 and v0.8 addenda below; not an external certification.

This file records the security properties reviewed for v0.2 and the evidence expected before release. It deliberately replaces v0.1 claims that overstated host-filesystem isolation, PID-namespace behavior, event-log immutability, and hostile-test coverage.

## v0.8 review addendum — 2026-09-01

The v0.8 release expanded the bounded execution contract with per-job `input/`
and `output/` file staging, versioned runtime-pack identifiers, standalone
single-file CLI/MCP executables, and a tiered contribution gate:

- **Bounded `input/` and `output/` file mounts:** Submitted input files and
  requested output artifacts are restricted to relative, canonicalized paths
  inside the per-job staging directories (`input/` and `output/`). Absolute
  paths, `..` traversal segments, duplicate normalized paths, symlinks,
  special/device files, file-count overflows, per-file byte overflows, and
  aggregate byte-budget overflows fail closed before staging or collection.
  Collected output artifacts are SHA-256 hashed and bound into the terminal
  result and receipt.
- **Runtime-pack provenance binding:** Versioned runtime-pack identifiers (for
  example, the Bookworm base pack) do not weaken or replace executor evidence;
  receipts continue to bind the observed interpreter, private-rootfs manifest,
  gVisor `runsc` binary, and OCI configuration digests.
- **Temporary local service warning:** When `rookhold run` starts a temporary
  loopback-only local service for convenience, it explicitly reports
  `isolation: none` and `network: host` and emits an unisolated-run warning so
  local convenience is never mistaken for a containment boundary.

## v0.4 review addendum — 2026-08-30

The v0.4 work was reviewed in independent repository, runtime/supply-chain,
identity, observability, SDK/protocol, and adversarial reliability passes. No
validated P0 remained. The release-blocking P1 findings—global queue capture,
unbounded retained storage, idempotency handoff races, unsafe embedder listener
authority, and accounting-integrity laundering—were fixed and covered by
deterministic concurrency, migration, restart, and raw-SQL regression tests.

The current guarded production contract adds:

- a separate pinned gVisor OCI workload per job, with real ready/execute/cancel/timeout/delete/crash-recovery gates;
- atomic tenant/global admission, memory, logical-storage, and disk-reserve controls;
- scoped indexed credentials and strict RFC 9068 JWT validation;
- executor-observed isolation requirements checked at admission, scheduling, and terminal evidence;
- schema-v4 signing outbox, deterministic result artifacts, Ed25519 DSSE/in-toto envelopes, exact-byte download digests, and restart backfill;
- bounded OpenMetrics, request IDs, W3C trace links, and JSON production logs;
- dual-era MCP, safe idempotent SDK submission, typed cancellation, and live packaged-client tests.

The gVisor gate found one P2 direct-provider input-bound bypass; the provider
now rejects code/stdin before staging or cloning and the final runtime review
reported no remaining validated P0/P1/P2. Identity review likewise reported no
remaining P0/P1/P2 after bounded JWKS-cache and credential-lifetime fixes.

Current residual constraints are explicit:

| ID | Area | Constraint | Required operator response |
|---|---|---|---|
| V4-R-001 | Outer control plane | Compose remains host-equivalent even though each job uses runsc | Dedicated x86_64 VM; protect and patch the outer service |
| V4-R-002 | Runtime class | gVisor is an application-kernel boundary, not a hardware or confidential VM | Do not label it VM/TEE isolation; use a future reviewed provider when that property is required |
| V4-R-003 | Signed evidence | DSSE proves possession of the configured key, not execution truth; the current key endpoint is not a trust anchor | Pin/distribute public keys out of band; preserve rotation history and external records |
| V4-R-004 | Signing availability | Signing is durable but eventual; a terminal job can briefly have no envelope | Require `attestation.available`, retry boundedly, and alert on persistent backlog/warnings |
| V4-R-005 | Key custody | The integrated signer is a local PEM, without KMS/HSM isolation | Store owner-only outside job roots; back up/rotate deliberately; use an external signer in a future release when required |
| V4-R-006 | Single node | SQLite, queue ownership, quotas, and live fan-out remain one-node | Run one active server per database; no horizontal-scaling claim |
| V4-R-007 | Network policy | Isolated jobs have no general egress or credential broker | Fetch through trusted adapters and pass bounded inputs |
| V4-R-008 | Development provider | `off` is the service account's authority and host network | Same-trust local testing only; never hostile tenants |

## Review outcome

The v0.2 design is an audit-first single-node execution gateway with a shared-kernel Linux x86_64 backend. The release boundary is narrower than “safely execute arbitrary hostile code anywhere”:

- namespace execution requires a private rootfs and never falls back to host `/`;
- PID-namespace setup includes a namespace PID 1/reaper rather than executing in the parent namespace;
- terminal cleanup targets the whole cgroup, not only the original process group;
- privilege drop, mount setup, cgroup controls, and seccomp are fail-closed in production;
- output has byte and record caps so a single unterminated line cannot allocate without bound;
- blank-tenant/weak-key production configurations and dangerous job-root paths are rejected;
- requested policy remains separate from executor-observed effective controls;
  development execution reports only wall-time enforcement, while namespace
  posture is activated only by the helper's workload-ready frame;
- effective policy, output digests, lifecycle, event-chain head, and receipt digest are persisted as execution evidence.

These changes materially improve the previous release, but they do not turn Linux namespaces or a privileged container into a VM boundary.

## Residual risks and accepted constraints

| ID | Area | Constraint | Required operator response |
|---|---|---|---|
| R-001 | Shared kernel | Namespace jobs share the VM kernel and interpreter attack surface | Dedicated VM; patch promptly; use a hardened external runtime for hostile multi-tenancy when integrated |
| R-002 | Container packaging | Compose uses `privileged: true` to manage namespaces/mounts/cgroups | Run only inside a dedicated VM; never on a mixed-trust Docker host |
| R-003 | Trusted server/store | The Rookhold process and SQLite administrator can rewrite state and recompute hashes | Restrict access; export evidence to independently controlled immutable storage when required |
| R-004 | Browser streaming | Browser WebSockets cannot send a bearer header; URL-key compatibility can leak in logs/history | Keep dashboard trusted/private; avoid query credentials where possible; rotate exposed keys |
| R-005 | Single node | Queue, tenant admission, and live fan-out are process-local | One active server per database; no horizontal scaling claim |
| R-006 | No egress broker | Namespace jobs have no supported network access; development subprocesses retain host egress | Fetch through trusted adapters and pass bounded input; never run untrusted code in subprocess mode |
| R-007 | Rootfs supply chain | Interpreter packages inside the private rootfs are trusted inputs | Build from approved snapshots, record manifests/digests, scan and patch |
| R-008 | Architecture support | The v0.2 namespace/seccomp backend supports Linux x86_64 only | Treat macOS, Windows, and non-x86_64 Linux as unisolated development platforms |
| R-009 | Forced-abort cleanup | Lease drop synchronously requests `cgroup.kill`, waits up to two seconds for `populated 0`, and removes the leaf; a hard process/host kill can still interrupt that bounded cleanup | Keep shutdown grace above worker grace; alert on and reconcile populated or stale Rookhold cgroups before admission |

## Receipt and event-chain semantics

A v0.2 terminal receipt is intended to bind:

- code and stdin hashes
- requested limits and nullable backend-effective controls with per-control
  enforcement metadata
- executor-observed readiness, isolation, backend, seccomp, and network posture
- accepted, started, and finished timestamps plus duration
- outcome, exit code, and kill cause; violation events are covered by the bound event-chain head
- raw drained stdout/stderr hashes, observed/retained byte counts, record counts, and truncation flags
- event-chain head, event count, and completeness
- a canonical receipt SHA-256

The digest lets the server or an auditor with the canonical fields detect accidental or unauthorized modification relative to the stored hash. It is not signed and is not anchored outside the database. A privileged database operator can rewrite records and recompute the chain. Pre-ready failures explicitly record false/null posture and controls; restart-recovered or pre-v0.2 rows with no executor observation omit that evidence rather than receiving facts inferred from current configuration.

## Verification matrix

| Property | Required evidence |
|---|---|
| Formatting and type safety | `cargo fmt --all --check`; clippy with warnings denied |
| Rust behavior | locked workspace tests on Linux, macOS, and Windows |
| Containment | ignored hostile suite on x86_64 Linux with root + writable cgroup v2; prerequisite gate must fail rather than skip |
| API tenancy | cross-tenant list/detail/result/replay/stream/cancel tests |
| Lifecycle atomicity | queued/running cancellation, crash recovery, event/state finalization tests |
| Bounded output | huge unterminated record and sustained flood tests; timeout/cancel remains responsive |
| Rootfs isolation | probes cannot read outer database, host mounts, sibling staging, or old root |
| Descendant cleanup | `setsid`/background descendants leave cgroup `populated 0` |
| SDK contracts | Python unit tests and TypeScript type/tests against v0.2 fixtures |
| API contract | generated/static OpenAPI validation and examples |
| Packaging | locked Docker build plus image/rootfs canary |
| Dependencies | RustSec advisory scan of `Cargo.lock` |
| Release integrity | tag/version check, exact asset allowlist, checksums, artifact-scoped SPDX/SBOM attestation, GitHub provenance, one reconciled atomic publish job |

A skipped containment suite is not a passing result. Ordinary `cargo test` runs do not execute ignored hostile tests.

## Dependency review

The local 2026-08-30 RustSec scan evaluated 296 locked Rust dependencies and reported no known vulnerabilities. That is a point-in-time advisory lookup, not a guarantee; release CI repeats the lockfile scan and dependency updates require normal review.

## Claims intentionally not made

- hardware-VM, confidential-computing, or protection-from-runtime/kernel-zero-day guarantees
- deterministic re-execution
- signatures as proof of semantic execution truth, remote hardware attestation, transparency anchoring, or WORM audit storage
- arbitrary network egress with credential safety
- persistent workspaces or multi-node scheduling
- production support for macOS, Windows, or non-x86_64 Linux subprocess execution of untrusted code
