# Crates

The Rust workspace implements the Rookhold execution gateway: one process that
acts as the API boundary, admission scheduler, execution supervisor, and
evidence store for short-lived agent jobs. The high-level design contract is
written down in [docs/architecture.md](../docs/architecture.md); this file is
the map of the code itself.

## Dependency graph

```text
coop-types    coop-store    coop-attestation
    ▲              ▲               ▲
    │              │               │
    └──────┬───────┴───────────────┘
           │           ▲
           ▼           │
        coop-exec ─────┘
           ▲
           │
        coop-server  (depends on all four)
```

`coop-types`, `coop-store`, and `coop-attestation` are leaves. `coop-exec`
builds on `coop-types`. `coop-server` is the composition root and depends on
everything.

## Crate map

### `coop-types` — shared contracts

JSON-facing job types (`JobSpec`), lifecycle enums, `IsolationClass`,
`LimitEnforcement`, the compiled global limit ceilings, supported language and
runtime-pack tables. Everything here is API surface: keep it small, stable, and
free of server or store logic. Single file (`src/lib.rs`).

### `coop-store` — persistence

SQLite schema, migrations, and all persistence operations for jobs, ordered
events, retained artifacts, and attestations, plus transactional tenant/global
byte quotas and the attestation outbox. Single file (`src/lib.rs`). The store
knows nothing about HTTP or execution; the jobs table is the current-state
projection and the events table is the ordered history.

### `coop-exec` — execution providers

The `ExecutionProvider` interface and every backend behind it:

- `naive.rs` — unisolated development subprocess backend (macOS, Windows,
  non-x86_64 Linux).
- `linux_sandbox.rs` — shared-kernel Linux backend using namespaces, rlimits,
  cgroup v2, and the seccomp profile in `seccomp.rs`.
- `gvisor.rs` — per-job gVisor `runsc` OCI backend with a reviewed private
  rootfs and manifest pinning (production containment).
- `bounded_output.rs` — fixed-memory output decoder shared by all backends.
- `oci_init.rs` — the trusted PID 1 started inside the OCI sandbox.

Ships two helper binaries: `rookhold-sandbox-init` and `rookhold-oci-init`
(with `coop-sandbox-init` / `coop-oci-init` as legacy aliases). The server
locates them through the `ROOKHOLD_SANDBOX_HELPER` environment or the verified
rootfs. `examples/seccomp_diag.rs` is a development diagnostic for the seccomp
profile.

### `coop-attestation` — evidence signing and verification

The DSSE/in-toto signing profile, strict canonical Ed25519 key files,
duplicate-key-rejecting JSON parsing, exact-byte verification, the statement
schema (`schema/`), and golden test vectors (`tests/vectors/v1/`). Builds
`rookhold-verify`, the offline key-management and verification CLI (`coop-verify`
is the legacy alias). Has its own [README](coop-attestation/README.md) and a
[FORMAT.md](coop-attestation/FORMAT.md) that must be read before integrating.

### `coop-server` — the gateway

The composition root. `main.rs` is the `rookhold` service binary (`coop` is
the legacy alias); notable modules:

- `config.rs` — environment configuration (`ROOKHOLD_*` with `COOP_*`
  fallbacks).
- `auth.rs` — scoped API keys, HMAC/JWT/OIDC middleware.
- `routes.rs` — the HTTP API and the embedded dashboard
  (`include_str!("dashboard.html")`).
- `scheduler.rs` — fair admission, worker pool, cancellation, finalization.
- `attestation.rs` — signing orchestration over the store outbox.
- `cli.rs` — the remote client, doctor, and `setup` subcommands.
- `metrics.rs`, `ratelimit.rs`, `readiness.rs`, `transport.rs`, `openapi.rs`,
  `bus.rs` — observability, admission control, health, WebSocket streaming,
  OpenAPI, and live event fan-out.

Tests live in `tests/`: `api.rs` (HTTP contract), `hostile.rs` (containment
suite; payload fixtures in
[tests/fixtures/hostile-jobs](coop-server/tests/fixtures/hostile-jobs/README.md)),
`logging.rs`, and `store_regression.rs`.

## Naming

The crates keep the `coop-*` names as durable compatibility identities: module
paths, SQL trigger names, metrics, media types, and signed evidence URIs all
embed them, and published receipts reference those names. Product-facing
binaries and documentation use the Rookhold names (`rookhold`,
`rookhold-verify`, …); the `coop-*` binaries are legacy aliases that include
the same implementation. See [docs/compatibility.md](../docs/compatibility.md)
and the rename history in [docs/upgrading.md](../docs/upgrading.md).

## Working in this workspace

Run the same checks CI runs (from [CONTRIBUTING.md](../CONTRIBUTING.md)):

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

For a fast local server on macOS or Windows:

```bash
ROOKHOLD_SANDBOX=off ROOKHOLD_API_KEYS="local:dev-key" cargo run -p coop-server
```

The real containment suite (`cargo test -p coop-server --test hostile
-- --ignored`) requires a dedicated Linux x86_64 VM with cgroup v2, namespaces,
the sandbox helpers, and a reviewed rootfs — follow
[docs/deployment.md](../docs/deployment.md). Do not run it on a workstation
that contains important unsaved work.
