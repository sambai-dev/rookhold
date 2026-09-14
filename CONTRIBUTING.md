# Contributing to Rookhold

Thanks for helping make agent code execution safer and easier to audit.

## Before you start

- Use [GitHub Discussions](https://github.com/sambai-dev/rookhold/discussions) for questions and showcases. Use [GitHub Issues](https://github.com/sambai-dev/rookhold/issues) for reproducible bugs and scoped feature requests.
- For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
- For large changes, open an issue first so the approach, declared scope, and containment tradeoffs can be agreed before implementation.
- Identify the contribution tier below before choosing checks. The full security lifecycle applies only to Tier C.

Good first contributions include recipes, starter applications, MCP configurations, runtime-pack proposals, SDK ergonomics, and documentation. Core containment work is welcome but deliberately requires deeper evidence.

## Local development

Install Rust with `rustup`; the repository's `rust-toolchain.toml` selects the supported toolchain. Run the same workspace checks as CI:

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

On macOS or Windows, Rookhold uses the development subprocess backend. Start the server explicitly in that mode. For macOS or another POSIX shell:

```bash
ROOKHOLD_SANDBOX=off ROOKHOLD_API_KEYS="local:dev-key" cargo run -p coop-server
```

For PowerShell:

```powershell
$env:ROOKHOLD_SANDBOX = "off"
$env:ROOKHOLD_API_KEYS = "local:dev-key"
cargo run -p coop-server
```

The real containment suite requires a supported Linux x86_64 kernel, cgroup v2, namespaces, the matching sandbox helper, a trusted private rootfs, and elevated privileges. Follow the complete setup in the [deployment guide](docs/deployment.md); the workspace map in [crates/README.md](crates/README.md) shows where each component lives. Do not run the hostile-job suite on a workstation that contains important unsaved work. A dedicated Linux VM is preferred.

## Repository layout

- `crates/` — the Rust workspace. `coop-server` is the HTTP gateway, scheduler,
  and embedded dashboard; `coop-exec` holds the execution providers
  (development subprocess, Linux namespaces, gVisor OCI);
  `coop-store` persists jobs, events, and evidence in SQLite;
  `coop-attestation` signs and verifies receipts and builds `rookhold-verify`;
  `coop-types` holds the shared API types and global limits. The `coop-*` crate
  and module names are durable compatibility identities; shipped binaries and
  documentation use the Rookhold names, with `coop-*` binaries kept only as
  legacy aliases.
- `crates/coop-server/tests/fixtures/hostile-jobs/` — adversarial payloads
  (fork bombs, escape probes) for the ignored containment suite. Treat them as
  test fixtures, not sample jobs.
- `sdks/` — the Python and TypeScript client SDKs, including the `rookhold-cli`
  and `rookhold-mcp` adapters.
- `docs/` — the VitePress documentation site; `docs/public/` is deployed as-is.
- `scripts/` — release, verification, and drift-gate automation.
  `check-release-surface.py` is the central consistency gate and pins many of
  the paths in this map; `scripts/tests/` holds its unittest suite.
- `integrations/` — MCP host configuration snippets (Claude Code, OpenCode,
  Hermes, OpenClaw).
- `templates/` — starter applications (Next.js and FastAPI runners).
- `examples/` — runnable recipes referenced by the docs.
- `deploy/` — systemd unit, Caddy example, and production env template.
- `assets/` — demo captures and product-evidence media; not part of the site.
- Root files: `README.md` (product overview), `CONTRIBUTING.md` (this guide),
  `SECURITY.md` (vulnerability policy), `AUDIT.md` (security review record),
  `DESIGN.md` (visual system), `PRODUCT.md` (product schema), `CHANGELOG.md`
  (release log), and `release.json` (canonical release URLs).

Keep this map current: moving or renaming top-level files usually requires
updating `scripts/check-release-surface.py` in the same change.

## Contribution tiers

### Tier A — docs, examples, and integrations

Run the formatter or linter relevant to the files and execute or validate the
example or configuration you changed. A maintainer review is required. RED
reproduction, hostile jobs, and exact-head containment evidence are not
required for copy, recipes, starter apps, diagrams, package-manager manifests,
or MCP host configuration.

### Tier B — SDK, CLI, and public API

Add unit and integration coverage, assess backward compatibility, update the
changelog when behavior changes, and run a clean wheel, source-distribution, or
npm-package install as applicable. Public examples must keep working.

### Tier C — executor, authentication, storage, receipts, and isolation

Read the [contribution lifecycle](docs/contribution-lifecycle.md). Keep the full
security standard below: RED reproduction, adversarial cases, exact-head
evidence, hostile-job coverage, platform verification, and rollback analysis.

## Tier C definition of technically done

A mergeable branch or green focused test is not sufficient. Technical completion requires all applicable conditions below.

1. **Declared behavior is complete.** Every promise maps to implementation, regression coverage, and direct evidence. A deliberately partial solution names its independently useful boundary and records remaining work.
2. **The regression proves RED.** The new test fails on unchanged source for the reported reason, then passes after the fix. Record the command and failure; do not weaken assertions or rely on a mock artifact.
3. **Adversarial cases are considered.** Check missing/null-like and annotated inputs, alternate valid layouts, zero/partial/all-state boundaries, retry/fallback paths, sibling call sites, classifier fallthrough, and platform behavior where relevant.
4. **The root invariant is repaired.** Do not mask symptoms with broad exception handling, silent defaults, premature skipping, optional state suppression, disabled tests, or weaker assertions.
5. **The final exact diff is rescanned.** Re-read the declared scope, issue, review comments, final diff, affected sibling paths, and evidence after the last code change.
6. **Exact-head integration evidence exists.** Run focused tests, the affected suite, lint/type/format checks, required full gates, and platform verification. CI must be attached to the current head; fork-only evidence is described as locally validated with trusted integration pending.

## Pull requests

State the contribution tier. Complete the sections applicable to that tier with concrete evidence. Tier C changes must include:

- declared scope and non-goals;
- the root invariant;
- reproduction and RED evidence, or a reason it does not apply;
- adversarial coverage;
- exact final-head SHA and checks;
- safety, compatibility, and rollback implications; and
- separate implementation, validation, review, and integration states.

Before requesting review, run the applicable tier checks plus `git diff --check`. Tier A changes need a clear scope and relevant validation, not security-core ceremony.

If a commit was genuinely produced by more than one person, use GitHub's standard `Co-authored-by:` trailer. Do not add attribution for review, tooling, or work the named person did not perform.

## Automated review

CodeRabbit automatically reviews eligible non-draft pull requests targeting
`main` using the version-controlled [`.coderabbit.yaml`](.coderabbit.yaml).
Titles containing `WIP` or `[skip review]` are excluded, and automatic reviews
pause after ten reviewed commits. Its comments and status supplement the
required CI and maintainer review; they do not certify technical completion or
replace the exact-head evidence above.

After addressing new commits or review findings, comment `@coderabbitai review`
on the pull request to request a fresh review. Evaluate each finding against the
declared scope and root invariant, resolve valid defects with regression
coverage, and explain rejected suggestions rather than changing reviewed code
only to silence automation.

## Status language

Use these terms precisely:

- **Implementation incomplete:** valid cases within the declared promise remain mishandled.
- **Validation incomplete:** implementation may be correct, but exact-head or trusted-platform evidence is missing.
- **Review incomplete:** implementation and validation are complete, but approval is pending or changes are requested.
- **Integration incomplete:** the contribution is ready but has not entered the protected merge/release path.
- **Scoped complete:** one explicit, independently useful part of a broader issue is complete; remaining work is recorded and not overclaimed.
- **Stale/unverified:** the base, relevance, merge result, or current CI is no longer established; reproduce and rebuild before presenting it as ready.

Do not update an approved, green PR merely because it is behind the base when intervening commits do not overlap or affect its invariant. Conversely, matching file contents do not prove correct ancestry: simulate the merge or rebase on the intended base when history changes Git's integration result.

## Design principles

- Fail closed when a requested safety boundary cannot be established.
- Report the active isolation mode honestly; never present a subprocess fallback as a sandbox.
- Keep tenant boundaries explicit in storage, routing, and logs.
- Preserve replayability: every execution outcome should be explainable from persisted events.
- Prefer small, auditable mechanisms over broad abstractions in security-sensitive paths.
