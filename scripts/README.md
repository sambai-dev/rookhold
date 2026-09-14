# Scripts

Automation for the drift gate, CI, release packaging, deployment, and live
verification. Everything here runs from the repository root unless a script
documents otherwise.

Many of these files are pinned by name and content in
[check-release-surface.py](check-release-surface.py), the repository's central
consistency gate. When you move, rename, or behaviorally change a script,
update the gate — and its tests — in the same change.

## Map

### Drift gate and CI support

| Script | Purpose |
|---|---|
| [check-release-surface.py](check-release-surface.py) | The central gate: versions, release URLs, workflow/Docker/Compose contracts, pins, hostile-test count, doc claims, and plain-language policy across the whole repo. Run `python3 scripts/check-release-surface.py`. |
| [check-pr-description.py](check-pr-description.py) | Validates the Tier A/B/C sections of a pull request body against the event payload. |
| [adoption-pulse.py](adoption-pulse.py) | Builds a conservative weekly adoption report from repository signals; consumed by the `adoption-pulse` workflow. |
| [release-artifacts.py](release-artifacts.py) | Exact-allowlist release pipeline: assemble, prepare, verify-sbom, finalize, and remote-draft reconciliation. |
| [reconcile-registries.py](reconcile-registries.py) | Compares exact local release bytes against PyPI/npm before and after publishing. |

### Deployment and verification

| Script | Purpose |
|---|---|
| [bootstrap-production.sh](bootstrap-production.sh) | Guarded production bootstrap on a dedicated x86_64 VM: pinned runsc, key generation, rendered env, Compose bring-up, verification. |
| [verify-production.py](verify-production.py) | Authenticated end-to-end verification of a live service: canaries, receipts, DSSE attestation, offline `rookhold-verify`. |
| [verify-local-demo.py](verify-local-demo.py) | Verifies `rookhold run --json` output from a trusted local demo (stdout, posture, receipt on disk). |
| [verify-python-adapter.py](verify-python-adapter.py) | Live Python SDK, MCP, and CLI canary against a running service. |
| [smoke-container.sh](smoke-container.sh) | Final-image smoke: keygen, namespace backend, production and adapter verification. |
| [smoke-gvisor.sh](smoke-gvisor.sh) | Mandatory real-runsc gVisor gate with crash reconciliation and provider-switch kill checks. |
| [prepare-test-rootfs.sh](prepare-test-rootfs.sh) | Builds the private rootfs used by the privileged hostile tests. |
| [build-rootfs-manifest.py](build-rootfs-manifest.py) | Writes the canonical SHA-256 manifest over a rootfs tree. |
| [container-entrypoint.sh](container-entrypoint.sh) | Container entrypoint: stages host-supplied runsc/keys before exec'ing the service. Copied into the image by the Dockerfile. |
| [bench.py](bench.py) | End-to-end job-latency benchmark against a live server. |

### Media generation

| Script | Purpose |
|---|---|
| [render-cli-demo.py](render-cli-demo.py) | Records the deterministic CLI demo HTML to WebM with Playwright; maintainers convert the result for [assets/](../assets/README.md). |

## Tests

[tests/](tests/) holds the unittest suite. The scripts use kebab-case names
(that convention is pinned across CI and the gate), so the tests load them by
path with `runpy`/`importlib` instead of importing them as modules. Run the
whole suite from the repository root:

```bash
python3 -m unittest discover -s scripts/tests -v
```

## Conventions

- Executable scripts use kebab-case names (`check-release-surface.py`); test
  modules use snake_case (`test_check_pr_description.py`).
- Scripts take arguments over environment variables; production-affecting
  scripts fail closed when inputs are missing or ambiguous.
