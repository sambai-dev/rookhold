# Rookhold

Run short-lived Python, Node, and Bash code with hard limits—and keep a
verifiable receipt of what happened.

[![CI](https://github.com/sambai-dev/rookhold/actions/workflows/ci.yml/badge.svg)](https://github.com/sambai-dev/rookhold/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/sambai-dev/rookhold)](https://github.com/sambai-dev/rookhold/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Current release:** [v0.8.0](https://github.com/sambai-dev/rookhold/releases/tag/v0.8.0).
Downloads and direct SDK packages are available now. Named PyPI and npm installs
remain deferred while maintainer registry accounts are activated.

Rookhold is for applications, agents, evaluators, graders, and automations that
receive a short piece of code but should not hand it the host machine. It is a
bounded job runner—not a persistent workspace, browser environment, remote IDE,
or general-purpose cloud sandbox.

<p align="center">
  <img src="https://github.com/sambai-dev/rookhold/blob/main/assets/rookhold-cli-mcp-demo.gif"
       alt="Rookhold terminal demo: running a short Python job with hard limits and saving the verifiable receipt"
       width="720">
</p>

## Try Rookhold locally

Choose the complete **Rookhold app** bundle. It contains
the unified `rookhold` command, remote client, MCP adapter, offline verifier,
and setup templates.

| Your computer | App bundle |
|---|---|
| Windows, 64-bit | [Download for Windows](https://github.com/sambai-dev/rookhold/releases/download/v0.8.0/rookhold-x86_64-pc-windows-msvc.zip) |
| Mac with Apple Silicon | [Download for Mac](https://github.com/sambai-dev/rookhold/releases/download/v0.8.0/rookhold-aarch64-apple-darwin.tar.gz) |
| Linux x86_64 | [Download for Linux](https://github.com/sambai-dev/rookhold/releases/download/v0.8.0/rookhold-x86_64-unknown-linux-musl.tar.gz) |

Extract the archive, then run one trusted local job:

```console
$ rookhold run python 'print(6 * 7)'
42

status       succeeded
network      host
isolation    none
receipt      saved to .rookhold/runs/019…/receipt.json

WARNING: isolation is none; this run did not contain untrusted code.
```

On macOS or Linux, run `chmod +x rookhold rookhold-cli rookhold-mcp
rookhold-verify` once after extracting. On Windows, use `rookhold.exe`.

> [!WARNING]
> With no configured endpoint, `rookhold run` starts a temporary loopback-only
> service for code you trust. It has host networking and no sandbox boundary.
> Do not use this mode for hostile or mutually untrusted code.

Connected to a guarded Linux service, the same command can require and report
the gVisor boundary:

```console
$ ROOKHOLD_BASE_URL=https://executor.example \
  ROOKHOLD_API_KEY=replace-with-a-scoped-key \
  rookhold run python 'print(6 * 7)' \
    --minimum-isolation gvisor-application-kernel
42

status       succeeded
network      disabled
isolation    gvisor-application-kernel
receipt      saved to .rookhold/runs/019…/receipt.json
```

The CLI explicitly requests `allow_network: false`; the guarded service must
also report disabled networking and the required isolation class.

[Read the quickstart](https://rookhold.pages.dev/getting-started/quickstart) ·
[Deploy the secure boundary](https://rookhold.pages.dev/getting-started/first-secure-deployment) ·
[Share 60-second feedback](https://github.com/sambai-dev/rookhold/issues/new?template=first-run-feedback.yml)

## Add Rookhold to an application

The **Rookhold SDK** is the client library for your code. It does not create a
secure Linux execution boundary by itself; point it at a Rookhold service for
untrusted workloads.

### Python

Install the v0.8.0 release wheel:

```bash
pip install https://github.com/sambai-dev/rookhold/releases/download/v0.8.0/rookhold-0.8.0-py3-none-any.whl
```

```python
from rookhold import Rookhold

result = Rookhold.from_env().run("python", "print(6 * 7)")
print(result.stdout)
```

### TypeScript

Install the v0.8.0 release tarball:

```bash
npm install https://github.com/sambai-dev/rookhold/releases/download/v0.8.0/rookhold-0.8.0.tgz
```

```typescript
import { Rookhold } from "rookhold";

const result = await Rookhold.fromEnv().run({
  language: "python",
  code: "print(6 * 7)",
});
console.log(result.stdout);
```

[Python guide](https://rookhold.pages.dev/use/python) ·
[TypeScript guide](https://rookhold.pages.dev/use/typescript) ·
[API reference](https://rookhold.pages.dev/api)

## Connect to an existing Rookhold server

The **Rookhold client** is the smallest download for a
person or MCP host that already has a Rookhold endpoint. It does not include
the local service.

| Your computer | Standalone client |
|---|---|
| Windows, 64-bit | [Download the Windows client](https://github.com/sambai-dev/rookhold/releases/download/v0.8.0/rookhold-cli-x86_64-pc-windows-msvc.exe) |
| Mac with Apple Silicon | [Download the Mac client](https://github.com/sambai-dev/rookhold/releases/download/v0.8.0/rookhold-cli-aarch64-apple-darwin) |
| Linux x86_64 | [Download the Linux client](https://github.com/sambai-dev/rookhold/releases/download/v0.8.0/rookhold-cli-x86_64-unknown-linux-gnu) |

Run it normally for the operator terminal, or register the same file with the
`mcp-server` argument in Claude Code, OpenCode, Hermes, or another MCP host.
The model never chooses the service URL, API key, language allowlist, or
required isolation class.

```bash
rookhold setup claude-code
rookhold setup opencode
rookhold setup hermes
```

Adding Rookhold does not disable a host's built-in shell or other execution
tools. Remove or deny those routes when a model must cross only the Rookhold
boundary.

[CLI guide](https://rookhold.pages.dev/use/cli) ·
[MCP guide](https://rookhold.pages.dev/use/mcp) ·
[Integration templates](integrations/README.md)

## What Rookhold does

For every submitted job, Rookhold:

1. authenticates the caller and checks admission policy;
2. applies server-controlled time, memory, process, file, and output limits;
3. runs the job using the configured execution provider;
4. preserves bounded output, events, cancellation state, and artifacts; and
5. records the effective runtime posture and receipt.

The API and persisted store remain the source of truth. The CLI, SDKs, MCP
adapter, and dashboard are views over the same contracts.

Under the hood, the gateway enforces pre-commit per-tenant and global admission
leases, a two-phase `32 MiB → 20 MiB` logical storage reserve across execution
and asynchronous `attestation_outbox` signing, a length-prefixed SHA-256 event
hash chain (`MAX_EVENT_BATCH_SIZE = 256` per WAL commit), and full `cgroup.kill`
descendant teardown. Stage-by-stage latency numbers and single-node scaling
trade-offs are documented in [docs/architecture.md](docs/architecture.md).

## Three useful recipes

- [Run an LLM-generated function](examples/llm-tool-call/)—submit generated
  source without evaluating it inside the agent process.
- [Apply a user-defined JSON transform](examples/json-transform/)—send
  structured input and read structured output.
- [Grade code against hidden tests](examples/evaluator/)—bound evaluation time
  and retain the result record.

[See every recipe](examples/README.md) or start from the
[Next.js](templates/nextjs-code-runner/) and
[FastAPI](templates/fastapi-code-runner/) examples.

## Is Rookhold right for the task?

| Use Rookhold for | Keep using the normal workspace for |
|---|---|
| short generated or user-supplied scripts | editing a repository |
| stateless transforms, checks, and evaluators | persistent files and package installation |
| jobs needing limits, cancellation, or evidence | browsers, ports, and long-running services |
| execution behind a separately controlled API | trusted development already isolated well enough |

Using both is normal. Rookhold owns short execution policy and evidence; it
does not replace the rest of an agent or application runtime.

## Before running untrusted code

The guarded production profile is **Linux x86_64-only**. macOS, Windows, and
other Linux architectures support only the unisolated same-trust development
provider. Production uses a dedicated Linux x86_64 VM, pinned gVisor `runsc`, a
private root filesystem, cgroup v2, scoped credentials, and non-skipping
containment checks.

The service container has host-equivalent outer authority even though each job
runs inside a separate gVisor workload. Do not place it on a shared
multi-tenant Docker host.

[Read the security boundary](docs/security-boundary.md) before accepting
untrusted jobs.

## Documentation

- [Getting started](https://rookhold.pages.dev/getting-started/quickstart)
- [Installation choices](https://rookhold.pages.dev/getting-started/installation)
- [How Rookhold compares](https://rookhold.pages.dev/compare)
- [Execution model](https://rookhold.pages.dev/understand/execution-model)
- [Receipts and verification](https://rookhold.pages.dev/understand/receipts)
- [Deployment and operations](https://rookhold.pages.dev/deployment)
- [Compatibility](https://rookhold.pages.dev/compatibility)
- [Feedback](https://rookhold.pages.dev/feedback)
- [Release process](docs/releasing.md)

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). The repository separates:

- **Tier A**—docs, examples, and integrations;
- **Tier B**—SDK, CLI, and public API work; and
- **Tier C**—authentication, execution, storage, receipts, and isolation.

Tier A changes should not inherit security-core ceremony. Tier C changes must
prove the root invariant, regression, adversarial cases, and final exact-head
validation.

## Build from source

Prebuilt releases are the normal path. Contributors need Rust 1.98 and the job
runtimes they intend to test:

```bash
git clone https://github.com/sambai-dev/rookhold.git
cd rookhold
cargo build --locked --workspace
```

Run the complete checks from [CONTRIBUTING.md](CONTRIBUTING.md) before opening a
pull request. The [workspace map](crates/README.md) explains how the crates fit
together; the [automation map](scripts/README.md) does the same for the release
and verification scripts.

## License

Rookhold is released under the [MIT License](LICENSE).
