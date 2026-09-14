# CLI

The v0.8.0 Rookhold app provides the unified local and remote workflow:

```bash
rookhold run python 'print(6 * 7)'
rookhold run python script.py --wall-seconds 2
rookhold run python transform.py --file data.csv --output output/report.json
rookhold check
rookhold jobs
rookhold show JOB_ID
rookhold verify --envelope job.dsse.json --subject job-result.json --public-key key.pem --tenant acme
```

`rookhold run` uses `ROOKHOLD_BASE_URL` and `ROOKHOLD_API_KEY` when both are
set. Otherwise it starts and stops a temporary local development service.
`rookhold check` tests the service, credential, runtimes, actual isolation, and
MCP connection with plain pass/warn/fail output.

The separately downloadable `rookhold-cli` is the existing-server client. It
does not contain the service or the zero-configuration `rookhold run` path.

## Terminal clients

Rookhold ships two terminal commands in the verified Python wheel:

- `rookhold-cli` is for a human operator. It can run code, list and inspect
  jobs, read results/events, cancel work, show server posture, and inspect the
  MCP catalog.
- `rookhold-mcp` is for an agent host. It speaks newline-delimited JSON-RPC over
  stdio and exposes four narrow tools; it is not an interactive shell.

Both call the same authenticated Rookhold service. Neither command is the
execution boundary by itself.

### Download the standalone apps

The normal consumer path is the platform archive on the
[v0.8.0 release](https://github.com/sambai-dev/rookhold/releases/tag/v0.8.0).
Each Windows, Apple-silicon macOS, and Linux x86_64 archive contains both
`rookhold-cli` and `rookhold-mcp` as self-contained executables. Extract the
archive and run them directly; Python and `pip` are not required.

If the Rookhold service already exists elsewhere, download only the standalone
`rookhold-cli-*` file for the current platform. That one file serves both human
and agent hosts: run it normally for the interactive terminal or add
`mcp-server` to start the stdio MCP adapter. Rename the download to
`rookhold-cli` (`rookhold-cli.exe` on Windows) and place it on `PATH`, or use its
absolute path in the host configuration.

```bash
./rookhold-cli --version
./rookhold-cli
```

On Windows, use `rookhold-cli.exe` and `rookhold-mcp.exe`.

### Install the Python package for development

SDK authors who specifically want importable Python modules can download the
exact `rookhold-0.8.0-py3-none-any.whl` release asset and
verify it using [the SDK release procedure](../sdks.md). Install it into an
operator-owned virtual environment:

```bash
python -m venv ~/.local/share/rookhold
~/.local/share/rookhold/bin/python -m pip install --no-deps \
  ./rookhold-0.8.0-py3-none-any.whl
```

On Windows, the commands are under
`%USERPROFILE%\.local\share\rookhold\Scripts\`.

Set connection and policy outside the prompt:

```bash
export ROOKHOLD_BASE_URL=https://rookhold.internal.example
export ROOKHOLD_API_KEY=replace-with-the-key-only
export ROOKHOLD_CLI_MINIMUM_ISOLATION=gvisor-application-kernel
export ROOKHOLD_MCP_MINIMUM_ISOLATION=gvisor-application-kernel
export ROOKHOLD_MCP_ALLOWED_LANGUAGES=python,node
```

The CLI accepts `COOP_*` fallbacks during migration and fails closed when
matching non-empty old and new values disagree.

### Interactive use

Run `rookhold-cli`. It authenticates first and shows the tenant, endpoint,
actual backend, observed isolation class, live MCP tool count, and an explicit
warning when the server is unisolated.

| Command | Purpose |
|---|---|
| `/run python "print(6 * 7)"` | Submit and wait for a short one-line job |
| `/paste python` | Paste multiline code; finish with `.end` |
| `/jobs 20` | List recent jobs for this tenant |
| `/show JOB_ID` | Print the complete job record |
| `/result JOB_ID` | Wait for and render the terminal result |
| `/events JOB_ID` | Replay retained events |
| `/cancel JOB_ID` | Cancel queued or running work |
| `/posture` | Show the provider, isolation, network, languages, and limits |
| `/mcp` | Initialize the real adapter and list its live tools |
| `/clear` | Clear an interactive terminal |
| `/quit` | Exit |

Commands that omit `JOB_ID` use the most recently selected/submitted job.
Errors redact the configured key.

### One-shot use

The same command works in scripts:

```bash
rookhold-cli posture
rookhold-cli mcp
rookhold-cli run python "print(6 * 7)"
rookhold-cli --json jobs --limit 20
rookhold-cli --json result JOB_ID --wait 60
```

`--minimum-isolation` overrides the CLI minimum for that process. Production
automation should set an exact non-`none` class and should use `--json` when
another program consumes output.

### Agent CLIs

Register the same standalone CLI file as a local stdio MCP server with the
`mcp-server` argument:

- [Claude Code template](https://github.com/sambai-dev/rookhold/blob/main/integrations/claude-code/mcp.json)
- [OpenCode v2 template](https://github.com/sambai-dev/rookhold/blob/main/integrations/opencode/opencode.snippet.json)
- [all supported host patterns](https://github.com/sambai-dev/rookhold/blob/main/integrations/README.md)

This lets the host keep its own polished conversational TUI while Rookhold
remains the separate policy-controlled executor. The host may prefix tool names
with its MCP server name; the underlying Rookhold tools remain
`rookhold_run_code`, `rookhold_job_result`, `rookhold_job_events`, and
`rookhold_cancel_job`.

Adding the MCP server does not disable the host's built-in shell, terminal, or
code-execution tools. Deny those alternate routes in the host when every job
must cross Rookhold.

### Terminal design

The terminal uses a compact posture summary, progressive output hierarchy,
near-black surface, off-white text, and one accessible electric-blue action
voice. Green, amber, red, and slate are reserved for explicit execution or
security states. The terminal remains a small client over Rookhold's own API
and MCP contracts.
