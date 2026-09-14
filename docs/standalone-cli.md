# Standalone terminal apps

This quickstart ships in every release archive as `QUICKSTART.md`. It covers
everything needed to use Rookhold from a terminal:

- `rookhold` runs one job, checks a connection, configures an MCP host, or starts the service;
- `rookhold-cli` is the interactive human client; and
- `rookhold-mcp` connects Claude Code, OpenCode, Hermes, OpenClaw, and other MCP hosts.

For the smallest download, only `rookhold-cli` is needed. The same executable
starts the MCP adapter with `rookhold-cli mcp-server`; the separate
`rookhold-mcp` file remains a compatibility entry point.

Windows executables end in `.exe`. Python, Rust, `pip`, and a source checkout are
not required.

The direct Linux x86_64 CLI is built and smoked on GNU/Linux for mainstream
Ubuntu, Debian, and RHEL-class systems. The self-hosting service binary in the
complete Linux archive remains statically linked with musl.

The current community binaries are covered by release checksums, an SBOM, and
GitHub provenance attestations, but not yet by commercial Windows or Apple
code-signing certificates. If the operating system shows an unidentified
publisher warning, verify the downloaded archive before allowing it.

## Local trusted-code demo

Run one command. It manages a temporary loopback service, saves the receipt,
then stops the service:

```bash
rookhold run python 'print(6 * 7)'
```

This mode is intentionally unisolated, reports `isolation: none`, retains host
network access, and may receive only trusted code.

Use `rookhold dev` when you want the local API and dashboard to remain open.
The equivalent explicit environment remains available below.

macOS or Linux:

```bash
ROOKHOLD_SANDBOX=off ROOKHOLD_JOBS_ROOT="$PWD/.rookhold-dev/jobs" ./rookhold serve
```

Windows PowerShell:

```powershell
$env:ROOKHOLD_SANDBOX = "off"
$env:ROOKHOLD_JOBS_ROOT = Join-Path (Get-Location) ".rookhold-dev\jobs"
.\rookhold.exe serve
```

Open a second terminal and start the human client.

macOS or Linux:

```bash
ROOKHOLD_BASE_URL=http://127.0.0.1:7300 \
ROOKHOLD_API_KEY=rookhold-dev-key \
  ./rookhold-cli
```

Windows PowerShell:

```powershell
$env:ROOKHOLD_BASE_URL = "http://127.0.0.1:7300"
$env:ROOKHOLD_API_KEY = "rookhold-dev-key"
.\rookhold-cli.exe
```

Try `/mcp`, then `/run python "print(6 * 7)"`. Type `/help` for every command.
Use `rookhold check` from another terminal to test the service, credential,
runtimes, actual isolation, and packaged MCP adapter.

## Connect an agent CLI

Run `rookhold setup claude-code`, `rookhold setup opencode`, or `rookhold setup
hermes`. The command previews the change, backs up an existing file, keeps the
API key in the host environment, writes only after confirmation, and tests the
connection afterward.

Adding Rookhold does not disable an agent host's built-in shell or other
execution tools. Deny those alternate routes in the host when every job must
cross Rookhold.

The local demo is not a security boundary. Before running untrusted code, read
`docs/security-boundary.md` and deploy the guarded Linux x86_64 profile on a
dedicated VM.
