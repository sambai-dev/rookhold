# Hostile job fixtures

> [!WARNING]
> These payloads are adversarial: fork bombs, memory bombs, disk flooders, and
> escape probes. They exist to prove the containment boundary. Running them
> outside the sandbox can wedge or destroy a workstation. They are only ever
> executed embedded inside the Rookhold hostile test suite, on a dedicated
> Linux x86_64 VM, under the gVisor or namespace provider with full limits
> enforced. Do not run them directly.

## What each payload probes

| Fixture | Boundary under test |
|---|---|
| `fork_bomb.sh` | PID ceiling (`pids.max`) under fork pressure. |
| `background_holder.sh` | Worker hygiene: detached children must not hang the worker. |
| `memory_bomb.py` | cgroup `memory.max` with `oom.group`. |
| `infinite_loop.py` | Wall-clock supervisor timeout. |
| `network_probe.py` | No `AF_INET`, no `io_uring`; nodename is the sandbox identity. |
| `disk_filler.py` | Per-job file-size limit (`max_file_mb`). |
| `escape_probe.py` | Host leak checks: `/etc/shadow`, marker writes, nodename. |
| `pid_bomb.py` | Process-count limits under `multiprocessing` pressure. |
| `ptrace_probe.py` | seccomp kill on `PTRACE_TRACEME`. |

## How they are consumed

The suite embeds every payload at compile time with `include_str!` in
[hostile.rs](../hostile.rs), so the tests never read from disk at run time and
the payloads cannot be tampered with after build. Keep the file names and this
directory location stable: the embed paths, the ignored-test count pinned in
CI, and the drift gate all assume them.

## Running the suite

The tests are `#[ignore]`d by default. Running them requires the full
containment setup — supported Linux x86_64 kernel, cgroup v2, namespaces, the
sandbox helper binaries, a reviewed private rootfs, and elevated privileges —
described in [docs/deployment.md](../../../../docs/deployment.md):

```bash
cargo test -p coop-server --test hostile -- --ignored
```

CI runs the same suite in a privileged container
(.github/workflows/ci.yml and release.yml, `hostile` job). If you add or
remove a payload or an ignored test, update the discovery guards in those
workflows and in `scripts/check-release-surface.py` in the same change.
