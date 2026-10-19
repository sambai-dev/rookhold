use crate::bounded_output::BoundedOutput;
use crate::{
    ext_for, resolve_interpreter, ExecContext, ExecOutcome, ExecTelemetry, ExecutionObserver,
    ProcessLaunchPermit, Sink, Stream,
};
use coop_types::{Limits, OutcomeStatus, MAX_CODE_BYTES, MAX_STDIN_BYTES};
use nix::sys::resource::{setrlimit, Resource};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{
    chdir, dup2, execve, fork, setgroups, setresgid, setresuid, ForkResult, Gid, Pid, Uid,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::ffi::CString;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::os::fd::AsRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{
    SocketAddr as StdUnixSocketAddr, UnixListener as StdUnixListener, UnixStream as StdUnixStream,
};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixListener;
use tokio::process::{Child, Command};

const PLAN_VERSION: u32 = 2;
const MAX_PLAN_BYTES: usize = 64 * 1024;
const MAX_CONTROL_FRAME_BYTES: usize = 1024;
const NOBODY_GID: u32 = 65534;
const NOBODY_UID: u32 = 65534;
// Supervision cadence for polling namespace-init readiness, wall-clock timeout,
// and cancellation state when no control-socket frame is immediately ready.
// A 20 ms tick keeps idle CPU overhead negligible while bounding worst-case
// cancellation/timeout reaction latency to <=20 ms. Replacing this poll cadence
// with a `pidfd_open` + `epoll` / `tokio::signal::unix::sigchld` readiness
// wakeup is the primary path to shaving ~10-20 ms off short-job p99 tail latency.
const CONTROL_TICK: Duration = Duration::from_millis(20);
const DRAIN_GRACE: Duration = Duration::from_secs(2);
const CLEANUP_GRACE: Duration = Duration::from_secs(2);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_REJECTED_CONTROL_PEERS: usize = 64;
const SANDBOX_HOSTNAME: &[u8] = b"coop-sandbox";
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
const CGROUP_JOBS_DIR: &str = "coop-jobs";
const CGROUP_SUPERVISOR_DIR: &str = "coop-supervisor";

static CGROUP_BASE: OnceLock<PathBuf> = OnceLock::new();
static CGROUP_SETUP: Mutex<()> = Mutex::new(());
static CGROUP_PREFLIGHT: Mutex<()> = Mutex::new(());

const STAGE_PLAN: &str = "validating sandbox plan";
const STAGE_NAMESPACES: &str = "entering kernel namespaces";
const STAGE_ROOTFS: &str = "preparing private root filesystem";
const STAGE_PID1: &str = "starting namespace init";
const STAGE_CGROUP_ATTACH: &str = "attaching job cgroup";
const STAGE_PROC: &str = "mounting private proc";
const STAGE_LIMITS: &str = "applying resource limits";
const STAGE_PRIVILEGES: &str = "dropping workload privileges";
const STAGE_STDIN: &str = "preparing standard input";
const STAGE_SECCOMP: &str = "applying syscall filter";
const STAGE_EXEC: &str = "starting interpreter";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxPlan {
    version: u32,
    nonce: String,
    control_name: String,
    rootfs: PathBuf,
    mount_point: PathBuf,
    payload_dir: PathBuf,
    input_dir: PathBuf,
    output_dir: PathBuf,
    program: String,
    source: String,
    stdin_present: bool,
    limits: Limits,
    seccomp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ControlFrame {
    Hello {
        nonce: String,
        version: u32,
    },
    Pid1LaunchReady {
        nonce: String,
    },
    StartPid1 {
        nonce: String,
    },
    Pid1Spawned {
        nonce: String,
        host_pid: i32,
    },
    Attached {
        nonce: String,
    },
    WorkloadSpawned {
        nonce: String,
    },
    Ready {
        nonce: String,
    },
    Error {
        nonce: String,
        stage: String,
        errno: i32,
    },
    Final {
        nonce: String,
        disposition: String,
        value: i32,
    },
}

impl ControlFrame {
    fn nonce(&self) -> &str {
        match self {
            Self::Hello { nonce, .. }
            | Self::Pid1LaunchReady { nonce }
            | Self::StartPid1 { nonce }
            | Self::Pid1Spawned { nonce, .. }
            | Self::Attached { nonce }
            | Self::WorkloadSpawned { nonce }
            | Self::Ready { nonce }
            | Self::Error { nonce, .. }
            | Self::Final { nonce, .. } => nonce,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum WorkloadStatus {
    Exited(i32),
    Signaled(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalCause {
    Cancelled,
    WallClock,
    Cpu,
}

#[derive(Debug)]
struct BootstrapFailure {
    stage: String,
    errno: i32,
}

struct AsyncControlReader {
    reader: OwnedReadHalf,
    buffer: [u8; MAX_CONTROL_FRAME_BYTES + 1],
    len: usize,
}

impl AsyncControlReader {
    fn new(reader: OwnedReadHalf) -> Self {
        Self {
            reader,
            buffer: [0; MAX_CONTROL_FRAME_BYTES + 1],
            len: 0,
        }
    }

    async fn next_frame(&mut self) -> io::Result<Option<ControlFrame>> {
        loop {
            if let Some(newline) = self.buffer[..self.len]
                .iter()
                .position(|byte| *byte == b'\n')
            {
                if newline == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sandbox helper sent an empty control frame",
                    ));
                }
                let frame = serde_json::from_slice::<ControlFrame>(&self.buffer[..newline])
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                let remaining = self.len - newline - 1;
                self.buffer.copy_within(newline + 1..self.len, 0);
                self.len = remaining;
                return Ok(Some(frame));
            }
            if self.len > MAX_CONTROL_FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sandbox helper control frame exceeded its bound",
                ));
            }
            let read = self.reader.read(&mut self.buffer[self.len..]).await?;
            if read == 0 {
                return if self.len == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "sandbox helper closed an unterminated control frame",
                    ))
                };
            }
            self.len += read;
        }
    }

    fn reunite(self, writer: OwnedWriteHalf) -> io::Result<tokio::net::UnixStream> {
        if self.len != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sandbox helper sent data before workload launch authorization",
            ));
        }
        self.reader
            .reunite(writer)
            .map_err(|_| io::Error::other("sandbox control halves did not belong together"))
    }
}

async fn accept_helper(
    listener: &UnixListener,
    expected_pid: u32,
) -> io::Result<tokio::net::UnixStream> {
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let mut rejected = 0_usize;
    loop {
        // A continuously-ready backlog of unauthenticated local peers must
        // not starve the timer future. Check the absolute deadline before
        // every accept in addition to timeout_at's normal pending-path check.
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "sandbox helper handshake timed out",
            ));
        }
        let (stream, _) = tokio::time::timeout_at(deadline, listener.accept())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "sandbox helper handshake timed out",
                )
            })??;
        let peer_pid = unix_peer_pid(&stream)?;
        if peer_pid == expected_pid {
            return Ok(stream);
        }
        tracing::warn!(
            peer_pid,
            expected_pid,
            "rejected unexpected local sandbox-control peer"
        );
        rejected += 1;
        if rejected >= MAX_REJECTED_CONTROL_PEERS {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "sandbox helper handshake rejected too many unexpected local peers",
            ));
        }
        tokio::task::yield_now().await;
    }
}

fn unix_peer_pid(stream: &tokio::net::UnixStream) -> io::Result<u32> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sandbox control peer returned malformed credentials",
        ));
    }
    let pid = unsafe { credentials.assume_init() }.pid;
    u32::try_from(pid).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "sandbox control peer returned an invalid process id",
        )
    })
}

pub async fn run(ctx: ExecContext, sink: Arc<dyn Sink>) -> io::Result<ExecOutcome> {
    run_observed(ctx, sink, ExecutionObserver::default()).await
}

pub(crate) async fn run_observed(
    ctx: ExecContext,
    sink: Arc<dyn Sink>,
    observer: ExecutionObserver,
) -> io::Result<ExecOutcome> {
    validate_job_key(&ctx.job_key)?;
    if ctx.code.len() > MAX_CODE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("code exceeds {MAX_CODE_BYTES} bytes"),
        ));
    }
    if ctx
        .stdin
        .as_ref()
        .is_some_and(|value| value.len() > MAX_STDIN_BYTES)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("stdin exceeds {MAX_STDIN_BYTES} bytes"),
        ));
    }

    let rootfs = validate_rootfs(
        ctx.rootfs
            .as_deref()
            .ok_or_else(|| io::Error::other("namespace sandbox requires ROOKHOLD_ROOTFS"))?,
        &ctx.workdir,
    )?;
    crate::ensure_job_artifact_dirs(&ctx.workdir)?;
    let helper = validate_helper(resolve_helper(ctx.helper_path.as_deref())?)?;
    let interpreter = resolve_interpreter(&ctx.language, ctx.interpreter_override.as_deref())?;
    let program = resolve_rootfs_interpreter(&rootfs, &interpreter)?;

    let payload_dir = ctx.workdir.join("payload");
    let input_dir = ctx.workdir.join("input");
    let output_dir = ctx.workdir.join("output");
    let mount_point = ctx.workdir.join("root");
    prepare_payload(&payload_dir, &ctx)?;
    fs::create_dir(&mount_point).map_err(|error| {
        io::Error::other(format!(
            "create sandbox mountpoint {}: {error}",
            mount_point.display()
        ))
    })?;
    fs::set_permissions(&mount_point, fs::Permissions::from_mode(0o700))?;

    let lease = create_job_cgroup(&ctx.job_key, &ctx.limits)?;
    let oom_before = read_named_counter_checked(lease.path().join("memory.events"), "oom_kill")?;
    let cpu_before = read_named_counter(lease.path().join("cpu.stat"), "usage_usec");
    let started = Instant::now();

    let nonce = random_nonce()?;
    // Linux abstract sockets avoid the 108-byte pathname ceiling without
    // placing an attacker-connectable socket in a shared filesystem directory.
    // The independently validated nonce still authenticates every frame.
    let control_name = format!("coop-{}", random_nonce()?);
    let control_addr = StdUnixSocketAddr::from_abstract_name(control_name.as_bytes())?;
    let std_listener = StdUnixListener::bind_addr(&control_addr)?;
    std_listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(std_listener)?;

    let source = format!("/work/job.{}", ext_for(&ctx.language));
    let plan = SandboxPlan {
        version: PLAN_VERSION,
        nonce: nonce.clone(),
        control_name,
        rootfs,
        mount_point,
        payload_dir,
        input_dir,
        output_dir,
        program,
        source,
        stdin_present: ctx.stdin.is_some(),
        limits: ctx.limits.clone(),
        seccomp: ctx.seccomp,
    };

    let helper_launch = match ctx.begin_process_launch() {
        Ok(permit) => permit,
        Err(reason) => return Ok(ExecOutcome::cancelled_before_launch(reason)),
    };
    let mut child = spawn_helper(&helper)?;
    // The helper is now owned by Tokio's kill-on-drop Child. Release the
    // process-wide/per-job fence immediately; it is never held for bootstrap
    // or execution duration.
    drop(helper_launch);
    let helper_pid = child
        .id()
        .ok_or_else(|| io::Error::other("sandbox helper has no process id"))?;
    write_plan(&mut child, &plan).await?;
    let control = accept_helper(&listener, helper_pid).await?;
    drop(listener);
    let (control_read, control_write) = control.into_split();
    let mut control_frames = AsyncControlReader::new(control_read);

    expect_hello(&mut control_frames, &nonce).await?;
    expect_pid1_launch_ready(&mut control_frames, &nonce).await?;
    let pid1_launch = match ctx.begin_process_launch() {
        Ok(permit) => permit,
        Err(reason) => return Ok(ExecOutcome::cancelled_before_launch(reason)),
    };
    let (next_frames, next_write, pid1) =
        authorize_pid1_launch(control_frames, control_write, nonce.clone(), pid1_launch).await?;
    control_frames = next_frames;
    let control_write = next_write;
    fs::write(lease.path().join("cgroup.procs"), pid1.to_string()).map_err(|error| {
        io::Error::other(format!("cgroup: attach namespace init {pid1}: {error}"))
    })?;
    // `Attached` authorizes namespace PID1 to fork the user workload. Keep the
    // launch permit until PID1 acknowledges the successful fork, so shutdown
    // cannot finish closing the gate in the authorization-to-fork interval.
    let workload_launch = match ctx.begin_process_launch() {
        Ok(permit) => permit,
        Err(reason) => return Ok(ExecOutcome::cancelled_before_launch(reason)),
    };
    let (control_frames, _control_write) = authorize_workload_launch(
        control_frames,
        control_write,
        nonce.clone(),
        workload_launch,
    )
    .await?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("sandbox helper stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("sandbox helper stderr was not piped"))?;

    let result = supervise(
        &ctx,
        &nonce,
        sink,
        &mut child,
        stdout,
        stderr,
        control_frames,
        lease.path(),
        cpu_before,
        oom_before,
        started,
        observer,
    )
    .await;

    let path = lease.release();
    let cleanup = tokio::task::spawn_blocking(move || cleanup_cgroup_sync(&path, CLEANUP_GRACE))
        .await
        .map_err(|error| io::Error::other(format!("cgroup cleanup task failed: {error}")))?;
    if let Err(error) = cleanup {
        tracing::error!(error = %error, "failed to fully clean sandbox cgroup");
        if result.is_ok() {
            return Err(error);
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn supervise<R1, R2>(
    ctx: &ExecContext,
    nonce: &str,
    sink: Arc<dyn Sink>,
    helper: &mut Child,
    mut stdout: R1,
    mut stderr: R2,
    mut control: AsyncControlReader,
    cgroup: &Path,
    cpu_before: u64,
    oom_before: u64,
    started: Instant,
    observer: ExecutionObserver,
) -> io::Result<ExecOutcome>
where
    R1: tokio::io::AsyncRead + Unpin,
    R2: tokio::io::AsyncRead + Unpin,
{
    let deadline = started + Duration::from_secs(ctx.limits.wall_seconds.max(1) as u64);
    let cpu_budget = u64::from(ctx.limits.cpu_seconds.max(1)) * 1_000_000;
    let mut tick = tokio::time::interval(CONTROL_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut stdout_capture = BoundedOutput::new(Stream::Stdout);
    let mut stderr_capture = BoundedOutput::new(Stream::Stderr);
    let mut stdout_buf = [0_u8; 8192];
    let mut stderr_buf = [0_u8; 8192];
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut control_done = false;
    let mut helper_status: Option<std::process::ExitStatus> = None;
    let mut workload_status: Option<WorkloadStatus> = None;
    let mut bootstrap_failure: Option<BootstrapFailure> = None;
    let mut control_error: Option<io::Error> = None;
    let mut ready = false;
    let mut terminal_cause: Option<TerminalCause> = None;
    let mut drain_deadline: Option<Instant> = None;

    while helper_status.is_none() || !stdout_done || !stderr_done || !control_done {
        let drain = async {
            match drain_deadline {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending::<()>().await,
            }
        };
        let read_stdout = read_chunk(&mut stdout, &mut stdout_buf, stdout_done);
        let read_stderr = read_chunk(&mut stderr, &mut stderr_buf, stderr_done);
        let read_control = next_control(&mut control, control_done);

        tokio::select! {
            biased;

            _ = tick.tick() => {
                if terminal_cause.is_none() && helper_status.is_none() {
                    let cause = if ctx.is_cancelled() {
                        Some(TerminalCause::Cancelled)
                    } else if Instant::now() >= deadline {
                        Some(TerminalCause::WallClock)
                    } else if cpu_budget_exceeded(cgroup, cpu_before, cpu_budget) {
                        Some(TerminalCause::Cpu)
                    } else {
                        None
                    };
                    if let Some(cause) = cause {
                        terminal_cause = Some(cause);
                        match cause {
                            TerminalCause::Cancelled => sink.violation("job_cancelled", json!({})),
                            TerminalCause::WallClock => sink.violation(
                                "wall_clock_exceeded",
                                json!({"wall_seconds": ctx.limits.wall_seconds}),
                            ),
                            TerminalCause::Cpu => sink.violation(
                                "cpu_limit_exceeded",
                                json!({"cpu_seconds": ctx.limits.cpu_seconds}),
                            ),
                        }
                        kill_cgroup(cgroup)?;
                    }
                }

                if helper_status.is_none() {
                    if let Some(status) = helper.try_wait()? {
                        helper_status = Some(status);
                        drain_deadline = Some(Instant::now() + DRAIN_GRACE);
                    }
                }
            }

            _ = drain => {
                stdout_done = true;
                stderr_done = true;
                control_done = true;
            }

            read = read_stdout => match read {
                Ok(0) => {
                    stdout_capture.finish(sink.as_ref());
                    stdout_done = true;
                }
                Ok(n) => stdout_capture.push(&stdout_buf[..n], sink.as_ref()),
                Err(error) => {
                    tracing::debug!(error = %error, "sandbox stdout reader closed");
                    stdout_capture.finish(sink.as_ref());
                    stdout_done = true;
                }
            },

            read = read_stderr => match read {
                Ok(0) => {
                    stderr_capture.finish(sink.as_ref());
                    stderr_done = true;
                }
                Ok(n) => stderr_capture.push(&stderr_buf[..n], sink.as_ref()),
                Err(error) => {
                    tracing::debug!(error = %error, "sandbox stderr reader closed");
                    stderr_capture.finish(sink.as_ref());
                    stderr_done = true;
                }
            },

            frame = read_control => match frame {
                Ok(Some(frame)) if frame.nonce() != nonce => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "sandbox helper control nonce mismatch",
                    ));
                }
                Ok(Some(ControlFrame::Ready { .. })) => {
                    ready = true;
                    observer.mark_ready();
                }
                Ok(Some(ControlFrame::Error { stage, errno, .. })) => {
                    bootstrap_failure = Some(BootstrapFailure { stage, errno });
                }
                Ok(Some(ControlFrame::Final { disposition, value, .. })) => {
                    workload_status = match disposition.as_str() {
                        "exited" => Some(WorkloadStatus::Exited(value)),
                        "signaled" => Some(WorkloadStatus::Signaled(value)),
                        _ => None,
                    };
                }
                Ok(Some(_)) => {}
                Ok(None) => control_done = true,
                Err(error) => {
                    control_error = Some(error);
                    control_done = true;
                }
            },
        }
    }

    stdout_capture.finish(sink.as_ref());
    stderr_capture.finish(sink.as_ref());
    let cpu_after = read_named_counter(cgroup.join("cpu.stat"), "usage_usec");
    let oom_after = read_named_counter_checked(cgroup.join("memory.events"), "oom_kill")?;
    let memory_peak = read_scalar(cgroup.join("memory.peak"));
    let telemetry = ExecTelemetry {
        wall_time_ms: started.elapsed().as_millis() as u64,
        cpu_time_usec: Some(cpu_after.saturating_sub(cpu_before)),
        memory_peak_bytes: memory_peak,
        stdout: stdout_capture.telemetry(),
        stderr: stderr_capture.telemetry(),
    };

    if let Some(failure) = bootstrap_failure {
        sink.violation(
            "sandbox_bootstrap_failed",
            json!({"stage": sanitize_stage(&failure.stage)}),
        );
        return Err(io::Error::other(format!(
            "sandbox bootstrap failed during '{}' (errno {})",
            sanitize_stage(&failure.stage),
            failure.errno
        )));
    }

    if let Some(cause) = terminal_cause {
        let (status, killed_by) = match cause {
            TerminalCause::Cancelled => (OutcomeStatus::Cancelled, "cancelled"),
            TerminalCause::WallClock => (OutcomeStatus::TimedOut, "wall-clock"),
            TerminalCause::Cpu => (OutcomeStatus::Failed, "cgroup-cpu"),
        };
        return Ok(ExecOutcome {
            status,
            exit_code: None,
            killed_by: Some(killed_by.to_string()),
            telemetry,
        });
    }

    let oom = oom_after > oom_before;
    if oom {
        return classify_workload(workload_status, true, &ctx.limits, sink.as_ref(), telemetry);
    }

    if let Some(error) = control_error {
        return Err(error);
    }

    if !ready {
        return Err(io::Error::other(
            "sandbox helper exited before confirming workload readiness",
        ));
    }
    classify_workload(
        workload_status,
        false,
        &ctx.limits,
        sink.as_ref(),
        telemetry,
    )
}

fn classify_workload(
    status: Option<WorkloadStatus>,
    oom: bool,
    limits: &Limits,
    sink: &dyn Sink,
    telemetry: ExecTelemetry,
) -> io::Result<ExecOutcome> {
    if oom {
        sink.violation("memory_cap_exceeded", json!({"mem_mb": limits.mem_mb}));
        return Ok(ExecOutcome {
            status: OutcomeStatus::OomKilled,
            exit_code: None,
            killed_by: Some("cgroup-oom".to_string()),
            telemetry,
        });
    }
    let status = status.ok_or_else(|| io::Error::other("sandbox helper omitted final status"))?;
    let outcome = match status {
        WorkloadStatus::Exited(code) => ExecOutcome {
            status: if code == 0 {
                OutcomeStatus::Succeeded
            } else {
                OutcomeStatus::Failed
            },
            exit_code: Some(code),
            killed_by: None,
            telemetry,
        },
        WorkloadStatus::Signaled(signal) if signal == libc::SIGSYS => {
            sink.violation("seccomp_violation", json!({"signal": "SIGSYS"}));
            ExecOutcome {
                status: OutcomeStatus::Failed,
                exit_code: None,
                killed_by: Some("seccomp".to_string()),
                telemetry,
            }
        }
        WorkloadStatus::Signaled(signal) if signal == libc::SIGXCPU => {
            sink.violation(
                "cpu_limit_exceeded",
                json!({"cpu_seconds": limits.cpu_seconds}),
            );
            ExecOutcome {
                status: OutcomeStatus::Failed,
                exit_code: None,
                killed_by: Some("rlimit-cpu".to_string()),
                telemetry,
            }
        }
        WorkloadStatus::Signaled(signal) => ExecOutcome {
            status: OutcomeStatus::Failed,
            exit_code: None,
            killed_by: Some(format!("signal-{signal}")),
            telemetry,
        },
    };
    Ok(outcome)
}

async fn read_chunk<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
    done: bool,
) -> io::Result<usize> {
    if done {
        std::future::pending::<io::Result<usize>>().await
    } else {
        reader.read(buffer).await
    }
}

async fn next_control(
    reader: &mut AsyncControlReader,
    done: bool,
) -> io::Result<Option<ControlFrame>> {
    if done {
        return std::future::pending::<io::Result<Option<ControlFrame>>>().await;
    }
    reader.next_frame().await
}

async fn expect_hello(control: &mut AsyncControlReader, nonce: &str) -> io::Result<()> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, next_control(control, false)).await {
        Ok(Ok(Some(ControlFrame::Hello {
            nonce: received,
            version: PLAN_VERSION,
        }))) if received == nonce => Ok(()),
        Ok(Ok(Some(ControlFrame::Error { stage, errno, .. }))) => Err(io::Error::other(format!(
            "sandbox helper failed during {stage} (errno {errno})"
        ))),
        Ok(Ok(other)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected sandbox helper hello: {other:?}"),
        )),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "sandbox helper hello timed out",
        )),
    }
}

async fn expect_pid1_launch_ready(control: &mut AsyncControlReader, nonce: &str) -> io::Result<()> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, next_control(control, false)).await {
        Ok(Ok(Some(ControlFrame::Pid1LaunchReady { nonce: received }))) if received == nonce => {
            Ok(())
        }
        Ok(Ok(Some(ControlFrame::Error { stage, errno, .. }))) => Err(io::Error::other(format!(
            "sandbox helper failed during {stage} (errno {errno})"
        ))),
        Ok(Ok(other)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected sandbox PID1 launch-ready frame: {other:?}"),
        )),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "sandbox PID1 launch-ready handshake timed out",
        )),
    }
}

async fn authorize_pid1_launch(
    control: AsyncControlReader,
    writer: OwnedWriteHalf,
    nonce: String,
    permit: ProcessLaunchPermit,
) -> io::Result<(AsyncControlReader, OwnedWriteHalf, i32)> {
    let control = control.reunite(writer)?.into_std()?;
    let (control, pid1) = tokio::task::spawn_blocking(move || {
        authorize_pid1_launch_blocking(control, &nonce, permit)
    })
    .await
    .map_err(|error| io::Error::other(format!("sandbox PID1 launch task failed: {error}")))??;
    let control = tokio::net::UnixStream::from_std(control)?;
    let (reader, writer) = control.into_split();
    Ok((AsyncControlReader::new(reader), writer, pid1))
}

fn authorize_pid1_launch_blocking(
    control: StdUnixStream,
    nonce: &str,
    _permit: ProcessLaunchPermit,
) -> io::Result<(StdUnixStream, i32)> {
    prepare_blocking_launch_control(&control)?;
    send_frame(
        &control,
        &ControlFrame::StartPid1 {
            nonce: nonce.to_string(),
        },
    )?;
    let pid1 = match read_sync_frame(&control)? {
        ControlFrame::Pid1Spawned {
            nonce: received,
            host_pid,
        } if received == nonce && host_pid > 1 => host_pid,
        ControlFrame::Error {
            nonce: received,
            stage,
            errno,
        } if received == nonce => {
            return Err(io::Error::other(format!(
                "sandbox helper failed during {stage} (errno {errno})"
            )));
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected sandbox PID1 launch frame: {other:?}"),
            ));
        }
    };
    restore_async_launch_control(&control)?;
    Ok((control, pid1))
}

async fn authorize_workload_launch(
    control: AsyncControlReader,
    writer: OwnedWriteHalf,
    nonce: String,
    permit: ProcessLaunchPermit,
) -> io::Result<(AsyncControlReader, OwnedWriteHalf)> {
    let control = control.reunite(writer)?.into_std()?;
    let control = tokio::task::spawn_blocking(move || {
        authorize_workload_launch_blocking(control, &nonce, permit)
    })
    .await
    .map_err(|error| {
        io::Error::other(format!("sandbox launch handshake task failed: {error}"))
    })??;
    let control = tokio::net::UnixStream::from_std(control)?;
    let (reader, writer) = control.into_split();
    Ok((AsyncControlReader::new(reader), writer))
}

fn authorize_workload_launch_blocking(
    control: StdUnixStream,
    nonce: &str,
    _permit: ProcessLaunchPermit,
) -> io::Result<StdUnixStream> {
    // This blocking handshake deliberately owns the launch permit. A
    // synchronous `ExecutionStartGate::close` can therefore wait even on a
    // single-thread Tokio runtime: PID1 and this blocking-pool task make the
    // progress that releases the permit, not the blocked async worker.
    prepare_blocking_launch_control(&control)?;
    send_frame(
        &control,
        &ControlFrame::Attached {
            nonce: nonce.to_string(),
        },
    )?;
    match read_sync_frame(&control)? {
        ControlFrame::WorkloadSpawned { nonce: received } if received == nonce => {}
        ControlFrame::Error {
            nonce: received,
            stage,
            errno,
        } if received == nonce => {
            return Err(io::Error::other(format!(
                "sandbox helper failed during {stage} (errno {errno})"
            )));
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected sandbox workload-launch frame: {other:?}"),
            ));
        }
    }
    restore_async_launch_control(&control)?;
    Ok(control)
}

fn prepare_blocking_launch_control(control: &StdUnixStream) -> io::Result<()> {
    control.set_nonblocking(false)?;
    control.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    control.set_write_timeout(Some(HANDSHAKE_TIMEOUT))
}

fn restore_async_launch_control(control: &StdUnixStream) -> io::Result<()> {
    control.set_read_timeout(None)?;
    control.set_write_timeout(None)?;
    control.set_nonblocking(true)
}

fn spawn_helper(path: &Path) -> io::Result<Child> {
    let mut command = Command::new(path);
    command
        .arg("--internal-v2")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    command.spawn()
}

async fn write_plan(child: &mut Child, plan: &SandboxPlan) -> io::Result<()> {
    let bytes = serde_json::to_vec(plan).map_err(io::Error::other)?;
    if bytes.len() > MAX_PLAN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sandbox plan exceeded its fixed bound",
        ));
    }
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("sandbox helper stdin was not piped"))?;
    let len = (bytes.len() as u32).to_be_bytes();
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        stdin.write_all(&len).await?;
        stdin.write_all(&bytes).await?;
        stdin.shutdown().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "writing sandbox plan timed out"))?
}

fn prepare_payload(payload: &Path, ctx: &ExecContext) -> io::Result<()> {
    fs::create_dir(payload)?;
    fs::set_permissions(payload, fs::Permissions::from_mode(0o700))?;
    let source = payload.join(format!("job.{}", ext_for(&ctx.language)));
    write_mode(&source, ctx.code.as_bytes(), 0o444)?;
    if let Some(stdin) = &ctx.stdin {
        write_mode(&payload.join("stdin"), stdin.as_bytes(), 0o444)?;
    }
    fs::set_permissions(payload, fs::Permissions::from_mode(0o555))
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_data()?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

fn validate_job_key(job_key: &str) -> io::Result<()> {
    if job_key.is_empty()
        || job_key.len() > 64
        || !job_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "job key must be 1-64 ASCII letters, digits, '-' or '_'",
        ));
    }
    Ok(())
}

pub(crate) fn validate_rootfs(rootfs: &Path, workdir: &Path) -> io::Result<PathBuf> {
    ensure_absolute_no_symlinks(rootfs, "ROOKHOLD_ROOTFS")?;
    let rootfs = fs::canonicalize(rootfs)?;
    if rootfs == Path::new("/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ROOKHOLD_ROOTFS must never be host /",
        ));
    }
    let metadata = fs::metadata(&rootfs)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ROOKHOLD_ROOTFS must be a root-owned directory that is not group/world writable",
        ));
    }
    let workdir = fs::canonicalize(workdir)?;
    if workdir.starts_with(&rootfs) || rootfs.starts_with(&workdir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ROOKHOLD_ROOTFS and the job workdir must not overlap",
        ));
    }
    for required in [
        ".pivot_old",
        "tmp",
        "proc",
        "dev",
        "work",
        "input",
        "output",
    ] {
        let path = rootfs.join(required);
        let required_metadata = fs::symlink_metadata(&path).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("ROOKHOLD_ROOTFS is missing required directory /{required}"),
            )
        })?;
        if required_metadata.file_type().is_symlink() || !required_metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("ROOKHOLD_ROOTFS /{required} must be a real directory"),
            ));
        }
    }
    if fs::read_dir(rootfs.join(".pivot_old"))?.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ROOKHOLD_ROOTFS /.pivot_old must be empty",
        ));
    }
    Ok(rootfs)
}

fn ensure_absolute_no_symlinks(path: &Path, label: &str) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be an absolute normalized path"),
        ));
    }
    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(part) => current.push(part),
            _ => continue,
        }
        if current.exists() {
            let metadata = fs::symlink_metadata(&current)?;
            if metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{label} must not traverse symlink {}", current.display()),
                ));
            }
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{label} must traverse only root-owned, non-writable components; {} is insecure",
                        current.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn resolve_helper(configured: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(path) = configured {
        return Ok(path.to_path_buf());
    }
    let current = std::env::current_exe()?;
    let parent = current
        .parent()
        .ok_or_else(|| io::Error::other("current executable has no parent directory"))?;
    let primary = parent.join("rookhold-sandbox-init");
    if primary.exists() {
        return Ok(primary);
    }
    let legacy = parent.join("coop-sandbox-init");
    if legacy.exists() {
        return Ok(legacy);
    }
    Ok(primary)
}

fn validate_helper(helper: PathBuf) -> io::Result<PathBuf> {
    ensure_absolute_no_symlinks(&helper, "ROOKHOLD_SANDBOX_HELPER")?;
    let metadata = fs::metadata(&helper)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sandbox helper must be a root-owned, non-writable executable file",
        ));
    }
    fs::canonicalize(helper)
}

pub(crate) fn resolve_rootfs_interpreter(rootfs: &Path, configured: &str) -> io::Result<String> {
    let requested = Path::new(configured);
    if requested
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interpreter path must not contain '..'",
        ));
    }
    let candidates: Vec<PathBuf> = if requested.components().count() > 1 {
        vec![rootfs.join(requested.strip_prefix("/").unwrap_or(requested))]
    } else {
        ["usr/local/bin", "usr/bin", "bin"]
            .iter()
            .map(|dir| rootfs.join(dir).join(requested))
            .collect()
    };
    for candidate in candidates {
        let Ok(canonical) = fs::canonicalize(&candidate) else {
            continue;
        };
        if canonical.starts_with(rootfs) && canonical.is_file() {
            let internal = canonical.strip_prefix(rootfs).map_err(io::Error::other)?;
            return Ok(format!(
                "/{}",
                internal.to_string_lossy().replace('\\', "/")
            ));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("interpreter {configured:?} was not found inside ROOKHOLD_ROOTFS"),
    ))
}

fn random_nonce() -> io::Result<String> {
    let mut bytes = [0_u8; 24];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        value.push(TABLE[(byte >> 4) as usize] as char);
        value.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    value
}

fn prepare_cgroup_base() -> io::Result<PathBuf> {
    if let Some(base) = CGROUP_BASE.get() {
        return Ok(base.clone());
    }
    let _setup = CGROUP_SETUP
        .lock()
        .map_err(|_| io::Error::other("cgroup setup lock was poisoned"))?;
    if let Some(base) = CGROUP_BASE.get() {
        return Ok(base.clone());
    }

    let delegation = current_cgroup_delegation()?;
    let mount = fs::canonicalize(CGROUP_MOUNT)
        .map_err(|error| io::Error::other(format!("cgroup: resolve mount: {error}")))?;
    if delegation != mount {
        evacuate_delegation_processes(&delegation)?;
    }
    enable_controllers(&delegation)?;
    let base = delegation.join(CGROUP_JOBS_DIR);
    fs::create_dir_all(&base)
        .map_err(|error| io::Error::other(format!("cgroup: create base: {error}")))?;
    enable_controllers(&base)?;
    CGROUP_BASE
        .set(base.clone())
        .map_err(|_| io::Error::other("cgroup base initialized concurrently"))?;
    Ok(base)
}

/// Exercise the exact cgroup-v2 controls required by namespace execution
/// before the server advertises an isolated posture or admits tenant work.
pub fn preflight_cgroup_runtime() -> io::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "namespace execution requires root inside its delegated runtime",
        ));
    }
    // Multiple embedded app instances (and the hostile suite) can ask for
    // availability concurrently. Serialize the disposable controller probe
    // so racing cgroup creation/removal cannot make an otherwise healthy
    // process advertise isolation nondeterministically. Deliberately do not
    // cache success: every startup must revalidate its delegated controls.
    let _preflight = CGROUP_PREFLIGHT
        .lock()
        .map_err(|_| io::Error::other("cgroup preflight lock was poisoned"))?;
    let base = prepare_cgroup_base()?;
    let nonce = random_nonce()?;
    let key = format!("preflight-{}", &nonce[..32]);
    let path = create_cgroup_dir(&base, &key)?;
    let probe = (|| {
        write_cgroup_limits(&path, &Limits::default())?;
        let _ = read_named_counter_checked(path.join("memory.events"), "oom_kill")?;
        let _ = read_named_counter_checked(path.join("cpu.stat"), "usage_usec")?;
        kill_cgroup(&path)
    })();
    let cleanup = cleanup_cgroup_sync(&path, CLEANUP_GRACE);
    match (probe, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

const CONTROLLERS: [&str; 3] = ["memory", "pids", "cpu"];

fn enable_controllers(group: &Path) -> io::Result<()> {
    let available = fs::read_to_string(group.join("cgroup.controllers"))?;
    for controller in CONTROLLERS {
        if !available.split_whitespace().any(|item| item == controller) {
            return Err(io::Error::other(format!(
                "cgroup v2 controller {controller:?} is unavailable at {}",
                group.display()
            )));
        }
    }
    let subtree = group.join("cgroup.subtree_control");
    let enabled = fs::read_to_string(&subtree).unwrap_or_default();
    let missing: Vec<String> = CONTROLLERS
        .iter()
        .filter(|controller| !enabled.split_whitespace().any(|item| item == **controller))
        .map(|controller| format!("+{controller}"))
        .collect();
    if !missing.is_empty() {
        fs::write(&subtree, missing.join(" ")).map_err(|error| {
            io::Error::other(format!(
                "cgroup: enable controllers at {}: {error}",
                subtree.display()
            ))
        })?;
    }
    let enabled = fs::read_to_string(&subtree).map_err(|error| {
        io::Error::other(format!(
            "cgroup: verify controllers at {}: {error}",
            subtree.display()
        ))
    })?;
    for controller in CONTROLLERS {
        if !enabled.split_whitespace().any(|item| item == controller) {
            return Err(io::Error::other(format!(
                "cgroup v2 controller {controller:?} could not be enabled at {}",
                group.display()
            )));
        }
    }
    Ok(())
}

fn current_cgroup_delegation() -> io::Result<PathBuf> {
    let membership = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| io::Error::other(format!("cgroup: read membership: {error}")))?;
    let relative = parse_unified_cgroup_path(&membership)?;
    let mount = fs::canonicalize(CGROUP_MOUNT)
        .map_err(|error| io::Error::other(format!("cgroup: resolve mount: {error}")))?;
    let current = fs::canonicalize(mount.join(&relative)).map_err(|error| {
        io::Error::other(format!(
            "cgroup: resolve delegated path {:?}: {error}",
            relative
        ))
    })?;
    if !current.starts_with(&mount) || !current.join("cgroup.controllers").is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unified cgroup membership escaped the cgroup v2 mount",
        ));
    }
    if current
        .file_name()
        .is_some_and(|name| name == CGROUP_SUPERVISOR_DIR)
    {
        return current.parent().map(Path::to_path_buf).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "cgroup supervisor has no delegated parent",
            )
        });
    }
    Ok(current)
}

fn parse_unified_cgroup_path(membership: &str) -> io::Result<PathBuf> {
    let mut matches = membership
        .lines()
        .filter_map(|line| line.strip_prefix("0::"));
    let raw = matches.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "a unified cgroup v2 membership entry is required",
        )
    })?;
    if matches.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "multiple unified cgroup membership entries were reported",
        ));
    }
    let path = Path::new(raw);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unified cgroup membership path was malformed",
        ));
    }
    path.strip_prefix("/")
        .map(Path::to_path_buf)
        .map_err(io::Error::other)
}

fn evacuate_delegation_processes(delegation: &Path) -> io::Result<()> {
    let in_container =
        Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists();
    let broad_host_scope = delegation
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .any(|name| name == "init.scope" || name == "user.slice" || name.starts_with("session-"));
    if broad_host_scope && !in_container {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "cgroup delegation {} is a shared host scope; run Rookhold in a dedicated systemd unit or container",
                delegation.display()
            ),
        ));
    }
    let supervisor = delegation.join(CGROUP_SUPERVISOR_DIR);
    fs::create_dir_all(&supervisor).map_err(|error| {
        io::Error::other(format!(
            "cgroup: create supervisor leaf {}: {error}",
            supervisor.display()
        ))
    })?;
    // A dedicated systemd unit/container delegates the entire current node.
    // Move every direct member into a leaf so domain controllers can be
    // enabled at the now-empty parent. Shared host scopes are rejected above.
    for _ in 0..8 {
        let procs = fs::read_to_string(delegation.join("cgroup.procs")).map_err(|error| {
            io::Error::other(format!(
                "cgroup: list internal processes at {}: {error}",
                delegation.display()
            ))
        })?;
        if procs.trim().is_empty() {
            return Ok(());
        }
        for pid in procs.split_whitespace() {
            let pid = pid.parse::<u32>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cgroup.procs contained a malformed process identifier",
                )
            })?;
            if let Err(error) = fs::write(supervisor.join("cgroup.procs"), pid.to_string()) {
                // `cgroup.procs` is a snapshot. A short-lived service helper
                // can exit between the read and this write, in which case the
                // kernel reports ESRCH and there is no task left to evacuate.
                // Retry the authoritative list; every other write failure is
                // a real delegation/setup failure and remains fail-closed.
                if error.raw_os_error() == Some(libc::ESRCH) {
                    continue;
                }
                return Err(io::Error::other(format!(
                    "cgroup: move delegated process {pid} into supervisor leaf: {error}"
                )));
            }
        }
    }
    Err(io::Error::other(format!(
        "cgroup delegation {} remained internally populated",
        delegation.display()
    )))
}

fn create_cgroup_dir(base: &Path, job_key: &str) -> io::Result<PathBuf> {
    let path = base.join(format!("job-{job_key}"));
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if cgroup_populated(&path) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "a live cgroup already owns this job key",
                ));
            }
            cleanup_cgroup_sync(&path, CLEANUP_GRACE)?;
            fs::create_dir(&path)?;
        }
        Err(error) => return Err(error),
    }
    if !path.join("cgroup.kill").is_file() {
        let _ = fs::remove_dir(&path);
        return Err(io::Error::other(
            "kernel cgroup.kill support is required for namespace execution",
        ));
    }
    Ok(path)
}

fn write_cgroup_limits(group: &Path, limits: &Limits) -> io::Result<()> {
    write_cgroup_limits_with_pids_overhead(group, limits, 1)
}

fn write_cgroup_limits_with_pids_overhead(
    group: &Path,
    limits: &Limits,
    pids_overhead: u32,
) -> io::Result<()> {
    let memory = u64::from(limits.mem_mb) * 1024 * 1024;
    write_cgroup(group, "memory.max", memory)?;
    write_cgroup(group, "memory.swap.max", 0)?;
    write_cgroup(group, "memory.oom.group", 1)?;
    // One-core instantaneous quota prevents a single job from saturating the
    // host between cumulative cpu.stat checks.
    fs::write(group.join("cpu.max"), "100000 100000")?;
    write_cgroup(
        group,
        "pids.max",
        u64::from(limits.max_pids).saturating_add(u64::from(pids_overhead)),
    )?;
    Ok(())
}

fn write_cgroup(group: &Path, name: &str, value: u64) -> io::Result<()> {
    fs::write(group.join(name), value.to_string())
        .map_err(|error| io::Error::other(format!("cgroup: write {name}: {error}")))
}

fn kill_cgroup(group: &Path) -> io::Result<()> {
    fs::write(group.join("cgroup.kill"), "1")
        .map_err(|error| io::Error::other(format!("cgroup.kill failed: {error}")))
}

fn cleanup_cgroup_sync(group: &Path, grace: Duration) -> io::Result<()> {
    if !group.exists() {
        return Ok(());
    }
    if let Err(error) = kill_cgroup(group) {
        if cgroup_populated(group) {
            return Err(error);
        }
    }
    let deadline = Instant::now() + grace;
    while cgroup_populated(group) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if cgroup_populated(group) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("cgroup {} remained populated", group.display()),
        ));
    }
    fs::remove_dir(group)
        .map_err(|error| io::Error::other(format!("remove cgroup {}: {error}", group.display())))
}

pub(crate) fn cgroup_populated(group: &Path) -> bool {
    cgroup_populated_checked(group).unwrap_or(true)
}

pub(crate) fn cgroup_populated_checked(group: &Path) -> io::Result<bool> {
    fs::read_to_string(group.join("cgroup.events"))
        .and_then(|value| {
            value
                .lines()
                .find_map(|line| {
                    line.strip_prefix("populated ")
                        .and_then(|number| number.trim().parse::<u8>().ok())
                })
                .map(|value| value != 0)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "cgroup.events omitted the populated counter",
                    )
                })
        })
        .or_else(|_| {
            fs::read_to_string(group.join("cgroup.procs")).map(|value| !value.trim().is_empty())
        })
}

pub(crate) fn read_named_counter(path: PathBuf, name: &str) -> u64 {
    read_named_counter_checked(path, name).unwrap_or(0)
}

pub(crate) fn read_named_counter_checked(path: PathBuf, name: &str) -> io::Result<u64> {
    let text = fs::read_to_string(&path).map_err(|error| {
        io::Error::other(format!("read cgroup counter {}: {error}", path.display()))
    })?;
    text.lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some(name))
                .then(|| fields.next()?.parse::<u64>().ok())
                .flatten()
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cgroup counter {name:?} was missing from {}",
                    path.display()
                ),
            )
        })
}

pub(crate) fn read_scalar(path: PathBuf) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn cpu_budget_exceeded(group: &Path, before: u64, budget: u64) -> bool {
    read_named_counter(group.join("cpu.stat"), "usage_usec").saturating_sub(before) >= budget
}

pub(crate) struct CgroupLease {
    path: Option<PathBuf>,
}

impl CgroupLease {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    pub(crate) fn path(&self) -> &Path {
        self.path.as_deref().expect("cgroup lease is active")
    }

    pub(crate) fn release(mut self) -> PathBuf {
        self.path.take().expect("cgroup lease is active")
    }
}

pub(crate) fn create_job_cgroup(job_key: &str, limits: &Limits) -> io::Result<CgroupLease> {
    create_job_cgroup_with_pids_overhead(job_key, limits, 1)
}

pub(crate) fn create_job_cgroup_with_pids_overhead(
    job_key: &str,
    limits: &Limits,
    pids_overhead: u32,
) -> io::Result<CgroupLease> {
    let base = prepare_cgroup_base()?;
    let lease = CgroupLease::new(create_cgroup_dir(&base, job_key)?);
    if let Err(error) = write_cgroup_limits_with_pids_overhead(lease.path(), limits, pids_overhead)
    {
        drop(lease);
        return Err(error);
    }
    Ok(lease)
}

pub(crate) async fn cleanup_job_cgroup(lease: CgroupLease) -> io::Result<()> {
    let path = lease.release();
    tokio::task::spawn_blocking(move || cleanup_cgroup_sync(&path, CLEANUP_GRACE))
        .await
        .map_err(|error| io::Error::other(format!("cgroup cleanup task failed: {error}")))?
}

pub(crate) async fn cleanup_job_cgroup_by_key(job_key: &str) -> io::Result<()> {
    validate_job_key(job_key)?;
    let base = prepare_cgroup_base()?;
    let path = base.join(format!("job-{job_key}"));
    tokio::task::spawn_blocking(move || cleanup_cgroup_sync(&path, CLEANUP_GRACE))
        .await
        .map_err(|error| io::Error::other(format!("cgroup cleanup task failed: {error}")))?
}

impl Drop for CgroupLease {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            // This path is reached only when `run` is aborted or unwinds
            // before its normal awaited spawn_blocking cleanup. Complete the
            // bounded teardown here: an unjoined best-effort reaper could be
            // lost during process shutdown and make cleanup unobservable.
            if let Err(error) = cleanup_cgroup_sync(&path, CLEANUP_GRACE) {
                tracing::error!(
                    path = %path.display(),
                    error = %error,
                    "abnormal synchronous cgroup cleanup failed"
                );
            }
        }
    }
}

fn sanitize_stage(stage: &str) -> &'static str {
    match stage {
        STAGE_PLAN => STAGE_PLAN,
        STAGE_NAMESPACES => STAGE_NAMESPACES,
        STAGE_ROOTFS => STAGE_ROOTFS,
        STAGE_PID1 => STAGE_PID1,
        STAGE_CGROUP_ATTACH => STAGE_CGROUP_ATTACH,
        STAGE_PROC => STAGE_PROC,
        STAGE_LIMITS => STAGE_LIMITS,
        STAGE_PRIVILEGES => STAGE_PRIVILEGES,
        STAGE_STDIN => STAGE_STDIN,
        STAGE_SECCOMP => STAGE_SECCOMP,
        STAGE_EXEC => STAGE_EXEC,
        _ => "initializing sandbox",
    }
}

// -------------------------------------------------------------------------
// Fresh single-threaded helper entry point.

pub fn helper_main() -> i32 {
    let plan = match read_plan() {
        Ok(plan) => plan,
        Err(_) => return 126,
    };
    let control_addr = match StdUnixSocketAddr::from_abstract_name(plan.control_name.as_bytes()) {
        Ok(address) => address,
        Err(_) => return 126,
    };
    let control = match StdUnixStream::connect_addr(&control_addr) {
        Ok(stream) => stream,
        Err(_) => return 126,
    };
    if set_cloexec(control.as_raw_fd()).is_err() {
        return 126;
    }
    let _ = send_frame(
        &control,
        &ControlFrame::Hello {
            nonce: plan.nonce.clone(),
            version: PLAN_VERSION,
        },
    );

    if let Err(error) = arm_parent_death() {
        let _ = send_error(&control, &plan.nonce, STAGE_NAMESPACES, &error);
        return 126;
    }
    if let Err(error) = helper_setup_namespaces_and_rootfs(&plan) {
        let stage = if error.to_string().contains("namespace") {
            STAGE_NAMESPACES
        } else {
            STAGE_ROOTFS
        };
        let _ = send_error(&control, &plan.nonce, stage, &error);
        return 126;
    }
    if let Err(error) = nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWPID) {
        let error = io::Error::other(error);
        let _ = send_error(&control, &plan.nonce, STAGE_PID1, &error);
        return 126;
    }

    let (sync_parent, sync_child) = match StdUnixStream::pair() {
        Ok(pair) => pair,
        Err(error) => {
            let _ = send_error(&control, &plan.nonce, STAGE_PID1, &error);
            return 126;
        }
    };
    if send_frame(
        &control,
        &ControlFrame::Pid1LaunchReady {
            nonce: plan.nonce.clone(),
        },
    )
    .is_err()
        || !matches!(
            read_sync_frame(&control),
            Ok(ControlFrame::StartPid1 { nonce }) if nonce == plan.nonce
        )
    {
        return 126;
    }
    let fork_result = unsafe { fork() };
    match fork_result {
        Ok(ForkResult::Parent { child }) => {
            drop(sync_child);
            if send_frame(
                &control,
                &ControlFrame::Pid1Spawned {
                    nonce: plan.nonce.clone(),
                    host_pid: child.as_raw(),
                },
            )
            .is_err()
            {
                let _ = kill(child, Signal::SIGKILL);
                let _ = waitpid(child, None);
                return 126;
            }
            if !matches!(
                read_sync_frame(&control),
                Ok(ControlFrame::Attached { nonce }) if nonce == plan.nonce
            ) {
                let _ = kill(child, Signal::SIGKILL);
                let _ = waitpid(child, None);
                return 126;
            }
            let _ = (&sync_parent).write_all(b"1");
            let status = loop {
                match waitpid(child, None) {
                    Ok(status) => break status,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(_) => return 126,
                }
            };
            match status {
                WaitStatus::Exited(_, code) => code,
                WaitStatus::Signaled(_, signal, _) => 128 + signal as i32,
                _ => 126,
            }
        }
        Ok(ForkResult::Child) => {
            drop(sync_parent);
            pid1_main(&plan, &control, sync_child)
        }
        Err(error) => {
            let error = io::Error::other(error);
            let _ = send_error(&control, &plan.nonce, STAGE_PID1, &error);
            126
        }
    }
}

fn read_plan() -> io::Result<SandboxPlan> {
    let mut length = [0_u8; 4];
    io::stdin().read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_PLAN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid sandbox plan length",
        ));
    }
    let mut bytes = vec![0_u8; length];
    io::stdin().read_exact(&mut bytes)?;
    let plan: SandboxPlan = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if plan.version != PLAN_VERSION
        || plan.nonce.len() != 48
        || !plan.nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
        || plan.control_name.strip_prefix("coop-").is_none_or(|name| {
            name.len() != 48 || !name.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        || !plan.rootfs.is_absolute()
        || !plan.mount_point.is_absolute()
        || !plan.payload_dir.is_absolute()
        || !plan.input_dir.is_absolute()
        || !plan.output_dir.is_absolute()
        || !plan.program.starts_with('/')
        || !plan.source.starts_with("/work/")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sandbox plan failed structural validation",
        ));
    }
    Ok(plan)
}

fn helper_setup_namespaces_and_rootfs(plan: &SandboxPlan) -> io::Result<()> {
    nix::sched::unshare(
        nix::sched::CloneFlags::CLONE_NEWNS
            | nix::sched::CloneFlags::CLONE_NEWNET
            | nix::sched::CloneFlags::CLONE_NEWIPC
            | nix::sched::CloneFlags::CLONE_NEWUTS,
    )
    .map_err(io::Error::other)?;
    set_sandbox_hostname().map_err(|error| {
        io::Error::other(format!("namespace: set sandbox UTS hostname: {error}"))
    })?;
    mount_raw(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
    )?;
    mount_raw(
        Some(&plan.rootfs),
        &plan.mount_point,
        None,
        libc::MS_BIND,
        None,
    )?;
    recursive_mount_attributes(&plan.mount_point)?;

    let tmp = plan.mount_point.join("tmp");
    let tmp_size = u64::from(plan.limits.max_file_mb)
        .saturating_mul(1024 * 1024)
        .min(u64::from(plan.limits.mem_mb).saturating_mul(1024 * 1024));
    mount_raw(
        Some(Path::new("tmpfs")),
        &tmp,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some(&format!("size={tmp_size},mode=1777")),
    )?;
    fs::create_dir_all(tmp.join("home"))?;

    let dev = plan.mount_point.join("dev");
    mount_raw(
        Some(Path::new("tmpfs")),
        &dev,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("size=65536,mode=755"),
    )?;
    create_device(&dev.join("null"), 1, 3, 0o666)?;
    create_device(&dev.join("zero"), 1, 5, 0o666)?;
    create_device(&dev.join("full"), 1, 7, 0o666)?;
    create_device(&dev.join("random"), 1, 8, 0o444)?;
    create_device(&dev.join("urandom"), 1, 9, 0o444)?;
    fs::create_dir(dev.join("shm"))?;
    mount_raw(
        Some(Path::new("tmpfs")),
        &dev.join("shm"),
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("size=16777216,mode=1777"),
    )?;

    let work = plan.mount_point.join("work");
    mount_raw(Some(&plan.payload_dir), &work, None, libc::MS_BIND, None)?;
    mount_raw(
        Some(&plan.payload_dir),
        &work,
        None,
        libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_RDONLY
            | libc::MS_NOSUID
            | libc::MS_NODEV
            | libc::MS_NOEXEC,
        None,
    )?;

    let input = plan.mount_point.join("input");
    mount_raw(Some(&plan.input_dir), &input, None, libc::MS_BIND, None)?;
    mount_raw(
        Some(&plan.input_dir),
        &input,
        None,
        libc::MS_BIND
            | libc::MS_REMOUNT
            | libc::MS_RDONLY
            | libc::MS_NOSUID
            | libc::MS_NODEV
            | libc::MS_NOEXEC,
        None,
    )?;
    let output = plan.mount_point.join("output");
    mount_raw(Some(&plan.output_dir), &output, None, libc::MS_BIND, None)?;
    mount_raw(
        Some(&plan.output_dir),
        &output,
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )?;

    pivot_root(&plan.mount_point, &plan.mount_point.join(".pivot_old"))?;
    chdir("/").map_err(io::Error::other)?;
    let old = CString::new("/.pivot_old")?;
    if unsafe { libc::umount2(old.as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn pid1_main(plan: &SandboxPlan, control: &StdUnixStream, mut sync: StdUnixStream) -> i32 {
    if let Err(error) = arm_parent_death() {
        let _ = send_error(control, &plan.nonce, STAGE_PID1, &error);
        return 126;
    }
    let mut attached = [0_u8; 1];
    if sync.read_exact(&mut attached).is_err() {
        let error = io::Error::other("parent did not confirm cgroup attachment");
        let _ = send_error(control, &plan.nonce, STAGE_CGROUP_ATTACH, &error);
        return 126;
    }
    drop(sync);
    if let Err(error) = mount_proc() {
        let _ = send_error(control, &plan.nonce, STAGE_PROC, &error);
        return 126;
    }

    let (exec_read, exec_write) = match StdUnixStream::pair() {
        Ok(pair) => pair,
        Err(error) => {
            let _ = send_error(control, &plan.nonce, STAGE_EXEC, &error);
            return 126;
        }
    };
    if let Err(error) = set_cloexec(exec_write.as_raw_fd()) {
        let _ = send_error(control, &plan.nonce, STAGE_EXEC, &error);
        return 126;
    }
    let workload = unsafe { fork() };
    let workload = match workload {
        Ok(ForkResult::Parent { child }) => child,
        Ok(ForkResult::Child) => workload_exec(plan, exec_read, exec_write),
        Err(error) => {
            let error = io::Error::other(error);
            let _ = send_error(control, &plan.nonce, STAGE_EXEC, &error);
            return 126;
        }
    };
    if send_frame(
        control,
        &ControlFrame::WorkloadSpawned {
            nonce: plan.nonce.clone(),
        },
    )
    .is_err()
    {
        let _ = kill(workload, Signal::SIGKILL);
        loop {
            match waitpid(workload, None) {
                Ok(_) | Err(nix::errno::Errno::ECHILD) => break,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => break,
            }
        }
        return 126;
    }
    drop(exec_write);
    let mut setup = io::BufReader::new(exec_read);
    let mut failure = String::new();
    match setup.read_line(&mut failure) {
        Ok(0) => {
            let _ = send_frame(
                control,
                &ControlFrame::Ready {
                    nonce: plan.nonce.clone(),
                },
            );
        }
        Ok(_) | Err(_) => {
            let (stage, errno) = failure
                .trim_end()
                .split_once('\t')
                .and_then(|(stage, errno)| Some((stage, errno.parse::<i32>().ok()?)))
                .unwrap_or((STAGE_EXEC, 0));
            let _ = send_frame(
                control,
                &ControlFrame::Error {
                    nonce: plan.nonce.clone(),
                    stage: sanitize_stage(stage).to_string(),
                    errno,
                },
            );
        }
    }

    let primary = loop {
        match waitpid(workload, None) {
            Ok(status) => break status,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return 126,
        }
    };
    // PID1 owns the namespace lifecycle. Once the primary exits, no daemon or
    // pipe-holding descendant is allowed to outlive the job.
    if let Err(error) = kill(Pid::from_raw(-1), Signal::SIGKILL) {
        if error != nix::errno::Errno::ESRCH {
            let error = io::Error::other(error);
            let _ = send_error(control, &plan.nonce, STAGE_PID1, &error);
            return 126;
        }
    }
    loop {
        match waitpid(Pid::from_raw(-1), None) {
            Ok(_) | Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => break,
            Err(_) => break,
        }
    }

    let (disposition, value) = match primary {
        WaitStatus::Exited(_, code) => ("exited", code),
        WaitStatus::Signaled(_, signal, _) => ("signaled", signal as i32),
        _ => ("exited", 126),
    };
    let _ = send_frame(
        control,
        &ControlFrame::Final {
            nonce: plan.nonce.clone(),
            disposition: disposition.to_string(),
            value,
        },
    );
    if disposition == "exited" {
        value
    } else {
        128 + value
    }
}

fn workload_exec(plan: &SandboxPlan, exec_read: StdUnixStream, exec_write: StdUnixStream) -> ! {
    drop(exec_read);
    let fail = |stage: &'static str, error: io::Error| -> ! {
        let mut writer = &exec_write;
        let _ = writeln!(
            writer,
            "{}\t{}",
            sanitize_stage(stage),
            error.raw_os_error().unwrap_or(0)
        );
        unsafe { libc::_exit(126) }
    };

    if let Err(error) = apply_limits(&plan.limits) {
        fail(STAGE_LIMITS, error);
    }
    let stdin_path = if plan.stdin_present {
        Path::new("/work/stdin")
    } else {
        Path::new("/dev/null")
    };
    let stdin = match fs::File::open(stdin_path) {
        Ok(file) => file,
        Err(error) => fail(STAGE_STDIN, error),
    };
    if let Err(error) = dup2(stdin.as_raw_fd(), 0).map_err(io::Error::other) {
        fail(STAGE_STDIN, error);
    }
    if let Err(error) = chdir("/").map_err(io::Error::other) {
        fail(STAGE_ROOTFS, error);
    }
    if let Err(error) = drop_workload_privileges() {
        fail(STAGE_PRIVILEGES, error);
    }

    let program = match CString::new(plan.program.as_bytes()) {
        Ok(value) => value,
        Err(error) => fail(
            STAGE_EXEC,
            io::Error::new(io::ErrorKind::InvalidInput, error),
        ),
    };
    let source = match CString::new(plan.source.as_bytes()) {
        Ok(value) => value,
        Err(error) => fail(
            STAGE_EXEC,
            io::Error::new(io::ErrorKind::InvalidInput, error),
        ),
    };
    let argv = [&program, &source];
    let env = [
        CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .expect("static env"),
        CString::new("HOME=/tmp/home").expect("static env"),
        CString::new("TMPDIR=/tmp").expect("static env"),
        CString::new("LANG=C.UTF-8").expect("static env"),
    ];
    let env_refs: Vec<&CString> = env.iter().collect();

    if plan.seccomp {
        #[cfg(not(target_arch = "x86_64"))]
        fail(
            STAGE_SECCOMP,
            io::Error::other("seccomp policy is not available on this architecture"),
        );
        #[cfg(target_arch = "x86_64")]
        if let Err(error) = crate::seccomp::install() {
            fail(STAGE_SECCOMP, io::Error::other(error));
        }
    }

    let Err(error) = execve(&program, &argv, &env_refs);
    fail(STAGE_EXEC, errno_as_io_error(error));
}

fn errno_as_io_error(error: nix::errno::Errno) -> io::Error {
    error.into()
}

fn apply_limits(limits: &Limits) -> io::Result<()> {
    let cpu = u64::from(limits.cpu_seconds.max(1));
    let file = u64::from(limits.max_file_mb) * 1024 * 1024;
    setrlimit(Resource::RLIMIT_CPU, cpu + 1, cpu + 2).map_err(io::Error::other)?;
    // memory.max is the aggregate physical-memory boundary for namespace jobs.
    // RLIMIT_AS is intentionally omitted: V8 reserves a large sparse virtual
    // address range even when its resident memory remains below the cgroup cap.
    // Do not set RLIMIT_NPROC: it is accounted across every process sharing
    // host UID 65534 and would let one job deny fork/thread creation to
    // unrelated jobs. The job-local cgroup pids.max is the authoritative cap.
    setrlimit(Resource::RLIMIT_NOFILE, 256, 256).map_err(io::Error::other)?;
    setrlimit(Resource::RLIMIT_FSIZE, file, file).map_err(io::Error::other)?;
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(io::Error::other)?;
    Ok(())
}

fn drop_workload_privileges() -> io::Result<()> {
    setgroups(&[]).map_err(io::Error::other)?;
    for capability in 0..=63 {
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
            return Err(io::Error::last_os_error());
        }
    }
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    setresgid(
        Gid::from_raw(NOBODY_GID),
        Gid::from_raw(NOBODY_GID),
        Gid::from_raw(NOBODY_GID),
    )
    .map_err(io::Error::other)?;
    setresuid(
        Uid::from_raw(NOBODY_UID),
        Uid::from_raw(NOBODY_UID),
        Uid::from_raw(NOBODY_UID),
    )
    .map_err(io::Error::other)?;
    clear_capability_sets()?;
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    verify_workload_identity()
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn clear_capability_sets() -> io::Result<()> {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    let result = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn verify_capability_sets() -> io::Result<()> {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    if unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if data
        .iter()
        .any(|word| word.effective != 0 || word.permitted != 0 || word.inheritable != 0)
    {
        return Err(io::Error::other(
            "effective, permitted, or inheritable capabilities were retained",
        ));
    }

    // Linux capability IDs are contiguous. The first EINVAL after at least
    // capability zero is cap_last_cap + 1; every valid ID must be absent from
    // both the bounding and ambient sets.
    for capability in 0..=63 {
        let bounding = unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0) };
        match bounding {
            0 => {}
            1 => {
                return Err(io::Error::other(format!(
                    "capability {capability} remained in the bounding set"
                )))
            }
            -1 => {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINVAL) && capability > 0 {
                    break;
                }
                return Err(error);
            }
            value => {
                return Err(io::Error::other(format!(
                    "PR_CAPBSET_READ returned unexpected value {value}"
                )))
            }
        }

        let ambient = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET,
                capability,
                0,
                0,
            )
        };
        match ambient {
            0 => {}
            1 => {
                return Err(io::Error::other(format!(
                    "capability {capability} remained in the ambient set"
                )))
            }
            -1 => return Err(io::Error::last_os_error()),
            value => {
                return Err(io::Error::other(format!(
                    "PR_CAP_AMBIENT_IS_SET returned unexpected value {value}"
                )))
            }
        }
    }
    Ok(())
}

fn verify_workload_identity() -> io::Result<()> {
    let mut ruid = 0;
    let mut euid = 0;
    let mut suid = 0;
    let mut rgid = 0;
    let mut egid = 0;
    let mut sgid = 0;
    if unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) } != 0
        || unsafe { libc::getresgid(&mut rgid, &mut egid, &mut sgid) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if [ruid, euid, suid] != [NOBODY_UID; 3] || [rgid, egid, sgid] != [NOBODY_GID; 3] {
        return Err(io::Error::other("workload uid/gid drop did not stick"));
    }
    let groups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if groups != 0 {
        return Err(if groups < 0 {
            io::Error::last_os_error()
        } else {
            io::Error::other("supplementary groups were retained")
        });
    }
    verify_capability_sets()?;

    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    match no_new_privs {
        1 => {}
        -1 => return Err(io::Error::last_os_error()),
        value => {
            return Err(io::Error::other(format!(
                "no_new_privs verification returned {value}"
            )))
        }
    }
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    match dumpable {
        0 => Ok(()),
        -1 => Err(io::Error::last_os_error()),
        value => Err(io::Error::other(format!(
            "workload remained dumpable ({value})"
        ))),
    }
}

fn mount_proc() -> io::Result<()> {
    mount_raw(
        Some(Path::new("proc")),
        Path::new("/proc"),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
    )
}

fn set_sandbox_hostname() -> io::Result<()> {
    let result =
        unsafe { libc::sethostname(SANDBOX_HOSTNAME.as_ptr().cast(), SANDBOX_HOSTNAME.len()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn arm_parent_death() -> io::Result<()> {
    let parent_before = unsafe { libc::getppid() };
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let parent_after = unsafe { libc::getppid() };
    if !parent_identity_is_stable(parent_before, parent_after) {
        return Err(io::Error::other("sandbox parent died during bootstrap"));
    }
    Ok(())
}

fn parent_identity_is_stable(before: libc::pid_t, after: libc::pid_t) -> bool {
    before == after
}

fn set_cloexec(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn send_frame(stream: &StdUnixStream, frame: &ControlFrame) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(frame).map_err(io::Error::other)?;
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sandbox helper control frame exceeded its bound",
        ));
    }
    bytes.push(b'\n');
    (&*stream).write_all(&bytes)
}

fn read_sync_frame(stream: &StdUnixStream) -> io::Result<ControlFrame> {
    let mut bytes = [0_u8; MAX_CONTROL_FRAME_BYTES];
    let mut len = 0_usize;
    loop {
        let mut byte = [0_u8; 1];
        (&*stream).read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            if len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sandbox parent sent an empty control frame",
                ));
            }
            return serde_json::from_slice(&bytes[..len])
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
        }
        if len == MAX_CONTROL_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sandbox parent control frame exceeded its bound",
            ));
        }
        bytes[len] = byte[0];
        len += 1;
    }
}

fn send_error(
    stream: &StdUnixStream,
    nonce: &str,
    stage: &'static str,
    error: &io::Error,
) -> io::Result<()> {
    send_frame(
        stream,
        &ControlFrame::Error {
            nonce: nonce.to_string(),
            stage: sanitize_stage(stage).to_string(),
            errno: error.raw_os_error().unwrap_or(0),
        },
    )
}

fn mount_raw(
    source: Option<&Path>,
    target: &Path,
    filesystem: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let source = source.map(path_cstring).transpose()?;
    let target = path_cstring(target)?;
    let filesystem = filesystem.map(CString::new).transpose()?;
    let data = data.map(CString::new).transpose()?;
    let result = unsafe {
        libc::mount(
            source
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            target.as_ptr(),
            filesystem
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn path_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

fn recursive_mount_attributes(path: &Path) -> io::Result<()> {
    const AT_RECURSIVE: u32 = 0x8000;
    const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
    const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
    const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
    let path = path_cstring(path)?;
    let attributes = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            path.as_ptr(),
            AT_RECURSIVE,
            &attributes as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn pivot_root(new_root: &Path, put_old: &Path) -> io::Result<()> {
    let new_root = path_cstring(new_root)?;
    let put_old = path_cstring(put_old)?;
    let result =
        unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), put_old.as_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn create_device(path: &Path, major: u32, minor: u32, mode: u32) -> io::Result<()> {
    let encoded_path = path_cstring(path)?;
    let device = libc::makedev(major, minor);
    let result = unsafe { libc::mknod(encoded_path.as_ptr(), libc::S_IFCHR | mode, device) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    // mknod(2) applies the helper's inherited umask. Production service
    // managers commonly use a restrictive umask (for example 0077), which
    // would otherwise turn /dev/null and /dev/urandom into root-only nodes
    // before the workload drops to nobody. Establish and verify the complete
    // metadata explicitly while the private /dev is still inaccessible to
    // the tenant.
    if unsafe { libc::chown(encoded_path.as_ptr(), 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::chmod(encoded_path.as_ptr(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != 0 || metadata.gid() != 0 || metadata.mode() & 0o7777 != mode {
        return Err(io::Error::other(format!(
            "device {} metadata mismatch after creation: uid={}, gid={}, mode={:04o}; expected uid=0, gid=0, mode={mode:04o}",
            path.display(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode() & 0o7777,
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingSink {
        violations: std::sync::Mutex<Vec<&'static str>>,
    }

    impl Sink for RecordingSink {
        fn output(&self, _stream: Stream, _line: String) {}

        fn violation(&self, rule: &'static str, _detail: serde_json::Value) {
            self.violations.lock().unwrap().push(rule);
        }

        fn truncated(&self, _stream: Stream) {}
    }

    #[test]
    fn job_key_rejects_path_components_and_overlong_values() {
        for invalid in ["", "../x", "a/b", "a\\b", "..", "💣"] {
            assert!(validate_job_key(invalid).is_err(), "accepted {invalid:?}");
        }
        assert!(validate_job_key(&"a".repeat(65)).is_err());
        assert!(validate_job_key("018f-fedc_123").is_ok());
    }

    #[test]
    fn rootfs_rejects_host_root() {
        let work = std::env::temp_dir();
        assert!(validate_rootfs(Path::new("/"), &work).is_err());
    }

    #[test]
    fn interpreter_errno_conversion_preserves_the_kernel_error() {
        let error = errno_as_io_error(nix::errno::Errno::EACCES);
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn unified_cgroup_membership_is_relative_and_traversal_free() {
        assert_eq!(
            parse_unified_cgroup_path("0::/system.slice/coop.service\n").unwrap(),
            PathBuf::from("system.slice/coop.service")
        );
        assert_eq!(parse_unified_cgroup_path("0::/\n").unwrap(), PathBuf::new());
        for invalid in [
            "",
            "1:name=/legacy\n",
            "0::relative\n",
            "0::/safe/../escape\n",
            "0::/one\n0::/two\n",
        ] {
            assert!(
                parse_unified_cgroup_path(invalid).is_err(),
                "accepted malformed membership {invalid:?}"
            );
        }
    }

    #[test]
    fn stable_init_parent_is_valid_but_reparenting_is_not() {
        assert!(parent_identity_is_stable(1, 1));
        assert!(parent_identity_is_stable(0, 0));
        assert!(parent_identity_is_stable(42, 42));
        assert!(!parent_identity_is_stable(42, 1));
        assert!(!parent_identity_is_stable(42, 0));
    }

    #[test]
    fn cgroup_oom_classifies_without_helper_final_status() {
        let sink = RecordingSink::default();
        let outcome = classify_workload(
            None,
            true,
            &Limits::default(),
            &sink,
            ExecTelemetry::default(),
        )
        .unwrap();
        assert_eq!(outcome.status, OutcomeStatus::OomKilled);
        assert_eq!(outcome.killed_by.as_deref(), Some("cgroup-oom"));
        assert_eq!(
            sink.violations.lock().unwrap().as_slice(),
            ["memory_cap_exceeded"]
        );

        let error = classify_workload(
            None,
            false,
            &Limits::default(),
            &RecordingSink::default(),
            ExecTelemetry::default(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("omitted final status"));
    }

    #[test]
    fn control_frames_are_small_and_tagged() {
        let frame = ControlFrame::Final {
            nonce: "a".repeat(48),
            disposition: "exited".to_string(),
            value: 0,
        };
        let bytes = serde_json::to_vec(&frame).unwrap();
        assert!(bytes.len() < MAX_CONTROL_FRAME_BYTES);
        assert!(String::from_utf8(bytes)
            .unwrap()
            .contains("\"type\":\"final\""));
    }

    #[test]
    fn synchronous_control_reader_rejects_oversized_frame_before_allocating() {
        let (mut writer, reader) = StdUnixStream::pair().unwrap();
        writer
            .write_all(&vec![b'x'; MAX_CONTROL_FRAME_BYTES + 1])
            .unwrap();
        let error = read_sync_frame(&reader).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn async_control_reader_handles_coalesced_bounded_frames() {
        let (mut sender, receiver) = tokio::net::UnixStream::pair().unwrap();
        assert_eq!(unix_peer_pid(&receiver).unwrap(), std::process::id());
        let nonce = "a".repeat(48);
        let frames = [
            ControlFrame::Ready {
                nonce: nonce.clone(),
            },
            ControlFrame::Final {
                nonce: nonce.clone(),
                disposition: "exited".to_string(),
                value: 0,
            },
        ];
        let mut encoded = Vec::new();
        for frame in &frames {
            encoded.extend(serde_json::to_vec(frame).unwrap());
            encoded.push(b'\n');
        }
        sender.write_all(&encoded).await.unwrap();
        sender.shutdown().await.unwrap();

        let (read, _write) = receiver.into_split();
        let mut reader = AsyncControlReader::new(read);
        assert!(matches!(
            reader.next_frame().await.unwrap(),
            Some(ControlFrame::Ready { nonce: received }) if received == nonce
        ));
        assert!(matches!(
            reader.next_frame().await.unwrap(),
            Some(ControlFrame::Final { value: 0, .. })
        ));
        assert!(reader.next_frame().await.unwrap().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pid1_launch_ack_drains_a_sync_close_without_runtime_deadlock() {
        let (server, helper) = StdUnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        let server = tokio::net::UnixStream::from_std(server).unwrap();
        let (reader, writer) = server.into_split();
        let gate = Arc::new(crate::ExecutionStartGate::default());
        let permit = ProcessLaunchPermit {
            _process: Some(gate.enter().expect("open launch gate")),
            _job: None,
        };
        let nonce = "pid1-launch-nonce".to_string();
        let helper_nonce = nonce.clone();
        let (authorized_tx, authorized_rx) = tokio::sync::oneshot::channel();
        let (fork_tx, fork_rx) = std::sync::mpsc::channel();
        let helper = std::thread::spawn(move || {
            assert!(matches!(
                read_sync_frame(&helper),
                Ok(ControlFrame::StartPid1 { nonce }) if nonce == helper_nonce
            ));
            authorized_tx.send(()).unwrap();
            fork_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            send_frame(
                &helper,
                &ControlFrame::Pid1Spawned {
                    nonce: helper_nonce,
                    host_pid: 4242,
                },
            )
            .unwrap();
        });
        let handshake = tokio::spawn(authorize_pid1_launch(
            AsyncControlReader::new(reader),
            writer,
            nonce,
            permit,
        ));
        authorized_rx.await.unwrap();

        let release_gate = Arc::clone(&gate);
        let release = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(1);
            while !release_gate.is_closed() {
                assert!(Instant::now() < deadline, "start gate did not close");
                std::thread::yield_now();
            }
            fork_tx.send(()).unwrap();
        });
        // This deliberately blocks the sole async runtime thread. The ACK
        // handshake lives on the blocking pool and must still release us.
        gate.close();

        let (_, _, pid1) = handshake.await.unwrap().unwrap();
        assert_eq!(pid1, 4242);
        release.join().unwrap();
        helper.join().unwrap();
        assert!(gate.enter().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn workload_fork_ack_drains_a_sync_close_without_runtime_deadlock() {
        let (server, helper) = StdUnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        let server = tokio::net::UnixStream::from_std(server).unwrap();
        let (reader, writer) = server.into_split();
        let gate = Arc::new(crate::ExecutionStartGate::default());
        let permit = ProcessLaunchPermit {
            _process: Some(gate.enter().expect("open launch gate")),
            _job: None,
        };
        let nonce = "workload-launch-nonce".to_string();
        let helper_nonce = nonce.clone();
        let (authorized_tx, authorized_rx) = tokio::sync::oneshot::channel();
        let (fork_tx, fork_rx) = std::sync::mpsc::channel();
        let helper = std::thread::spawn(move || {
            assert!(matches!(
                read_sync_frame(&helper),
                Ok(ControlFrame::Attached { nonce }) if nonce == helper_nonce
            ));
            authorized_tx.send(()).unwrap();
            fork_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            send_frame(
                &helper,
                &ControlFrame::WorkloadSpawned {
                    nonce: helper_nonce,
                },
            )
            .unwrap();
        });
        let handshake = tokio::spawn(authorize_workload_launch(
            AsyncControlReader::new(reader),
            writer,
            nonce,
            permit,
        ));
        authorized_rx.await.unwrap();

        let release_gate = Arc::clone(&gate);
        let release = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(1);
            while !release_gate.is_closed() {
                assert!(Instant::now() < deadline, "start gate did not close");
                std::thread::yield_now();
            }
            fork_tx.send(()).unwrap();
        });
        gate.close();

        handshake.await.unwrap().unwrap();
        release.join().unwrap();
        helper.join().unwrap();
        assert!(gate.enter().is_err());
    }

    #[tokio::test]
    async fn helper_accept_bounds_unexpected_peer_backlogs() {
        let name = format!(
            "coop-wrong-peer-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let address = StdUnixSocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let std_listener = StdUnixListener::bind_addr(&address).unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let listener = UnixListener::from_std(std_listener).unwrap();
        let accept = tokio::spawn(async move { accept_helper(&listener, u32::MAX).await });

        let mut peers = Vec::with_capacity(MAX_REJECTED_CONTROL_PEERS);
        for _ in 0..MAX_REJECTED_CONTROL_PEERS {
            peers.push(StdUnixStream::connect_addr(&address).unwrap());
        }
        let error = tokio::time::timeout(Duration::from_secs(2), accept)
            .await
            .expect("unexpected-peer cap must finish before the handshake timeout")
            .expect("accept task")
            .expect_err("wrong-peer backlog must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("too many unexpected"));
        drop(peers);
    }
}
