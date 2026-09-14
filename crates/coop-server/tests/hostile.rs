#![cfg(target_os = "linux")]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use coop_server::config::Config;
use coop_server::scheduler;
use coop_store::Store;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const TERMINAL: [&str; 6] = [
    "succeeded",
    "failed",
    "timed_out",
    "oom_killed",
    "cancelled",
    "error",
];

fn init_tracing() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new("info,coop_server=debug")
                }),
            )
            .with_test_writer()
            .try_init();
    });
}

fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn preflight() -> bool {
    init_tracing();

    if !is_root() {
        eprintln!("SKIP: hostile suite needs root (namespaces + cgroup delegation)");
        return false;
    }

    let controllers = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers");
    if !controllers.exists() {
        eprintln!(
            "SKIP: cgroup v2 unified hierarchy not found ({controllers:?} missing); \
             host may be running cgroup v1"
        );
        return false;
    }

    for (variable, legacy) in [
        ("ROOKHOLD_ROOTFS", "COOP_ROOTFS"),
        ("ROOKHOLD_SANDBOX_HELPER", "COOP_SANDBOX_HELPER"),
    ] {
        let configured = std::env::var(variable)
            .ok()
            .or_else(|| std::env::var(legacy).ok());
        if configured
            .as_deref()
            .is_none_or(|value| !std::path::Path::new(value).exists())
        {
            eprintln!(
                "SKIP: {variable} (or legacy {legacy}) must point to a prepared containment test artifact"
            );
            return false;
        }
    }

    eprintln!("preflight: root=yes, cgroup-v2=yes — running containment suite");
    true
}

fn coop_cgroup_jobs_root() -> std::path::PathBuf {
    let membership =
        std::fs::read_to_string("/proc/self/cgroup").expect("read unified cgroup membership");
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("unified cgroup v2 membership");
    let mut delegated =
        std::path::Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
    if delegated
        .file_name()
        .is_some_and(|name| name == "coop-supervisor")
    {
        delegated.pop();
    }
    delegated.join("coop-jobs")
}

async fn spawn_app_with_root() -> (Router, String) {
    let db = std::env::temp_dir().join(format!("coop-hostile-{}.db", uuid::Uuid::now_v7()));
    let mut api_keys = HashMap::new();
    api_keys.insert("test-key".to_string(), "t1".to_string());
    let jobs_root = format!("/var/lib/coop/jobs-test-{}", uuid::Uuid::now_v7());
    let cfg = Config {
        addr: "127.0.0.1:0".to_string(),
        db_path: db.to_string_lossy().into_owned(),
        api_keys,
        metrics_token: None,
        attestation_mode: coop_server::config::AttestationMode::Off,
        attestation_key_file: None,
        credentials: Default::default(),
        jwt: None,
        workers: 2,
        tenant_concurrency: 4,
        tenant_queue_capacity: 64,
        rate_per_min: 10_000,
        max_job_mem_mb: 1024,
        memory_budget_mb: 4096,
        storage_global_mb: 16 * 1024,
        storage_tenant_mb: 4 * 1024,
        storage_free_reserve_mb: 0,
        sandbox: "ns".to_string(),
        jobs_root,
        rootfs: std::env::var("ROOKHOLD_ROOTFS")
            .ok()
            .or_else(|| std::env::var("COOP_ROOTFS").ok()),
        sandbox_helper: std::env::var("ROOKHOLD_SANDBOX_HELPER")
            .ok()
            .or_else(|| std::env::var("COOP_SANDBOX_HELPER").ok()),
        gvisor_runsc: None,
        gvisor_rootfs_sha256: None,
        gvisor_platform: "systrap".to_string(),
        gvisor_uid: 65_534,
        gvisor_gid: 65_534,
        production: false,
        unsafe_allow_naive: false,
        unsafe_allow_public_dev: false,
        python_bin: None,
        node_bin: None,
        bash_bin: None,
        retention_hours: 0,
        sweep_interval_secs: 3600,
        seccomp: true,
    };
    let store = Arc::new(Store::open(&db).await.expect("open store"));
    let (app, state, queue_rx) = coop_server::build_app(cfg, store, "127.0.0.1:0".parse().unwrap())
        .await
        .expect("build app");
    // Read everything needed off `state` before it moves into the workers.
    let cfg_jobs_root = state.cfg.jobs_root.clone();
    eprintln!(
        "sandbox resolved by server: {}",
        state.sandbox_mode.as_str()
    );
    scheduler::spawn_workers(state, queue_rx);
    (app, cfg_jobs_root)
}

async fn spawn_app() -> Router {
    spawn_app_with_root().await.0
}

async fn send_raw(app: &Router, req: Request<Body>) -> serde_json::Value {
    let res = app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK, "unexpected http status");
    let bytes = axum::body::to_bytes(res.into_body(), 4 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json body")
}

async fn submit(app: &Router, language: &str, code: &str, limits: serde_json::Value) -> String {
    let payload = serde_json::json!({ "language": language, "code": code, "limits": limits });
    let req = Request::builder()
        .method("POST")
        .uri("/v1/jobs")
        .header(header::AUTHORIZATION, "Bearer test-key")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "submit rejected");
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["job_id"].as_str().unwrap().to_string()
}

async fn wait_terminal(app: &Router, job_id: &str) -> (String, f64) {
    let started = std::time::Instant::now();
    for _ in 0..300 {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/v1/jobs/{job_id}"))
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let v = send_raw(app, req).await;
        let status = v["status"].as_str().unwrap_or("").to_string();
        if TERMINAL.contains(&status.as_str()) {
            return (status, started.elapsed().as_secs_f64());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("job {job_id} never reached a terminal state within 30s");
}

async fn replay_events(app: &Router, job_id: &str) -> serde_json::Value {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/v1/jobs/{job_id}/replay"))
        .header(header::AUTHORIZATION, "Bearer test-key")
        .body(Body::empty())
        .unwrap();
    send_raw(app, req).await
}

async fn replay_stdout(app: &Router, job_id: &str) -> String {
    let replay = replay_events(app, job_id).await;
    event_values(&replay)
        .iter()
        .filter(|e| e["kind"] == "stdout")
        .filter_map(|e| e["data"]["line"].as_str().map(str::to_string))
        .collect::<Vec<_>>()
        .join("\n")
}

fn event_values(replay: &serde_json::Value) -> &[serde_json::Value] {
    replay
        .get("events")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn render_events(events: &serde_json::Value) -> String {
    let rendered = event_values(events)
        .iter()
        .map(|e| {
            format!(
                "  {:>3} [{:<9}] {}",
                e["seq"],
                e["kind"].as_str().unwrap_or("?"),
                e["data"]
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    if rendered.is_empty() {
        "<no events>".to_string()
    } else {
        rendered
    }
}

async fn expect_status(app: &Router, job_id: &str, acceptable: &[&str]) -> (String, f64) {
    let (status, elapsed) = wait_terminal(app, job_id).await;
    if !acceptable.contains(&status.as_str()) {
        let events = replay_events(app, job_id).await;
        panic!(
            "job {job_id}: expected one of {acceptable:?}, got '{status}' after {elapsed:.2}s\n\
             --- event log ---\n{}\n-----------------",
            render_events(&events)
        );
    }
    (status, elapsed)
}

async fn assert_host_still_serves(app: &Router) {
    let id = submit(
        app,
        "python",
        "print('host-alive')",
        serde_json::json!({ "wall_seconds": 10 }),
    )
    .await;
    let (status, _) = expect_status(app, &id, &["succeeded"]).await;
    assert_eq!(
        status, "succeeded",
        "host must stay healthy after hostile job"
    );
}

const FORK_BOMB: &str = include_str!("fixtures/hostile-jobs/fork_bomb.sh");
const BACKGROUND_HOLDER: &str = include_str!("fixtures/hostile-jobs/background_holder.sh");
const MEMORY_BOMB: &str = include_str!("fixtures/hostile-jobs/memory_bomb.py");
const INFINITE_LOOP: &str = include_str!("fixtures/hostile-jobs/infinite_loop.py");
const NETWORK_PROBE: &str = include_str!("fixtures/hostile-jobs/network_probe.py");
const DISK_FILLER: &str = include_str!("fixtures/hostile-jobs/disk_filler.py");
const ESCAPE_PROBE: &str = include_str!("fixtures/hostile-jobs/escape_probe.py");
const PID_BOMB: &str = include_str!("fixtures/hostile-jobs/pid_bomb.py");
const PTRACE_PROBE: &str = include_str!("fixtures/hostile-jobs/ptrace_probe.py");

#[tokio::test]
#[ignore]
async fn contains_fork_bomb() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let capabilities = send_raw(
        &app,
        Request::builder()
            .method("GET")
            .uri("/v1/capabilities")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(capabilities["execution"]["isolated"], true);
    assert_eq!(capabilities["execution"]["seccomp"], true);
    assert_eq!(capabilities["execution"]["networking"], "disabled");
    let id = submit(
        &app,
        "bash",
        FORK_BOMB,
        serde_json::json!({ "wall_seconds": 8, "max_pids": 32 }),
    )
    .await;
    let (_, elapsed) = expect_status(&app, &id, &["succeeded", "failed", "timed_out"]).await;
    assert!(
        elapsed < 25.0,
        "fork bomb must be contained quickly, took {elapsed}s"
    );
    let stdout = replay_stdout(&app, &id).await;
    let alive: u32 = stdout
        .split("alive=")
        .nth(1)
        .map(|rest| {
            rest.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()
                .unwrap_or(u32::MAX)
        })
        .unwrap_or(0);
    assert!(
        alive <= 33,
        "pids.max must cap the live process tree; job reported alive={alive}\nstdout:\n{stdout}"
    );
    assert_host_still_serves(&app).await;
}

#[tokio::test]
#[ignore]
async fn background_holder_does_not_hang_worker() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let id = submit(
        &app,
        "bash",
        BACKGROUND_HOLDER,
        serde_json::json!({ "wall_seconds": 5 }),
    )
    .await;
    let (status, elapsed) = expect_status(&app, &id, &["succeeded"]).await;
    assert_eq!(status, "succeeded");
    let stdout = replay_stdout(&app, &id).await;
    assert!(
        stdout.contains("done"),
        "'echo done' output must survive the post-reap group kill; stdout was:\n{stdout}"
    );
    assert!(
        elapsed < 15.0,
        "background `sleep infinity` holding the pipes must not pin the worker \
         past wall(5s)+grace; job took {elapsed:.2}s"
    );
    assert_host_still_serves(&app).await;
}

#[tokio::test]
#[ignore]
async fn contains_memory_bomb() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let id = submit(
        &app,
        "python",
        MEMORY_BOMB,
        serde_json::json!({ "wall_seconds": 15, "mem_mb": 128 }),
    )
    .await;
    let (status, _) = expect_status(&app, &id, &["oom_killed"]).await;
    assert_eq!(
        status, "oom_killed",
        "aggregate cgroup OOM must remain classifiable when PID1 cannot send a final frame"
    );
    let events = replay_events(&app, &id).await;
    let values = event_values(&events);
    assert!(
        values
            .iter()
            .any(|event| event["kind"] == "violation"
                && event["data"]["rule"] == "memory_cap_exceeded"),
        "expected memory_cap_exceeded violation; events:\n{}",
        render_events(&events)
    );
    assert!(
        !values.iter().any(|event| {
            event["kind"] == "violation" && event["data"]["rule"] == "executor_error"
        }),
        "cgroup OOM must not degrade to executor_error; events:\n{}",
        render_events(&events)
    );
    assert_host_still_serves(&app).await;
}

#[tokio::test]
#[ignore]
async fn kills_infinite_loop_on_wall_clock() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let id = submit(
        &app,
        "python",
        INFINITE_LOOP,
        serde_json::json!({ "wall_seconds": 3 }),
    )
    .await;
    let (_, elapsed) = expect_status(&app, &id, &["timed_out"]).await;
    assert!(
        elapsed < 15.0,
        "wall-clock kill must land near t=3s, took {elapsed}s"
    );
    assert_host_still_serves(&app).await;
}

#[tokio::test]
#[ignore]
async fn network_is_disabled_by_default() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let id = submit(
        &app,
        "python",
        NETWORK_PROBE,
        serde_json::json!({ "wall_seconds": 10 }),
    )
    .await;
    let (status, _) = expect_status(&app, &id, &["succeeded"]).await;
    assert_eq!(status, "succeeded");
    let stdout = replay_stdout(&app, &id).await;
    assert!(
        stdout.contains("network blocked"),
        "network must be unreachable; probe said:\n{stdout}"
    );
    assert!(
        stdout.contains("RUNTIME-PROBES-DENIED-SAFELY"),
        "io_uring and non-UNIX socketpair probes must return safe errno denials; stdout:\n{stdout}"
    );
    let detail = send_raw(
        &app,
        Request::builder()
            .method("GET")
            .uri(format!("/v1/jobs/{id}"))
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(detail["effective_spec"]["limits"]["allow_network"], false);
    assert_eq!(detail["execution_policy"]["network_allowed"], false);
    assert_eq!(detail["execution_policy"]["networking"], "disabled");
    assert_eq!(detail["execution_policy"]["bootstrap_ready"], true);
    assert_eq!(detail["execution_policy"]["isolated"], true);
    assert_eq!(detail["execution_policy"]["private_rootfs"], true);
    assert_eq!(detail["execution_policy"]["dedicated_bootstrap"], true);
    assert_eq!(detail["execution_policy"]["seccomp"], true);
    for enforced in [
        "wall_seconds",
        "cpu_seconds",
        "mem_mb",
        "max_pids",
        "max_file_mb",
    ] {
        assert_eq!(
            detail["execution_policy"]["limit_enforcement"][enforced], true,
            "namespace receipt must attest {enforced}: {detail}"
        );
        assert!(
            detail["effective_spec"]["limits"][enforced].is_number(),
            "namespace effective limit missing {enforced}: {detail}"
        );
    }
    assert_eq!(detail["receipt"]["network_allowed"], false);
    assert_eq!(detail["receipt"]["networking"], "disabled");
    assert_eq!(detail["receipt"]["bootstrap_ready"], true);

    let node = submit(
        &app,
        "node",
        "console.log('NODE-SECCOMP-OK')",
        serde_json::json!({ "wall_seconds": 10, "mem_mb": 128 }),
    )
    .await;
    let (node_status, _) = expect_status(&app, &node, &["succeeded"]).await;
    assert_eq!(
        node_status, "succeeded",
        "Node must survive its denied io_uring capability probe at low resident-memory limits"
    );
    let node_stdout = replay_stdout(&app, &node).await;
    assert!(
        node_stdout.contains("NODE-SECCOMP-OK"),
        "Node did not reach console.log; stdout:\n{node_stdout}"
    );
    assert_host_still_serves(&app).await;
}

#[tokio::test]
#[ignore]
async fn disk_filler_hits_filesystem_cap() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let id = submit(
        &app,
        "python",
        DISK_FILLER,
        serde_json::json!({ "wall_seconds": 20, "mem_mb": 128 }),
    )
    .await;
    let (_, elapsed) = expect_status(&app, &id, &["failed", "timed_out"]).await;
    assert!(
        elapsed < 40.0,
        "disk filler must die fast against capped tmpfs, took {elapsed}s"
    );
    assert_host_still_serves(&app).await;
}

#[tokio::test]
#[ignore]
async fn escape_probes_fail_without_leaking() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let id = submit(
        &app,
        "python",
        ESCAPE_PROBE,
        serde_json::json!({ "wall_seconds": 10 }),
    )
    .await;
    expect_status(&app, &id, &["failed"]).await;
    let stdout = replay_stdout(&app, &id).await;
    assert!(
        !stdout.contains("LEAK"),
        "sandbox must not allow host reads/writes; probe reported:\n{stdout}"
    );
    assert_host_still_serves(&app).await;
}

#[tokio::test]
#[ignore]
async fn pid_bomb_is_capped() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let id = submit(
        &app,
        "python",
        PID_BOMB,
        serde_json::json!({ "wall_seconds": 8, "max_pids": 32 }),
    )
    .await;
    expect_status(&app, &id, &["failed", "timed_out"]).await;
    let stdout = replay_stdout(&app, &id).await;
    assert!(
        stdout.contains("spawn refused"),
        "process-spawn storm must hit pids.max; stdout was:\n{stdout}"
    );
    assert_host_still_serves(&app).await;
}

/// Per-job pids.max must not be supplemented with RLIMIT_NPROC while every
/// workload shares host UID 65534: that rlimit is UID-wide and lets one job
/// deny fork/thread creation to an otherwise empty sibling cgroup.
#[tokio::test]
#[ignore]
async fn pid_limits_are_independent_across_concurrent_jobs() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let aggressor_code = r#"import os, time
children = []
for _ in range(48):
    pid = os.fork()
    if pid == 0:
        time.sleep(10)
        os._exit(0)
    children.append(pid)
print('AGGRESSOR-READY=' + str(len(children)), flush=True)
time.sleep(10)
"#;
    let aggressor = submit(
        &app,
        "python",
        aggressor_code,
        serde_json::json!({ "wall_seconds": 15, "max_pids": 64 }),
    )
    .await;

    let ready_deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let stdout = replay_stdout(&app, &aggressor).await;
        if stdout.contains("AGGRESSOR-READY=48") {
            break;
        }
        assert!(
            std::time::Instant::now() < ready_deadline,
            "aggressor did not fill its own cgroup:\n{stdout}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let victim = submit(
        &app,
        "python",
        "import os\npid=os.fork()\nif pid == 0: os._exit(0)\nos.waitpid(pid, 0)\nprint('VICTIM-FORK-OK')",
        serde_json::json!({ "wall_seconds": 5, "max_pids": 8 }),
    )
    .await;
    expect_status(&app, &victim, &["succeeded"]).await;
    assert!(replay_stdout(&app, &victim)
        .await
        .contains("VICTIM-FORK-OK"));

    let request = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/jobs/{aggressor}"))
        .header(header::AUTHORIZATION, "Bearer test-key")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    expect_status(&app, &aggressor, &["cancelled"]).await;
    assert_host_still_serves(&app).await;
}

/// N-1: two jobs run concurrently on the shared jobs root; job B knows job
/// A's workdir path exactly (the test composes it) and must get nothing —
/// no directory listing, no file contents. The jobs root and each workdir
/// are 0700 for the server account while sandboxed jobs run unprivileged,
/// so both the relative sweep and the absolute read come up empty.
#[tokio::test]
#[ignore]
async fn sibling_workdir_not_readable() {
    if !preflight() {
        return;
    }
    let (app, jobs_root) = spawn_app_with_root().await;

    let marker = format!("coop-src-marker-{}", uuid::Uuid::now_v7());
    let victim_code =
        format!("MARKER = {marker:?}\nprint('alive', flush=True)\nimport time\ntime.sleep(8)\n");
    let victim = submit(
        &app,
        "python",
        &victim_code,
        serde_json::json!({ "wall_seconds": 15 }),
    )
    .await;

    // Job B starts while A is still running (workers=2), so A's workdir and
    // its 0600 source file exist for the whole probe window.
    let target = format!("{jobs_root}/job-{victim}/job.py");
    let probe_code = format!(
        r#"import glob
hits = sorted(glob.glob('../job-*'))
hits += sorted(glob.glob({jobs_root:?} + '/job-*'))
try:
    with open({target:?}) as fh:
        hits.append(fh.read())
except OSError:
    pass
print('PROBE-HITS', len(hits))
"#,
    );
    let prober = submit(
        &app,
        "python",
        &probe_code,
        serde_json::json!({ "wall_seconds": 10 }),
    )
    .await;

    let (victim_status, _) = expect_status(&app, &victim, &["succeeded"]).await;
    assert_eq!(victim_status, "succeeded", "victim must run normally");
    let (prober_status, _) = expect_status(&app, &prober, &["succeeded"]).await;
    assert_eq!(prober_status, "succeeded");
    let stdout = replay_stdout(&app, &prober).await;
    assert!(
        stdout.contains("PROBE-HITS 0"),
        "sibling workdir enumeration/read must return nothing; stdout was:\n{stdout}"
    );
    assert!(
        !stdout.contains(&marker),
        "victim source must never reach another job; stdout was:\n{stdout}"
    );
    assert_host_still_serves(&app).await;
}

/// F-005: the seccomp allowlist traps ptrace with SIGSYS. The probe must die
/// before it can print a success line, and the violation must surface as
/// `killed_by = "seccomp"` in the event log.
#[tokio::test]
#[ignore]
async fn ptrace_probe_is_killed_by_seccomp() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let id = submit(
        &app,
        "python",
        PTRACE_PROBE,
        serde_json::json!({ "wall_seconds": 10 }),
    )
    .await;

    // SIGSYS kill lands in `failed` (killed_by=seccomp); if the interpreter
    // refuses to even load ctypes on some minimal images we accept `error`.
    let (status, _) = expect_status(&app, &id, &["failed", "error"]).await;
    assert_eq!(status, "failed", "ptrace probe should be SIGSYS-killed");

    let events = replay_events(&app, &id).await;
    let killed_by_seccomp = event_values(&events)
        .iter()
        .any(|e| e["kind"] == "violation" && e["data"]["rule"] == "seccomp_violation");
    assert!(
        killed_by_seccomp,
        "expected a seccomp_violation event; events were:\n{}",
        render_events(&events)
    );
    let stdout = replay_stdout(&app, &id).await;
    assert!(
        !stdout.contains("ptrace returned"),
        "probe must be killed before reporting success; stdout was:\n{stdout}"
    );
    assert_host_still_serves(&app).await;
}

/// Deep-hunt: the ns backend used to silently wire fd 0 to /dev/null, so
/// submitted stdin never reached the job (the naive backend honored it).
/// Staged stdin must arrive on the job-private tmpfs.
#[tokio::test]
#[ignore]
async fn stdin_reaches_sandboxed_jobs() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    // bash `read` consumes exactly one line from fd 0; echo proves it arrived.
    let payload = serde_json::json!({ "wall_seconds": 10 });
    let code = r#"read -r line; echo "GOT:$line""#.to_string();
    // Use the `stdin` field via raw submit (the helper below has no stdin param)
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/jobs")
        .header(axum::http::header::AUTHORIZATION, "Bearer test-key")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({"language":"bash","code":code,"stdin":"hello-ns\n","limits":payload}).to_string(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::CREATED);
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let id = v["job_id"].as_str().unwrap().to_string();

    let (status, _) = expect_status(&app, &id, &["succeeded"]).await;
    assert_eq!(status, "succeeded");
    let stdout = replay_stdout(&app, &id).await;
    assert!(
        stdout.contains("GOT:hello-ns"),
        "stdin must reach sandboxed job; stdout was:\n{stdout}"
    );
    assert_host_still_serves(&app).await;
}

/// Deep-hunt: cumulative CPU is now polling `cpu.stat` tree-wide, not the
/// kernel's `cpu.max` rate limiter. A multi-threaded spin that burns
/// `cpu_seconds` core-seconds total must be killed even though the old
/// `cpu.max` quota (cpu_seconds cores * 1s) would have let it run.
#[tokio::test]
#[ignore]
async fn cpu_budget_is_enforced_tree_wide() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let code = r#"
import threading
def spin():
    while True:
        pass
ts=[threading.Thread(target=spin) for _ in range(4)]
[t.start() for t in ts]
for t in ts: t.join()
"#;
    let id = submit(
        &app,
        "python",
        code,
        serde_json::json!({ "wall_seconds": 20, "cpu_seconds": 1 }),
    )
    .await;
    let (status, elapsed) = expect_status(&app, &id, &["failed"]).await;
    assert_eq!(status, "failed", "CPU-budget exceeded must be Failed");
    assert!(
        elapsed < 15.0,
        "4-thread spin with cpu_seconds=1 must be killed in ~1 core-second (~0.25s wall), took {elapsed:.2}s"
    );
    let events = replay_events(&app, &id).await;
    let has_violation = event_values(&events)
        .iter()
        .any(|e| e["kind"] == "violation" && e["data"]["rule"] == "cpu_limit_exceeded");
    assert!(
        has_violation,
        "expected cpu_limit_exceeded violation; events:\n{}",
        render_events(&events)
    );
    assert_host_still_serves(&app).await;
}

/// The production boundary is the purpose-built rootfs, not a read-only view
/// of the host/container root. Even a world-readable marker outside that
/// root must be absent from the workload namespace.
#[tokio::test]
#[ignore]
async fn private_rootfs_hides_world_readable_host_files_and_old_root() {
    if !preflight() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let marker_path =
        std::env::temp_dir().join(format!("coop-host-marker-{}", uuid::Uuid::now_v7()));
    let marker = format!("HOST-ONLY-{}", uuid::Uuid::now_v7());
    std::fs::write(&marker_path, &marker).expect("write host marker");
    std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o644))
        .expect("world-readable marker");

    let app = spawn_app().await;
    let code = format!(
        r#"import os
targets = [{marker_path:?}, '/data/coop.db', '/proc/1/root/.pivot_old']
leaks = []
for path in targets:
    try:
        if os.path.isdir(path):
            leaks.append(path + ':DIR')
        else:
            with open(path, 'rb') as fh:
                leaks.append(path + ':' + fh.read(4096).decode('utf-8', 'replace'))
    except OSError:
        pass
assert os.path.isdir('/.pivot_old')
assert os.listdir('/.pivot_old') == [], os.listdir('/.pivot_old')
assert not any('/.pivot_old' in line for line in open('/proc/self/mountinfo'))
print('LEAKS', leaks)
"#,
        marker_path = marker_path.to_string_lossy(),
    );
    let id = submit(
        &app,
        "python",
        &code,
        serde_json::json!({ "wall_seconds": 10 }),
    )
    .await;
    expect_status(&app, &id, &["succeeded"]).await;
    let stdout = replay_stdout(&app, &id).await;
    assert!(!stdout.contains(&marker), "host marker leaked:\n{stdout}");
    assert!(
        stdout.contains("LEAKS []"),
        "old root or data mount was visible:\n{stdout}"
    );
    let _ = std::fs::remove_file(marker_path);
}

/// PID1 is a trusted reaper and the interpreter is PID2. The server's host
/// PID must not appear in the workload's freshly mounted procfs.
#[tokio::test]
#[ignore]
async fn pid_namespace_has_real_pid1_and_hides_server() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let server_pid = std::process::id();
    let code = format!(
        r#"import os
assert os.getpid() == 2, os.getpid()
assert os.path.exists('/proc/1/status')
assert not os.path.exists('/proc/{server_pid}'), 'server visible in procfs'
child = os.fork()
if child == 0:
    os._exit(0)
assert os.waitpid(child, 0)[0] == child
print('PID-BOUNDARY-OK')
"#,
    );
    let id = submit(
        &app,
        "python",
        &code,
        serde_json::json!({ "wall_seconds": 10 }),
    )
    .await;
    expect_status(&app, &id, &["succeeded"]).await;
    assert!(replay_stdout(&app, &id).await.contains("PID-BOUNDARY-OK"));
}

/// Credentials are verified again from the tenant process rather than
/// trusting successful setup syscalls alone.
#[tokio::test]
#[ignore]
async fn sandbox_credentials_groups_and_capabilities_are_zero() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let code = r#"import os, signal
assert os.getresuid() == (65534, 65534, 65534), os.getresuid()
assert os.getresgid() == (65534, 65534, 65534), os.getresgid()
assert os.getgroups() == [], os.getgroups()
status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'):
    assert int(status[key].strip(), 16) == 0, (key, status[key])
assert status['NoNewPrivs'].strip() == '1'
child = os.fork()
if child == 0:
    try:
        os.setuid(0)
        os._exit(42)
    except PermissionError:
        os._exit(0)
_, child_status = os.waitpid(child, 0)
assert ((os.WIFEXITED(child_status) and os.WEXITSTATUS(child_status) == 0) or
        (os.WIFSIGNALED(child_status) and os.WTERMSIG(child_status) == signal.SIGSYS)), child_status
print('CREDENTIALS-OK')
"#;
    let id = submit(
        &app,
        "python",
        code,
        serde_json::json!({ "wall_seconds": 10 }),
    )
    .await;
    expect_status(&app, &id, &["succeeded"]).await;
    assert!(replay_stdout(&app, &id).await.contains("CREDENTIALS-OK"));
}

/// A double-forked, setsid descendant is outside the leader's process group.
/// PID1 and cgroup.kill must still remove it before the job completes.
#[tokio::test]
#[ignore]
async fn pid1_kills_setsided_background_descendant_and_cgroup_is_removed() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let code = r#"import os, sys, time
pid = os.fork()
if pid == 0:
    os.setsid()
    print('DETACHED-READY', flush=True)
    while True:
        time.sleep(1)
time.sleep(1)
print('PRIMARY-DONE', flush=True)
"#;
    let id = submit(
        &app,
        "python",
        code,
        serde_json::json!({ "wall_seconds": 10 }),
    )
    .await;
    let cgroup = coop_cgroup_jobs_root().join(format!(
        "job-{}",
        id.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
    ));
    let observation_deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut observed = Vec::<(u32, String)>::new();
    while std::time::Instant::now() < observation_deadline {
        if let Ok(procs) = std::fs::read_to_string(cgroup.join("cgroup.procs")) {
            let pids = procs
                .lines()
                .filter_map(|line| line.parse::<u32>().ok())
                .collect::<Vec<_>>();
            if pids.len() >= 3 {
                observed = pids
                    .into_iter()
                    .filter_map(|pid| {
                        std::fs::read_to_string(format!("/proc/{pid}/stat"))
                            .ok()
                            .map(|stat| (pid, stat))
                    })
                    .collect();
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        observed.len() >= 3,
        "did not observe PID1, primary, and detached descendant in {}",
        cgroup.display()
    );
    expect_status(&app, &id, &["succeeded"]).await;
    let stdout = replay_stdout(&app, &id).await;
    assert!(
        stdout.contains("DETACHED-READY") && stdout.contains("PRIMARY-DONE"),
        "setsid probe did not reach both lifecycle points:\n{stdout}"
    );
    for (pid, before) in observed {
        if let Ok(after) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            assert_ne!(after, before, "job process {pid} survived terminal status");
        }
    }
    assert!(!cgroup.exists(), "job cgroup leaked: {}", cgroup.display());
}

/// Continuous readiness on both output pipes must never delay the priority
/// control tick that observes cancellation and invokes cgroup.kill.
#[tokio::test]
#[ignore]
async fn output_flood_cannot_starve_cgroup_cancellation() {
    if !preflight() {
        return;
    }
    let app = spawn_app().await;
    let code = r#"import os
chunk = b'x' * 8192
while True:
    os.write(1, chunk)
    os.write(2, chunk)
"#;
    let id = submit(
        &app,
        "python",
        code,
        serde_json::json!({ "wall_seconds": 30 }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = std::time::Instant::now();
    let request = Request::builder()
        .method("DELETE")
        .uri(format!("/v1/jobs/{id}"))
        .header(header::AUTHORIZATION, "Bearer test-key")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (status, _) = expect_status(&app, &id, &["cancelled"]).await;
    assert_eq!(status, "cancelled");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "output flood delayed cancellation for {:?}",
        started.elapsed()
    );
    let events = replay_events(&app, &id).await;
    let retained_bytes: usize = event_values(&events)
        .iter()
        .filter(|event| event["kind"] == "stdout" || event["kind"] == "stderr")
        .filter_map(|event| event["data"]["line"].as_str())
        .map(str::len)
        .sum();
    assert!(
        retained_bytes <= 2 * coop_types::MAX_OUTPUT_BYTES_PER_STREAM,
        "persisted output exceeded independent stream caps: {retained_bytes}"
    );
}
