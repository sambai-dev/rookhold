use crate::bus::WireEvent;
use crate::AppState;
use base64::Engine as _;
use coop_attestation::bytes_to_hex;
use coop_exec::{ExecContext, Sink, Stream};
use coop_types::{EffectiveLimits, JobSpec, JobStatus, LimitEnforcement};
use futures_util::FutureExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

pub struct QueuedJob {
    pub job_id: String,
    pub tenant: String,
    pub mem_mb: u32,
    admission: Option<OwnedSemaphorePermit>,
    tenant_admission: Option<TenantAdmissionLease>,
}

impl std::fmt::Debug for QueuedJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedJob")
            .field("job_id", &self.job_id)
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

/// A process-local hard bound over every accepted job which is still durably
/// queued. The channel is only the handoff; the semaphore lease follows a job
/// through the channel, the fair per-tenant queues, and the worker handoff.
#[derive(Clone)]
pub struct Admission {
    tx: mpsc::Sender<QueuedJob>,
    slots: Arc<Semaphore>,
    tenant_depths: Arc<dashmap::DashMap<String, Arc<std::sync::atomic::AtomicUsize>>>,
    per_tenant: usize,
    accepting: Arc<std::sync::atomic::AtomicBool>,
    capacity: usize,
}

pub struct AdmissionReservation {
    channel: mpsc::OwnedPermit<QueuedJob>,
    slot: OwnedSemaphorePermit,
    tenant_slot: TenantAdmissionLease,
    tenant: String,
    mem_mb: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryAdmissionError {
    GlobalFull,
    TenantFull,
    Closed,
}

struct TenantAdmissionLease {
    depth: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for TenantAdmissionLease {
    fn drop(&mut self) {
        self.depth.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

impl Admission {
    pub fn channel(capacity: usize, per_tenant: usize) -> (Self, mpsc::Receiver<QueuedJob>) {
        assert!(capacity > 0, "admission capacity must be positive");
        assert!(per_tenant > 0, "tenant admission capacity must be positive");
        assert!(
            per_tenant <= capacity,
            "tenant admission capacity must not exceed global capacity"
        );
        let (tx, rx) = mpsc::channel(capacity);
        let admission = Self {
            tx,
            slots: Arc::new(Semaphore::new(capacity)),
            tenant_depths: Arc::new(dashmap::DashMap::new()),
            per_tenant,
            accepting: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            capacity,
        };
        (admission, rx)
    }

    /// Reserve without waiting. Both the global queued-job budget and the
    /// channel handoff are reserved before durable acceptance.
    pub fn try_reserve(
        &self,
        tenant: &str,
        mem_mb: u32,
    ) -> Result<AdmissionReservation, TryAdmissionError> {
        assert!(mem_mb > 0, "queued memory charge must be positive");
        if !self.accepting.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TryAdmissionError::Closed);
        }
        let tenant_depth = self
            .tenant_depths
            .entry(tenant.to_string())
            .or_insert_with(|| Arc::new(std::sync::atomic::AtomicUsize::new(0)))
            .clone();
        let tenant_slot = loop {
            let depth = tenant_depth.load(std::sync::atomic::Ordering::Acquire);
            if depth >= self.per_tenant {
                return Err(TryAdmissionError::TenantFull);
            }
            if tenant_depth
                .compare_exchange_weak(
                    depth,
                    depth + 1,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_ok()
            {
                break TenantAdmissionLease {
                    depth: Arc::clone(&tenant_depth),
                };
            }
        };
        let slot = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::Closed => TryAdmissionError::Closed,
                tokio::sync::TryAcquireError::NoPermits => TryAdmissionError::GlobalFull,
            })?;
        let channel = self
            .tx
            .clone()
            .try_reserve_owned()
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => TryAdmissionError::GlobalFull,
                mpsc::error::TrySendError::Closed(_) => TryAdmissionError::Closed,
            })?;
        if !self.accepting.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TryAdmissionError::Closed);
        }
        Ok(AdmissionReservation {
            channel,
            slot,
            tenant_slot,
            tenant: tenant.to_string(),
            mem_mb,
        })
    }

    /// Wait for recovery admission while retaining the same hard global
    /// bound. HTTP submission deliberately uses `try_reserve` instead.
    pub async fn reserve_recovery(
        &self,
        tenant: &str,
        mem_mb: u32,
    ) -> Result<AdmissionReservation, TryAdmissionError> {
        assert!(mem_mb > 0, "queued memory charge must be positive");
        if !self.accepting.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TryAdmissionError::Closed);
        }
        let tenant_depth = self
            .tenant_depths
            .entry(tenant.to_string())
            .or_insert_with(|| Arc::new(std::sync::atomic::AtomicUsize::new(0)))
            .clone();
        tenant_depth.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let tenant_slot = TenantAdmissionLease {
            depth: tenant_depth,
        };
        let slot = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(|_| TryAdmissionError::Closed)?;
        if !self.accepting.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TryAdmissionError::Closed);
        }
        let channel = self
            .tx
            .clone()
            .reserve_owned()
            .await
            .map_err(|_| TryAdmissionError::Closed)?;
        if !self.accepting.load(std::sync::atomic::Ordering::Acquire) {
            return Err(TryAdmissionError::Closed);
        }
        Ok(AdmissionReservation {
            channel,
            slot,
            tenant_slot,
            tenant: tenant.to_string(),
            mem_mb,
        })
    }

    /// Atomically stop new admission and wake asynchronous recovery waiters.
    /// Reservations which already linearized may still durably commit; their
    /// row remains queued for the next process if the dispatcher has exited.
    pub fn close(&self) {
        self.accepting
            .store(false, std::sync::atomic::Ordering::Release);
        self.slots.close();
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn depth(&self) -> usize {
        self.capacity.saturating_sub(self.slots.available_permits())
    }

    pub fn tenant_capacity(&self) -> usize {
        self.per_tenant
    }

    pub fn tenant_depth(&self, tenant: &str) -> usize {
        self.tenant_depths
            .get(tenant)
            .map(|depth| depth.load(std::sync::atomic::Ordering::Acquire))
            .unwrap_or(0)
    }
}

impl AdmissionReservation {
    /// Commit the reservation to a queued job. This contains no await point,
    /// so a successfully persisted accepted row cannot be cancelled between
    /// registration of its capacity lease and channel handoff.
    pub fn send(self, job_id: String) {
        self.channel.send(QueuedJob {
            job_id,
            tenant: self.tenant,
            mem_mb: self.mem_mb,
            admission: Some(self.slot),
            tenant_admission: Some(self.tenant_slot),
        });
    }
}

impl QueuedJob {
    fn release_admission(&mut self) {
        self.admission.take();
        self.tenant_admission.take();
    }
}

struct WorkItem {
    queued: QueuedJob,
    _tenant_permit: OwnedSemaphorePermit,
    _memory_permit: OwnedSemaphorePermit,
}

/// Handles for the fair dispatcher and executor workers. Dropping this value
/// detaches the tasks (useful for embedded/test servers); `shutdown` performs
/// an orderly stop and cancels any active executions. The binary must also
/// poll `failure`: every scheduler task is supervised, and the first
/// unexpected exit is retained until the runtime lifecycle observes it.
pub struct WorkerPool {
    handles: Vec<JoinHandle<()>>,
    failure_rx: mpsc::Receiver<String>,
    // Retaining one sender makes a pending `failure()` wait stable while the
    // pool is alive. Supervised tasks publish into clones with first-wins
    // bounded semantics.
    _failure_tx: mpsc::Sender<String>,
}

enum Op {
    Output(Stream, String),
    Violation(&'static str, Value),
    Truncated(Stream),
    /// At least one executor record could not enter the bounded persistence
    /// pipeline. Retained hashes remain truthful, but the evidence set is not
    /// a complete representation of what the executor observed.
    EvidenceIncomplete,
    Artifact(Value),
    Finished {
        status: &'static str,
        exit_code: Option<i32>,
        duration_ms: i64,
        killed_by: Option<String>,
        telemetry: Option<coop_exec::ExecTelemetry>,
        provenance: Option<Box<coop_exec::ExecutionProvenance>>,
    },
}

const EVENT_BATCH_MAX: usize = 64;
const EVENT_BATCH_LATENCY: Duration = Duration::from_millis(5);
const _: () = assert!(EVENT_BATCH_MAX <= coop_store::MAX_EVENT_BATCH_SIZE);

struct FinishedOp {
    status: &'static str,
    exit_code: Option<i32>,
    duration_ms: i64,
    killed_by: Option<String>,
    telemetry: Option<coop_exec::ExecTelemetry>,
    provenance: Option<Box<coop_exec::ExecutionProvenance>>,
}

struct JobSink {
    tx: mpsc::Sender<Op>,
    metrics: Arc<crate::metrics::Metrics>,
    stdout_dropped: Arc<std::sync::atomic::AtomicBool>,
    stderr_dropped: Arc<std::sync::atomic::AtomicBool>,
    deferred_controls: Arc<std::sync::Mutex<Vec<Op>>>,
}

impl Sink for JobSink {
    fn output(&self, stream: Stream, line: String) {
        if self.tx.try_send(Op::Output(stream, line)).is_err() {
            let flag = match stream {
                Stream::Stdout => &self.stdout_dropped,
                Stream::Stderr => &self.stderr_dropped,
            };
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn violation(&self, rule: &'static str, detail: Value) {
        if let Err(error) = self.tx.try_send(Op::Violation(rule, detail)) {
            defer_control(&self.deferred_controls, error.into_inner());
        }
    }

    fn truncated(&self, stream: Stream) {
        self.metrics.truncation(match stream {
            Stream::Stdout => crate::metrics::TruncationKind::Stdout,
            Stream::Stderr => crate::metrics::TruncationKind::Stderr,
        });
        if let Err(error) = self.tx.try_send(Op::Truncated(stream)) {
            defer_control(&self.deferred_controls, error.into_inner());
        }
    }
}

fn defer_control(queue: &std::sync::Mutex<Vec<Op>>, op: Op) {
    let mut queue = queue
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if queue.len() < 64 {
        queue.push(op);
    }
}

/// RAII guard for the per-job cancellation flag (deep-hunt #4). Every early
/// return after the flag is registered must remove it, otherwise the map and
/// the `coop_running_jobs` gauge grow forever. The guard is disarmed by
/// forgetting or dropping after an explicit remove in the normal path.
struct CancelGuard {
    map: Arc<dashmap::DashMap<String, crate::RunningJob>>,
    job_id: String,
}

struct JobTraceGuard {
    map: Arc<dashmap::DashMap<String, crate::request_context::JobTraceContext>>,
    job_id: String,
}

impl Drop for JobTraceGuard {
    fn drop(&mut self) {
        self.map.remove(&self.job_id);
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.map.remove(&self.job_id);
    }
}

pub fn spawn_workers(state: AppState, rx: mpsc::Receiver<QueuedJob>) -> WorkerPool {
    let (work_tx, work_rx) = mpsc::channel::<WorkItem>(state.cfg.workers);
    let work_rx = Arc::new(tokio::sync::Mutex::new(work_rx));
    let (done_tx, done_rx) = mpsc::unbounded_channel::<String>();
    let (failure_tx, failure_rx) = mpsc::channel::<String>(1);
    let mut handles = Vec::with_capacity(state.cfg.workers + 1);

    handles.push(spawn_supervised_task(
        state.clone(),
        failure_tx.clone(),
        "scheduler dispatcher".to_string(),
        dispatch_fair(state.clone(), rx, work_tx, done_rx),
    ));

    for worker_id in 0..state.cfg.workers {
        handles.push(spawn_supervised_task(
            state.clone(),
            failure_tx.clone(),
            format!("scheduler worker {worker_id}"),
            worker_loop(
                state.clone(),
                Arc::clone(&work_rx),
                done_tx.clone(),
                worker_id,
            ),
        ));
    }

    WorkerPool {
        handles,
        failure_rx,
        _failure_tx: failure_tx,
    }
}

fn spawn_supervised_task<F>(
    state: AppState,
    failure_tx: mpsc::Sender<String>,
    task_name: String,
    future: F,
) -> JoinHandle<()>
where
    F: Future<Output = Result<(), String>> + Send + 'static,
{
    tokio::spawn(async move {
        let completion = AssertUnwindSafe(future).catch_unwind().await;
        let failure = match completion {
            Ok(Ok(())) if *state.shutdown.borrow() => return,
            Ok(Ok(())) => format!("{task_name} exited unexpectedly"),
            Ok(Err(error)) => format!("{task_name} failed: {error}"),
            Err(payload) => format!(
                "{task_name} panicked: {}",
                panic_payload_message(payload.as_ref())
            ),
        };

        // Only an explicit Ok return is an expected shutdown exit. Once an
        // error or panic has been captured it remains fatal even if an
        // operator signal races publication of this diagnosis.
        state
            .startup_ready
            .store(false, std::sync::atomic::Ordering::Release);
        // Publish before shutdown wakes the main lifecycle select. The
        // receiver is capacity one by design: the first observed failure is
        // useful diagnosis, and a full channel means it is already retained.
        let _ = failure_tx.try_send(failure.clone());
        tracing::error!(error = %failure, "fatal scheduler task failure");
        state.begin_shutdown();
    })
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

async fn worker_loop(
    state: AppState,
    work_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<WorkItem>>>,
    done_tx: mpsc::UnboundedSender<String>,
    worker_id: usize,
) -> Result<(), String> {
    let mut shutdown = state.shutdown.subscribe();
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let work = tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow() => return Ok(()),
                    Ok(()) => continue,
                    Err(_) => return Err("shutdown signal channel closed unexpectedly".to_string()),
                }
            }
            work = async {
                let mut receiver = work_rx.lock().await;
                receiver.recv().await
            } => work,
        };
        let Some(work) = work else {
            if *shutdown.borrow() {
                return Ok(());
            }
            return Err("worker handoff channel closed unexpectedly".to_string());
        };
        if *shutdown.borrow() {
            return Ok(());
        }
        let tenant = work.queued.tenant.clone();
        handle_job(
            state.clone(),
            work.queued,
            worker_id,
            work._tenant_permit,
            work._memory_permit,
        )
        .await;
        if done_tx.send(tenant).is_err() {
            if *shutdown.borrow() {
                return Ok(());
            }
            return Err("dispatcher completion channel closed unexpectedly".to_string());
        }
    }
}

async fn dispatch_fair(
    state: AppState,
    mut admission: mpsc::Receiver<QueuedJob>,
    work_tx: mpsc::Sender<WorkItem>,
    mut done_rx: mpsc::UnboundedReceiver<String>,
) -> Result<(), String> {
    let mut pending: HashMap<String, VecDeque<QueuedJob>> = HashMap::new();
    let mut round_robin = VecDeque::<String>::new();
    let mut active_tenants = HashSet::<String>::new();
    let mut shutdown = state.shutdown.subscribe();

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        dispatch_available(
            &state,
            &work_tx,
            &mut pending,
            &mut round_robin,
            &mut active_tenants,
        )?;

        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow() => return Ok(()),
                    Ok(()) => {}
                    Err(_) => return Err("shutdown signal channel closed unexpectedly".to_string()),
                }
            }
            queued = admission.recv() => match queued {
                Some(queued) => {
                    let tenant = queued.tenant.clone();
                    pending.entry(tenant.clone()).or_default().push_back(queued);
                    if active_tenants.insert(tenant.clone()) {
                        round_robin.push_back(tenant);
                    }
                }
                None if *shutdown.borrow() => return Ok(()),
                None => return Err("scheduler admission channel closed unexpectedly".to_string()),
            },
            done = done_rx.recv() => {
                if done.is_none() {
                    if *shutdown.borrow() {
                        return Ok(());
                    }
                    return Err("worker completion channel closed unexpectedly".to_string());
                }
                // A tenant permit has just been released; looping retries all
                // tenants in round-robin order.
            }
        }
    }
}

fn dispatch_available(
    state: &AppState,
    work_tx: &mpsc::Sender<WorkItem>,
    pending: &mut HashMap<String, VecDeque<QueuedJob>>,
    round_robin: &mut VecDeque<String>,
    active_tenants: &mut HashSet<String>,
) -> Result<(), String> {
    while work_tx.capacity() > 0 && !round_robin.is_empty() {
        let tenants_this_round = round_robin.len();
        let mut dispatched = false;
        for _ in 0..tenants_this_round {
            let Some(tenant) = round_robin.pop_front() else {
                break;
            };
            let semaphore = semaphore_for(state, &tenant);
            let Ok(permit) = semaphore.try_acquire_owned() else {
                round_robin.push_back(tenant);
                continue;
            };

            let queue = pending.get_mut(&tenant).expect("active tenant has queue");
            let memory_mb = queue
                .front()
                .expect("active tenant queue is non-empty")
                .mem_mb;
            let Ok(memory_permit) =
                Arc::clone(&state.memory_slots).try_acquire_many_owned(memory_mb)
            else {
                drop(permit);
                // Preserve weighted fairness: once an older job is blocked
                // on aggregate memory, stop backfilling smaller jobs. A
                // completion notification retries this tenant first, so a
                // steady stream of small jobs cannot starve a large request.
                round_robin.push_front(tenant);
                return Ok(());
            };
            let queued = queue.pop_front().expect("active tenant queue is non-empty");
            if queue.is_empty() {
                pending.remove(&tenant);
                active_tenants.remove(&tenant);
            } else {
                round_robin.push_back(tenant);
            }
            match work_tx.try_send(WorkItem {
                queued,
                _tenant_permit: permit,
                _memory_permit: memory_permit,
            }) {
                Ok(()) => dispatched = true,
                Err(mpsc::error::TrySendError::Full(work)) => {
                    let tenant = work.queued.tenant.clone();
                    pending
                        .entry(tenant.clone())
                        .or_default()
                        .push_front(work.queued);
                    if active_tenants.insert(tenant.clone()) {
                        round_robin.push_front(tenant);
                    }
                    return Ok(());
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err("worker handoff channel closed unexpectedly".to_string());
                }
            }
        }
        if !dispatched {
            break;
        }
    }
    Ok(())
}

impl WorkerPool {
    /// Wait for the first retained fatal scheduler failure. The pool retains
    /// a sender, so absence of a failure remains pending instead of being
    /// confused with normal task completion.
    pub async fn failure(&mut self) -> String {
        self.failure_rx.recv().await.unwrap_or_else(|| {
            "scheduler failure notification channel closed unexpectedly".to_string()
        })
    }

    /// Inspect a failure retained while another runtime stop condition won a
    /// `select!` poll. This closes the cross-thread race where the supervisor
    /// publishes a failure and shutdown during the same poll, but the later
    /// shutdown branch is observed before the failure future is polled again.
    pub fn try_failure(&mut self) -> Option<String> {
        self.failure_rx.try_recv().ok()
    }

    pub async fn shutdown(mut self, state: &AppState, grace: Duration) -> Option<String> {
        state.begin_shutdown();
        let deadline = tokio::time::Instant::now() + grace;
        for mut handle in self.handles.drain(..) {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() || tokio::time::timeout(remaining, &mut handle).await.is_err() {
                handle.abort();
                let _ = handle.await;
                tracing::warn!("worker shutdown grace period elapsed; task aborted");
            }
        }
        // A fatal completion can race the lifecycle's pre-shutdown snapshot.
        // All supervised handles have now joined, so this final read closes
        // that window and lets the binary preserve a non-zero exit status.
        self.try_failure()
    }
}

#[tracing::instrument(
    name = "job",
    skip_all,
    fields(
        job_id = %queued.job_id,
        request_id = tracing::field::Empty,
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
        parent_span_id = tracing::field::Empty,
        trace_flags = tracing::field::Empty,
        linked_trace_id = tracing::field::Empty,
        linked_span_id = tracing::field::Empty,
    )
)]
async fn handle_job(
    state: AppState,
    mut queued: QueuedJob,
    worker_id: usize,
    _tenant_permit: OwnedSemaphorePermit,
    _memory_permit: OwnedSemaphorePermit,
) {
    let job_id = queued.job_id.clone();
    if let Some(context) = state.job_traces.get(&job_id) {
        context.record_on_current_job_span();
    }
    let _job_trace_guard = JobTraceGuard {
        map: Arc::clone(&state.job_traces),
        job_id: job_id.clone(),
    };
    let Some(row) = load_queued_job_retrying(&state, &job_id).await else {
        return;
    };
    if row.tenant != queued.tenant {
        tracing::error!(
            envelope_tenant = %queued.tenant,
            durable_tenant = %row.tenant,
            "queued tenant lease disagreed with durable ownership"
        );
        finalize_without_execution_retrying(&state, &job_id, "tenant_lease_mismatch").await;
        queued.release_admission();
        return;
    }

    // A cancelled-while-queued job arrives here after the DELETE endpoint
    // already finalized it. Skip silently; do not consume a worker slot.
    if let Some(status) = JobStatus::parse(&row.status) {
        if status.is_terminal() {
            // Cancellation may have committed before a delayed scheduler
            // envelope was received. Close any candidate/recovery channel so
            // process-local ownership cannot outlive the durable terminal row.
            state.bus.complete(&job_id);
            queued.release_admission();
            return;
        }
    }

    let spec: JobSpec = match serde_json::from_str(&row.spec_json) {
        Ok(spec) => spec,
        Err(e) => {
            tracing::error!(error = %e, "stored job spec is invalid");
            finalize_without_execution_retrying(&state, &job_id, "invalid_stored_spec").await;
            queued.release_admission();
            return;
        }
    };
    let durable_mem_mb = match state.store.job_requested_mem_mb(&job_id).await {
        Ok(Some(mem_mb)) => state.cfg.clamp_mem_mb(mem_mb),
        Ok(None) => {
            tracing::error!("queued job has no durable memory charge");
            finalize_without_execution_retrying(&state, &job_id, "missing_memory_lease").await;
            queued.release_admission();
            return;
        }
        Err(error) => {
            tracing::error!(%error, "could not load durable memory charge");
            finalize_without_execution_retrying(&state, &job_id, "memory_lease_read_failed").await;
            queued.release_admission();
            return;
        }
    };
    if queued.mem_mb != durable_mem_mb {
        tracing::error!(
            queued_mem_mb = queued.mem_mb,
            durable_mem_mb,
            "queued memory lease disagreed with the durable job specification"
        );
        finalize_without_execution_retrying(&state, &job_id, "memory_lease_mismatch").await;
        queued.release_admission();
        return;
    }

    if !state
        .execution_provider
        .isolation_class()
        .satisfies(spec.requirements.minimum_isolation)
    {
        tracing::error!(
            requested = ?spec.requirements.minimum_isolation,
            available = ?state.execution_provider.isolation_class(),
            "queued job isolation requirement cannot be satisfied"
        );
        finalize_without_execution_retrying(&state, &job_id, "minimum_isolation_unsatisfied").await;
        queued.release_admission();
        return;
    }

    if matches!(state.sandbox_mode, coop_exec::SandboxMode::Off)
        && !state
            .resolved_naive_interpreters
            .contains_key(&spec.language)
    {
        tracing::error!(
            language = %spec.language,
            "queued job runtime did not pass this process's startup preflight"
        );
        finalize_without_execution_retrying(&state, &job_id, "runtime_unavailable").await;
        queued.release_admission();
        return;
    }

    let mut execution_spec = spec.clone();
    execution_spec.limits = state.cfg.clamp_limits(execution_spec.limits.clone());
    // The acceptance-time ceiling is durable policy. A later lower ceiling
    // tightens it during recovery; increasing the server ceiling never grants
    // an already-accepted queued job more memory than it originally received.
    execution_spec.limits.mem_mb = queued.mem_mb;
    let isolated = state.execution_provider.isolation_class() != coop_types::IsolationClass::None;
    // The request flag is not an egress grant. In the development subprocess
    // backend, however, host networking still exists and must be represented
    // truthfully in the effective spec and evidence receipt.
    execution_spec.limits.allow_network = !isolated;
    // The durable start precedes executor readiness. Persist an explicit
    // unobserved snapshot here; the terminal transaction replaces it with the
    // executor-observed effective spec once (and only if) provenance exists.
    let effective_value = json!({
        "storage_version": 2,
        "limits": EffectiveLimits::from_enforcement(
            &execution_spec.limits,
            &LimitEnforcement::NONE,
            None,
        ),
        "requirements": execution_spec.requirements.clone(),
        "isolation_class": serde_json::Value::Null,
    });

    // Register cancellation ownership before the guarded durable start. This
    // closes the shutdown/cancel window in which a row could become running
    // after the global cancellation scan but before its flag existed.
    let running = state
        .cancels
        .entry(job_id.clone())
        .or_insert_with(|| crate::RunningJob {
            tenant: row.tenant.clone(),
            cancel: Arc::new(coop_exec::ExecutionCancellation::default()),
        })
        .clone();
    let cancel_flag = Arc::clone(&running.cancel);
    let _cancel_guard = CancelGuard {
        map: Arc::clone(&state.cancels),
        job_id: job_id.clone(),
    };

    // Work not yet started remains durable and queued across shutdown. A
    // later process will recover it; this process must not dequeue new work.
    if *state.shutdown.borrow() {
        return;
    }
    if cancel_flag.is_cancelled() {
        finalize_queued_cancel_retrying(&state, &row).await;
        queued.release_admission();
        return;
    }

    // Transition, effective policy, and evidence event are one transaction.
    // A concurrent queued cancel can no longer be overwritten to running.
    match start_job_retrying(&state, &row, &effective_value, &cancel_flag).await {
        Ok(StartOutcome::Started(Some(event))) => state.bus.send(&job_id, wire_event(event)),
        Ok(StartOutcome::Started(None)) => {
            tracing::warn!(job_id = %job_id, "reconciled an ambiguously committed job start from durable state");
        }
        Ok(StartOutcome::NotStarted) => {
            tracing::info!(job_id = %job_id, "job was cancelled while queued — skipping execution");
            queued.release_admission();
            return;
        }
        Err(()) => {
            return;
        }
    }
    if let Some(reason) = pre_execution_stop_reason(&state, &cancel_flag) {
        // Shutdown/cancellation can linearize while SQLite is committing the
        // guarded start. The durable row is running at this point, so finish
        // it without ever entering the executor instead of leaving a stale
        // running row or briefly launching user code after shutdown.
        queued.release_admission();
        finalize_cancelled_without_execution_retrying(&state, &job_id, reason).await;
        return;
    }
    // The durable row is running now. Releasing the queued-job lease is the
    // only point (other than durable queued cancellation) at which new HTTP
    // admission may consume this capacity.
    queued.release_admission();

    // Bounded handoff prevents high-volume stdout from turning the server
    // process (which sits outside the job cgroup) into an unbounded buffer.
    let (op_tx, op_rx) = mpsc::channel::<Op>(1024);
    let pump = tokio::spawn(pump_events(state.clone(), job_id.clone(), op_rx));

    let workdir =
        std::path::PathBuf::from(&state.cfg.jobs_root).join(format!("job-{}", short_key(&job_id)));
    // N-1: workdirs hold tenant source and artifacts; mode 0700 (no-op off
    // unix) keeps sibling jobs from traversing each other's directories. The
    // jobs root was validated and prepared once during build_app; never chmod
    // that configurable path again after startup, when a development-mode
    // ancestor could have been replaced.
    if let Err(e) = tokio::fs::create_dir_all(&workdir)
        .await
        .and_then(|()| coop_exec::owner_only_dir(&workdir))
    {
        tracing::error!(error = %e, "failed to create workdir");
        let _ = op_tx
            .send(Op::Violation("executor_error", executor_error_detail(&e)))
            .await;
        finish_via(
            op_tx,
            "error",
            None,
            0,
            None,
            None,
            Some(state.execution_provider.not_ready_provenance()),
        )
        .await;
        await_event_pump(&state, &job_id, pump).await;
        return;
    }

    if let Err(e) = prepare_job_artifacts(&workdir, &execution_spec).await {
        tracing::error!(error = %e, "failed to prepare bounded job files");
        let _ = op_tx
            .send(Op::Violation(
                "artifact_setup_failed",
                executor_error_detail(&e),
            ))
            .await;
        finish_via(
            op_tx,
            "error",
            None,
            0,
            Some("artifact_setup_failed".to_string()),
            None,
            Some(state.execution_provider.not_ready_provenance()),
        )
        .await;
        await_event_pump(&state, &job_id, pump).await;
        return;
    }

    if let Some(reason) = pre_execution_stop_reason(&state, &cancel_flag) {
        let _ = tokio::fs::remove_dir_all(&workdir).await;
        finish_via(
            op_tx,
            "cancelled",
            None,
            0,
            Some(reason.to_string()),
            None,
            Some(state.execution_provider.not_ready_provenance()),
        )
        .await;
        await_event_pump(&state, &job_id, pump).await;
        return;
    }

    let ctx = ExecContext {
        job_key: short_key(&job_id),
        language: execution_spec.language.clone(),
        code: execution_spec.code,
        stdin: execution_spec.stdin,
        limits: execution_spec.limits,
        workdir: workdir.clone(),
        rootfs: state.cfg.rootfs.as_ref().map(std::path::PathBuf::from),
        helper_path: state
            .cfg
            .sandbox_helper
            .as_ref()
            .map(std::path::PathBuf::from),
        interpreter_override: if matches!(state.sandbox_mode, coop_exec::SandboxMode::Off) {
            state
                .resolved_naive_interpreters
                .get(&spec.language)
                .cloned()
        } else {
            state.cfg.interpreter_override(&spec.language)
        },
        cancel: Some(cancel_flag),
        start_gate: Some(Arc::clone(&state.execution_start_gate)),
        seccomp: state.seccomp,
    };

    tracing::info!(
        worker = worker_id,
        tenant = %row.tenant,
        language = %spec.language,
        sandbox = coop_exec::SandboxMode::as_str(state.sandbox_mode),
        wall_seconds = ctx.limits.wall_seconds,
        mem_mb = ctx.limits.mem_mb,
        "executing job"
    );

    let started_at = std::time::Instant::now();
    let stdout_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stderr_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let deferred_controls = Arc::new(std::sync::Mutex::new(Vec::new()));
    let execution_observation = state
        .metrics
        .start_execution(crate::metrics::Language::classify(&spec.language));
    let coop_exec::ExecutionReport {
        outcome: result,
        provenance,
    } = state
        .execution_provider
        .execute(
            ctx,
            Arc::new(JobSink {
                tx: op_tx.clone(),
                metrics: Arc::clone(&state.metrics),
                stdout_dropped: Arc::clone(&stdout_dropped),
                stderr_dropped: Arc::clone(&stderr_dropped),
                deferred_controls: Arc::clone(&deferred_controls),
            }),
        )
        .await;

    let isolation_evidence_mismatch = execution_evidence_violates_requirement(
        &result,
        &provenance,
        spec.requirements.minimum_isolation,
    );

    let controls = {
        let mut queue = deferred_controls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *queue)
    };
    for control in controls {
        let _ = op_tx.send(control).await;
    }

    let artifact_collection_failed = match collect_output_artifacts(&workdir, &spec.outputs).await {
        Ok(artifacts) => {
            for artifact in artifacts {
                let _ = op_tx.send(Op::Artifact(artifact)).await;
            }
            false
        }
        Err(error) => {
            tracing::warn!(%error, job_id, "one or more requested output files were unavailable");
            let _ = op_tx
                .send(Op::Violation(
                    "artifact_collection_failed",
                    json!({"code": "requested_output_unavailable"}),
                ))
                .await;
            true
        }
    };

    for (stream, dropped) in [
        (Stream::Stdout, &stdout_dropped),
        (Stream::Stderr, &stderr_dropped),
    ] {
        if dropped.load(std::sync::atomic::Ordering::Relaxed) {
            state
                .metrics
                .truncation(crate::metrics::TruncationKind::Evidence);
            let _ = op_tx.send(Op::EvidenceIncomplete).await;
            let _ = op_tx.send(Op::Truncated(stream)).await;
        }
    }

    if isolation_evidence_mismatch {
        execution_observation.finish(crate::metrics::JobOutcome::Error);
        tracing::error!(
            requested = ?spec.requirements.minimum_isolation,
            observed = ?provenance.isolation_class,
            bootstrap_ready = provenance.bootstrap_ready,
            "executor-observed isolation evidence contradicted the admitted requirement"
        );
        let _ = op_tx
            .send(Op::Violation(
                "minimum_isolation_observation_mismatch",
                json!({
                    "minimum_isolation": spec.requirements.minimum_isolation,
                    "observed_isolation": provenance.isolation_class,
                    "bootstrap_ready": provenance.bootstrap_ready,
                }),
            ))
            .await;
        let (exit_code, duration_ms, telemetry) = match result {
            Ok(outcome) => (
                outcome.exit_code,
                outcome.telemetry.wall_time_ms.min(i64::MAX as u64) as i64,
                Some(outcome.telemetry),
            ),
            Err(_) => (None, started_at.elapsed().as_millis() as i64, None),
        };
        finish_via(
            op_tx,
            "error",
            exit_code,
            duration_ms,
            Some("minimum_isolation_observation_mismatch".to_string()),
            telemetry,
            Some(provenance),
        )
        .await;
    } else {
        match result {
            Ok(outcome)
                if artifact_collection_failed
                    && matches!(outcome.status, coop_types::OutcomeStatus::Succeeded) =>
            {
                execution_observation.finish(crate::metrics::JobOutcome::Error);
                finish_via(
                    op_tx,
                    "error",
                    outcome.exit_code,
                    outcome.telemetry.wall_time_ms.min(i64::MAX as u64) as i64,
                    Some("requested_output_unavailable".to_string()),
                    Some(outcome.telemetry),
                    Some(provenance),
                )
                .await;
            }
            Ok(outcome) => {
                let status = coop_types::JobStatus::from(outcome.status);
                execution_observation.finish(crate::metrics::JobOutcome::classify(status.as_str()));
                finish_via(
                    op_tx,
                    status.as_str(),
                    outcome.exit_code,
                    outcome.telemetry.wall_time_ms.min(i64::MAX as u64) as i64,
                    outcome.killed_by.clone(),
                    Some(outcome.telemetry.clone()),
                    Some(provenance),
                )
                .await;
                tracing::info!(
                    status = status.as_str(),
                    exit_code = outcome.exit_code,
                    killed_by = outcome.killed_by.as_deref().unwrap_or(""),
                    duration_ms = outcome.telemetry.wall_time_ms,
                    "job finished"
                );
            }
            Err(e) => {
                execution_observation.finish(crate::metrics::JobOutcome::Error);
                tracing::error!(error = %e, "executor failure");
                let _ = op_tx
                    .send(Op::Violation("executor_error", executor_error_detail(&e)))
                    .await;
                finish_via(
                    op_tx,
                    "error",
                    None,
                    started_at.elapsed().as_millis() as i64,
                    None,
                    None,
                    Some(provenance),
                )
                .await;
            }
        }
    }

    if state.execution_provider.has_recovery_state(&workdir) {
        tracing::error!(
            path = %workdir.display(),
            "preserving provider recovery state after incomplete cleanup"
        );
    } else {
        let _ = tokio::fs::remove_dir_all(&workdir).await;
    }
    await_event_pump(&state, &job_id, pump).await;
    state.cancels.remove(&job_id);
}

fn execution_evidence_violates_requirement(
    outcome: &std::io::Result<coop_exec::ExecOutcome>,
    provenance: &coop_exec::ExecutionProvenance,
    minimum: coop_types::IsolationClass,
) -> bool {
    if provenance.bootstrap_ready {
        return !provenance.isolation_class.satisfies(minimum);
    }

    // A provider can legitimately fail or observe cancellation before its
    // workload-ready boundary. Any other successful executor outcome without
    // that boundary is contradictory evidence and must not remain successful.
    matches!(
        outcome,
        Ok(result) if result.status != coop_types::OutcomeStatus::Cancelled
    )
}

async fn await_event_pump(state: &AppState, job_id: &str, pump: JoinHandle<()>) {
    if let Err(error) = pump.await {
        tracing::error!(error = %error, job_id, "event pump stopped before confirming durable terminal state");
        finalize_without_execution_retrying(state, job_id, "event_pump_failed").await;
    }
}

async fn load_queued_job_retrying(state: &AppState, job_id: &str) -> Option<coop_store::JobRow> {
    let mut delay = Duration::from_millis(10);
    loop {
        if *state.shutdown.borrow() {
            return None;
        }
        let started_at = std::time::Instant::now();
        let result = state.store.get_job(job_id).await;
        state.metrics.observe_storage(
            crate::metrics::StorageOperation::Read,
            started_at.elapsed(),
            result.is_ok(),
        );
        match result {
            Ok(row) => {
                if row.is_none() {
                    tracing::warn!(job_id, "queued job vanished from store");
                }
                return row;
            }
            Err(error) => {
                tracing::warn!(error = %error, job_id, "transient failure loading queued job; retaining scheduler ownership");
                if wait_for_retry_or_shutdown(state, delay).await {
                    return None;
                }
                delay = (delay * 2).min(Duration::from_secs(1));
            }
        }
    }
}

fn pre_execution_stop_reason(
    state: &AppState,
    cancel: &coop_exec::ExecutionCancellation,
) -> Option<&'static str> {
    if *state.shutdown.borrow() {
        Some("server_shutdown_before_execution")
    } else if cancel.is_cancelled() {
        Some("cancelled_before_execution")
    } else {
        None
    }
}

async fn start_job_retrying(
    state: &AppState,
    row: &coop_store::JobRow,
    effective_spec: &Value,
    cancel: &coop_exec::ExecutionCancellation,
) -> Result<StartOutcome, ()> {
    let mut delay = Duration::from_millis(10);
    loop {
        if *state.shutdown.borrow() {
            return Err(());
        }
        if cancel.is_cancelled() {
            finalize_queued_cancel_retrying(state, row).await;
            return Ok(StartOutcome::NotStarted);
        }
        let started_at = std::time::Instant::now();
        let result = state
            .store
            .start_with_event_if_queued(&row.job_id, effective_spec)
            .await;
        state.metrics.observe_storage(
            crate::metrics::StorageOperation::Start,
            started_at.elapsed(),
            result.is_ok(),
        );
        match result {
            Ok(Some(event)) => return Ok(StartOutcome::Started(Some(event))),
            Ok(None) => match reconcile_start(state, &row.job_id).await {
                Some(StartOutcome::Started(_)) => return Ok(StartOutcome::Started(None)),
                Some(StartOutcome::NotStarted) => return Ok(StartOutcome::NotStarted),
                None => {}
            },
            Err(error) => {
                tracing::warn!(error = %error, job_id = %row.job_id, "transient failure starting queued job; retaining scheduler ownership");
                match reconcile_start(state, &row.job_id).await {
                    Some(StartOutcome::Started(_)) => return Ok(StartOutcome::Started(None)),
                    Some(StartOutcome::NotStarted) => return Ok(StartOutcome::NotStarted),
                    None => {}
                }
                if wait_for_retry_or_shutdown(state, delay).await {
                    return Err(());
                }
                delay = (delay * 2).min(Duration::from_secs(1));
            }
        }
    }
}

enum StartOutcome {
    /// `None` means the transaction committed but its response was ambiguous;
    /// replay still contains the durable started event.
    Started(Option<coop_store::EventRow>),
    NotStarted,
}

async fn reconcile_start(state: &AppState, job_id: &str) -> Option<StartOutcome> {
    match state.store.get_job_summary(job_id).await {
        Ok(Some(row)) if row.status == "running" => Some(StartOutcome::Started(None)),
        Ok(Some(row))
            if JobStatus::parse(&row.status).is_some_and(|status| status.is_terminal()) =>
        {
            Some(StartOutcome::NotStarted)
        }
        Ok(None) => Some(StartOutcome::NotStarted),
        Ok(Some(_)) | Err(_) => None,
    }
}

async fn finalize_queued_cancel_retrying(state: &AppState, row: &coop_store::JobRow) {
    finalize_cancelled_without_execution_retrying(state, &row.job_id, "cancelled_before_start")
        .await;
}

async fn finalize_cancelled_without_execution_retrying(
    state: &AppState,
    job_id: &str,
    reason: &str,
) {
    let output = OutputEvidence::default();
    let provenance = state.execution_provider.not_ready_provenance();
    finalize_job(
        state,
        job_id,
        TerminalEvidence {
            status: "cancelled",
            exit_code: None,
            duration_ms: 0,
            killed_by: Some(reason),
            output: &output,
            telemetry: None,
            provenance: Some(&provenance),
        },
    )
    .await;
}

async fn finalize_without_execution_retrying(state: &AppState, job_id: &str, reason: &str) {
    let output = OutputEvidence::default();
    finalize_job(
        state,
        job_id,
        TerminalEvidence {
            status: "error",
            exit_code: None,
            duration_ms: 0,
            killed_by: Some(reason),
            output: &output,
            telemetry: None,
            provenance: None,
        },
    )
    .await;
}

/// Returns true once shutdown is sticky. Checking `borrow()` before entering
/// select avoids waiting forever when the watch value changed before this
/// receiver subscribed.
async fn wait_for_retry_or_shutdown(state: &AppState, delay: Duration) -> bool {
    let mut shutdown = state.shutdown.subscribe();
    if *shutdown.borrow() {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(delay) => *shutdown.borrow(),
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
    }
}

async fn prepare_job_artifacts(workdir: &std::path::Path, spec: &JobSpec) -> std::io::Result<()> {
    let workdir = workdir.to_path_buf();
    let files = spec.files.clone();
    let outputs = spec.outputs.clone();
    tokio::task::spawn_blocking(move || {
        if files.len() > coop_types::MAX_INPUT_FILES || outputs.len() > coop_types::MAX_OUTPUT_FILES
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "stored artifact count exceeds the execution limit",
            ));
        }
        let input_root = workdir.join("input");
        let output_root = workdir.join("output");
        std::fs::create_dir(&input_root)?;
        std::fs::create_dir(&output_root)?;
        let mut input_directories = HashSet::new();
        let mut total_input_bytes = 0_usize;
        input_directories.insert(input_root.clone());
        for file in files {
            if !coop_types::validate_artifact_path(&file.path, "input") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "stored input path is invalid",
                ));
            }
            let relative = file.path.strip_prefix("input/").expect("validated prefix");
            let target = input_root.join(relative);
            let parent = target.parent().expect("input files have a parent");
            std::fs::create_dir_all(parent)?;
            let mut cursor = parent.to_path_buf();
            loop {
                input_directories.insert(cursor.clone());
                if cursor == input_root {
                    break;
                }
                cursor = cursor
                    .parent()
                    .ok_or_else(|| std::io::Error::other("input path escaped its root"))?
                    .to_path_buf();
            }
            let max_encoded = coop_types::MAX_INPUT_FILE_BYTES.div_ceil(3) * 4;
            if file.content_base64.len() > max_encoded {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "stored input base64 exceeds the execution limit",
                ));
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(file.content_base64)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "stored input base64 is invalid",
                    )
                })?;
            if decoded.len() > coop_types::MAX_INPUT_FILE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "stored input file exceeds the execution limit",
                ));
            }
            total_input_bytes = total_input_bytes.saturating_add(decoded.len());
            if total_input_bytes > coop_types::MAX_INPUT_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "stored input files exceed the total execution limit",
                ));
            }
            coop_exec::write_private_file(&target, &decoded)?;
            make_input_file_read_only(&target)?;
        }
        for output in outputs {
            if !coop_types::validate_artifact_path(&output, "output") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "stored output path is invalid",
                ));
            }
            let relative = output.strip_prefix("output/").expect("validated prefix");
            if let Some(parent) = output_root.join(relative).parent() {
                std::fs::create_dir_all(parent)?;
                make_output_directories_writable(&output_root, parent)?;
            }
        }
        for directory in input_directories {
            make_input_directory_traversable(&directory)?;
        }
        make_output_directory_writable(&output_root)?;
        Ok(())
    })
    .await
    .map_err(|error| std::io::Error::other(format!("artifact setup task failed: {error}")))?
}

#[cfg(unix)]
fn make_input_file_read_only(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444))
}

#[cfg(not(unix))]
fn make_input_file_read_only(_path: &std::path::Path) -> std::io::Result<()> {
    // Development subprocess mode is not a containment boundary. Leaving the
    // host-user file writable avoids undeletable Windows job directories; the
    // API and receipt report isolation none rather than claiming immutable
    // input enforcement.
    Ok(())
}

#[cfg(unix)]
fn make_input_directory_traversable(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // The isolated providers additionally mount this tree read-only. Owner
    // write permission here lets an unprivileged development server remove
    // its workdir after a run without claiming that development mode is safe.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn make_input_directory_traversable(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn make_output_directory_writable(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // The outer job directory remains 0700. Inside the isolated bind mount,
    // the unprivileged workload needs write access without matching a host UID.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))
}

#[cfg(not(unix))]
fn make_output_directory_writable(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

fn make_output_directories_writable(
    root: &std::path::Path,
    leaf: &std::path::Path,
) -> std::io::Result<()> {
    let mut cursor = leaf.to_path_buf();
    loop {
        make_output_directory_writable(&cursor)?;
        if cursor == root {
            return Ok(());
        }
        cursor = cursor
            .parent()
            .ok_or_else(|| std::io::Error::other("output path escaped its root"))?
            .to_path_buf();
    }
}

async fn collect_output_artifacts(
    workdir: &std::path::Path,
    outputs: &[String],
) -> std::io::Result<Vec<Value>> {
    let workdir = workdir.to_path_buf();
    let outputs = outputs.to_vec();
    tokio::task::spawn_blocking(move || {
        use std::io::Read as _;

        let root = workdir.join("output");
        let mut total = 0_usize;
        let mut artifacts = Vec::with_capacity(outputs.len());
        for requested in outputs {
            if !coop_types::validate_artifact_path(&requested, "output") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "stored output path is invalid",
                ));
            }
            let relative = requested.strip_prefix("output/").expect("validated prefix");
            let mut target = root.clone();
            let parts = relative.split('/').collect::<Vec<_>>();
            for (index, part) in parts.iter().enumerate() {
                target.push(part);
                let metadata = std::fs::symlink_metadata(&target)?;
                if metadata.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "requested output traversed a symbolic link",
                    ));
                }
                if index + 1 == parts.len() {
                    if !metadata.is_file() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "requested output is not a regular file",
                        ));
                    }
                } else if !metadata.is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "requested output parent is not a directory",
                    ));
                }
            }
            let metadata = std::fs::metadata(&target)?;
            if metadata.len() > coop_types::MAX_OUTPUT_FILE_BYTES as u64 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::FileTooLarge,
                    "one requested output exceeded its byte limit",
                ));
            }
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            let mut file = std::fs::File::open(&target)?;
            file.by_ref()
                .take((coop_types::MAX_OUTPUT_FILE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > coop_types::MAX_OUTPUT_FILE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::FileTooLarge,
                    "one requested output grew beyond its byte limit",
                ));
            }
            total = total.saturating_add(bytes.len());
            if total > coop_types::MAX_OUTPUT_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::FileTooLarge,
                    "requested outputs exceeded the total byte limit",
                ));
            }
            artifacts.push(json!({
                "path": requested,
                "content_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
                "size_bytes": bytes.len(),
                "sha256": bytes_to_hex(Sha256::digest(&bytes).as_slice()),
            }));
        }
        Ok(artifacts)
    })
    .await
    .map_err(|error| std::io::Error::other(format!("artifact collection task failed: {error}")))?
}

/// N6: tenant-visible executor errors are reduced to a coarse, generic code.
/// Raw io::Error text can name interpreter paths and cgroup/jobs_root
/// topology, so it stays in server-side tracing only (see the callers).
fn executor_error_detail(e: &std::io::Error) -> Value {
    let code = match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            "executor_unavailable"
        }
        _ => "executor_failure",
    };
    json!({ "code": code })
}

async fn finish_via(
    tx: mpsc::Sender<Op>,
    status: &'static str,
    exit_code: Option<i32>,
    duration_ms: i64,
    killed_by: Option<String>,
    telemetry: Option<coop_exec::ExecTelemetry>,
    provenance: Option<coop_exec::ExecutionProvenance>,
) {
    let _ = tx
        .send(Op::Finished {
            status,
            exit_code,
            duration_ms,
            killed_by,
            telemetry,
            provenance: provenance.map(Box::new),
        })
        .await;
    drop(tx);
}

/// F-009 retention: periodically delete terminal jobs older than
/// `retention_hours` together with their events. A no-op when retention is
/// disabled (0). Errors are logged and swept again next interval — a failed
/// sweep must never take the server down.
pub fn spawn_retention_sweeper(state: AppState) {
    if state.cfg.retention_hours == 0 {
        tracing::info!(
            "retention disabled (ROOKHOLD_RETENTION_HOURS=0); event log grows unbounded"
        );
        return;
    }
    let max_age_ms = (state.cfg.retention_hours * 3600 * 1000) as i64;
    let interval = Duration::from_secs(state.cfg.sweep_interval_secs);
    tokio::spawn(async move {
        let mut shutdown = state.shutdown.subscribe();
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut catch_up = false;
        loop {
            if catch_up {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() { break; }
                        continue;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            } else {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() { break; }
                        continue;
                    }
                    _ = ticker.tick() => {}
                }
            }
            let mut jobs_deleted = 0_u64;
            let mut events_deleted = 0_u64;
            let mut more_remaining = false;
            let mut made_progress = false;
            let mut failed = false;
            let mut interrupted = false;
            for _ in 0..16 {
                if *shutdown.borrow() {
                    interrupted = true;
                    break;
                }
                let started_at = std::time::Instant::now();
                let result = state.store.prune_older_than_batch(max_age_ms, 250).await;
                state.metrics.observe_storage(
                    crate::metrics::StorageOperation::Retention,
                    started_at.elapsed(),
                    result.is_ok(),
                );
                match result {
                    Ok(report) => {
                        jobs_deleted += report.jobs_deleted;
                        events_deleted += report.events_deleted;
                        more_remaining = report.more_remaining;
                        let progress = report.jobs_deleted != 0 || report.events_deleted != 0;
                        made_progress |= progress;
                        if !more_remaining || !progress {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                    Err(e) => {
                        failed = true;
                        tracing::warn!(error = %e, "retention sweep failed");
                        more_remaining = false;
                        break;
                    }
                }
            }
            catch_up = more_remaining && made_progress;
            if failed {
                state.metrics.retention_failed(jobs_deleted, events_deleted);
            } else if interrupted {
                state
                    .metrics
                    .retention_interrupted(jobs_deleted, events_deleted);
            } else {
                state
                    .metrics
                    .retention_succeeded(jobs_deleted, events_deleted);
            }
            if jobs_deleted > 0 || events_deleted > 0 {
                tracing::info!(
                    jobs_deleted,
                    events_deleted,
                    more_remaining,
                    "retention sweep pruned expired jobs"
                );
            }
        }
    });
}

fn short_key(job_id: &str) -> String {
    job_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(64)
        .collect()
}

fn semaphore_for(state: &AppState, tenant: &str) -> Arc<Semaphore> {
    state
        .tenant_sems
        .entry(tenant.to_string())
        .or_insert_with(|| Arc::new(Semaphore::new(state.cfg.tenant_concurrency)))
        .clone()
}

#[derive(Clone)]
struct OutputEvidence {
    stdout: Sha256,
    stderr: Sha256,
    stdout_bytes: u64,
    stderr_bytes: u64,
    stdout_seen: bool,
    stderr_seen: bool,
    truncated: bool,
    persistence_complete: bool,
    artifacts: Vec<Value>,
}

struct TerminalEvidence<'a> {
    status: &'a str,
    exit_code: Option<i32>,
    duration_ms: i64,
    killed_by: Option<&'a str>,
    output: &'a OutputEvidence,
    telemetry: Option<&'a coop_exec::ExecTelemetry>,
    provenance: Option<&'a coop_exec::ExecutionProvenance>,
}

#[derive(Default)]
struct BuiltTerminalEvidence {
    receipt: Option<Value>,
    effective_spec: Option<Value>,
}

impl Default for OutputEvidence {
    fn default() -> Self {
        Self {
            stdout: Sha256::new(),
            stderr: Sha256::new(),
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_seen: false,
            stderr_seen: false,
            truncated: false,
            persistence_complete: true,
            artifacts: Vec::new(),
        }
    }
}

impl OutputEvidence {
    fn observe(&mut self, stream: Stream, line: &str) {
        let (hasher, bytes, seen) = match stream {
            Stream::Stdout => (
                &mut self.stdout,
                &mut self.stdout_bytes,
                &mut self.stdout_seen,
            ),
            Stream::Stderr => (
                &mut self.stderr,
                &mut self.stderr_bytes,
                &mut self.stderr_seen,
            ),
        };
        if *seen {
            hasher.update(b"\n");
            *bytes += 1;
        }
        hasher.update(line.as_bytes());
        *bytes += line.len() as u64;
        *seen = true;
    }

    fn as_json(&self) -> Value {
        json!({
            "encoding": "utf8-event-lines-joined-by-lf-no-trailing-lf",
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "stdout_sha256": bytes_to_hex(self.stdout.clone().finalize().as_slice()),
            "stderr_sha256": bytes_to_hex(self.stderr.clone().finalize().as_slice()),
            "truncated": self.truncated,
        })
    }
}

async fn pump_events(state: AppState, job_id: String, mut rx: mpsc::Receiver<Op>) {
    let mut evidence = OutputEvidence::default();
    let mut finalized = false;
    let mut pending = Vec::with_capacity(EVENT_BATCH_MAX);

    while let Some(first) = rx.recv().await {
        let mut terminal = stage_op(first, &mut pending, &mut evidence);
        let mut channel_closed = false;
        let flush_deadline = tokio::time::Instant::now() + EVENT_BATCH_LATENCY;

        // Coalesce the currently queued burst into one SQLite transaction. A
        // fixed deadline keeps low-volume streaming responsive, while the hard
        // item cap prevents a producer from creating an unbounded transaction.
        while terminal.is_none() && pending.len() < EVENT_BATCH_MAX {
            let received = tokio::select! {
                biased;
                op = rx.recv() => Some(op),
                () = tokio::time::sleep_until(flush_deadline) => None,
            };
            match received {
                Some(Some(op)) => terminal = stage_op(op, &mut pending, &mut evidence),
                Some(None) => {
                    channel_closed = true;
                    break;
                }
                None => break,
            }
        }

        flush_event_batch(&state, &job_id, &mut pending, &mut evidence).await;

        if let Some(terminal) = terminal {
            finalize_job(
                &state,
                &job_id,
                TerminalEvidence {
                    status: terminal.status,
                    exit_code: terminal.exit_code,
                    duration_ms: terminal.duration_ms,
                    killed_by: terminal.killed_by.as_deref(),
                    output: &evidence,
                    telemetry: terminal.telemetry.as_ref(),
                    provenance: terminal.provenance.as_deref(),
                },
            )
            .await;
            finalized = true;
            break;
        }
        if channel_closed {
            break;
        }
    }

    // Panic/cancellation-safe terminal transition. If the producer vanished
    // without a Finished op, callers still receive a durable error outcome.
    if !finalized {
        finalize_job(
            &state,
            &job_id,
            TerminalEvidence {
                status: "error",
                exit_code: None,
                duration_ms: 0,
                killed_by: Some("event_producer_stopped"),
                output: &evidence,
                telemetry: None,
                provenance: None,
            },
        )
        .await;
    }
}

fn stage_op(
    op: Op,
    pending: &mut Vec<(String, Value)>,
    evidence: &mut OutputEvidence,
) -> Option<FinishedOp> {
    match op {
        Op::Output(stream, line) => {
            pending.push((stream.as_str().to_string(), json!({ "line": line })));
            None
        }
        Op::Violation(rule, detail) => {
            pending.push((
                "violation".to_string(),
                json!({ "rule": rule, "detail": detail }),
            ));
            None
        }
        Op::Truncated(stream) => {
            pending.push((
                "truncated".to_string(),
                json!({
                    "stream": stream.as_str(),
                    "max_lines": coop_types::MAX_OUTPUT_LINES,
                    "max_bytes": coop_types::MAX_OUTPUT_BYTES_PER_STREAM,
                    "max_record_bytes": coop_types::MAX_OUTPUT_RECORD_BYTES,
                }),
            ));
            None
        }
        Op::EvidenceIncomplete => {
            evidence.persistence_complete = false;
            None
        }
        Op::Artifact(artifact) => {
            pending.push(("artifact".to_string(), artifact));
            None
        }
        Op::Finished {
            status,
            exit_code,
            duration_ms,
            killed_by,
            telemetry,
            provenance,
        } => Some(FinishedOp {
            status,
            exit_code,
            duration_ms,
            killed_by,
            telemetry,
            provenance,
        }),
    }
}

async fn flush_event_batch(
    state: &AppState,
    job_id: &str,
    pending: &mut Vec<(String, Value)>,
    evidence: &mut OutputEvidence,
) {
    if pending.is_empty() {
        return;
    }
    let expected = pending.len();
    let started_at = std::time::Instant::now();
    let result = state.store.append_events_batch(job_id, pending).await;
    state.metrics.observe_storage(
        crate::metrics::StorageOperation::Events,
        started_at.elapsed(),
        result.is_ok(),
    );
    match result {
        Ok(events) => {
            if events.len() != expected {
                evidence.persistence_complete = false;
                tracing::error!(
                    job_id,
                    expected,
                    persisted = events.len(),
                    "event batch returned an incomplete durable result"
                );
            }
            for event in events {
                observe_persisted_event(evidence, &event);
                state.bus.send(job_id, wire_event(event));
            }
        }
        Err(e) => {
            evidence.persistence_complete = false;
            tracing::error!(
                error = %e,
                job_id,
                events = expected,
                "failed to atomically persist job event batch"
            );
        }
    }
    pending.clear();
}

fn observe_persisted_event(evidence: &mut OutputEvidence, event: &coop_store::EventRow) {
    match event.kind.as_str() {
        "stdout" | "stderr" => {
            if let Some(line) = event.data.get("line").and_then(Value::as_str) {
                let stream = if event.kind == "stdout" {
                    Stream::Stdout
                } else {
                    Stream::Stderr
                };
                evidence.observe(stream, line);
            }
        }
        "truncated" => evidence.truncated = true,
        "artifact" => evidence.artifacts.push(event.data.clone()),
        _ => {}
    }
}

async fn finalize_job(state: &AppState, job_id: &str, terminal: TerminalEvidence<'_>) {
    let mut delay = Duration::from_millis(10);
    let built = loop {
        match try_build_receipt(state, job_id, &terminal).await {
            Ok(built) => break built,
            Err(error) => {
                tracing::warn!(error = %error, job_id, "failed to build receipt; retaining terminal ownership and retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(1));
            }
        }
    };

    delay = Duration::from_millis(10);
    loop {
        let started_at = std::time::Instant::now();
        let result = state
            .store
            .finalize_with_event_and_effective_spec(
                job_id,
                terminal.status,
                terminal.exit_code,
                terminal.duration_ms,
                built.effective_spec.as_ref(),
                built.receipt.as_ref(),
            )
            .await;
        state.metrics.observe_storage(
            crate::metrics::StorageOperation::Finalize,
            started_at.elapsed(),
            result.is_ok(),
        );
        match result {
            Ok(Some(event)) => {
                state.bus.send(job_id, wire_event(event));
                state.bus.complete(job_id);
                return;
            }
            Ok(None) => match state.store.get_job_summary(job_id).await {
                Ok(Some(row))
                    if JobStatus::parse(&row.status).is_some_and(|status| status.is_terminal()) =>
                {
                    tracing::info!(
                        job_id,
                        status = %row.status,
                        "observed a durable terminal state after a finalization race"
                    );
                    state.bus.complete(job_id);
                    return;
                }
                Ok(None) => {
                    tracing::warn!(job_id, "job disappeared while finalizing");
                    state.bus.complete(job_id);
                    return;
                }
                Ok(Some(row)) => tracing::warn!(
                    job_id,
                    status = %row.status,
                    "finalization changed no row but job is non-terminal; retrying"
                ),
                Err(error) => tracing::warn!(
                    error = %error,
                    job_id,
                    "could not reconcile a no-op finalization; retrying"
                ),
            },
            Err(error) => tracing::warn!(
                error = %error,
                job_id,
                status = terminal.status,
                "failed to atomically finalize job; retaining terminal ownership and retrying"
            ),
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(1));
    }
}

async fn try_build_receipt(
    state: &AppState,
    job_id: &str,
    terminal: &TerminalEvidence<'_>,
) -> coop_store::StoreResult<BuiltTerminalEvidence> {
    let row = match state.store.get_job(job_id).await {
        Ok(Some(row)) => row,
        Ok(None) => return Ok(BuiltTerminalEvidence::default()),
        Err(error) => return Err(error),
    };
    let Some(requested) = serde_json::from_str::<Value>(&row.spec_json).ok() else {
        return Ok(BuiltTerminalEvidence::default());
    };
    let requested_spec = serde_json::from_value::<JobSpec>(requested.clone()).ok();
    let input_files = requested_spec
        .as_ref()
        .map(|spec| {
            spec.files
                .iter()
                .filter_map(|file| {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(&file.content_base64)
                        .ok()?;
                    Some(json!({
                        "path": file.path,
                        "size_bytes": bytes.len(),
                        "sha256": bytes_to_hex(Sha256::digest(&bytes).as_slice()),
                    }))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let output_artifacts = terminal
        .output
        .artifacts
        .iter()
        .map(|artifact| {
            json!({
                "path": artifact.get("path"),
                "size_bytes": artifact.get("size_bytes"),
                "sha256": artifact.get("sha256"),
            })
        })
        .collect::<Vec<_>>();
    let code = requested.get("code").and_then(Value::as_str).unwrap_or("");
    let stdin = requested.get("stdin").and_then(Value::as_str).unwrap_or("");
    let finished_at_ms = now_ms();
    // Receipt output hashes/counts describe the durable hash-chain events,
    // not bytes merely observed by the executor or offered to a saturated
    // JobSink channel. Raw executor telemetry is retained separately below.
    let output = terminal.output.as_json();
    let mut receipt = json!({
        "version": 1,
        "job_id": job_id,
        "outcome": terminal.status,
        "exit_code": terminal.exit_code,
        "killed_by": terminal.killed_by,
        "created_at_ms": row.created_at_ms,
        "started_at_ms": row.started_at_ms,
        "finished_at_ms": finished_at_ms,
        "duration_ms": terminal.duration_ms.max(0),
        "evidence_complete": terminal.output.persistence_complete,
        "requested_limits": requested.get("limits").cloned().unwrap_or(Value::Null),
        "requirements": requested.get("requirements").cloned().unwrap_or_else(|| json!({"minimum_isolation": "none"})),
        "code_sha256": bytes_to_hex(Sha256::digest(code.as_bytes()).as_slice()),
        "stdin_sha256": bytes_to_hex(Sha256::digest(stdin.as_bytes()).as_slice()),
        "resource_usage": terminal.telemetry.map(|telemetry| json!({
            "wall_time_ms": telemetry.wall_time_ms,
            "cpu_time_usec": telemetry.cpu_time_usec,
            "memory_peak_bytes": telemetry.memory_peak_bytes,
        })),
        "executor_output": terminal.telemetry.map(|telemetry| json!({
            "stdout": {
                "bytes_seen": telemetry.stdout.bytes_seen,
                "bytes_offered_to_sink": telemetry.stdout.bytes_emitted,
                "records_offered_to_sink": telemetry.stdout.records_emitted,
                "raw_sha256": telemetry.stdout.sha256,
                "executor_truncated": telemetry.stdout.truncated,
            },
            "stderr": {
                "bytes_seen": telemetry.stderr.bytes_seen,
                "bytes_offered_to_sink": telemetry.stderr.bytes_emitted,
                "records_offered_to_sink": telemetry.stderr.records_emitted,
                "raw_sha256": telemetry.stderr.sha256,
                "executor_truncated": telemetry.stderr.truncated,
            },
        })),
        "output": output,
        "input_files": input_files,
        "artifacts": output_artifacts,
    });
    // Every execution posture member comes from the executor's observed ready
    // boundary. Configuration and a durable `running` transition are not
    // evidence that namespace/rootfs/seccomp bootstrap actually completed.
    let mut observed_effective_spec = None;
    if let (Some(provenance), Some(spec)) = (terminal.provenance, requested_spec.as_ref()) {
        let mut limits = state.cfg.clamp_limits(spec.limits.clone());
        if let Some(accepted_mem_mb) = state.store.job_requested_mem_mb(job_id).await? {
            limits.mem_mb = state.cfg.clamp_mem_mb(accepted_mem_mb);
        }
        let effective_limits = provenance.effective_limits(&limits);
        let policy = json!({
            "backend": provenance.backend,
            "minimum_isolation": spec.requirements.minimum_isolation,
            "isolation_class": provenance.isolation_class,
            "bootstrap_ready": provenance.bootstrap_ready,
            "isolated": provenance.isolated,
            "seccomp": provenance.seccomp,
            "network_allowed": provenance.network_allowed,
            "networking": provenance.networking,
            "private_rootfs": provenance.private_rootfs,
            "dedicated_bootstrap": provenance.dedicated_bootstrap,
            "effective_limits": effective_limits,
            "limit_enforcement": provenance.limit_enforcement,
            "runtime_version": provenance.runtime_version,
            "runtime_sha256": provenance.runtime_sha256,
            "rootfs_sha256": provenance.rootfs_sha256,
            "config_sha256": provenance.config_sha256,
        });
        let Some(policy_bytes) = serde_json::to_vec(&policy).ok() else {
            return Ok(BuiltTerminalEvidence::default());
        };
        observed_effective_spec = Some(json!({
            "storage_version": 2,
            "limits": effective_limits.clone(),
            "requirements": spec.requirements.clone(),
            "files": spec.files.clone(),
            "outputs": spec.outputs.clone(),
            "runtime": spec.runtime.clone(),
            "isolation_class": provenance
                .bootstrap_ready
                .then_some(provenance.isolation_class),
        }));
        if observed_effective_spec.is_none() {
            return Ok(BuiltTerminalEvidence::default());
        }
        receipt["backend"] = json!(provenance.backend);
        receipt["minimum_isolation"] = json!(spec.requirements.minimum_isolation);
        receipt["isolation_class"] = json!(provenance.isolation_class);
        receipt["bootstrap_ready"] = json!(provenance.bootstrap_ready);
        receipt["isolated"] = json!(provenance.isolated);
        receipt["seccomp"] = json!(provenance.seccomp);
        receipt["network_allowed"] = json!(provenance.network_allowed);
        receipt["networking"] = json!(provenance.networking);
        receipt["private_rootfs"] = json!(provenance.private_rootfs);
        receipt["dedicated_bootstrap"] = json!(provenance.dedicated_bootstrap);
        receipt["effective_limits"] = json!(effective_limits);
        receipt["limit_enforcement"] = json!(provenance.limit_enforcement);
        receipt["runtime_version"] = json!(provenance.runtime_version);
        receipt["runtime_sha256"] = json!(provenance.runtime_sha256);
        receipt["rootfs_sha256"] = json!(provenance.rootfs_sha256);
        receipt["config_sha256"] = json!(provenance.config_sha256);
        receipt["runtime_pack"] = json!(spec.runtime);
        receipt["policy_sha256"] = json!(bytes_to_hex(Sha256::digest(&policy_bytes).as_slice()));
    }
    Ok(BuiltTerminalEvidence {
        receipt: Some(receipt),
        effective_spec: observed_effective_spec,
    })
}

pub(crate) async fn build_queued_cancel_receipt(state: &AppState, job_id: &str) -> Option<Value> {
    let output = OutputEvidence::default();
    try_build_receipt(
        state,
        job_id,
        &TerminalEvidence {
            status: "cancelled",
            exit_code: None,
            duration_ms: 0,
            killed_by: Some("cancelled_before_start"),
            output: &output,
            telemetry: None,
            provenance: None,
        },
    )
    .await
    .ok()
    .and_then(|built| built.receipt)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn wire_event(event: coop_store::EventRow) -> WireEvent {
    WireEvent {
        seq: event.seq,
        ts_ms: event.ts_ms,
        kind: event.kind,
        data: event.data,
        prev_hash: event.prev_hash,
        event_hash: event.event_hash,
        hash_version: event.hash_version,
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    fn observed_provenance(
        isolation_class: coop_types::IsolationClass,
        bootstrap_ready: bool,
    ) -> coop_exec::ExecutionProvenance {
        coop_exec::ExecutionProvenance {
            backend: "test-provider".to_string(),
            isolation_class,
            bootstrap_ready,
            isolated: isolation_class != coop_types::IsolationClass::None && bootstrap_ready,
            private_rootfs: false,
            dedicated_bootstrap: false,
            seccomp: false,
            network_allowed: None,
            networking: None,
            limit_enforcement: coop_types::LimitEnforcement::NONE,
            runtime_version: None,
            runtime_sha256: None,
            rootfs_sha256: None,
            config_sha256: None,
        }
    }

    fn successful_outcome(
        status: coop_types::OutcomeStatus,
    ) -> std::io::Result<coop_exec::ExecOutcome> {
        Ok(coop_exec::ExecOutcome {
            status,
            exit_code: Some(0),
            killed_by: None,
            telemetry: coop_exec::ExecTelemetry::default(),
        })
    }

    #[test]
    fn terminal_execution_fails_closed_on_contradictory_isolation_evidence() {
        let gvisor = observed_provenance(coop_types::IsolationClass::GvisorApplicationKernel, true);
        assert!(!execution_evidence_violates_requirement(
            &successful_outcome(coop_types::OutcomeStatus::Succeeded),
            &gvisor,
            coop_types::IsolationClass::LinuxSharedKernel,
        ));

        let shared_kernel =
            observed_provenance(coop_types::IsolationClass::LinuxSharedKernel, true);
        assert!(execution_evidence_violates_requirement(
            &successful_outcome(coop_types::OutcomeStatus::Succeeded),
            &shared_kernel,
            coop_types::IsolationClass::GvisorApplicationKernel,
        ));

        let not_ready = observed_provenance(coop_types::IsolationClass::None, false);
        assert!(execution_evidence_violates_requirement(
            &successful_outcome(coop_types::OutcomeStatus::Succeeded),
            &not_ready,
            coop_types::IsolationClass::None,
        ));
        assert!(!execution_evidence_violates_requirement(
            &successful_outcome(coop_types::OutcomeStatus::Cancelled),
            &not_ready,
            coop_types::IsolationClass::GvisorApplicationKernel,
        ));
        assert!(!execution_evidence_violates_requirement(
            &Err(std::io::Error::other("failed before ready")),
            &not_ready,
            coop_types::IsolationClass::GvisorApplicationKernel,
        ));
    }

    async fn monitor_test_state() -> (AppState, mpsc::Receiver<QueuedJob>) {
        let base = std::env::temp_dir().join(format!(
            "coop-scheduler-monitor-test-{}",
            uuid::Uuid::now_v7()
        ));
        let db = base.join("state.db");
        let jobs_root = base.join("jobs");
        std::fs::create_dir_all(&base).expect("create test directory");
        let cfg = crate::config::Config {
            attestation_mode: crate::config::AttestationMode::Off,
            attestation_key_file: None,
            addr: "127.0.0.1:0".to_string(),
            db_path: db.to_string_lossy().into_owned(),
            api_keys: std::collections::HashMap::new(),
            metrics_token: None,
            credentials: Default::default(),
            jwt: None,
            workers: 1,
            tenant_concurrency: 1,
            tenant_queue_capacity: 64,
            rate_per_min: 60,
            max_job_mem_mb: 1024,
            memory_budget_mb: 4096,
            storage_global_mb: 16 * 1024,
            storage_tenant_mb: 4 * 1024,
            storage_free_reserve_mb: 0,
            sandbox: "off".to_string(),
            jobs_root: jobs_root.to_string_lossy().into_owned(),
            rootfs: None,
            sandbox_helper: None,
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
            sweep_interval_secs: 3_600,
            seccomp: false,
        };
        let store = Arc::new(coop_store::Store::open(&db).await.expect("open test store"));
        let (_app, state, queue_rx) = crate::build_app(cfg, store, "127.0.0.1:0".parse().unwrap())
            .await
            .expect("build test app");
        (state, queue_rx)
    }

    fn supervised_test_pool<F>(state: AppState, task_name: &str, future: F) -> WorkerPool
    where
        F: Future<Output = Result<(), String>> + Send + 'static,
    {
        let (failure_tx, failure_rx) = mpsc::channel(1);
        let handle =
            spawn_supervised_task(state, failure_tx.clone(), task_name.to_string(), future);
        WorkerPool {
            handles: vec![handle],
            failure_rx,
            _failure_tx: failure_tx,
        }
    }

    #[test]
    fn global_bound_survives_channel_drain_and_reclaims_on_dequeue() {
        const CAPACITY: usize = 16;
        let (admission, mut receiver) = Admission::channel(CAPACITY, CAPACITY);
        let mut fair_pending = Vec::new();
        let mut accepted = 0_usize;

        // Continuously drain ingress to model dispatch_fair moving envelopes
        // into per-tenant queues. The old channel-only bound accepted all of
        // these attempts; the lease bound must stop exactly at CAPACITY.
        for n in 0..10_000 {
            if let Ok(reservation) = admission.try_reserve("tenant", 256) {
                reservation.send(format!("job-{n}"));
                accepted += 1;
            }
            while let Ok(queued) = receiver.try_recv() {
                fair_pending.push(queued);
            }
        }

        assert_eq!(accepted, CAPACITY);
        assert_eq!(fair_pending.len(), CAPACITY);
        assert_eq!(admission.depth(), CAPACITY);
        assert_eq!(
            admission.try_reserve("tenant", 256).err(),
            Some(TryAdmissionError::TenantFull)
        );

        // A cancelled/terminal envelope retains its slot until the scheduler
        // actually dequeues/drops it; cancel/refill churn cannot accumulate
        // resident tombstones. Once dequeued, capacity is immediately reused.
        fair_pending.pop();
        assert_eq!(admission.depth(), CAPACITY - 1);
        admission
            .try_reserve("tenant", 256)
            .expect("capacity reclaimed")
            .send("replacement".to_string());
        assert_eq!(admission.depth(), CAPACITY);
    }

    #[test]
    fn tenant_and_global_queue_leases_are_atomic_and_distinguishable() {
        let (admission, mut receiver) = Admission::channel(3, 1);
        admission
            .try_reserve("tenant-a", 256)
            .unwrap()
            .send("a-1".to_string());
        let held_a = receiver.try_recv().unwrap();
        assert_eq!(
            admission.try_reserve("tenant-a", 256).err(),
            Some(TryAdmissionError::TenantFull)
        );
        admission
            .try_reserve("tenant-b", 256)
            .unwrap()
            .send("b-1".to_string());
        admission
            .try_reserve("tenant-c", 256)
            .unwrap()
            .send("c-1".to_string());
        let held_b = receiver.try_recv().unwrap();
        let held_c = receiver.try_recv().unwrap();
        assert_eq!(
            admission.try_reserve("tenant-d", 256).err(),
            Some(TryAdmissionError::GlobalFull)
        );
        drop(held_a);
        assert_eq!(admission.tenant_depth("tenant-a"), 0);
        admission
            .try_reserve("tenant-d", 256)
            .expect("dropping an envelope reclaims both leases");
        drop((held_b, held_c));
    }

    #[tokio::test]
    async fn older_weighted_memory_request_cannot_be_starved_by_smaller_jobs() {
        let (mut state, _queue_rx) = monitor_test_state().await;
        state.memory_slots = Arc::new(Semaphore::new(1024));
        let held = Arc::clone(&state.memory_slots)
            .try_acquire_many_owned(512)
            .unwrap();
        let (admission, mut ingress) = Admission::channel(2, 1);
        admission
            .try_reserve("large", 1024)
            .unwrap()
            .send("large-job".to_string());
        admission
            .try_reserve("small", 512)
            .unwrap()
            .send("small-job".to_string());
        let large = ingress.recv().await.unwrap();
        let small = ingress.recv().await.unwrap();
        let mut pending = HashMap::from([
            ("large".to_string(), VecDeque::from([large])),
            ("small".to_string(), VecDeque::from([small])),
        ]);
        let mut round_robin = VecDeque::from(["large".to_string(), "small".to_string()]);
        let mut active = HashSet::from(["large".to_string(), "small".to_string()]);
        let (work_tx, mut work_rx) = mpsc::channel(2);
        dispatch_available(
            &state,
            &work_tx,
            &mut pending,
            &mut round_robin,
            &mut active,
        )
        .unwrap();
        assert!(
            work_rx.try_recv().is_err(),
            "small job backfilled past older large job"
        );
        drop(held);
        dispatch_available(
            &state,
            &work_tx,
            &mut pending,
            &mut round_robin,
            &mut active,
        )
        .unwrap();
        let work = work_rx
            .try_recv()
            .expect("large job dispatched after memory release");
        assert_eq!(work.queued.job_id, "large-job");
        assert_eq!(state.memory_slots.available_permits(), 0);
        drop(work);
        assert_eq!(state.memory_slots.available_permits(), 1024);
    }

    #[tokio::test]
    async fn grandfathered_recovery_overflow_blocks_only_that_tenants_new_admission() {
        let (admission, mut receiver) = Admission::channel(4, 1);
        admission
            .reserve_recovery("tenant-a", 256)
            .await
            .unwrap()
            .send("old-a-1".to_string());
        admission
            .reserve_recovery("tenant-a", 256)
            .await
            .unwrap()
            .send("old-a-2".to_string());
        assert_eq!(admission.tenant_depth("tenant-a"), 2);
        assert_eq!(
            admission.try_reserve("tenant-a", 256).err(),
            Some(TryAdmissionError::TenantFull)
        );
        admission
            .try_reserve("tenant-b", 256)
            .expect("another tenant retains capacity")
            .send("new-b".to_string());
        drop(receiver.recv().await.unwrap());
        drop(receiver.recv().await.unwrap());
        drop(receiver.recv().await.unwrap());
        assert_eq!(admission.depth(), 0);
    }

    #[tokio::test]
    async fn closing_saturated_admission_wakes_async_waiters() {
        let (admission, mut receiver) = Admission::channel(1, 1);
        admission
            .try_reserve("tenant", 256)
            .unwrap()
            .send("held".to_string());

        let waiter_admission = admission.clone();
        let waiter =
            tokio::spawn(
                async move { waiter_admission.reserve_recovery("other", 256).await.err() },
            );
        tokio::task::yield_now().await;
        admission.close();
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(250), waiter)
                .await
                .expect("waiter woke")
                .expect("waiter joined"),
            Some(TryAdmissionError::Closed)
        );

        drop(receiver.try_recv().expect("held envelope"));
        assert_eq!(admission.depth(), 0);
        assert_eq!(
            admission.try_reserve("tenant", 256).err(),
            Some(TryAdmissionError::Closed)
        );
    }

    #[tokio::test]
    async fn receipt_hashes_only_canonical_persisted_lines_under_sink_backpressure() {
        let (tx, mut rx) = mpsc::channel(1);
        let stdout_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sink = JobSink {
            tx,
            metrics: Arc::new(crate::metrics::Metrics::new()),
            stdout_dropped: Arc::clone(&stdout_dropped),
            stderr_dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            deferred_controls: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        sink.output(Stream::Stdout, "retained".to_string());
        sink.output(Stream::Stdout, "not-retained".to_string());
        assert!(stdout_dropped.load(std::sync::atomic::Ordering::Relaxed));

        let mut pending = Vec::new();
        let mut evidence = OutputEvidence::default();
        let op = rx.recv().await.expect("one retained operation");
        assert!(stage_op(op, &mut pending, &mut evidence).is_none());
        assert_eq!(
            evidence.stdout_bytes, 0,
            "offered output is not durable evidence"
        );

        let persisted = coop_store::EventRow {
            seq: 1,
            ts_ms: 1,
            kind: "stdout".to_string(),
            data: json!({ "line": "retained" }),
            prev_hash: String::new(),
            event_hash: String::new(),
            hash_version: 1,
        };
        observe_persisted_event(&mut evidence, &persisted);
        let encoded = b"retained";
        assert_eq!(evidence.stdout_bytes, encoded.len() as u64);
        assert_eq!(
            evidence.as_json()["stdout_sha256"],
            format!("{}", bytes_to_hex(Sha256::digest(encoded).as_slice()))
        );
        assert_eq!(
            evidence.as_json()["encoding"],
            "utf8-event-lines-joined-by-lf-no-trailing-lf"
        );

        assert!(stage_op(Op::EvidenceIncomplete, &mut pending, &mut evidence).is_none());
        assert!(
            !evidence.persistence_complete,
            "sink backpressure makes the retained evidence set incomplete"
        );
    }

    #[tokio::test]
    async fn pre_ready_failure_receipt_never_attests_configured_isolation_or_limits() {
        let (state, _queue_rx) = monitor_test_state().await;
        let job_id = "pre-ready-receipt";
        let spec = JobSpec {
            language: "python".to_string(),
            code: "print('never ready')".to_string(),
            stdin: None,
            limits: coop_types::Limits::default(),
            requirements: coop_types::JobRequirements::default(),
            files: Vec::new(),
            outputs: Vec::new(),
            runtime: None,
        };
        state
            .store
            .create_job(
                job_id,
                "tenant",
                "python",
                &serde_json::to_string(&spec).unwrap(),
            )
            .await
            .unwrap();
        state
            .store
            .start_with_event_if_queued(
                job_id,
                &json!({
                    "storage_version": 2,
                    "limits": EffectiveLimits::from_enforcement(
                        &spec.limits,
                        &LimitEnforcement::NAMESPACE_SANDBOX,
                        Some(false),
                    ),
                    "requirements": coop_types::JobRequirements::default(),
                    "isolation_class": serde_json::Value::Null,
                }),
            )
            .await
            .unwrap()
            .unwrap();

        let output = OutputEvidence::default();
        // Telemetry can exist on a cancellation/timeout before the namespace
        // helper emits Ready. It must not be used as a readiness heuristic.
        let telemetry = coop_exec::ExecTelemetry::default();
        let provenance =
            coop_exec::ExecutionProvenance::not_ready(coop_exec::SandboxMode::Namespaces);
        let built = try_build_receipt(
            &state,
            job_id,
            &TerminalEvidence {
                status: "error",
                exit_code: None,
                duration_ms: 1,
                killed_by: Some("bootstrap_failed"),
                output: &output,
                telemetry: Some(&telemetry),
                provenance: Some(&provenance),
            },
        )
        .await
        .unwrap();
        let receipt = built.receipt.as_ref().unwrap();

        assert_eq!(receipt["bootstrap_ready"], false);
        assert_eq!(receipt["isolated"], false);
        assert_eq!(receipt["private_rootfs"], false);
        assert_eq!(receipt["dedicated_bootstrap"], false);
        assert_eq!(receipt["seccomp"], false);
        assert!(receipt["network_allowed"].is_null());
        assert!(receipt["networking"].is_null());
        assert_eq!(
            receipt["limit_enforcement"],
            serde_json::to_value(LimitEnforcement::NONE).unwrap()
        );
        for control in [
            "wall_seconds",
            "cpu_seconds",
            "mem_mb",
            "max_pids",
            "max_file_mb",
            "allow_network",
        ] {
            assert!(
                receipt["effective_limits"][control].is_null(),
                "pre-ready receipt claimed {control}: {receipt}"
            );
        }

        let observed_effective = built.effective_spec.as_ref().unwrap();
        for control in [
            "wall_seconds",
            "cpu_seconds",
            "mem_mb",
            "max_pids",
            "max_file_mb",
            "allow_network",
        ] {
            assert!(
                observed_effective["limits"][control].is_null(),
                "pre-ready effective spec claimed {control}: {observed_effective}"
            );
        }
        state
            .store
            .finalize_with_event_and_effective_spec(
                job_id,
                "error",
                None,
                1,
                Some(observed_effective),
                Some(receipt),
            )
            .await
            .unwrap()
            .expect("terminal event");
        let persisted = state.store.get_job(job_id).await.unwrap().unwrap();
        let persisted_effective: Value = serde_json::from_str(
            persisted
                .effective_spec_json
                .as_deref()
                .expect("observed effective spec persisted"),
        )
        .unwrap();
        assert_eq!(persisted_effective["storage_version"], 2);
        assert!(persisted_effective.get("code").is_none());
        assert!(persisted_effective.get("stdin").is_none());
        for control in [
            "wall_seconds",
            "cpu_seconds",
            "mem_mb",
            "max_pids",
            "max_file_mb",
            "allow_network",
        ] {
            assert!(
                persisted_effective["limits"][control].is_null(),
                "terminal transaction retained planned {control}: {persisted_effective}"
            );
        }
    }

    #[tokio::test]
    async fn shutdown_observed_after_start_commit_finalizes_without_execution() {
        let (state, _queue_rx) = monitor_test_state().await;
        let job_id = "shutdown-during-start-commit";
        let spec = JobSpec {
            language: "python".to_string(),
            code: "raise SystemExit('must not execute')".to_string(),
            stdin: None,
            limits: coop_types::Limits::default(),
            requirements: coop_types::JobRequirements::default(),
            files: Vec::new(),
            outputs: Vec::new(),
            runtime: None,
        };
        state
            .store
            .create_job(
                job_id,
                "tenant",
                "python",
                &serde_json::to_string(&spec).unwrap(),
            )
            .await
            .unwrap();
        state
            .store
            .start_with_event_if_queued(job_id, &serde_json::json!({ "limits": {} }))
            .await
            .unwrap()
            .expect("start committed");

        let cancel = coop_exec::ExecutionCancellation::default();
        state.begin_shutdown();
        let reason = pre_execution_stop_reason(&state, &cancel)
            .expect("post-commit fence observes sticky shutdown");
        assert_eq!(reason, "server_shutdown_before_execution");
        finalize_cancelled_without_execution_retrying(&state, job_id, reason).await;

        let row = state.store.get_job(job_id).await.unwrap().unwrap();
        assert_eq!(row.status, "cancelled");
        let receipt: Value = serde_json::from_str(row.receipt_json.as_deref().unwrap()).unwrap();
        assert_eq!(receipt["killed_by"], "server_shutdown_before_execution");
        assert_eq!(receipt["bootstrap_ready"], false);
    }

    #[tokio::test]
    async fn supervised_panic_is_fatal_closes_admission_and_fails_readiness() {
        let (state, _queue_rx) = monitor_test_state().await;
        let mut workers = supervised_test_pool(state.clone(), "test worker", async {
            panic!("worker invariant");
            #[allow(unreachable_code)]
            Ok::<(), String>(())
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            while !*state.shutdown.borrow() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("supervision initiated shutdown");
        let failure = tokio::time::timeout(Duration::from_secs(1), workers.failure())
            .await
            .expect("fatal notification was prompt");
        assert!(failure.contains("test worker panicked"), "{failure}");
        assert!(failure.contains("worker invariant"), "{failure}");
        assert!(!state
            .startup_ready
            .load(std::sync::atomic::Ordering::Acquire));
        assert!(*state.shutdown.borrow());
        assert_eq!(
            state.admission.try_reserve("tenant", 256).err(),
            Some(TryAdmissionError::Closed)
        );
        let _ = workers.shutdown(&state, Duration::from_millis(250)).await;
    }

    #[tokio::test]
    async fn supervised_unexpected_return_is_fatal_but_normal_shutdown_is_clean() {
        let (state, queue_rx) = monitor_test_state().await;
        let mut failed_workers = supervised_test_pool(state.clone(), "test dispatcher", async {
            Ok::<(), String>(())
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !*state.shutdown.borrow() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("supervision initiated shutdown");
        let failure = tokio::time::timeout(Duration::from_secs(1), failed_workers.failure())
            .await
            .expect("fatal notification was prompt");
        assert!(failure.contains("exited unexpectedly"), "{failure}");
        assert!(!state
            .startup_ready
            .load(std::sync::atomic::Ordering::Acquire));
        assert!(*state.shutdown.borrow());
        assert_eq!(
            state.admission.try_reserve("tenant", 256).err(),
            Some(TryAdmissionError::Closed)
        );
        let _ = failed_workers
            .shutdown(&state, Duration::from_millis(250))
            .await;

        let (clean_state, clean_queue_rx) = monitor_test_state().await;
        clean_state.begin_shutdown();
        let mut workers = spawn_workers(clean_state.clone(), clean_queue_rx);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), workers.failure())
                .await
                .is_err(),
            "expected worker exits must not publish a fatal failure"
        );
        let _ = workers
            .shutdown(&clean_state, Duration::from_millis(250))
            .await;

        drop(queue_rx);
    }

    #[tokio::test]
    async fn captured_failure_during_shutdown_is_retained_after_supervisor_join() {
        let (state, _queue_rx) = monitor_test_state().await;
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let workers = supervised_test_pool(state.clone(), "late worker", async move {
            let _ = release_rx.await;
            Err::<(), String>("captured before publication".to_string())
        });

        // Model Ctrl-C winning main's select before the supervised wrapper can
        // publish an already-determined task error.
        state.begin_shutdown();
        release_tx.send(()).expect("release failing task");
        let failure = workers
            .shutdown(&state, Duration::from_secs(1))
            .await
            .expect("shutdown join retained the late failure");
        assert!(failure.contains("late worker failed"), "{failure}");
        assert!(failure.contains("captured before publication"), "{failure}");
    }

    #[tokio::test]
    async fn closed_worker_handoff_channel_is_an_unexpected_exit() {
        let (state, _queue_rx) = monitor_test_state().await;
        let (work_tx, work_rx) = mpsc::channel::<WorkItem>(1);
        drop(work_tx);
        let (done_tx, _done_rx) = mpsc::unbounded_channel();

        let error = worker_loop(
            state,
            Arc::new(tokio::sync::Mutex::new(work_rx)),
            done_tx,
            0,
        )
        .await
        .expect_err("closed handoff must fail a worker");
        assert!(error.contains("handoff channel closed"), "{error}");
    }

    #[tokio::test]
    async fn dispatcher_detects_closed_worker_handoff_channel() {
        let (state, _queue_rx) = monitor_test_state().await;
        let (admission, admission_rx) = Admission::channel(1, 1);
        admission
            .try_reserve("tenant", 256)
            .expect("test admission")
            .send("queued-job".to_string());
        let (work_tx, work_rx) = mpsc::channel::<WorkItem>(1);
        drop(work_rx);
        let (_done_tx, done_rx) = mpsc::unbounded_channel();

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            dispatch_fair(state, admission_rx, work_tx, done_rx),
        )
        .await
        .expect("dispatcher noticed the closed handoff")
        .expect_err("closed handoff must fail the dispatcher");
        assert!(error.contains("handoff channel closed"), "{error}");
        assert_eq!(
            admission.depth(),
            0,
            "failed dispatch dropped the process-local lease while the durable row remains queued"
        );
    }
}
