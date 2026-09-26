use std::collections::HashMap;
use std::path::{Component, Path};

pub const DEV_DEFAULT_API_KEY: &str = "local:rookhold-dev-key";
const LEGACY_DEV_DEFAULT_API_KEY: &str = "local:coop-dev-key";
const PUBLIC_DEV_API_KEY: &str = "rookhold-dev-key";
const LEGACY_PUBLIC_DEV_API_KEY: &str = "coop-dev-key";
const PRIMARY_ENV_PREFIX: &str = "ROOKHOLD_";
const LEGACY_ENV_PREFIX: &str = "COOP_";
const CONFIG_ENV_KEYS: &[&str] = &[
    "ROOKHOLD_ADDR",
    "ROOKHOLD_API_KEYS",
    "ROOKHOLD_ATTESTATION_KEY_FILE",
    "ROOKHOLD_ATTESTATION_MODE",
    "ROOKHOLD_BASH",
    "ROOKHOLD_CREDENTIAL_PEPPER_FILE",
    "ROOKHOLD_CREDENTIALS_FILE",
    "ROOKHOLD_DB",
    "ROOKHOLD_ENV",
    "ROOKHOLD_GVISOR_GID",
    "ROOKHOLD_GVISOR_PLATFORM",
    "ROOKHOLD_GVISOR_ROOTFS_SHA256",
    "ROOKHOLD_GVISOR_RUNSC",
    "ROOKHOLD_GVISOR_UID",
    "ROOKHOLD_JOBS_ROOT",
    "ROOKHOLD_LOG_FORMAT",
    "ROOKHOLD_MAX_JOB_MEM_MB",
    "ROOKHOLD_MEMORY_BUDGET_MB",
    "ROOKHOLD_METRICS_TOKEN",
    "ROOKHOLD_NODE",
    "ROOKHOLD_OIDC_ALGORITHMS",
    "ROOKHOLD_OIDC_AUDIENCE",
    "ROOKHOLD_OIDC_ISSUER",
    "ROOKHOLD_OIDC_JWKS_TTL_SECONDS",
    "ROOKHOLD_OIDC_JWKS_URL",
    "ROOKHOLD_OIDC_MAX_TOKEN_AGE_SECONDS",
    "ROOKHOLD_OIDC_TENANT_CLAIM",
    "ROOKHOLD_OIDC_TENANT_MAP",
    "ROOKHOLD_PYTHON",
    "ROOKHOLD_RATE_PER_MIN",
    "ROOKHOLD_RETENTION_HOURS",
    "ROOKHOLD_ROOTFS",
    "ROOKHOLD_SANDBOX",
    "ROOKHOLD_SANDBOX_HELPER",
    "ROOKHOLD_SECCOMP",
    "ROOKHOLD_STORAGE_FREE_RESERVE_MB",
    "ROOKHOLD_STORAGE_GLOBAL_MB",
    "ROOKHOLD_STORAGE_TENANT_MB",
    "ROOKHOLD_SWEEP_INTERVAL_SECS",
    "ROOKHOLD_TENANT_CONCURRENCY",
    "ROOKHOLD_TENANT_QUEUE_CAPACITY",
    "ROOKHOLD_UNSAFE_ALLOW_NAIVE",
    "ROOKHOLD_UNSAFE_ALLOW_PUBLIC_DEV",
    "ROOKHOLD_WORKERS",
];
pub const DEFAULT_TENANT_QUEUE_CAPACITY: usize = 64;
pub const DEFAULT_MAX_JOB_MEM_MB: u32 = 1024;
pub const DEFAULT_MEMORY_BUDGET_MB: u32 = 4096;
pub const DEFAULT_STORAGE_GLOBAL_MB: u64 = 16 * 1024;
pub const DEFAULT_STORAGE_TENANT_MB: u64 = 4 * 1024;
pub const DEFAULT_STORAGE_FREE_RESERVE_MB: u64 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationMode {
    Off,
    Sign,
}

#[derive(Clone)]
pub struct Config {
    pub addr: String,
    pub db_path: String,
    pub api_keys: HashMap<String, String>,
    /// Optional, separately scoped bearer credential for the global operator
    /// metrics endpoint. It is never accepted by tenant API middleware.
    pub metrics_token: Option<String>,
    /// Signing is enabled only with an operator-supplied Ed25519 key file.
    /// Production defaults fail closed; `Off` must be explicitly selected to
    /// acknowledge that terminal jobs will not receive signed attestations.
    pub attestation_mode: AttestationMode,
    pub attestation_key_file: Option<String>,
    pub credentials: crate::auth::CredentialStore,
    pub jwt: Option<crate::auth::JwtConfig>,
    pub workers: usize,
    pub tenant_concurrency: usize,
    pub tenant_queue_capacity: usize,
    pub rate_per_min: u32,
    pub max_job_mem_mb: u32,
    pub memory_budget_mb: u32,
    pub storage_global_mb: u64,
    pub storage_tenant_mb: u64,
    pub storage_free_reserve_mb: u64,
    pub sandbox: String,
    pub jobs_root: String,
    /// A private, purpose-built root filesystem used by the namespace
    /// executor. Host `/` is never an acceptable sandbox root.
    pub rootfs: Option<String>,
    /// Dedicated single-threaded bootstrap executable for namespace setup.
    pub sandbox_helper: Option<String>,
    /// Absolute path to the reviewed, operator-installed runsc binary.
    pub gvisor_runsc: Option<String>,
    /// Operator-generated content digest of the immutable trusted rootfs.
    pub gvisor_rootfs_sha256: Option<String>,
    /// gVisor syscall interception platform: systrap in a VM, or KVM on a
    /// suitably isolated bare-metal host.
    pub gvisor_platform: String,
    /// Non-root identity used by the OCI init and workload inside gVisor.
    pub gvisor_uid: u32,
    pub gvisor_gid: u32,
    /// Whether production policy is active. Kept in the parsed configuration
    /// so embedded servers cannot accidentally use the caller process' env.
    pub production: bool,
    /// Conspicuous acknowledgement required for the unisolated executor in
    /// production. This is deliberately separate from `ROOKHOLD_SANDBOX=off`.
    pub unsafe_allow_naive: bool,
    pub unsafe_allow_public_dev: bool,
    pub python_bin: Option<String>,
    pub node_bin: Option<String>,
    pub bash_bin: Option<String>,
    /// F-009 retention: delete terminal jobs (and their events) older than
    /// this many hours. 0 disables sweeping entirely.
    pub retention_hours: u64,
    /// Seconds between retention sweeps.
    pub sweep_interval_secs: u64,
    /// F-005: install a seccomp-BPF syscall allowlist in sandboxed jobs
    /// (namespace backend only). Default on; `ROOKHOLD_SECCOMP=off` disables.
    pub seccomp: bool,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("addr", &self.addr)
            .field("db_path", &self.db_path)
            .field(
                "api_keys",
                &format!("{} key(s), redacted", self.api_keys.len()),
            )
            .field(
                "metrics_token",
                &self.metrics_token.as_ref().map(|_| "configured, redacted"),
            )
            .field("attestation_mode", &self.attestation_mode)
            .field(
                "attestation_key_file",
                &self.attestation_key_file.as_ref().map(|_| "configured"),
            )
            .field("credentials", &self.credentials)
            .field("jwt", &self.jwt)
            .field("workers", &self.workers)
            .field("tenant_concurrency", &self.tenant_concurrency)
            .field("tenant_queue_capacity", &self.tenant_queue_capacity)
            .field("rate_per_min", &self.rate_per_min)
            .field("max_job_mem_mb", &self.max_job_mem_mb)
            .field("memory_budget_mb", &self.memory_budget_mb)
            .field("storage_global_mb", &self.storage_global_mb)
            .field("storage_tenant_mb", &self.storage_tenant_mb)
            .field("storage_free_reserve_mb", &self.storage_free_reserve_mb)
            .field("sandbox", &self.sandbox)
            .field("jobs_root", &self.jobs_root)
            .field("rootfs", &self.rootfs)
            .field("sandbox_helper", &self.sandbox_helper)
            .field("gvisor_runsc", &self.gvisor_runsc)
            .field("gvisor_rootfs_sha256", &self.gvisor_rootfs_sha256)
            .field("gvisor_platform", &self.gvisor_platform)
            .field("gvisor_uid", &self.gvisor_uid)
            .field("gvisor_gid", &self.gvisor_gid)
            .field("production", &self.production)
            .field("unsafe_allow_naive", &self.unsafe_allow_naive)
            .field("unsafe_allow_public_dev", &self.unsafe_allow_public_dev)
            .field("python_bin", &self.python_bin)
            .field("node_bin", &self.node_bin)
            .field("bash_bin", &self.bash_bin)
            .finish()
    }
}

fn env_or(getenv: &dyn Fn(&str) -> Option<String>, key: &str, default: &str) -> String {
    getenv(key)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn parse_number<T>(
    getenv: &dyn Fn(&str) -> Option<String>,
    key: &str,
    default: &str,
    min: T,
    max: T,
) -> Result<T, String>
where
    T: std::str::FromStr + PartialOrd + Copy + std::fmt::Display,
{
    let raw = env_or(getenv, key, default);
    let value = raw
        .parse::<T>()
        .map_err(|_| format!("{key} must be a base-10 integer, got {raw:?}"))?;
    if value < min || value > max {
        return Err(format!(
            "{key} must be between {min} and {max}, got {value}"
        ));
    }
    Ok(value)
}

fn env_true(getenv: &dyn Fn(&str) -> Option<String>, key: &str) -> bool {
    matches!(
        getenv(key)
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

fn listener_is_loopback(addr: &str) -> bool {
    let addr = addr.trim();
    if let Ok(socket) = addr.parse::<std::net::SocketAddr>() {
        return socket.ip().is_loopback();
    }
    false
}

fn legacy_api_key_is_weak(key: &str) -> bool {
    key == PUBLIC_DEV_API_KEY || key == LEGACY_PUBLIC_DEV_API_KEY || key.len() < 16
}

fn legacy_env_key(primary: &str) -> Option<String> {
    primary
        .strip_prefix(PRIMARY_ENV_PREFIX)
        .map(|suffix| format!("{LEGACY_ENV_PREFIX}{suffix}"))
}

fn validate_compatible_env(getenv: &dyn Fn(&str) -> Option<String>) -> Result<(), String> {
    for primary in CONFIG_ENV_KEYS {
        let Some(legacy) = legacy_env_key(primary) else {
            continue;
        };
        if let (Some(primary_value), Some(legacy_value)) = (getenv(primary), getenv(&legacy)) {
            if !primary_value.is_empty()
                && !legacy_value.is_empty()
                && primary_value != legacy_value
            {
                return Err(format!(
                    "{primary} conflicts with legacy compatibility variable {legacy}; configure only {primary} or give both the same value"
                ));
            }
        }
    }
    Ok(())
}

fn ensure_metrics_token_is_separate(
    metrics_token: Option<&str>,
    api_keys: &HashMap<String, String>,
    credentials: &crate::auth::CredentialStore,
) -> Result<(), String> {
    if metrics_token.is_some_and(|token| {
        api_keys.contains_key(token) || credentials.matches_active_credential(token)
    }) {
        return Err(
            "ROOKHOLD_METRICS_TOKEN must be different from every active tenant API credential"
                .to_string(),
        );
    }
    Ok(())
}

/// Reject paths for which a permissions call could affect a broad or
/// redirected part of the host. The executor creates children beneath this
/// directory, so it must be an absolute, dedicated, non-symlink path.
pub fn validate_jobs_root(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("ROOKHOLD_JOBS_ROOT must be an absolute path".to_string());
    }
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err("ROOKHOLD_JOBS_ROOT must not contain '.' or '..' components".to_string());
    }

    let normal_components = path
        .components()
        .filter(|part| matches!(part, Component::Normal(_)))
        .count();
    if normal_components < 2 {
        return Err(format!(
            "ROOKHOLD_JOBS_ROOT={} is too broad; choose a dedicated directory such as /var/lib/rookhold/jobs",
            path.display()
        ));
    }

    // Known broad directories are dangerous even though some have two path
    // components on Windows (for example C:\\Users).
    let lexical: std::path::PathBuf = path.components().collect();
    let normalized = lexical
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let normalized = normalized.trim_end_matches('/');
    let broad = [
        "/applications",
        "/library",
        "/network",
        "/system",
        "/users",
        "/volumes",
        "/app",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/tmp",
        "/var",
        "/var/cache",
        "/var/lib",
        "/var/log",
        "/var/run",
        "/var/spool",
        "/var/tmp",
        "/usr",
        "/usr/bin",
        "/usr/include",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/etc",
        "/usr/local/lib",
        "/usr/local/sbin",
        "/usr/sbin",
        "/usr/share",
        "/opt",
        "/home",
        "/lib",
        "/lib64",
        "/media",
        "/mnt",
        "/proc",
        "/private",
        "/private/etc",
        "/private/tmp",
        "/private/var",
        "/private/var/lib",
        "/private/var/tmp",
        "/root",
        "/run",
        "/sbin",
        "/srv",
        "/sys",
        "/workspace",
        "c:/windows",
        "c:/windows/system32",
        "c:/program files",
        "c:/program files (x86)",
        "c:/programdata",
        "c:/users",
    ];
    if broad.contains(&normalized) {
        return Err(format!(
            "ROOKHOLD_JOBS_ROOT={} is a shared system directory; choose a dedicated child",
            path.display()
        ));
    }
    let mut dynamic_forbidden = vec![std::env::temp_dir()];
    if let Ok(current) = std::env::current_dir() {
        dynamic_forbidden.push(current);
    }
    for variable in ["HOME", "USERPROFILE"] {
        if let Some(value) = std::env::var_os(variable) {
            dynamic_forbidden.push(value.into());
        }
    }
    if dynamic_forbidden.iter().any(|candidate| {
        candidate
            .to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
            .eq_ignore_ascii_case(normalized)
    }) {
        return Err(format!(
            "ROOKHOLD_JOBS_ROOT={} must not be a home, temporary, or current working directory",
            path.display()
        ));
    }

    validate_existing_jobs_root_chain(path, false)
}

/// Validate, create, lock down, and revalidate the jobs directory. Strict
/// mode is for Linux production/namespace execution, where every existing
/// component must be root-owned and immune to group/world path replacement.
pub fn prepare_jobs_root(path: &Path, strict: bool) -> Result<(), String> {
    validate_jobs_root(path)?;
    validate_existing_jobs_root_chain(path, strict)?;
    if std::fs::symlink_metadata(path).is_ok() {
        require_existing_jobs_root_private(path)?;
    } else {
        let parent = path.parent().ok_or_else(|| {
            format!(
                "ROOKHOLD_JOBS_ROOT {} has no dedicated parent",
                path.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut parents = std::fs::DirBuilder::new();
            parents.recursive(true).mode(0o700);
            parents.create(parent).map_err(|error| {
                format!(
                    "failed to create ROOKHOLD_JOBS_ROOT parent {}: {error}",
                    parent.display()
                )
            })?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create ROOKHOLD_JOBS_ROOT parent {}: {error}",
                parent.display()
            )
        })?;

        // Validate the freshly completed parent chain before the atomic leaf
        // create. Existing shared directories are never chmodded: if another
        // creator wins this race, it must already satisfy the private-leaf
        // invariant or startup fails without mutating it.
        validate_existing_jobs_root_chain(parent, strict)?;
        #[cfg(unix)]
        let create_result = {
            use std::os::unix::fs::DirBuilderExt;
            let mut leaf = std::fs::DirBuilder::new();
            leaf.mode(0o700).create(path)
        };
        #[cfg(not(unix))]
        let create_result = std::fs::create_dir(path);
        match create_result {
            Ok(()) => coop_exec::owner_only_dir(path).map_err(|error| {
                format!(
                    "failed to lock down newly created ROOKHOLD_JOBS_ROOT {}: {error}",
                    path.display()
                )
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                require_existing_jobs_root_private(path)?;
            }
            Err(error) => {
                return Err(format!(
                    "failed to create ROOKHOLD_JOBS_ROOT {}: {error}",
                    path.display()
                ));
            }
        }
    }
    validate_existing_jobs_root_chain(path, strict)
}

fn require_existing_jobs_root_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|error| {
                format!(
                    "cannot inspect existing ROOKHOLD_JOBS_ROOT {}: {error}",
                    path.display()
                )
            })?
            .permissions()
            .mode()
            & 0o7777;
        if mode != 0o700 {
            return Err(format!(
                "existing ROOKHOLD_JOBS_ROOT {} must already have mode 0700; refusing to chmod a potentially shared directory (found {mode:04o})",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn validate_existing_jobs_root_chain(path: &Path, strict: bool) -> Result<(), String> {
    #[cfg(not(target_os = "linux"))]
    let _ = strict;
    for ancestor in path.ancestors() {
        let metadata = match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "cannot inspect ROOKHOLD_JOBS_ROOT ancestor {}: {error}",
                    ancestor.display()
                ))
            }
        };
        if metadata.file_type().is_symlink() {
            #[cfg(target_os = "macos")]
            if is_trusted_macos_system_alias(ancestor) {
                continue;
            }
            return Err(format!(
                "ROOKHOLD_JOBS_ROOT must not traverse a symlink: {}",
                ancestor.display()
            ));
        }
        if !metadata.is_dir() {
            return Err(format!(
                "ROOKHOLD_JOBS_ROOT ancestor {} is not a directory",
                ancestor.display()
            ));
        }
        #[cfg(target_os = "linux")]
        if strict {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
                return Err(format!(
                    "ROOKHOLD_JOBS_ROOT strict mode requires root-owned, non-group/world-writable components; {} is insecure",
                    ancestor.display()
                ));
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(format!(
                    "ROOKHOLD_JOBS_ROOT must not traverse a junction or reparse point: {}",
                    ancestor.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn is_trusted_macos_system_alias(path: &Path) -> bool {
    let expected = match path.to_str() {
        Some("/var") => "/private/var",
        Some("/tmp") => "/private/tmp",
        Some("/etc") => "/private/etc",
        _ => return false,
    };
    path.canonicalize()
        .is_ok_and(|target| target == Path::new(expected))
}

fn default_jobs_root() -> String {
    let (primary, legacy) = if cfg!(target_os = "linux") {
        (
            std::path::PathBuf::from("/var/lib/rookhold/jobs"),
            std::path::PathBuf::from("/var/lib/coop/jobs"),
        )
    } else {
        (
            std::env::temp_dir().join("rookhold-jobs"),
            std::env::temp_dir().join("coop-jobs"),
        )
    };
    if legacy.exists() && !primary.exists() {
        legacy.to_string_lossy().into_owned()
    } else {
        primary.to_string_lossy().into_owned()
    }
}

fn default_db_path() -> String {
    let primary = Path::new("rookhold.db");
    let legacy = Path::new("coop.db");
    if legacy.exists() && !primary.exists() {
        legacy.to_string_lossy().into_owned()
    } else {
        primary.to_string_lossy().into_owned()
    }
}

fn default_sandbox_helper() -> Option<String> {
    let executable = std::env::current_exe().ok()?;
    let names = if cfg!(windows) {
        ["rookhold-sandbox-init.exe", "coop-sandbox-init.exe"]
    } else {
        ["rookhold-sandbox-init", "coop-sandbox-init"]
    };
    names.into_iter().find_map(|name| {
        let candidate = executable.parent()?.join(name);
        candidate
            .is_file()
            .then(|| candidate.to_string_lossy().into_owned())
    })
}

fn is_production_env(value: Option<String>) -> bool {
    matches!(
        value
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("prod" | "production" | "release")
    )
}

/// True when the process should be treated as a production deployment.
/// `ROOKHOLD_ENV` is authoritative; `COOP_ENV` remains a v0.6 compatibility
/// alias, and `NODE_ENV` keeps its documented compatibility behavior.
pub fn is_production() -> bool {
    is_production_env(
        std::env::var("ROOKHOLD_ENV")
            .ok()
            .or_else(|| std::env::var("COOP_ENV").ok()),
    ) || is_production_env(std::env::var("NODE_ENV").ok())
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_sources(&|k| std::env::var(k).ok(), is_production())
    }

    /// Build config from an explicit env-source + production flag (unit-testable core).
    pub fn from_sources(
        getenv: &dyn Fn(&str) -> Option<String>,
        production: bool,
    ) -> Result<Self, String> {
        validate_compatible_env(getenv)?;
        let source = getenv;
        let compatible_getenv = |key: &str| {
            let primary = source(key);
            if primary.as_ref().is_some_and(|value| !value.is_empty()) {
                return primary;
            }
            legacy_env_key(key)
                .and_then(|legacy| source(legacy.as_str()))
                .or(primary)
        };
        let getenv = &compatible_getenv;

        let credentials_path = getenv("ROOKHOLD_CREDENTIALS_FILE")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let pepper_path = getenv("ROOKHOLD_CREDENTIAL_PEPPER_FILE")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let credentials = match (credentials_path.as_deref(), pepper_path.as_deref()) {
            (Some(credentials), Some(pepper)) => crate::auth::CredentialStore::load(
                Path::new(credentials),
                Path::new(pepper),
                production,
            )?,
            (None, None) => crate::auth::CredentialStore::default(),
            _ => return Err(
                "ROOKHOLD_CREDENTIALS_FILE and ROOKHOLD_CREDENTIAL_PEPPER_FILE must be configured together"
                    .to_string(),
            ),
        };

        let oidc_issuer = getenv("ROOKHOLD_OIDC_ISSUER")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let oidc_audience = getenv("ROOKHOLD_OIDC_AUDIENCE")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let oidc_jwks = getenv("ROOKHOLD_OIDC_JWKS_URL")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let oidc_tenant_map = getenv("ROOKHOLD_OIDC_TENANT_MAP")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let optional_oidc_values = [
            getenv("ROOKHOLD_OIDC_TENANT_CLAIM"),
            getenv("ROOKHOLD_OIDC_ALGORITHMS"),
            getenv("ROOKHOLD_OIDC_JWKS_TTL_SECONDS"),
            getenv("ROOKHOLD_OIDC_MAX_TOKEN_AGE_SECONDS"),
        ];
        let oidc_requested = oidc_issuer.is_some()
            || oidc_audience.is_some()
            || oidc_jwks.is_some()
            || oidc_tenant_map.is_some()
            || optional_oidc_values
                .iter()
                .any(|value| value.as_ref().is_some_and(|value| !value.trim().is_empty()));
        let jwt = if oidc_requested {
            let issuer = oidc_issuer.as_deref().ok_or_else(|| {
                "ROOKHOLD_OIDC_ISSUER is required when OIDC authentication is configured"
                    .to_string()
            })?;
            let audience = oidc_audience.as_deref().ok_or_else(|| {
                "ROOKHOLD_OIDC_AUDIENCE is required when OIDC authentication is configured"
                    .to_string()
            })?;
            let jwks = oidc_jwks.as_deref().ok_or_else(|| {
                "ROOKHOLD_OIDC_JWKS_URL is required when OIDC authentication is configured"
                    .to_string()
            })?;
            let tenant_map = oidc_tenant_map.as_deref().ok_or_else(|| {
                "ROOKHOLD_OIDC_TENANT_MAP is required when OIDC authentication is configured"
                    .to_string()
            })?;
            Some(crate::auth::JwtConfig::parse(
                issuer,
                audience,
                jwks,
                &env_or(getenv, "ROOKHOLD_OIDC_TENANT_CLAIM", "tenant_id"),
                tenant_map,
                &env_or(getenv, "ROOKHOLD_OIDC_ALGORITHMS", "RS256,ES256,EdDSA"),
                parse_number(
                    getenv,
                    "ROOKHOLD_OIDC_JWKS_TTL_SECONDS",
                    "300",
                    60_u64,
                    3600_u64,
                )?,
                parse_number(
                    getenv,
                    "ROOKHOLD_OIDC_MAX_TOKEN_AGE_SECONDS",
                    "3600",
                    60_u64,
                    86_400_u64,
                )?,
            )?)
        } else {
            None
        };

        let mut api_keys = HashMap::new();
        let raw = getenv("ROOKHOLD_API_KEYS").filter(|v| !v.trim().is_empty());
        let raw = match raw {
            Some(raw) => Some(raw),
            None if !credentials.is_empty() || jwt.is_some() => None,
            None if production => {
                return Err(
                    "configure ROOKHOLD_CREDENTIALS_FILE with ROOKHOLD_CREDENTIAL_PEPPER_FILE or provide \
                     legacy ROOKHOLD_API_KEYS; refusing to start production without credentials"
                        .to_string(),
                );
            }
            None => {
                tracing::warn!(
                    "SECURITY: no ROOKHOLD_API_KEYS configured — falling back to the PUBLIC development \
                     default key '{DEV_DEFAULT_API_KEY}'. Anyone who can reach this server can run \
                     code on it. The legacy key 'coop-dev-key' is also accepted during v0.6 migration. \
                     Set ROOKHOLD_API_KEYS before exposing Rookhold beyond localhost."
                );
                Some(format!(
                    "{DEV_DEFAULT_API_KEY},{LEGACY_DEV_DEFAULT_API_KEY}"
                ))
            }
        };
        if let Some(raw) = raw {
            for entry in raw.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                let (tenant, key) =
                    match entry.split_once(':') {
                        Some((tenant, key)) => (tenant.trim(), key.trim()),
                        None if !production => ("local", entry),
                        None => return Err(
                            "each production ROOKHOLD_API_KEYS entry must use tenant:key syntax"
                                .to_string(),
                        ),
                    };
                if tenant.is_empty() {
                    return Err("ROOKHOLD_API_KEYS contains a blank tenant".to_string());
                }
                crate::auth::validate_identity("legacy ROOKHOLD_API_KEYS tenant", tenant)?;
                if key.is_empty() {
                    return Err(format!(
                        "ROOKHOLD_API_KEYS contains a blank key for tenant {tenant:?}"
                    ));
                }
                if production && legacy_api_key_is_weak(key) {
                    return Err(format!(
                        "production API key for tenant {tenant:?} is public or too short (minimum 16 characters)"
                    ));
                }
                if api_keys
                    .insert(key.to_string(), tenant.to_string())
                    .is_some()
                {
                    return Err("ROOKHOLD_API_KEYS contains a duplicate key".to_string());
                }
            }
        }

        if api_keys.is_empty() && credentials.is_empty() && jwt.is_none() {
            return Err(
                "credential configuration did not contain any usable credentials".to_string(),
            );
        }
        if production && !api_keys.is_empty() {
            tracing::warn!(
                "SECURITY: legacy ROOKHOLD_API_KEYS are enabled in production; migrate to the indexed \
                 peppered ROOKHOLD_CREDENTIALS_FILE format"
            );
        }

        let metrics_token = getenv("ROOKHOLD_METRICS_TOKEN")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if metrics_token.as_ref().is_some_and(|token| token.len() < 16) {
            return Err(
                "ROOKHOLD_METRICS_TOKEN must contain at least 16 characters when configured"
                    .to_string(),
            );
        }
        ensure_metrics_token_is_separate(metrics_token.as_deref(), &api_keys, &credentials)?;

        let attestation_key_file = getenv("ROOKHOLD_ATTESTATION_KEY_FILE")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let attestation_mode = match getenv("ROOKHOLD_ATTESTATION_MODE")
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .as_deref()
        {
            None if attestation_key_file.is_some() => AttestationMode::Sign,
            None if production => {
                return Err(
                    "production requires ROOKHOLD_ATTESTATION_KEY_FILE for signed terminal evidence; set ROOKHOLD_ATTESTATION_MODE=off only as an explicit policy decision to disable signing"
                        .to_string(),
                )
            }
            None => AttestationMode::Off,
            Some("sign" | "signed" | "on" | "enabled") => {
                if attestation_key_file.is_none() {
                    return Err(
                        "ROOKHOLD_ATTESTATION_MODE=sign requires ROOKHOLD_ATTESTATION_KEY_FILE"
                            .to_string(),
                    );
                }
                AttestationMode::Sign
            }
            Some("off" | "disabled" | "none") => {
                if attestation_key_file.is_some() {
                    return Err(
                        "ROOKHOLD_ATTESTATION_MODE=off must not also configure ROOKHOLD_ATTESTATION_KEY_FILE"
                            .to_string(),
                    );
                }
                AttestationMode::Off
            }
            Some(_) => {
                return Err(
                    "ROOKHOLD_ATTESTATION_MODE must be either sign or off".to_string(),
                )
            }
        };
        if production {
            if let Some(path) = attestation_key_file.as_deref() {
                if !Path::new(path).is_absolute() {
                    return Err(
                        "ROOKHOLD_ATTESTATION_KEY_FILE must be an absolute path in production"
                            .to_string(),
                    );
                }
            }
        }

        let sandbox = env_or(getenv, "ROOKHOLD_SANDBOX", "auto");
        let unsafe_allow_naive = env_true(getenv, "ROOKHOLD_UNSAFE_ALLOW_NAIVE");
        let unsafe_allow_public_dev = env_true(getenv, "ROOKHOLD_UNSAFE_ALLOW_PUBLIC_DEV");
        let seccomp = !matches!(
            env_or(getenv, "ROOKHOLD_SECCOMP", "auto")
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "off" | "none" | "disabled" | "false" | "0"
        );
        if production && !seccomp {
            return Err("ROOKHOLD_SECCOMP cannot be disabled in production".to_string());
        }

        let tenant_queue_capacity = parse_number(
            getenv,
            "ROOKHOLD_TENANT_QUEUE_CAPACITY",
            &DEFAULT_TENANT_QUEUE_CAPACITY.to_string(),
            1usize,
            crate::QUEUE_CAPACITY,
        )?;
        let max_job_mem_mb = parse_number(
            getenv,
            "ROOKHOLD_MAX_JOB_MEM_MB",
            &DEFAULT_MAX_JOB_MEM_MB.to_string(),
            16u32,
            coop_types::MEM_MAX_MB,
        )?;
        let memory_budget_mb = parse_number(
            getenv,
            "ROOKHOLD_MEMORY_BUDGET_MB",
            &DEFAULT_MEMORY_BUDGET_MB.to_string(),
            16u32,
            1_048_576u32,
        )?;
        if max_job_mem_mb > memory_budget_mb {
            return Err(format!(
                "ROOKHOLD_MAX_JOB_MEM_MB ({max_job_mem_mb}) must not exceed ROOKHOLD_MEMORY_BUDGET_MB ({memory_budget_mb})"
            ));
        }
        let storage_global_mb = parse_number(
            getenv,
            "ROOKHOLD_STORAGE_GLOBAL_MB",
            &DEFAULT_STORAGE_GLOBAL_MB.to_string(),
            128u64,
            1_048_576u64,
        )?;
        let storage_tenant_mb = parse_number(
            getenv,
            "ROOKHOLD_STORAGE_TENANT_MB",
            &DEFAULT_STORAGE_TENANT_MB.to_string(),
            64u64,
            1_048_576u64,
        )?;
        if storage_tenant_mb > storage_global_mb {
            return Err(format!(
                "ROOKHOLD_STORAGE_TENANT_MB ({storage_tenant_mb}) must not exceed ROOKHOLD_STORAGE_GLOBAL_MB ({storage_global_mb})"
            ));
        }
        let storage_free_reserve_mb = parse_number(
            getenv,
            "ROOKHOLD_STORAGE_FREE_RESERVE_MB",
            &DEFAULT_STORAGE_FREE_RESERVE_MB.to_string(),
            0u64,
            1_048_576u64,
        )?;

        let config = Self {
            addr: env_or(getenv, "ROOKHOLD_ADDR", "127.0.0.1:7300"),
            db_path: env_or(getenv, "ROOKHOLD_DB", &default_db_path()),
            api_keys,
            metrics_token,
            attestation_mode,
            attestation_key_file,
            credentials,
            jwt,
            workers: parse_number(getenv, "ROOKHOLD_WORKERS", "4", 1usize, 256usize)?,
            tenant_concurrency: parse_number(
                getenv,
                "ROOKHOLD_TENANT_CONCURRENCY",
                "2",
                1usize,
                256usize,
            )?,
            tenant_queue_capacity,
            rate_per_min: parse_number(getenv, "ROOKHOLD_RATE_PER_MIN", "120", 1u32, 1_000_000u32)?,
            max_job_mem_mb,
            memory_budget_mb,
            storage_global_mb,
            storage_tenant_mb,
            storage_free_reserve_mb,
            sandbox,
            jobs_root: env_or(getenv, "ROOKHOLD_JOBS_ROOT", &default_jobs_root()),
            rootfs: getenv("ROOKHOLD_ROOTFS")
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            sandbox_helper: getenv("ROOKHOLD_SANDBOX_HELPER")
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .or_else(default_sandbox_helper),
            gvisor_runsc: getenv("ROOKHOLD_GVISOR_RUNSC")
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            gvisor_rootfs_sha256: getenv("ROOKHOLD_GVISOR_ROOTFS_SHA256")
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty()),
            gvisor_platform: env_or(getenv, "ROOKHOLD_GVISOR_PLATFORM", "systrap"),
            gvisor_uid: parse_number(
                getenv,
                "ROOKHOLD_GVISOR_UID",
                "65534",
                1u32,
                4_294_967_294u32,
            )?,
            gvisor_gid: parse_number(
                getenv,
                "ROOKHOLD_GVISOR_GID",
                "65534",
                1u32,
                4_294_967_294u32,
            )?,
            production,
            unsafe_allow_naive,
            unsafe_allow_public_dev,
            python_bin: getenv("ROOKHOLD_PYTHON"),
            node_bin: getenv("ROOKHOLD_NODE"),
            bash_bin: getenv("ROOKHOLD_BASH"),
            retention_hours: parse_number(
                getenv,
                "ROOKHOLD_RETENTION_HOURS",
                "168",
                0u64,
                87_600u64,
            )?,
            sweep_interval_secs: parse_number(
                getenv,
                "ROOKHOLD_SWEEP_INTERVAL_SECS",
                "3600",
                60u64,
                86_400u64,
            )?,
            seccomp,
        };
        config.validate_declared_listener_security()?;
        Ok(config)
    }

    pub fn validate_declared_listener_security(&self) -> Result<(), String> {
        if listener_is_loopback(&self.addr) || self.unsafe_allow_public_dev {
            return Ok(());
        }
        if self.api_keys.keys().any(|key| legacy_api_key_is_weak(key)) {
            return Err(
                "a non-loopback ROOKHOLD_ADDR cannot use the public development API key or a legacy API key shorter than 16 characters; configure a strong ROOKHOLD_API_KEYS value or set ROOKHOLD_UNSAFE_ALLOW_PUBLIC_DEV=true to acknowledge the unsafe development exposure"
                    .to_string(),
            );
        }
        if matches!(
            self.sandbox.trim().to_ascii_lowercase().as_str(),
            "off" | "none" | "naive"
        ) {
            return Err(
                "a non-loopback ROOKHOLD_ADDR cannot use the unisolated subprocess backend unless ROOKHOLD_UNSAFE_ALLOW_PUBLIC_DEV=true is set"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub(crate) fn validate_metrics_token_separation(&self) -> Result<(), String> {
        ensure_metrics_token_is_separate(
            self.metrics_token.as_deref(),
            &self.api_keys,
            &self.credentials,
        )
    }

    pub fn validate_resolved_listener_security(
        &self,
        mode: coop_exec::SandboxMode,
    ) -> Result<(), String> {
        self.validate_declared_listener_security()?;
        if !listener_is_loopback(&self.addr)
            && mode == coop_exec::SandboxMode::Off
            && !self.unsafe_allow_public_dev
        {
            return Err(
                "ROOKHOLD_SANDBOX=auto resolved to the unisolated subprocess backend on a non-loopback listener; configure namespace isolation or set ROOKHOLD_UNSAFE_ALLOW_PUBLIC_DEV=true to acknowledge the unsafe development exposure"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn validate_bound_listener_security(
        &self,
        bound: std::net::SocketAddr,
        mode: coop_exec::SandboxMode,
    ) -> Result<(), String> {
        if bound.ip().is_loopback() || self.unsafe_allow_public_dev {
            return Ok(());
        }
        if self.api_keys.keys().any(|key| legacy_api_key_is_weak(key))
            || mode == coop_exec::SandboxMode::Off
        {
            return Err(format!(
                "listener resolved to non-loopback address {bound} with an unsafe development credential or executor; configure production keys and namespace isolation, or explicitly set ROOKHOLD_UNSAFE_ALLOW_PUBLIC_DEV=true"
            ));
        }
        Ok(())
    }

    pub fn interpreter_override(&self, language: &str) -> Option<String> {
        match language {
            "python" => self.python_bin.clone(),
            "node" => self.node_bin.clone(),
            _ => self.bash_bin.clone(),
        }
    }

    pub fn clamp_limits(&self, limits: coop_types::Limits) -> coop_types::Limits {
        let mut limits = limits.clamped();
        limits.mem_mb = self.clamp_mem_mb(limits.mem_mb);
        limits
    }

    pub fn clamp_mem_mb(&self, mem_mb: u32) -> u32 {
        mem_mb
            .clamp(16, coop_types::MEM_MAX_MB)
            .min(self.max_job_mem_mb)
    }

    pub fn storage_limits(&self) -> coop_store::StorageLimits {
        let mib = 1024_u64 * 1024;
        coop_store::StorageLimits::new(
            self.storage_global_mb.saturating_mul(mib),
            self.storage_tenant_mb.saturating_mul(mib),
            self.storage_free_reserve_mb.saturating_mul(mib),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};

    fn source<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |key: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    fn indexed_credential_fixture(
        token: &str,
        expires_at_ms: Option<i64>,
        revoked_at_ms: Option<i64>,
    ) -> (std::path::PathBuf, String, String) {
        let root = std::env::temp_dir().join(format!(
            "coop-config-indexed-collision-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let pepper = [0x6d_u8; 32];
        let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(&pepper).unwrap();
        hmac.update(token.as_bytes());
        let digest = hmac.finalize().into_bytes();
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let credentials = root.join("credentials.json");
        let pepper_file = root.join("pepper");
        std::fs::write(&pepper_file, hex(&pepper)).unwrap();
        std::fs::write(
            &credentials,
            serde_json::json!({
                "version": 1,
                "credentials": [{
                    "key_id": "metrics-alias",
                    "tenant_id": "tenant-a",
                    "principal_id": "principal-a",
                    "digest_hmac_sha256": hex(&digest),
                    "scopes": ["metrics:read"],
                    "created_at_ms": 1,
                    "expires_at_ms": expires_at_ms,
                    "revoked_at_ms": revoked_at_ms
                }]
            })
            .to_string(),
        )
        .unwrap();
        (
            root,
            credentials.to_string_lossy().into_owned(),
            pepper_file.to_string_lossy().into_owned(),
        )
    }

    #[test]
    fn prod_mode_without_api_keys_is_rejected() {
        let err = Config::from_sources(&source(&[]), true).unwrap_err();
        assert!(err.contains("ROOKHOLD_API_KEYS"), "{err}");
    }

    #[test]
    fn empty_api_keys_value_counts_as_unset_in_prod() {
        assert!(Config::from_sources(&source(&[("ROOKHOLD_API_KEYS", "  ")]), true).is_err());
    }

    #[test]
    fn dev_mode_without_api_keys_falls_back_to_dev_default() {
        let cfg = Config::from_sources(&source(&[]), false).expect("dev default applies");
        assert_eq!(
            cfg.api_keys.get("rookhold-dev-key").map(String::as_str),
            Some("local")
        );
        assert_eq!(
            cfg.api_keys.get("coop-dev-key").map(String::as_str),
            Some("local")
        );
        assert_eq!(cfg.api_keys.len(), 2);
    }

    #[test]
    fn legacy_coop_environment_names_remain_compatible() {
        let cfg = Config::from_sources(
            &source(&[
                ("COOP_API_KEYS", "legacy:a-long-legacy-key"),
                ("COOP_ATTESTATION_MODE", "off"),
                ("COOP_WORKERS", "7"),
            ]),
            true,
        )
        .unwrap();
        assert_eq!(
            cfg.api_keys.get("a-long-legacy-key").map(String::as_str),
            Some("legacy")
        );
        assert_eq!(cfg.workers, 7);
    }

    #[test]
    fn conflicting_rookhold_and_coop_environment_names_fail_closed() {
        let error = Config::from_sources(
            &source(&[
                ("ROOKHOLD_API_KEYS", "new:a-long-primary-key"),
                ("COOP_API_KEYS", "old:a-long-legacy-key"),
            ]),
            false,
        )
        .unwrap_err();
        assert!(error.contains("ROOKHOLD_API_KEYS"), "{error}");
        assert!(error.contains("COOP_API_KEYS"), "{error}");
        assert!(!error.contains("a-long"), "{error}");
    }

    #[test]
    fn prod_mode_with_explicit_keys_does_not_get_dev_default() {
        let cfg = Config::from_sources(
            &source(&[
                ("ROOKHOLD_API_KEYS", "acme:correct-horse-battery-staple"),
                ("ROOKHOLD_ATTESTATION_MODE", "off"),
            ]),
            true,
        )
        .unwrap();
        assert_eq!(
            cfg.api_keys
                .get("correct-horse-battery-staple")
                .map(String::as_str),
            Some("acme")
        );
        assert!(!cfg.api_keys.contains_key("coop-dev-key"));
    }

    #[test]
    fn production_attestation_policy_is_fail_closed_and_off_is_explicit() {
        let base = [("ROOKHOLD_API_KEYS", "acme:correct-horse-battery-staple")];
        let error = Config::from_sources(&source(&base), true).unwrap_err();
        assert!(error.contains("ROOKHOLD_ATTESTATION_KEY_FILE"), "{error}");
        assert!(error.contains("ROOKHOLD_ATTESTATION_MODE=off"), "{error}");

        let off = Config::from_sources(
            &source(&[
                ("ROOKHOLD_API_KEYS", "acme:correct-horse-battery-staple"),
                ("ROOKHOLD_ATTESTATION_MODE", "off"),
            ]),
            true,
        )
        .unwrap();
        assert_eq!(off.attestation_mode, AttestationMode::Off);
        assert!(off.attestation_key_file.is_none());

        let missing_key = Config::from_sources(
            &source(&[
                ("ROOKHOLD_API_KEYS", "acme:correct-horse-battery-staple"),
                ("ROOKHOLD_ATTESTATION_MODE", "sign"),
            ]),
            true,
        )
        .unwrap_err();
        assert!(missing_key.contains("requires ROOKHOLD_ATTESTATION_KEY_FILE"));

        let ambiguous = Config::from_sources(
            &source(&[
                ("ROOKHOLD_API_KEYS", "acme:correct-horse-battery-staple"),
                ("ROOKHOLD_ATTESTATION_MODE", "off"),
                ("ROOKHOLD_ATTESTATION_KEY_FILE", "/var/lib/coop/signing.pem"),
            ]),
            true,
        )
        .unwrap_err();
        assert!(ambiguous.contains("must not also configure"), "{ambiguous}");
        assert!(Config::from_sources(
            &source(&[
                ("ROOKHOLD_API_KEYS", "acme:correct-horse-battery-staple"),
                ("ROOKHOLD_ATTESTATION_MODE", "maybe"),
            ]),
            true,
        )
        .is_err());
    }

    #[test]
    fn credentials_file_can_be_the_only_auth_source_and_requires_a_paired_pepper() {
        let root =
            std::env::temp_dir().join(format!("coop-config-credentials-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let credentials = root.join("credentials.json");
        let pepper = root.join("pepper");
        std::fs::write(&pepper, "11".repeat(32)).unwrap();
        std::fs::write(
            &credentials,
            serde_json::json!({
                "version":1,
                "credentials":[{
                    "key_id":"agent-a",
                    "tenant_id":"tenant-a",
                    "principal_id":"principal-a",
                    "digest_hmac_sha256":"22".repeat(32),
                    "scopes":["jobs:read"],
                    "created_at_ms":1
                }]
            })
            .to_string(),
        )
        .unwrap();
        let credential_path = credentials.to_string_lossy().into_owned();
        let pepper_path = pepper.to_string_lossy().into_owned();
        let cfg = Config::from_sources(
            &source(&[
                ("ROOKHOLD_CREDENTIALS_FILE", credential_path.as_str()),
                ("ROOKHOLD_CREDENTIAL_PEPPER_FILE", pepper_path.as_str()),
            ]),
            false,
        )
        .unwrap();
        assert!(cfg.api_keys.is_empty());
        assert_eq!(cfg.credentials.len(), 1);
        assert!(Config::from_sources(
            &source(&[("ROOKHOLD_CREDENTIALS_FILE", credential_path.as_str())]),
            false
        )
        .is_err());
    }

    #[test]
    fn oidc_can_be_the_only_auth_source_but_partial_or_insecure_config_fails_closed() {
        let complete = [
            ("ROOKHOLD_OIDC_ISSUER", "https://issuer.example"),
            ("ROOKHOLD_OIDC_AUDIENCE", "https://coop.example"),
            ("ROOKHOLD_OIDC_JWKS_URL", "https://issuer.example/jwks"),
            ("ROOKHOLD_OIDC_TENANT_MAP", "external=internal"),
        ];
        let cfg = Config::from_sources(&source(&complete), false).unwrap();
        assert!(cfg.api_keys.is_empty());
        assert!(cfg.jwt.is_some());

        assert!(Config::from_sources(
            &source(&[("ROOKHOLD_OIDC_ISSUER", "https://issuer.example")]),
            false
        )
        .is_err());
        let mut insecure = complete;
        insecure[2].1 = "http://issuer.example/jwks";
        assert!(Config::from_sources(&source(&insecure), false).is_err());
    }

    #[test]
    fn debug_output_never_contains_plaintext_keys() {
        let cfg = Config::from_sources(
            &source(&[
                ("ROOKHOLD_API_KEYS", "acme:s3cr3t-value-that-is-long"),
                ("ROOKHOLD_METRICS_TOKEN", "metrics-secret-value"),
                ("ROOKHOLD_ATTESTATION_MODE", "off"),
            ]),
            true,
        )
        .unwrap();
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains("s3cr3t-value-that-is-long"),
            "leaked: {rendered}"
        );
        assert!(
            !rendered.contains("metrics-secret-value"),
            "leaked: {rendered}"
        );
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn metrics_token_is_optional_but_must_be_strong_when_configured() {
        let cfg = Config::from_sources(&source(&[]), false).unwrap();
        assert!(cfg.metrics_token.is_none());

        let error =
            Config::from_sources(&source(&[("ROOKHOLD_METRICS_TOKEN", "too-short")]), false)
                .unwrap_err();
        assert!(error.contains("ROOKHOLD_METRICS_TOKEN"), "{error}");

        let cfg = Config::from_sources(
            &source(&[("ROOKHOLD_METRICS_TOKEN", "separate-operator-secret")]),
            false,
        )
        .unwrap();
        assert_eq!(
            cfg.metrics_token.as_deref(),
            Some("separate-operator-secret")
        );

        let error = Config::from_sources(
            &source(&[
                ("ROOKHOLD_API_KEYS", "tenant:shared-secret-value"),
                ("ROOKHOLD_METRICS_TOKEN", "shared-secret-value"),
            ]),
            false,
        )
        .unwrap_err();
        assert!(error.contains("different"), "{error}");
    }

    #[test]
    fn metrics_token_cannot_alias_an_active_indexed_credential() {
        let token = format!("coop_metrics-alias_{}", "a".repeat(43));

        for (expires_at_ms, revoked_at_ms) in [(Some(i64::MAX), None), (None, Some(i64::MAX))] {
            let (root, credentials, pepper) =
                indexed_credential_fixture(&token, expires_at_ms, revoked_at_ms);
            let error = Config::from_sources(
                &source(&[
                    ("ROOKHOLD_CREDENTIALS_FILE", credentials.as_str()),
                    ("ROOKHOLD_CREDENTIAL_PEPPER_FILE", pepper.as_str()),
                    ("ROOKHOLD_METRICS_TOKEN", token.as_str()),
                ]),
                false,
            )
            .expect_err("an active tenant credential cannot double as the metrics token");
            assert!(error.contains("active tenant API credential"), "{error}");
            std::fs::remove_dir_all(root).unwrap();
        }

        let (root, credentials, pepper) = indexed_credential_fixture(&token, Some(i64::MAX), None);
        let unrelated_same_key_id = format!("coop_metrics-alias_{}", "b".repeat(43));
        Config::from_sources(
            &source(&[
                ("ROOKHOLD_CREDENTIALS_FILE", credentials.as_str()),
                ("ROOKHOLD_CREDENTIAL_PEPPER_FILE", pepper.as_str()),
                ("ROOKHOLD_METRICS_TOKEN", unrelated_same_key_id.as_str()),
            ]),
            false,
        )
        .expect("a key-id match without an HMAC match is not a credential collision");
        std::fs::remove_dir_all(root).unwrap();

        for (expires_at_ms, revoked_at_ms) in [(Some(2), None), (None, Some(2))] {
            let (root, credentials, pepper) =
                indexed_credential_fixture(&token, expires_at_ms, revoked_at_ms);
            Config::from_sources(
                &source(&[
                    ("ROOKHOLD_CREDENTIALS_FILE", credentials.as_str()),
                    ("ROOKHOLD_CREDENTIAL_PEPPER_FILE", pepper.as_str()),
                    ("ROOKHOLD_METRICS_TOKEN", token.as_str()),
                ]),
                false,
            )
            .expect("an expired or revoked credential is not an active tenant alias");
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn build_app_revalidates_metrics_token_separation_after_config_mutation() {
        let token = format!("coop_metrics-alias_{}", "a".repeat(43));
        let (root, credentials, pepper) = indexed_credential_fixture(&token, Some(i64::MAX), None);
        let jobs = root.join("jobs").to_string_lossy().into_owned();
        let mut cfg = Config::from_sources(
            &source(&[
                ("ROOKHOLD_CREDENTIALS_FILE", credentials.as_str()),
                ("ROOKHOLD_CREDENTIAL_PEPPER_FILE", pepper.as_str()),
                ("ROOKHOLD_SANDBOX", "off"),
                ("ROOKHOLD_JOBS_ROOT", jobs.as_str()),
                ("ROOKHOLD_STORAGE_FREE_RESERVE_MB", "0"),
            ]),
            false,
        )
        .unwrap();
        cfg.metrics_token = Some(token);
        let db = root.join("coop.db");
        let store = std::sync::Arc::new(
            coop_store::Store::open_with_limits(&db, cfg.storage_limits())
                .await
                .unwrap(),
        );
        let error = match crate::build_app(cfg, store, "127.0.0.1:0".parse().unwrap()).await {
            Err(error) => error,
            Ok(_) => panic!("public build_app bypassed metrics-token separation"),
        };
        assert!(error.contains("active tenant API credential"), "{error}");
    }

    #[test]
    fn blank_tenants_keys_and_public_production_keys_are_rejected() {
        for raw in [
            ":a-long-enough-secret",
            "acme:",
            "acme:coop-dev-key",
            "acme:too-short",
        ] {
            let err =
                Config::from_sources(&source(&[("ROOKHOLD_API_KEYS", raw)]), true).expect_err(raw);
            assert!(
                err.contains("blank") || err.contains("short") || err.contains("public"),
                "{raw}: {err}"
            );
        }
    }

    #[test]
    fn legacy_tenants_share_the_indexed_identity_contract() {
        let too_long = "t".repeat(129);
        for tenant in [
            "tenant with space",
            "tenant-é",
            "tenant\ncontrol",
            "tenant\"quote",
            "tenant\\slash",
            too_long.as_str(),
        ] {
            let raw = format!("{tenant}:correct-horse-battery-staple");
            let error = Config::from_sources(
                &source(&[
                    ("ROOKHOLD_API_KEYS", raw.as_str()),
                    ("ROOKHOLD_ATTESTATION_MODE", "off"),
                ]),
                true,
            )
            .expect_err(tenant);
            assert!(
                error.contains("1-128 safe printable ASCII"),
                "{tenant:?}: {error}"
            );
        }

        let maximum = "t".repeat(128);
        let raw = format!("{maximum}:correct-horse-battery-staple");
        let config = Config::from_sources(
            &source(&[
                ("ROOKHOLD_API_KEYS", raw.as_str()),
                ("ROOKHOLD_ATTESTATION_MODE", "off"),
            ]),
            true,
        )
        .unwrap();
        assert_eq!(
            config
                .api_keys
                .get("correct-horse-battery-staple")
                .map(String::as_str),
            Some(maximum.as_str())
        );
    }

    #[test]
    fn invalid_numeric_configuration_is_not_silently_defaulted() {
        for (key, value) in [
            ("ROOKHOLD_WORKERS", "many"),
            ("ROOKHOLD_TENANT_CONCURRENCY", "0"),
            ("ROOKHOLD_RATE_PER_MIN", "-1"),
            ("ROOKHOLD_SWEEP_INTERVAL_SECS", "59"),
        ] {
            let err = Config::from_sources(&source(&[(key, value)]), false).expect_err(key);
            assert!(err.contains(key), "{key}: {err}");
        }
    }

    #[test]
    fn production_cannot_disable_seccomp() {
        let err = Config::from_sources(
            &source(&[
                ("ROOKHOLD_API_KEYS", "acme:correct-horse-battery-staple"),
                ("ROOKHOLD_SECCOMP", "off"),
                ("ROOKHOLD_ATTESTATION_MODE", "off"),
            ]),
            true,
        )
        .unwrap_err();
        assert!(err.contains("ROOKHOLD_SECCOMP"), "{err}");
    }

    #[test]
    fn jobs_root_must_be_absolute_and_dedicated() {
        assert!(validate_jobs_root(Path::new("relative/jobs")).is_err());
        let root = if cfg!(windows) {
            Path::new("C:\\")
        } else {
            Path::new("/")
        };
        assert!(validate_jobs_root(root).is_err());
        let dedicated =
            std::env::temp_dir().join(format!("coop-config-test-{}/jobs", uuid::Uuid::now_v7()));
        assert!(
            validate_jobs_root(&dedicated).is_ok(),
            "{}",
            dedicated.display()
        );
    }

    #[test]
    fn shared_system_leaf_is_rejected_before_any_permission_change() {
        let configured = if cfg!(windows) {
            Path::new("C:\\Program Files")
        } else {
            Path::new("/usr/local")
        };
        let shared = if cfg!(unix) {
            Path::new("/usr/bin")
        } else {
            configured
        };
        #[cfg(unix)]
        let before = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(shared)
                .expect("standard shared system directory exists")
                .permissions()
                .mode()
                & 0o7777
        };

        let error =
            validate_jobs_root(configured).expect_err("shared system leaf is never dedicated");
        assert!(
            error.contains("shared system directory") || error.contains("too broad"),
            "{error}"
        );
        assert!(validate_jobs_root(shared).is_err());
        if cfg!(unix) {
            for broad in [
                "/opt",
                "/private/var/lib",
                "/usr/local",
                "/var/lib",
                "/workspace",
            ] {
                assert!(
                    validate_jobs_root(Path::new(broad)).is_err(),
                    "broad shared path was accepted: {broad}"
                );
            }
            let dotted = Path::new("/usr/./bin");
            let dotted_error = validate_jobs_root(dotted)
                .expect_err("dot components must not bypass the shared-root policy");
            assert!(
                dotted_error.contains("shared system directory"),
                "{dotted_error}"
            );
            let repeated = validate_jobs_root(Path::new("/usr//bin"))
                .expect_err("repeated separators must not bypass the shared-root policy");
            assert!(repeated.contains("shared system directory"), "{repeated}");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let after = std::fs::metadata(shared)
                .expect("validation did not alter the directory")
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(after, before, "validation must be strictly non-mutating");
        }
    }

    #[cfg(unix)]
    #[test]
    fn existing_non_private_leaf_is_rejected_without_chmod() {
        use std::os::unix::fs::PermissionsExt;
        let base =
            std::env::temp_dir().join(format!("coop-existing-root-{}", uuid::Uuid::now_v7()));
        let root = base.join("jobs");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();

        let error = prepare_jobs_root(&root, false)
            .expect_err("startup must not chmod an arbitrary existing directory");
        assert!(error.contains("must already have mode 0700"), "{error}");
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn development_jobs_root_under_os_temp_is_prepared_owner_only() {
        let root =
            std::env::temp_dir().join(format!("coop-config-prepare-{}/jobs", uuid::Uuid::now_v7()));
        prepare_jobs_root(&root, false).expect("prepare development jobs root");
        assert!(root.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_jobs_root_rejects_shared_writable_ancestor() {
        let root =
            std::env::temp_dir().join(format!("coop-config-strict-{}/jobs", uuid::Uuid::now_v7()));
        let error = prepare_jobs_root(&root, true).unwrap_err();
        assert!(
            error.contains("root-owned") || error.contains("writable"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn jobs_root_rejects_dangling_symlink_component() {
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("coop-config-link-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&base).unwrap();
        let link = base.join("redirect");
        symlink(base.join("missing-target"), &link).unwrap();
        let error = validate_jobs_root(&link.join("jobs")).unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_default_temp_jobs_root_accepts_trusted_system_aliases() {
        let root = std::env::temp_dir().join("coop-jobs");
        validate_jobs_root(&root).expect("macOS /var or /tmp system alias is trusted");
    }

    #[test]
    fn production_detection_matches_common_values() {
        for v in ["prod", "PRODUCTION", "production", "release", " Prod "] {
            assert!(is_production_env(Some(v.to_string())), "{v}");
        }
        for v in ["dev", "development", "", "staging"] {
            assert!(!is_production_env(Some(v.to_string())), "{v}");
        }
        assert!(!is_production_env(None));
    }

    #[test]
    fn non_loopback_development_listener_fails_closed_without_acknowledgement() {
        let error = Config::from_sources(&source(&[("ROOKHOLD_ADDR", "0.0.0.0:7300")]), false)
            .expect_err("public fallback key must not bind publicly");
        assert!(error.contains("public development API key"), "{error}");

        let error = Config::from_sources(
            &source(&[
                ("ROOKHOLD_ADDR", "0.0.0.0:7300"),
                ("ROOKHOLD_API_KEYS", "local:coop-dev-key"),
                ("ROOKHOLD_SANDBOX", "namespaces"),
            ]),
            false,
        )
        .expect_err("explicit public key must be detected semantically");
        assert!(error.contains("public development API key"), "{error}");

        let error = Config::from_sources(
            &source(&[
                ("ROOKHOLD_ADDR", "[::]:7300"),
                ("ROOKHOLD_API_KEYS", "tenant:a-long-development-key"),
                ("ROOKHOLD_SANDBOX", "off"),
            ]),
            false,
        )
        .expect_err("public subprocess backend must not start");
        assert!(error.contains("unisolated subprocess"), "{error}");

        Config::from_sources(
            &source(&[
                ("ROOKHOLD_ADDR", "0.0.0.0:7300"),
                ("ROOKHOLD_UNSAFE_ALLOW_PUBLIC_DEV", "true"),
            ]),
            false,
        )
        .expect("conspicuous acknowledgement is explicit");
    }

    #[test]
    fn public_isolated_development_listener_requires_strong_legacy_keys() {
        for weak in ["123456789012345", PUBLIC_DEV_API_KEY] {
            let error = Config::from_sources(
                &source(&[
                    ("ROOKHOLD_ADDR", "0.0.0.0:7300"),
                    ("ROOKHOLD_API_KEYS", weak),
                    ("ROOKHOLD_SANDBOX", "namespaces"),
                ]),
                false,
            )
            .expect_err("a public isolated listener must reject weak legacy credentials");
            assert!(
                error.contains("shorter than 16") || error.contains("public development API key"),
                "{weak}: {error}"
            );
        }

        Config::from_sources(
            &source(&[
                ("ROOKHOLD_ADDR", "0.0.0.0:7300"),
                ("ROOKHOLD_API_KEYS", "1234567890123456"),
                ("ROOKHOLD_SANDBOX", "namespaces"),
            ]),
            false,
        )
        .expect("a 16-byte public development key meets the existing strength floor");
        Config::from_sources(
            &source(&[
                ("ROOKHOLD_API_KEYS", "short-loopback"),
                ("ROOKHOLD_SANDBOX", "namespaces"),
            ]),
            false,
        )
        .expect("weak development credentials remain available on literal loopback");
        Config::from_sources(
            &source(&[
                ("ROOKHOLD_ADDR", "0.0.0.0:7300"),
                ("ROOKHOLD_API_KEYS", "short-public"),
                ("ROOKHOLD_SANDBOX", "namespaces"),
                ("ROOKHOLD_UNSAFE_ALLOW_PUBLIC_DEV", "true"),
            ]),
            false,
        )
        .expect("the conspicuous public-development override remains available");

        let production_error = Config::from_sources(
            &source(&[
                ("ROOKHOLD_ADDR", "0.0.0.0:7300"),
                ("ROOKHOLD_API_KEYS", "tenant:short"),
                ("ROOKHOLD_SANDBOX", "namespaces"),
                ("ROOKHOLD_UNSAFE_ALLOW_PUBLIC_DEV", "true"),
            ]),
            true,
        )
        .expect_err("the development override must not weaken production key policy");
        assert!(production_error.contains("too short"), "{production_error}");

        let weak_loopback = Config::from_sources(
            &source(&[
                ("ROOKHOLD_API_KEYS", "short-loopback"),
                ("ROOKHOLD_SANDBOX", "namespaces"),
            ]),
            false,
        )
        .unwrap();
        let public: std::net::SocketAddr = "203.0.113.10:7300".parse().unwrap();
        let error = weak_loopback
            .validate_bound_listener_security(public, coop_exec::SandboxMode::Namespaces)
            .expect_err("actual non-loopback binding must revalidate an embedder's config");
        assert!(error.contains("unsafe development credential"), "{error}");

        let hostname_error = Config::from_sources(
            &source(&[
                ("ROOKHOLD_ADDR", "localhost:7300"),
                ("ROOKHOLD_API_KEYS", "short-hostname"),
                ("ROOKHOLD_SANDBOX", "namespaces"),
            ]),
            false,
        )
        .expect_err("unresolved hostnames retain the existing fail-closed policy");
        assert!(
            hostname_error.contains("shorter than 16"),
            "{hostname_error}"
        );
    }

    #[test]
    fn configured_resource_ceilings_are_coherent_and_clamp_memory() {
        let cfg = Config::from_sources(
            &source(&[
                ("ROOKHOLD_MAX_JOB_MEM_MB", "512"),
                ("ROOKHOLD_MEMORY_BUDGET_MB", "1024"),
                ("ROOKHOLD_STORAGE_TENANT_MB", "128"),
                ("ROOKHOLD_STORAGE_GLOBAL_MB", "256"),
            ]),
            false,
        )
        .unwrap();
        let limits = coop_types::Limits {
            mem_mb: 4096,
            ..coop_types::Limits::default()
        };
        assert_eq!(cfg.clamp_limits(limits).mem_mb, 512);

        let error = Config::from_sources(
            &source(&[
                ("ROOKHOLD_MAX_JOB_MEM_MB", "2048"),
                ("ROOKHOLD_MEMORY_BUDGET_MB", "1024"),
            ]),
            false,
        )
        .expect_err("one job cannot exceed aggregate memory");
        assert!(error.contains("must not exceed"), "{error}");
    }
}
