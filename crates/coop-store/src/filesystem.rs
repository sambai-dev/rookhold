//! Filesystem reserve checks, symlink traversal guards, and database/sidecar
//! permission hardening (`0600` files, `0700` dedicated parent directories).

use crate::models::{StoreResult, FREE_SPACE_MARKER};
use sqlx::Row;
use std::path::{Path, PathBuf};

pub(crate) fn ensure_filesystem_reserve(
    path: &Path,
    reserve: u64,
    additional: u64,
) -> StoreResult<()> {
    if reserve == 0 {
        return Ok(());
    }
    let available = filesystem_available_bytes(path)?;
    if available < reserve.saturating_add(additional) {
        return Err(sqlx::Error::Protocol(FREE_SPACE_MARKER.to_string()));
    }
    Ok(())
}

pub(crate) async fn ensure_filesystem_reserve_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    path: &Path,
    reserve: u64,
    additional: u64,
) -> StoreResult<()> {
    if reserve == 0 {
        return Ok(());
    }
    let outstanding: i64 = sqlx::query(
        "SELECT COALESCE(SUM(reserved_bytes), 0) AS reserved_bytes
         FROM job_storage_usage",
    )
    .fetch_one(&mut **tx)
    .await?
    .try_get("reserved_bytes")?;
    let outstanding = u64::try_from(outstanding).map_err(|_| {
        sqlx::Error::Protocol("global logical storage reservation became negative".to_string())
    })?;
    ensure_filesystem_reserve(path, reserve, outstanding.saturating_add(additional))
}

pub(crate) fn filesystem_probe_path(path: &Path) -> StoreResult<PathBuf> {
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => Ok(parent.to_path_buf()),
        None => std::env::current_dir().map_err(Into::into),
    }
}

#[cfg(unix)]
pub(crate) fn filesystem_available_bytes(path: &Path) -> StoreResult<u64> {
    fn saturating_product<Left, Right>(left: Left, right: Right) -> u64
    where
        Left: Into<u64>,
        Right: Into<u64>,
    {
        left.into().saturating_mul(right.into())
    }

    use std::os::unix::ffi::OsStrExt;
    let probe = filesystem_probe_path(path)?;
    let encoded = std::ffi::CString::new(probe.as_os_str().as_bytes())
        .map_err(|error| sqlx::Error::InvalidArgument(error.to_string()))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    if unsafe { libc::statvfs(encoded.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stats = unsafe { stats.assume_init() };
    Ok(saturating_product(stats.f_bavail, stats.f_frsize))
}

#[cfg(windows)]
pub(crate) fn filesystem_available_bytes(path: &Path) -> StoreResult<u64> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(
            directory: *const u16,
            available: *mut u64,
            total: *mut u64,
            free: *mut u64,
        ) -> i32;
    }
    let probe = filesystem_probe_path(path)?;
    let mut encoded = probe.as_os_str().encode_wide().collect::<Vec<_>>();
    encoded.push(0);
    let mut available = 0_u64;
    if unsafe {
        GetDiskFreeSpaceExW(
            encoded.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(available)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn filesystem_available_bytes(_path: &Path) -> StoreResult<u64> {
    Ok(u64::MAX)
}

#[cfg(unix)]
pub(crate) fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

pub(crate) fn prepare_storage_path(path: &Path) -> StoreResult<()> {
    if path.as_os_str().is_empty() {
        return Err(sqlx::Error::InvalidArgument(
            "database path must not be empty".to_string(),
        ));
    }
    reject_symlink_components(path)?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.file_type().is_file() {
            return Err(sqlx::Error::InvalidArgument(
                "database path must be a regular file".to_string(),
            ));
        }
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
        reject_symlink_components(parent)?;
        harden_storage_directory(parent)?;
    }

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
    }
    // Tighten pre-existing database and sidecar files before SQLite reads or
    // migrates any tenant data, not only after opening the pool.
    harden_storage_files(path)?;
    Ok(())
}

pub(crate) fn reject_symlink_components(path: &Path) -> StoreResult<()> {
    for component in path.ancestors() {
        match std::fs::symlink_metadata(component) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                #[cfg(target_os = "macos")]
                if is_trusted_macos_system_alias(component) {
                    continue;
                }
                return Err(sqlx::Error::InvalidArgument(format!(
                    "database path contains a symbolic link: {}",
                    component.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn is_trusted_macos_system_alias(path: &Path) -> bool {
    let expected = match path.to_str() {
        Some("/var") => "/private/var",
        Some("/tmp") => "/private/tmp",
        Some("/etc") => "/private/etc",
        _ => return false,
    };
    path.canonicalize()
        .is_ok_and(|target| target == Path::new(expected))
}

#[cfg(unix)]
pub(crate) fn harden_storage_directory(path: &Path) -> StoreResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let canonical = std::fs::canonicalize(path)?;
    let canonical_temp_dir = std::fs::canonicalize(std::env::temp_dir()).ok();
    match storage_parent_policy(&canonical, canonical_temp_dir.as_deref()) {
        StorageParentPolicy::PreserveSharedTemp => return Ok(()),
        StorageParentPolicy::RejectBroad => {
            return Err(sqlx::Error::InvalidArgument(format!(
                "database parent must be a dedicated directory, not {}",
                canonical.display()
            )))
        }
        StorageParentPolicy::HardenDedicated => {}
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StorageParentPolicy {
    PreserveSharedTemp,
    RejectBroad,
    HardenDedicated,
}

#[cfg(unix)]
pub(crate) fn storage_parent_policy(
    path: &Path,
    canonical_temp_dir: Option<&Path>,
) -> StorageParentPolicy {
    // Test harnesses and callers may intentionally put the 0600 database file
    // directly in the platform temp directory. Preserve its directory mode;
    // dedicated children are still hardened below.
    if canonical_temp_dir == Some(path) {
        return StorageParentPolicy::PreserveSharedTemp;
    }
    // Refuse other broad paths rather than changing their permissions. Include
    // macOS canonical targets as well as public aliases: trusting `/var` during
    // component traversal must never make `/private/var` eligible for chmod.
    if [
        "/",
        "/Applications",
        "/Library",
        "/Network",
        "/System",
        "/Users",
        "/Volumes",
        "/app",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/media",
        "/mnt",
        "/opt",
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
        "/tmp",
        "/usr",
        "/var",
        "/var/lib",
        "/var/tmp",
        "/workspace",
    ]
    .iter()
    .any(|broad| path == Path::new(broad))
    {
        StorageParentPolicy::RejectBroad
    } else {
        StorageParentPolicy::HardenDedicated
    }
}

#[cfg(not(unix))]
pub(crate) fn harden_storage_directory(_path: &Path) -> StoreResult<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn harden_storage_files(path: &Path) -> StoreResult<()> {
    use std::os::unix::fs::PermissionsExt;

    for candidate in [
        path.to_path_buf(),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
    ] {
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_file() => {
                std::fs::set_permissions(candidate, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(_) => {
                return Err(sqlx::Error::InvalidArgument(format!(
                    "database or sidecar path is not a regular file: {}",
                    candidate.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn harden_storage_files(_path: &Path) -> StoreResult<()> {
    Ok(())
}
