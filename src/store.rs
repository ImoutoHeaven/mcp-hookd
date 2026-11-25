//! Atomic single-file persistence for webhook subscriptions and endpoint verification cache.

use crate::types::{CallbackErrorReason, SecretString, SubscriptionKey, random_base64url};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, watch};
use zeroize::Zeroize;

pub const STATE_VERSION: u32 = 1;
const MAX_STATE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_GROUP_COMMIT_DEBOUNCE: Duration = Duration::from_millis(25);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PersistedSubscription {
    pub id: String,
    pub key: SubscriptionKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_ref: Option<String>,
    #[serde(default)]
    pub granted_scopes: Vec<String>,
    pub secret: SecretString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_secret: Option<SecretString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_secret_until: Option<u64>,
    pub refresh_before: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_cursor: Option<String>,
    #[serde(default)]
    pub pending_truncated_for_refresh: bool,
    #[serde(default)]
    pub suspended: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<CallbackErrorReason>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedEndpoint {
    pub principal: String,
    pub url: String,
    pub secret_sha256: String,
    pub verified_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PersistedState {
    pub version: u32,
    #[serde(default)]
    pub subscriptions: Vec<PersistedSubscription>,
    #[serde(default)]
    pub verified_endpoints: Vec<VerifiedEndpoint>,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self::empty()
    }
}

impl PersistedState {
    pub fn empty() -> Self {
        Self {
            version: STATE_VERSION,
            subscriptions: Vec::new(),
            verified_endpoints: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StateStore {
    path: PathBuf,
    save_lock: Arc<Mutex<()>>,
}

impl StateStore {
    pub fn open(path: PathBuf) -> Result<(Self, PersistedState), String> {
        let base_name = base_file_name(&path)?.to_owned();
        let store = Self {
            path,
            save_lock: Arc::new(Mutex::new(())),
        };
        cleanup_stale_temp_files(parent_dir(&store.path), &base_name);
        match fs::symlink_metadata(&store.path) {
            Ok(meta) => {
                validate_existing_metadata(&store.path, &meta)?;
                let state = read_state_file(&store.path)?;
                Ok((store, state))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let empty = PersistedState::empty();
                store.save(&empty)?;
                Ok((store, empty))
            }
            Err(err) => Err(format!(
                "cannot inspect state_path {}: {err}",
                store.path.display()
            )),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save(&self, state: &PersistedState) -> Result<(), String> {
        let _guard = self
            .save_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let parent = parent_dir(&self.path);
        create_state_dir(parent)?;
        validate_target_path(&self.path)?;

        let mut payload = serde_json::to_vec_pretty(state)
            .map_err(|e| format!("cannot serialize subscription state: {e}"))?;
        if payload.len() as u64 > MAX_STATE_FILE_BYTES {
            payload.zeroize();
            return Err(format!(
                "serialized subscription state exceeds maximum size limit ({MAX_STATE_FILE_BYTES} bytes)"
            ));
        }

        let base_name = base_file_name(&self.path)?;
        let suffix = random_base64url(12)?;
        let tmp_path = parent.join(format!(".{base_name}.tmp.{suffix}"));

        let write_res = write_temp_file(&tmp_path, &payload).and_then(|()| {
            validate_target_path(&self.path)?;
            replace_state_file(&tmp_path, &self.path).map_err(|e| {
                format!(
                    "cannot atomically replace state file {}: {e}",
                    self.path.display()
                )
            })
        });
        payload.zeroize();

        if let Err(err) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }

        sync_directory(parent)?;
        Ok(())
    }
}

#[derive(Default)]
struct PendingBuffer {
    latest: Option<PersistedState>,
    target_gen: u64,
    flush_requested: bool,
    shutdown: bool,
}

#[derive(Clone, Debug, Default)]
struct FlushStatus {
    completed_gen: u64,
    last_error: Option<String>,
    closed: bool,
}

/// Async group-commit persister that coalesces dirty snapshots onto a single writer task.
#[derive(Clone)]
pub struct StoreHandle {
    store: StateStore,
    pending: Arc<Mutex<PendingBuffer>>,
    notify: Arc<Notify>,
    flush_notify: Arc<Notify>,
    status_rx: watch::Receiver<FlushStatus>,
}

impl StoreHandle {
    pub fn spawn(store: StateStore) -> Self {
        Self::spawn_with_debounce(store, DEFAULT_GROUP_COMMIT_DEBOUNCE)
    }

    pub fn spawn_with_debounce(store: StateStore, debounce: Duration) -> Self {
        let pending = Arc::new(Mutex::new(PendingBuffer::default()));
        let notify = Arc::new(Notify::new());
        let flush_notify = Arc::new(Notify::new());
        let (status_tx, status_rx) = watch::channel(FlushStatus::default());

        let worker_store = store.clone();
        let worker_pending = Arc::clone(&pending);
        let worker_notify = Arc::clone(&notify);
        let worker_flush_notify = Arc::clone(&flush_notify);

        tokio::spawn(async move {
            loop {
                let (has_work, immediate, shutdown) = {
                    let buf = worker_pending.lock().unwrap_or_else(|p| p.into_inner());
                    (buf.latest.is_some(), buf.flush_requested, buf.shutdown)
                };

                if !has_work {
                    if shutdown {
                        let mut st = status_tx.borrow().clone();
                        st.closed = true;
                        let _ = status_tx.send(st);
                        break;
                    }
                    worker_notify.notified().await;
                    continue;
                }

                if !immediate && !shutdown && !debounce.is_zero() {
                    tokio::select! {
                        () = tokio::time::sleep(debounce) => {}
                        () = worker_flush_notify.notified() => {}
                    }
                }

                let (snapshot, generation) = {
                    let mut buf = worker_pending.lock().unwrap_or_else(|p| p.into_inner());
                    buf.flush_requested = false;
                    (buf.latest.take(), buf.target_gen)
                };

                let Some(state) = snapshot else {
                    continue;
                };

                let save_store = worker_store.clone();
                let save_result = tokio::task::spawn_blocking(move || save_store.save(&state))
                    .await
                    .unwrap_or_else(|e| Err(format!("state writer task failed: {e}")));

                let next_status = FlushStatus {
                    completed_gen: generation,
                    last_error: save_result.err(),
                    closed: false,
                };
                let _ = status_tx.send(next_status);
            }
        });

        Self {
            store,
            pending,
            notify,
            flush_notify,
            status_rx,
        }
    }

    pub fn path(&self) -> &Path {
        self.store.path()
    }

    /// Queue a state snapshot for group-commit persistence.
    pub fn mark_dirty(&self, state: PersistedState) {
        {
            let mut buf = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            buf.target_gen = buf.target_gen.saturating_add(1);
            buf.latest = Some(state);
        }
        self.notify.notify_one();
    }

    /// Wait until all snapshots queued before this call are persisted to disk.
    pub async fn flush(&self) -> Result<(), String> {
        let target = {
            let mut buf = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            buf.flush_requested = true;
            buf.target_gen
        };
        self.notify.notify_one();
        self.flush_notify.notify_one();

        let mut rx = self.status_rx.clone();
        loop {
            {
                let status = rx.borrow();
                if status.completed_gen >= target {
                    return match &status.last_error {
                        Some(err) => Err(err.clone()),
                        None => Ok(()),
                    };
                }
                if status.closed {
                    return Err("state writer task stopped before flush completed".into());
                }
            }
            if rx.changed().await.is_err() {
                return Err("state writer task terminated unexpectedly".into());
            }
        }
    }

    /// Queue a snapshot and wait for it to reach disk.
    pub async fn save_and_flush(&self, state: PersistedState) -> Result<(), String> {
        self.mark_dirty(state);
        self.flush().await
    }

    /// Flush pending writes and stop the background writer task.
    pub async fn shutdown(&self) -> Result<(), String> {
        let res = self.flush().await;
        {
            let mut buf = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            buf.shutdown = true;
        }
        self.notify.notify_one();
        self.flush_notify.notify_one();
        res
    }
}

fn base_file_name(path: &Path) -> Result<&str, String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("state_path {} has invalid file name", path.display()))
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn create_state_dir(parent: &Path) -> Result<(), String> {
    #[cfg(windows)]
    let existed = parent.exists();
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(parent)
        .map_err(|e| format!("cannot create state directory {}: {e}", parent.display()))?;
    #[cfg(windows)]
    if !existed {
        windows_platform::apply_owner_only_dacl(parent, true).map_err(|e| {
            format!(
                "cannot set owner-only DACL on state directory {}: {e}",
                parent.display()
            )
        })?;
    }
    Ok(())
}

fn cleanup_stale_temp_files(parent: &Path, base_name: &str) {
    let prefix = format!(".{base_name}.tmp.");
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_str().is_some_and(|s| s.starts_with(&prefix))
            && entry
                .file_type()
                .is_ok_and(|ft| ft.is_file() && !ft.is_symlink())
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn replace_state_file(tmp_path: &Path, target: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        fs::rename(tmp_path, target)
    }
    #[cfg(windows)]
    {
        windows_platform::replace_file_with_retry(tmp_path, target)
    }
}

fn validate_target_path(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) => validate_existing_metadata(path, &meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "cannot inspect state_path {}: {err}",
            path.display()
        )),
    }
}

fn validate_existing_metadata(path: &Path, meta: &fs::Metadata) -> Result<(), String> {
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Err(format!(
            "state_path {} must not be a symbolic link",
            path.display()
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (meta.file_attributes() & 0x400) != 0 {
            return Err(format!(
                "state_path {} must not be a reparse point",
                path.display()
            ));
        }
    }
    if ft.is_dir() || !ft.is_file() {
        return Err(format!(
            "state_path {} must be a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() > 1 {
            return Err(format!(
                "state_path {} must not have multiple hard links",
                path.display()
            ));
        }
    }
    Ok(())
}

fn read_state_file(path: &Path) -> Result<PersistedState, String> {
    let file = open_state_for_read(path)?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat open state file {}: {e}", path.display()))?;
    validate_existing_metadata(path, &meta)?;
    #[cfg(windows)]
    {
        windows_platform::check_single_link(&file)
            .map_err(|e| format!("state_path {} failed handle check: {e}", path.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if (meta.permissions().mode() & 0o777) != 0o600 {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    format!("cannot enforce 0600 on state file {}: {e}", path.display())
                })?;
        }
    }
    if meta.len() > MAX_STATE_FILE_BYTES {
        return Err(format!(
            "state file {} exceeds maximum size limit",
            path.display()
        ));
    }
    let mut buf = Vec::with_capacity((meta.len() as usize).min(MAX_STATE_FILE_BYTES as usize));
    file.take(MAX_STATE_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read state file {}: {e}", path.display()))?;
    if buf.len() as u64 > MAX_STATE_FILE_BYTES {
        buf.zeroize();
        return Err(format!(
            "state file {} exceeds maximum size limit",
            path.display()
        ));
    }
    let parsed: Result<PersistedState, _> = serde_json::from_slice(&buf);
    buf.zeroize();
    let parsed = parsed.map_err(|e| format!("invalid state JSON in {}: {e}", path.display()))?;
    if parsed.version != STATE_VERSION {
        return Err(format!(
            "unsupported state version {} in {}",
            parsed.version,
            path.display()
        ));
    }
    Ok(parsed)
}

fn open_state_for_read(path: &Path) -> Result<fs::File, String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    opts.open(path)
        .map_err(|e| format!("cannot open state file {}: {e}", path.display()))
}

fn write_temp_file(tmp_path: &Path, payload: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(tmp_path)
            .map_err(|e| {
                format!(
                    "cannot create temporary state file {}: {e}",
                    tmp_path.display()
                )
            })?
    };

    #[cfg(windows)]
    let mut file = windows_platform::create_private_temp_file(tmp_path).map_err(|e| {
        format!(
            "cannot create temporary state file {}: {e}",
            tmp_path.display()
        )
    })?;

    file.write_all(payload).map_err(|e| {
        format!(
            "cannot write temporary state file {}: {e}",
            tmp_path.display()
        )
    })?;
    file.sync_all().map_err(|e| {
        format!(
            "cannot sync temporary state file {}: {e}",
            tmp_path.display()
        )
    })?;
    Ok(())
}

fn sync_directory(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let dir_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(dir)
            .map_err(|e| format!("cannot open state directory {}: {e}", dir.display()))?;
        dir_file
            .sync_all()
            .map_err(|e| format!("cannot sync state directory {}: {e}", dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

#[cfg(windows)]
mod windows_platform {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, GENERIC_READ, GENERIC_WRITE,
        HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const SDDL_REVISION_1: u32 = 1;

    fn wide(s: &OsStr) -> io::Result<Vec<u16>> {
        let mut out: Vec<u16> = s.encode_wide().collect();
        if out.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        out.push(0);
        Ok(out)
    }

    fn current_user_sid() -> io::Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let res = token_user_sid(token);
        unsafe { CloseHandle(token) };
        res
    }

    fn token_user_sid(token: HANDLE) -> io::Result<String> {
        let mut needed = 0u32;
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        let length = (buffer.len() * std::mem::size_of::<usize>()) as u32;
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut text: *mut u16 = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0usize;
        unsafe {
            while *text.add(len) != 0 {
                len += 1;
            }
        }
        let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        unsafe { LocalFree(text as HLOCAL) };
        Ok(sid)
    }

    struct OwnedDescriptor(PSECURITY_DESCRIPTOR);
    impl Drop for OwnedDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0 as HLOCAL) };
            }
        }
    }

    fn owner_only_descriptor(inherit: bool) -> io::Result<OwnedDescriptor> {
        let sid = current_user_sid()?;
        let ace = if inherit { "OICI" } else { "" };
        let sddl = format!("D:P(A;{ace};GA;;;{sid})");
        let w = wide(OsStr::new(&sddl))?;
        let mut desc: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut desc,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedDescriptor(desc))
    }

    pub fn apply_owner_only_dacl(path: &Path, inherit: bool) -> io::Result<()> {
        let desc = owner_only_descriptor(inherit)?;
        let mut present = 0;
        let mut dacl = std::ptr::null_mut();
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorDacl(desc.0, &mut present, &mut dacl, &mut defaulted) }
            == 0
            || present == 0
        {
            return Err(io::Error::last_os_error());
        }
        let wpath = wide(path.as_os_str())?;
        let status = unsafe {
            SetNamedSecurityInfoW(
                wpath.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    pub fn create_private_temp_file(path: &Path) -> io::Result<File> {
        let desc = owner_only_descriptor(false)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: desc.0,
            bInheritHandle: 0,
        };
        let name = wide(path.as_os_str())?;
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &sa,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_handle(handle) };
        let meta = file.metadata()?;
        if !meta.is_file() || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "temporary file is not a regular file",
            ));
        }
        check_single_link(&file)?;
        Ok(file)
    }

    pub fn check_single_link(file: &File) -> io::Result<()> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.nNumberOfLinks > 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "state file must not have multiple hard links",
            ));
        }
        Ok(())
    }

    pub fn replace_file_with_retry(from: &Path, to: &Path) -> io::Result<()> {
        let from_w = wide(from.as_os_str())?;
        let to_w = wide(to.as_os_str())?;
        const MAX_RETRIES: usize = 5;
        for attempt in 0..=MAX_RETRIES {
            let ok = unsafe {
                MoveFileExW(
                    from_w.as_ptr(),
                    to_w.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            if ok != 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if attempt < MAX_RETRIES
                && matches!(
                    err.raw_os_error(),
                    Some(code)
                        if code == ERROR_ACCESS_DENIED as i32
                            || code == ERROR_SHARING_VIOLATION as i32
                )
            {
                std::thread::sleep(Duration::from_millis(10u64 << attempt));
                continue;
            }
            return Err(err);
        }
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, Value};

    fn sample_subscription(id_suffix: &str, refresh_before: u64) -> PersistedSubscription {
        let mut args = Map::new();
        args.insert("repo".into(), Value::String("demo".into()));
        let key = SubscriptionKey::new(
            "aref_user1",
            format!("https://hooks.example.com/{id_suffix}"),
            "ci.build_failed",
            &args,
        )
        .unwrap();
        PersistedSubscription {
            id: key.subscription_id(),
            key,
            auth_ref: Some("aref_user1".into()),
            granted_scopes: vec!["events:read".into()],
            secret: SecretString::new("whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            prev_secret: Some(SecretString::new(
                "whsec_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            )),
            prev_secret_until: Some(refresh_before + 300),
            refresh_before,
            safe_cursor: Some("cur_42".into()),
            pending_truncated_for_refresh: true,
            suspended: false,
            last_error: Some(CallbackErrorReason::Timeout),
        }
    }

    #[test]
    fn roundtrip_and_deny_unknown_fields() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nested/subscriptions.json");
        let (store, initial) = StateStore::open(path.clone()).unwrap();
        assert_eq!(initial, PersistedState::empty());

        let state = PersistedState {
            version: STATE_VERSION,
            subscriptions: vec![sample_subscription("a", 1_800_000_000)],
            verified_endpoints: vec![VerifiedEndpoint {
                principal: "aref_user1".into(),
                url: "https://hooks.example.com/a".into(),
                secret_sha256: "deadbeef".into(),
                verified_at: 1_799_999_000,
            }],
        };
        store.save(&state).unwrap();

        let (_, reloaded) = StateStore::open(path.clone()).unwrap();
        assert_eq!(reloaded, state);

        // Unknown fields must be rejected.
        let bad_json = r#"{"version":1,"subscriptions":[],"verified_endpoints":[],"extra":true}"#;
        fs::write(&path, bad_json).unwrap();
        assert!(StateStore::open(path.clone()).is_err());

        // Unsupported version must be rejected.
        let bad_ver = r#"{"version":2,"subscriptions":[],"verified_endpoints":[]}"#;
        fs::write(&path, bad_ver).unwrap();
        assert!(StateStore::open(path).is_err());
    }

    #[test]
    fn cleans_stale_temp_files_and_enforces_unix_permissions() {
        let dir = tempfile::TempDir::new().unwrap();
        let nested = dir.path().join("priv/subscriptions.json");
        let (_store, _) = StateStore::open(nested.clone()).unwrap();

        let parent = nested.parent().unwrap();
        let stale_tmp = parent.join(".subscriptions.json.tmp.leftover");
        fs::write(&stale_tmp, b"partial").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(parent).unwrap().permissions().mode() & 0o777,
                0o700
            );
            fs::set_permissions(&nested, fs::Permissions::from_mode(0o644)).unwrap();
        }

        let (_store, _) = StateStore::open(nested.clone()).unwrap();
        assert!(!stale_tmp.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_and_multiple_hard_links() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::TempDir::new().unwrap();
        let real_file = dir.path().join("real.json");
        fs::write(
            &real_file,
            r#"{"version":1,"subscriptions":[],"verified_endpoints":[]}"#,
        )
        .unwrap();

        // Symlink target must be rejected on open.
        let link_path = dir.path().join("link.json");
        symlink(&real_file, &link_path).unwrap();
        let err = StateStore::open(link_path).unwrap_err();
        assert!(err.contains("symbolic link"), "unexpected error: {err}");

        // Multiple hard links must be rejected on open and save.
        let hard_a = dir.path().join("hard_a.json");
        let hard_b = dir.path().join("hard_b.json");
        let (store, _) = StateStore::open(hard_a.clone()).unwrap();
        fs::hard_link(&hard_a, &hard_b).unwrap();

        let err_open = StateStore::open(hard_a.clone()).unwrap_err();
        assert!(
            err_open.contains("hard links"),
            "unexpected error: {err_open}"
        );

        let err_save = store.save(&PersistedState::empty()).unwrap_err();
        assert!(
            err_save.contains("hard links"),
            "unexpected error: {err_save}"
        );
    }

    #[tokio::test]
    async fn group_commit_coalesces_dirty_updates_and_flushes_latest() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("subscriptions.json");
        let (store, _) = StateStore::open(path.clone()).unwrap();
        let handle = StoreHandle::spawn_with_debounce(store, Duration::from_millis(40));

        for i in 1..=20u64 {
            let state = PersistedState {
                version: STATE_VERSION,
                subscriptions: vec![sample_subscription(&format!("sub{i}"), 1_700_000_000 + i)],
                verified_endpoints: Vec::new(),
            };
            handle.mark_dirty(state);
        }

        handle.flush().await.unwrap();
        handle.shutdown().await.unwrap();

        let (_, loaded) = StateStore::open(path).unwrap();
        assert_eq!(loaded.subscriptions.len(), 1);
        assert_eq!(loaded.subscriptions[0].refresh_before, 1_700_000_020);
    }
}
