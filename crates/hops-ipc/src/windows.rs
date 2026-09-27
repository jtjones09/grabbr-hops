//! The Windows half of the frontend channel: the daemon's named pipe, who
//! may open it, and the GUI's single-instance event.
//!
//! Kept to calls into the system. What is said over the pipe, and how the
//! names are made, is in [`crate::proof`], the same on every platform.

use std::ffi::OsStr;
use std::future::Future;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::pin::Pin;
use std::ptr::null_mut;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_PIPE_BUSY, GetLastError, HANDLE, HLOCAL,
    LocalFree, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, INFINITE, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, SetEvent, WaitForSingleObject,
};

/// Bytes each direction of a pipe instance buffers. An event or a request is
/// rarely more; a larger one waits for the reader.
const PIPE_BUFFER: u32 = 64 * 1024;

/// A NUL-terminated UTF-16 copy of `s`, as the system calls take strings.
fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// The string at `p`, a NUL-terminated UTF-16 string the system allocated,
/// which this frees.
///
/// # Safety
///
/// `p` must be a string returned by a call that says to free it with
/// `LocalFree`, and not be used again.
unsafe fn take_local_string(p: *mut u16) -> String {
    let mut len = 0;
    // SAFETY: the caller hands a NUL-terminated string.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` units were just read from `p`.
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) });
    // SAFETY: the caller says `p` is freed with LocalFree and not used again.
    unsafe { LocalFree(p as HLOCAL) };
    text
}

/// The user a process token belongs to, as a SID string (`S-1-5-21-...`).
fn user_of(token: HANDLE) -> io::Result<String> {
    let mut len = 0u32;
    // SAFETY: asks only for the size; no buffer is written.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // u64s, so the buffer is aligned for the TOKEN_USER written into it.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `len` bytes and outlives the call.
    let got =
        unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) };
    if got == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call wrote a TOKEN_USER at the start of the aligned buffer.
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let mut text = null_mut();
    // SAFETY: the SID points into `buf`, which is alive; `text` receives a
    // string freed below.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ConvertSidToStringSidW's string is freed with LocalFree.
    Ok(unsafe { take_local_string(text) })
}

/// The user this process runs as, as a SID string.
pub(crate) fn this_user() -> io::Result<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: GetCurrentProcess is a constant pseudo-handle; `token` receives
    // a handle owned below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle just opened, owned by nothing else.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    user_of(token.as_raw_handle())
}

/// The user process `pid` runs as, as a SID string.
fn user_of_process(pid: u32) -> io::Result<String> {
    // SAFETY: plain values; the handle is owned below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle just opened, owned by nothing else.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut token: HANDLE = null_mut();
    // SAFETY: `process` is open; `token` receives a handle owned below.
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle just opened, owned by nothing else.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    user_of(token.as_raw_handle())
}

/// A security descriptor whose DACL grants `sid` everything and no one
/// else anything, in SDDL.
///
/// Protected, so nothing is inherited. No entry for SYSTEM, administrators,
/// other users, services or app containers: the daemon's frontends run as
/// the user who runs the daemon.
pub(crate) fn only_sddl(sid: &str) -> String {
    format!("D:P(A;;GA;;;{sid})")
}

/// A security descriptor made from SDDL, freed when dropped.
pub(crate) struct Security {
    descriptor: PSECURITY_DESCRIPTOR,
}

// SAFETY: the descriptor is written once, when made, and only read after;
// the system reads it when an object is created and keeps its own copy.
unsafe impl Send for Security {}
// SAFETY: as above.
unsafe impl Sync for Security {}

impl Security {
    /// Grants this user alone.
    pub(crate) fn for_this_user() -> io::Result<Self> {
        Self::from_sddl(&only_sddl(&this_user()?))
    }

    pub(crate) fn from_sddl(sddl: &str) -> io::Result<Self> {
        let text = wide(sddl);
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `text` is NUL-terminated and outlives the call;
        // `descriptor` receives a buffer freed in Drop.
        let made = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if made == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { descriptor })
    }

    /// Attributes that apply this descriptor, for as long as `self` lives.
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor,
            bInheritHandle: 0,
        }
    }

    /// An instance of the pipe `name`, with this descriptor. The first
    /// instance fails when any pipe of that name exists, whoever made it.
    pub(crate) fn pipe(&self, name: &str, first: bool) -> io::Result<NamedPipeServer> {
        let mut attributes = self.attributes();
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .in_buffer_size(PIPE_BUFFER)
            .out_buffer_size(PIPE_BUFFER);
        // SAFETY: `attributes` points at a live descriptor for the call.
        unsafe {
            options.create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
        }
    }
}

impl Drop for Security {
    fn drop(&mut self) {
        // SAFETY: made by ConvertStringSecurityDescriptorToSecurityDescriptorW,
        // which says to free it with LocalFree, and not used after this.
        unsafe { LocalFree(self.descriptor as HLOCAL) };
    }
}

type Accepting = Pin<Box<dyn Future<Output = io::Result<NamedPipeServer>> + Send>>;

/// The daemon's pipe: one instance waiting for a frontend at all times it
/// is polled.
pub(crate) struct PipeListener {
    name: String,
    security: Arc<Security>,
    next: Accepting,
}

impl PipeListener {
    /// Create the pipe `name`, granting this user alone, as its first
    /// instance: fails when a pipe of that name already exists.
    pub(crate) fn first(name: &str) -> io::Result<Self> {
        let security = Arc::new(Security::for_this_user()?);
        let server = security.pipe(name, true)?;
        Ok(Self {
            name: name.to_string(),
            security,
            next: Box::pin(connected(server)),
        })
    }

    /// The next frontend to connect. A connection that fails before it is
    /// accepted is logged and skipped.
    pub(crate) fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<NamedPipeServer>> {
        loop {
            let done = ready!(self.next.as_mut().poll(cx));
            // The next instance first, so a frontend always has one to open.
            self.next = Box::pin(next_instance(self.name.clone(), self.security.clone()));
            match done {
                Ok(server) => return Poll::Ready(Ok(server)),
                Err(e) => log::debug!("a frontend connection to {} failed: {e}", self.name),
            }
        }
    }
}

async fn connected(server: NamedPipeServer) -> io::Result<NamedPipeServer> {
    server.connect().await?;
    Ok(server)
}

async fn next_instance(name: String, security: Arc<Security>) -> io::Result<NamedPipeServer> {
    loop {
        match security.pipe(&name, false) {
            Ok(server) => return connected(server).await,
            Err(e) => {
                log::warn!("could not open another instance of {name} ({e}); trying again");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}

/// Open the pipe `name` as a frontend, now or not at all.
///
/// Only identification, not impersonation, is allowed to whatever holds the
/// pipe, so a process that holds the name in the daemon's place cannot act
/// as this user.
pub(crate) fn open_pipe_now(name: &str) -> io::Result<NamedPipeClient> {
    ClientOptions::new()
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(name)
}

/// Open the pipe `name` as a frontend, waiting until `deadline` while every
/// instance of it is busy.
pub(crate) async fn open_pipe(name: &str, deadline: Instant) -> io::Result<NamedPipeClient> {
    loop {
        match open_pipe_now(name) {
            Err(e) if busy(&e) && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            other => return other,
        }
    }
}

fn busy(e: &io::Error) -> bool {
    e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
}

fn denied(e: &io::Error) -> bool {
    e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32)
}

/// Whether a pipe `name` exists that this user may open. See
/// [`crate::DaemonEndpoint::answers`].
pub(crate) fn pipe_answers(name: &str) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .security_qos_flags(SECURITY_IDENTIFICATION)
        .open(name);
    match opened {
        Ok(_) => true,
        Err(e) => busy(&e),
    }
}

/// Whether creating the first instance of a pipe failed because a pipe of
/// that name exists.
pub(crate) fn taken(e: &io::Error) -> bool {
    denied(e) || busy(e)
}

/// Who holds the pipe `name`, which this process could not create.
pub(crate) enum Holder {
    /// A process running as this user.
    ThisUser,
    /// Anything else, in words.
    Other(String),
}

/// Ask the system which process holds the pipe `name`, and whether it runs
/// as this user. Taken from the pipe, not from anything the process says.
pub(crate) async fn who_holds(name: &str) -> Holder {
    let deadline = Instant::now() + Duration::from_secs(2);
    let client = match open_pipe(name, deadline).await {
        Ok(client) => client,
        Err(e) if denied(&e) => {
            return Holder::Other(
                "a pipe this user may not open, so it was made by another user or a service"
                    .to_string(),
            );
        }
        Err(e) if busy(&e) => {
            return Holder::Other(format!(
                "a pipe whose every instance stayed busy for {} s",
                2
            ));
        }
        Err(e) => return Holder::Other(format!("a pipe that could not be opened ({e})")),
    };
    let mut pid = 0u32;
    // SAFETY: `client` is an open pipe handle; `pid` outlives the call.
    if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle(), &mut pid) } == 0 {
        let e = io::Error::last_os_error();
        return Holder::Other(format!("a pipe whose process could not be named ({e})"));
    }
    match (this_user(), user_of_process(pid)) {
        (Ok(me), Ok(them)) if me == them => Holder::ThisUser,
        (Ok(_), Ok(them)) => Holder::Other(format!("process {pid}, which runs as {them}")),
        (_, Err(e)) => Holder::Other(format!(
            "process {pid}, whose user could not be read ({e}), so not one of this user's"
        )),
        (Err(e), _) => Holder::Other(format!(
            "process {pid}; this process could not read its own user ({e})"
        )),
    }
}

/// The named event a running GUI waits on, as [`crate::instance`] asks for.
pub(crate) enum GuiEvent {
    /// This launch made it, and `on_show` runs each time it is set.
    New(OwnedHandle),
    /// One exists that this user may open; it has been set when `signalled`.
    Existing { signalled: bool },
    /// The name could not be used: something this user may not open, or an
    /// object of another kind, holds it.
    Refused(io::Error),
}

/// Create the event `name`, granting this user alone, or set the one that
/// is there.
pub(crate) fn gui_event(name: &str, on_show: impl Fn() + Send + 'static) -> GuiEvent {
    let security = match Security::for_this_user() {
        Ok(security) => security,
        Err(e) => return GuiEvent::Refused(e),
    };
    let attributes = security.attributes();
    let name = wide(name);
    // SAFETY: `attributes` and `name` outlive the call; the handle is owned
    // below.
    let handle = unsafe { CreateEventW(&attributes, 0, 0, name.as_ptr()) };
    // SAFETY: read at once, before any other call can change it.
    let error = unsafe { GetLastError() };
    if handle.is_null() {
        return GuiEvent::Refused(io::Error::from_raw_os_error(error as i32));
    }
    // SAFETY: a handle just opened, owned by nothing else.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    if error == ERROR_ALREADY_EXISTS {
        // SAFETY: `handle` is an open event handle.
        let signalled = unsafe { SetEvent(handle.as_raw_handle()) } != 0;
        return GuiEvent::Existing { signalled };
    }
    let waiting = match handle.try_clone() {
        Ok(waiting) => waiting,
        Err(e) => return GuiEvent::Refused(e),
    };
    std::thread::spawn(move || {
        // SAFETY: `waiting` is an open event handle this thread owns.
        while unsafe { WaitForSingleObject(waiting.as_raw_handle(), INFINITE) } == WAIT_OBJECT_0 {
            on_show();
        }
    });
    GuiEvent::New(handle)
}

#[cfg(test)]
pub(crate) mod testing {
    //! Objects standing where hops's own should be, for the tests.

    use super::{Security, wide};
    use std::io;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::Threading::{CreateEventW, CreateMutexW};

    /// A pipe named `name` that no one may open.
    pub(crate) fn pipe_no_one_may_open(
        name: &str,
    ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        Security::from_sddl("D:P")?.pipe(name, true)
    }

    /// An event named `name` that no one may open.
    pub(crate) fn event_no_one_may_open(name: &str) -> io::Result<OwnedHandle> {
        let security = Security::from_sddl("D:P")?;
        let attributes = security.attributes();
        let name = wide(name);
        // SAFETY: both outlive the call; the handle is owned below.
        let handle = unsafe { CreateEventW(&attributes, 0, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a handle just opened, owned by nothing else.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }

    /// A mutex named `name`: an object of another kind than an event.
    pub(crate) fn mutex(name: &str) -> io::Result<OwnedHandle> {
        let name = wide(name);
        // SAFETY: `name` outlives the call; the handle is owned below.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a handle just opened, owned by nothing else.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }

    /// The DACL of the object behind `handle`, in SDDL.
    pub(crate) fn dacl_of(handle: std::os::windows::io::RawHandle) -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_KERNEL_OBJECT,
        };
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `handle` is open; `descriptor` receives a buffer freed below.
        let got = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if got != 0 {
            return Err(io::Error::from_raw_os_error(got as i32));
        }
        let mut text = std::ptr::null_mut();
        // SAFETY: `descriptor` was just filled in; `text` receives a string
        // freed below.
        let made = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                std::ptr::null_mut(),
            )
        };
        // SAFETY: GetSecurityInfo's descriptor is freed with LocalFree.
        unsafe { windows_sys::Win32::Foundation::LocalFree(descriptor) };
        if made == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the string is freed with LocalFree.
        Ok(unsafe { super::take_local_string(text) })
    }
}
