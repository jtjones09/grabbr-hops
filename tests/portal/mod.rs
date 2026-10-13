//! A stand-in session bus with a stand-in desktop portal on it, which
//! records every method call a portal backend makes, in order.
//!
//! The consent prompt names the caller that registered its connection with
//! `org.freedesktop.host.portal.Registry` before that connection's first
//! portal call (#113). What a backend sends, and in which order, is what
//! these tests observe. The stand-in answers the bus's own calls, reports
//! the Registry as present, accepts `Register`, and refuses every other
//! portal call, so a backend stops at its first one. Started with
//! [`start_creating_capture_sessions`], it also grants input capture's
//! `CreateSession`, so a backend stops at the session's first setup step.
//!
//! One backend per test binary: the portal registration and ashpd's
//! session-bus connection are both made once per process.
// Each test binary that includes this uses part of it.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use zbus::message::Type;
use zbus::zvariant::{ObjectPath, OwnedValue, Value};
use zbus::{Guid, MessageStream};

const REGISTRY: &str = "org.freedesktop.host.portal.Registry";

pub struct StandIn {
    calls: Arc<Mutex<Vec<String>>>,
    dir: PathBuf,
}

impl Drop for StandIn {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Serves the stand-in and points this process's session bus at it. Call it
/// before anything in the process touches the session bus.
pub fn start(tag: &str) -> StandIn {
    serve_bus(tag, false)
}

/// As [`start`], granting input capture's `CreateSession` as well.
pub fn start_creating_capture_sessions(tag: &str) -> StandIn {
    serve_bus(tag, true)
}

fn serve_bus(tag: &str, create_sessions: bool) -> StandIn {
    let dir = std::env::temp_dir().join(format!("hops-portal-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let socket = dir.join("bus");
    let listener = tokio::net::UnixListener::bind(&socket).expect("the stand-in bus socket");
    std::env::set_var(
        "DBUS_SESSION_BUS_ADDRESS",
        format!("unix:path={}", socket.display()),
    );
    let calls = Arc::new(Mutex::new(Vec::new()));
    let record = calls.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(stream, record.clone(), create_sessions));
        }
    });
    StandIn { calls, dir }
}

impl StandIn {
    /// Each method call so far: `Register(<app id>)`, `<interface>.<property>`
    /// for a property read, `<interface>.*` for a read of all of them, or
    /// `<interface>.<method>`.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

async fn serve(
    stream: tokio::net::UnixStream,
    calls: Arc<Mutex<Vec<String>>>,
    create_sessions: bool,
) {
    let Ok(builder) = zbus::connection::Builder::unix_stream(stream).server(Guid::generate())
    else {
        return;
    };
    let Ok(conn) = builder.p2p().build().await else {
        return;
    };
    let mut messages = MessageStream::from(&conn);
    while let Some(Ok(msg)) = messages.next().await {
        let header = msg.header();
        if header.message_type() != Type::MethodCall {
            continue;
        }
        let interface = header
            .interface()
            .map(|i| i.to_string())
            .unwrap_or_default();
        let member = header.member().map(|m| m.to_string()).unwrap_or_default();
        let answered = match (interface.as_str(), member.as_str()) {
            ("org.freedesktop.DBus", "Hello") => conn.reply(&header, &":1.42").await,
            ("org.freedesktop.DBus", "GetNameOwner") => conn.reply(&header, &":1.1").await,
            ("org.freedesktop.DBus", "AddMatch" | "RemoveMatch") => conn.reply(&header, &()).await,
            ("org.freedesktop.DBus.Properties", "Get") => {
                let (of, property): (String, String) = msg.body().deserialize().unwrap_or_default();
                calls.lock().unwrap().push(format!("{of}.{property}"));
                if of == REGISTRY && property == "version" {
                    conn.reply(&header, &Value::U32(1)).await
                } else {
                    refuse(&conn, &header).await
                }
            }
            // A proxy reads all of an interface's properties when it is made,
            // which is a call to that interface like any other.
            ("org.freedesktop.DBus.Properties", "GetAll") => {
                let (of,): (String,) = msg.body().deserialize().unwrap_or_default();
                calls.lock().unwrap().push(format!("{of}.*"));
                if of == REGISTRY {
                    let all = HashMap::from([("version", Value::U32(1))]);
                    conn.reply(&header, &all).await
                } else {
                    refuse(&conn, &header).await
                }
            }
            (CAPTURE, "CreateSession") if create_sessions => {
                calls.lock().unwrap().push(format!("{interface}.{member}"));
                create_session(&conn, &msg).await
            }
            (REGISTRY, "Register") => {
                let (app_id, _): (String, HashMap<String, OwnedValue>) =
                    msg.body().deserialize().unwrap_or_default();
                calls.lock().unwrap().push(format!("Register({app_id})"));
                conn.reply(&header, &()).await
            }
            _ => {
                calls.lock().unwrap().push(format!("{interface}.{member}"));
                refuse(&conn, &header).await
            }
        };
        if answered.is_err() {
            return;
        }
    }
}

const CAPTURE: &str = "org.freedesktop.portal.InputCapture";

/// The caller's unique name, as `Hello` gave it, in a portal object path.
const CALLER: &str = "1_42";

/// Grants a `CreateSession`: replies with the request's path, then sends
/// the request's `Response` naming the session, as a portal does once the
/// user allows it.
async fn create_session(conn: &zbus::Connection, msg: &zbus::Message) -> zbus::Result<()> {
    let header = msg.header();
    let (_parent, options): (String, HashMap<String, OwnedValue>) = msg.body().deserialize()?;
    let token = |key: &str| -> String {
        options
            .get(key)
            .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default()
    };
    let request = ObjectPath::try_from(format!(
        "/org/freedesktop/portal/desktop/request/{CALLER}/{}",
        token("handle_token")
    ))?
    .into_owned();
    let session = ObjectPath::try_from(format!(
        "/org/freedesktop/portal/desktop/session/{CALLER}/{}",
        token("session_handle_token")
    ))?
    .into_owned();
    conn.reply(&header, &request).await?;
    let results = HashMap::from([
        ("session_handle", Value::from(session)),
        // Keyboard | Pointer
        ("capabilities", Value::U32(3)),
    ]);
    let response = zbus::Message::signal(
        request.clone(),
        "org.freedesktop.portal.Request",
        "Response",
    )?
    .sender(":1.1")?
    .destination(":1.42")?
    .build(&(0u32, results))?;
    conn.send(&response).await
}

async fn refuse(conn: &zbus::Connection, header: &zbus::message::Header<'_>) -> zbus::Result<()> {
    conn.reply_error(
        header,
        "org.freedesktop.DBus.Error.AccessDenied",
        &"the stand-in portal refuses everything but the Registry",
    )
    .await
}

/// Runs `start_backend` to completion against the stand-in, then checks that
/// hops registered as `input_event::APP_ID` before the backend's first call
/// to a portal interface.
pub async fn registers_before_the_first_portal_call<F, T, E>(
    stand_in: &StandIn,
    what: &str,
    start_backend: F,
) where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    let started = tokio::time::timeout(Duration::from_secs(60), start_backend)
        .await
        .unwrap_or_else(|_| panic!("{what} did not return within 60 s: {:?}", stand_in.calls()));
    assert!(
        started.is_err(),
        "{what} started against a portal that refuses every call"
    );
    let calls = stand_in.calls();
    eprintln!("{what}, calls in order: {calls:?}");
    let first_portal_call = calls
        .iter()
        .position(|c| c.starts_with("org.freedesktop.portal."))
        .unwrap_or_else(|| panic!("{what} never called the portal: {calls:?}"));
    let register = format!("Register({})", input_event::APP_ID);
    let registered = calls.iter().position(|c| *c == register);
    assert!(
        registered.is_some_and(|r| r < first_portal_call),
        "{what} called the portal without first registering as {}, so the \
         consent prompt cannot name hops. Calls, in order: {calls:?}",
        input_event::APP_ID
    );
}
