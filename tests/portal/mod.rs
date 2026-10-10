//! A stand-in session bus with a stand-in desktop portal on it, which
//! records every method call a portal backend makes, in order.
//!
//! The consent prompt names the caller that registered its connection with
//! `org.freedesktop.host.portal.Registry` before that connection's first
//! portal call (#113). What a backend sends, and in which order, is what
//! these tests observe. The stand-in answers the bus's own calls, reports
//! the Registry as present, accepts `Register`, and refuses every other
//! portal call, so a backend stops at its first one.
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
use zbus::zvariant::{OwnedValue, Value};
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
            tokio::spawn(serve(stream, record.clone()));
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

async fn serve(stream: tokio::net::UnixStream, calls: Arc<Mutex<Vec<String>>>) {
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
