//! Naming hops to xdg-desktop-portal, so its consent prompt says who asks.
//!
//! A portal takes the name of an unsandboxed caller from its systemd unit
//! (`app-<id>-….scope`), which a daemon started from a terminal or from
//! `hops.service` does not have: the prompt then names no application.
//! Portals from 1.20 on offer `org.freedesktop.host.portal.Registry`, whose
//! `Register` names the caller's D-Bus connection, provided a desktop entry
//! with that id is installed (`com.grabbr.hops.desktop`). It has to come
//! before the connection's first portal call, and only once.
//!
//! The name also scopes what the portal remembers: a restore token saved
//! while hops was unnamed does not apply once it is named, so the first
//! start after this change asks once more.

use std::future::Future;

use ashpd::zbus;
use tokio::sync::OnceCell;

// ashpd keeps one session-bus connection per process. This crate must use the
// same ashpd as input-capture and input-emulation (one version in Cargo.lock),
// or it would register a connection no portal call goes over.
static REGISTERED: OnceCell<()> = OnceCell::const_new();

/// Names this process to the portal as [`crate::APP_ID`].
///
/// Every portal backend awaits this before its first portal call. The first
/// caller registers; any other waits until that has finished, so no portal
/// call can overtake the registration. It never fails: a portal that cannot
/// name hops still works, and asks on behalf of an unnamed application.
pub async fn register() {
    register_once(&REGISTERED, try_register).await
}

/// Registers through `attempt` unless `done` says an earlier call settled it.
///
/// Success and a refusal settle it. A bus or portal that could not be reached
/// does not: no portal call can have gone over the connection then, so the
/// next backend to start (the daemon starts them again when input is turned
/// back on) tries again, instead of leaving hops unnamed for the life of the
/// process because the portal was still starting at login.
async fn register_once<F, Fut>(done: &OnceCell<()>, attempt: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), ashpd::Error>>,
{
    let _ = done
        .get_or_try_init(|| async {
            match attempt().await {
                Ok(()) => {
                    log::info!("named to the desktop portal as {}", crate::APP_ID);
                    Ok(())
                }
                Err(e) if unreachable(&e) => {
                    log::info!(
                        "the desktop portal could not be reached to name hops ({e}); \
                         trying again when a portal backend next starts"
                    );
                    Err(())
                }
                Err(e) => {
                    log::info!(
                        "the desktop portal will not show hops by name ({e}). It needs \
                         xdg-desktop-portal 1.20 or later and {}.desktop installed, \
                         its Exec the absolute path of hops (see docs/UPGRADING.md); \
                         restart hops after installing it",
                        crate::APP_ID
                    );
                    Ok(())
                }
            }
        })
        .await;
}

/// D-Bus errors that mean the bus or the portal was not there to answer,
/// rather than that the portal answered no.
const UNREACHABLE: [&str; 7] = [
    "org.freedesktop.DBus.Error.ServiceUnknown",
    "org.freedesktop.DBus.Error.NameHasNoOwner",
    "org.freedesktop.DBus.Error.NoReply",
    "org.freedesktop.DBus.Error.Timeout",
    "org.freedesktop.DBus.Error.TimedOut",
    "org.freedesktop.DBus.Error.Disconnected",
    "org.freedesktop.DBus.Error.NoServer",
];

fn unreachable(e: &ashpd::Error) -> bool {
    match e {
        ashpd::Error::IO(_) => true,
        ashpd::Error::Zbus(e) => match e {
            zbus::Error::InputOutput(_) | zbus::Error::Address(_) | zbus::Error::Handshake(_) => {
                true
            }
            zbus::Error::MethodError(name, _, _) => UNREACHABLE.contains(&name.as_str()),
            zbus::Error::FDO(e) => {
                UNREACHABLE.contains(&zbus::DBusError::name(e.as_ref()).as_str())
            }
            _ => false,
        },
        _ => false,
    }
}

async fn try_register() -> Result<(), ashpd::Error> {
    ashpd::register_host_app(app_id()?).await
}

fn app_id() -> Result<ashpd::AppID, ashpd::Error> {
    ashpd::AppID::try_from(crate::APP_ID)
}

#[cfg(test)]
mod tests {
    // LEDGER T1 | class B | 1 return value: ashpd::AppID parsing input_event::APP_ID
    /// The portal refuses to register an id that is not a valid application
    /// id, and the prompt then names nobody.
    #[test]
    fn the_app_id_is_one_the_portal_accepts() {
        assert!(
            super::app_id().is_ok(),
            "{:?} is not a valid application id, so Registry.Register cannot \
             name hops and the consent prompt stays anonymous",
            crate::APP_ID
        );
    }

    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::zbus;
    use tokio::sync::OnceCell;

    fn fdo(e: zbus::fdo::Error) -> ashpd::Error {
        ashpd::Error::Zbus(zbus::Error::FDO(Box::new(e)))
    }

    /// `Register` as the portal answered it: the error the bus sends as the
    /// reply named `name`.
    fn replied(name: &str) -> ashpd::Error {
        let call = zbus::Message::method_call("/org/freedesktop/portal/desktop", "Register")
            .unwrap()
            .build(&())
            .unwrap();
        ashpd::Error::Zbus(zbus::Error::MethodError(
            zbus::names::OwnedErrorName::try_from(name).unwrap(),
            None,
            call,
        ))
    }

    /// Calls `register_once` once per outcome, as the backends of one process
    /// would, and returns how many times it asked the portal.
    async fn attempts(outcomes: Vec<Result<(), ashpd::Error>>) -> usize {
        let done = OnceCell::new();
        let asked = AtomicUsize::new(0);
        for outcome in outcomes {
            super::register_once(&done, || async {
                asked.fetch_add(1, Ordering::SeqCst);
                outcome
            })
            .await;
        }
        asked.load(Ordering::SeqCst)
    }

    // LEDGER T2 | class B | 1 return value: how often register_once asks the portal
    /// A portal that was not there yet is asked again the next time a backend
    /// starts; once it has answered, it is not asked again.
    #[tokio::test]
    async fn a_portal_that_could_not_be_reached_is_asked_again() {
        for unreachable in [
            fdo(zbus::fdo::Error::ServiceUnknown("starting".into())),
            replied("org.freedesktop.DBus.Error.NoReply"),
            ashpd::Error::Zbus(zbus::Error::InputOutput(std::sync::Arc::new(
                std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
            ))),
        ] {
            let what = format!("{unreachable:?}");
            assert_eq!(
                attempts(vec![Err(unreachable), Ok(()), Ok(())]).await,
                2,
                "after {what}, hops must register the next time a backend starts, \
                 and only until it has"
            );
        }
    }

    // LEDGER T3 | class B | 1 return value: how often register_once asks the portal
    /// A portal that answered no is not asked again: it would answer the
    /// same, and a portal call may since have gone over the connection.
    #[tokio::test]
    async fn a_portal_that_refused_is_not_asked_again() {
        for refused in [
            replied("org.freedesktop.DBus.Error.UnknownMethod"),
            replied("org.freedesktop.portal.Error.NotAllowed"),
            ashpd::Error::PortalNotFound(
                zbus::names::OwnedInterfaceName::try_from("org.freedesktop.host.portal.Registry")
                    .unwrap(),
            ),
        ] {
            let what = format!("{refused:?}");
            assert_eq!(
                attempts(vec![Err(refused), Ok(())]).await,
                1,
                "after {what}, hops must not register again"
            );
        }
    }
}
