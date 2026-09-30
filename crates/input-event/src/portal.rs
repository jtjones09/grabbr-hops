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
    REGISTERED
        .get_or_init(|| async {
            match try_register().await {
                Ok(()) => log::info!("named to the desktop portal as {}", crate::APP_ID),
                Err(e) => log::info!(
                    "the desktop portal will not show hops by name ({e}). It needs \
                     xdg-desktop-portal 1.20 or later and {}.desktop installed \
                     (see docs/UPGRADING.md); restart hops after installing it",
                    crate::APP_ID
                ),
            }
        })
        .await;
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
}
