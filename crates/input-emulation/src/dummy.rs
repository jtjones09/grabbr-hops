use async_trait::async_trait;
use input_event::Event;

use crate::error::EmulationError;

use super::{ButtonScope, Emulation, EmulationHandle};

#[derive(Default)]
pub(crate) struct DummyEmulation;

impl DummyEmulation {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Emulation for DummyEmulation {
    async fn consume(
        &mut self,
        event: Event,
        client_handle: EmulationHandle,
    ) -> Result<(), EmulationError> {
        log::info!("received event: ({client_handle}) {event}");
        Ok(())
    }
    async fn create(&mut self, _: EmulationHandle) {}
    async fn destroy(&mut self, _: EmulationHandle) {}
    async fn terminate(&mut self) {
        /* nothing to do */
    }

    /// Injects nothing; one logger stands in for every handle.
    fn button_scope(&self) -> ButtonScope {
        ButtonScope::Machine
    }
}
