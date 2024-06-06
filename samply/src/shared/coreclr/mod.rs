mod dotnet_trace_manager;
mod eventpipe;
mod events;
mod markers;
mod provider;

use std::fmt::Display;

pub use dotnet_trace_manager::*;
pub use eventpipe::*;
pub use events::*;
pub use markers::*;
pub use provider::*;

#[derive(Debug, Clone)]
pub struct CoreClrProviderProps {
    pub is_attach: bool,
    pub gc_markers: bool,
    pub gc_suspensions: bool,
    pub gc_detailed_allocs: bool,
    pub event_stacks: bool,
}

pub(crate) struct SavedMarkerInfo {
    pub start_timestamp_raw: u64,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct CoreClrMethodName {
    pub name: String,
    pub namespace: String,
    pub signature: String,
}

impl Display for CoreClrMethodName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{name} [{namespace}] \u{2329}{signature}\u{232a}",
            name = self.name,
            namespace = self.namespace,
            signature = self.signature
        )
    }
}
