// The coreclr module contains the various coreclr event types, as well
// as the tools to convert ETW and eventpipe events into the generic event
// corelcr types.
mod coreclr;
pub use coreclr::*;

// The nettrace module handles parsing of nettrace files.
pub mod nettrace;

#[derive(Debug)]
pub struct EventMetadata {
    pub timestamp: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub stack: Option<Vec<u64>>,
}

impl EventMetadata {
    fn with_stack(mut self, stack: Vec<u64>) -> Self {
        self.stack = Some(stack);
        self
    }
}
