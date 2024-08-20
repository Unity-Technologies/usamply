// The coreclr module contains the various coreclr event types, as well
// as the tools to convert ETW and eventpipe events into the generic event
// corelcr types.
mod coreclr;
pub use coreclr::*;

// The nettrace module handles parsing of nettrace files.
pub mod nettrace;

#[derive(Debug, Clone)]
pub struct EventMetadata {
    pub timestamp: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub stack: Option<Vec<u64>>,
    pub is_rundown: bool,
}

impl EventMetadata {
    #[allow(unused)]
    fn with_stack(mut self, stack: Vec<u64>) -> Self {
        self.stack = Some(stack);
        self
    }

    #[allow(unused)]
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.process_id = pid;
        self
    }
}
