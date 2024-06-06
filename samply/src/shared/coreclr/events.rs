pub use eventpipe::coreclr::{GcAllocationKind, GcReason, GcType};

use super::CoreClrMethodName;

#[derive(Debug)]
pub enum CoreClrEvent {
    MethodLoad(MethodLoadEvent),
    MethodUnload(MethodUnloadEvent),
    GcTriggered(GcTriggeredEvent),
    GcAllocationTick(GcAllocationTickEvent),
    GcSampledObjectAllocation(GcSampledObjectAllocationEvent),
    GcStart(GcStartEvent),
    GcEnd(GcEndEvent),
    ReadyToRunMethodEntryPoint(ReadyToRunMethodEntryPointEvent),
}

impl CoreClrEvent {
    #[allow(unused)]
    pub fn with_stack(mut self, stack: Vec<u64>) -> Self {
        match self {
            CoreClrEvent::MethodLoad(ref mut e) => {
                e.common.stack = Some(stack);
            }
            CoreClrEvent::MethodUnload(ref mut e) => {
                e.common.stack = Some(stack);
            }
            CoreClrEvent::GcTriggered(ref mut e) => {
                e.common.stack = Some(stack);
            }
            CoreClrEvent::GcAllocationTick(ref mut e) => {
                e.common.stack = Some(stack);
            }
            CoreClrEvent::GcSampledObjectAllocation(ref mut e) => {
                e.common.stack = Some(stack);
            }
            CoreClrEvent::GcStart(ref mut e) => {
                e.common.stack = Some(stack);
            }
            CoreClrEvent::GcEnd(ref mut e) => {
                e.common.stack = Some(stack);
            }
            CoreClrEvent::ReadyToRunMethodEntryPoint(ref mut e) => {
                e.common.stack = Some(stack);
            }
        }
        self
    }
}

#[derive(Debug)]
pub struct EventCommon {
    pub timestamp: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub stack: Option<Vec<u64>>,
}

#[derive(Debug)]
pub struct MethodLoadEvent {
    pub common: EventCommon,
    pub start_address: u64,
    pub size: u32,
    pub name: CoreClrMethodName,
}

#[derive(Debug)]
pub struct MethodUnloadEvent {
    pub common: EventCommon,
    pub start_address: u64,
    pub size: u32,
}

#[derive(Debug)]
pub struct GcTriggeredEvent {
    pub common: EventCommon,
    pub reason: GcReason,
    pub clr_instance_id: u16,
}

#[derive(Debug)]
pub struct GcAllocationTickEvent {
    pub common: EventCommon,
    pub kind: GcAllocationKind,
    pub size: u64,
    pub type_name: Option<String>,
    pub type_namespace: Option<String>,
}

#[derive(Debug)]
pub struct GcSampledObjectAllocationEvent {
    pub common: EventCommon,
    pub address: u64,
    pub type_name: Option<String>,
    pub type_namespace: Option<String>,
    pub object_count: u32, // number of objects in this sample
    pub total_size: u64,   // total size of all objects
}

#[derive(Debug)]
pub struct GcStartEvent {
    pub common: EventCommon,
    pub count: u32,
    pub reason: GcReason,
    pub depth: Option<u32>,
    pub gc_type: Option<GcType>,
}

#[derive(Debug)]
pub struct GcEndEvent {
    pub common: EventCommon,
    pub count: u32,
    pub depth: u32,
    pub reason: Option<GcReason>,
}

#[derive(Debug)]
pub struct ReadyToRunMethodEntryPointEvent {
    pub common: EventCommon,
    pub start_address: u64,
    pub name: CoreClrMethodName,
}
