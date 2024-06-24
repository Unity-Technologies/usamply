#![allow(unused)]

pub use eventpipe::coreclr::{GcAllocationKind, GcReason, GcType};

use super::CoreClrMethodName;

#[derive(Debug)]
pub enum CoreClrEvent {
    ModuleLoad(ModuleLoadUnloadEvent),
    ModuleUnload(ModuleLoadUnloadEvent),
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
            CoreClrEvent::ModuleLoad(ref mut e) => {
                e.common.stack = Some(stack);
            }
            CoreClrEvent::ModuleUnload(ref mut e) => {
                e.common.stack = Some(stack);
            }
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

#[derive(Debug, Clone)]
pub struct EventCommon {
    pub timestamp: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub stack: Option<Vec<u64>>,
}

#[derive(Debug, Clone)]
pub enum MethodCompilationTier {
    Unknown,
    MinOptJitted,
    Optimized,
    QuickJitted,
    OptimizedTier1,
    OptimizedTier1OSR,
    InstrumentedTier,
    InstrumentedTierOptimized,
}

#[derive(Debug, Clone)]
pub struct ModuleLoadUnloadEvent {
    pub common: EventCommon,
    pub module_id: u64,
    pub assembly_id: u64,
    pub app_domain_id: Option<u64>,
    pub module_il_path: String,
    pub module_native_path: String,
}

#[derive(Debug, Clone)]
pub struct MethodLoadEvent {
    pub common: EventCommon,
    pub module_id: u64,
    pub start_address: u64,
    pub size: u32,
    pub name: CoreClrMethodName,
    pub tier: MethodCompilationTier,
    pub dc_end: bool,
}

#[derive(Debug, Clone)]
pub struct MethodUnloadEvent {
    pub common: EventCommon,
    pub start_address: u64,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct GcTriggeredEvent {
    pub common: EventCommon,
    pub reason: GcReason,
    pub clr_instance_id: u16,
}

#[derive(Debug, Clone)]
pub struct GcAllocationTickEvent {
    pub common: EventCommon,
    pub kind: GcAllocationKind,
    pub size: u64,
    pub type_name: Option<String>,
    pub type_namespace: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GcSampledObjectAllocationEvent {
    pub common: EventCommon,
    pub address: u64,
    pub type_name: Option<String>,
    pub type_namespace: Option<String>,
    pub object_count: u32, // number of objects in this sample
    pub total_size: u64,   // total size of all objects
}

#[derive(Debug, Clone)]
pub struct GcStartEvent {
    pub common: EventCommon,
    pub count: u32,
    pub reason: GcReason,
    pub depth: Option<u32>,
    pub gc_type: Option<GcType>,
}

#[derive(Debug, Clone)]
pub struct GcEndEvent {
    pub common: EventCommon,
    pub count: u32,
    pub depth: u32,
    pub reason: Option<GcReason>,
}

#[derive(Debug, Clone)]
pub struct ReadyToRunMethodEntryPointEvent {
    pub common: EventCommon,
    pub start_address: u64,
    pub name: CoreClrMethodName,
}
