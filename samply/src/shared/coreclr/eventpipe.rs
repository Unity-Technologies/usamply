use super::{CoreClrEvent, CoreClrMethodName, ReadyToRunMethodEntryPointEvent};
use eventpipe::{coreclr::decode_coreclr_event, NettraceEvent};

type EventPipeEvent = eventpipe::coreclr::CoreClrEvent;

// Given a NettraceEvent, convert it to a samply cross-platform CoreClrEvent.
pub fn eventpipe_event_to_coreclr_event(
    process_id: u32,
    ne: &NettraceEvent,
) -> Option<CoreClrEvent> {
    // Convert the NettraceEvent to a eventpipe CoreClrEvent, then convert that to
    // a samply CoreClrEvent
    let Some(event) = decode_coreclr_event(ne) else {
        return None;
    };

    let common = super::EventCommon {
        timestamp: ne.timestamp,
        process_id,
        thread_id: ne.thread_id as u32,
        stack: if ne.stack.len() > 0 {
            Some(ne.stack.clone())
        } else {
            None
        },
    };

    match &event {
        EventPipeEvent::ModuleLoad(m) |
        EventPipeEvent::ModuleUnload(m) => {
            let e = super::ModuleLoadUnloadEvent {
                common,
                module_id: m.module_id,
                assembly_id: m.assembly_id,
                app_domain_id: m.app_domain_id,
                module_il_path: m.module_il_path.to_string(),
                module_native_path: m.module_native_path.to_string(),
            };

            match &event {
                EventPipeEvent::ModuleLoad(_) => Some(CoreClrEvent::ModuleLoad(e)),
                EventPipeEvent::ModuleUnload(_) => Some(CoreClrEvent::ModuleUnload(e)),
                _ => unreachable!()
            }
        }
        EventPipeEvent::ReadyToRunGetEntryPoint(method) => {
            let name = if method.method_name.is_empty() {
                format!("JIT[0x{:x}]", method.entry_point)
            } else {
                method.method_name.to_string()
            };
            Some(CoreClrEvent::ReadyToRunMethodEntryPoint(
                ReadyToRunMethodEntryPointEvent {
                    common,
                    start_address: method.entry_point,
                    name: CoreClrMethodName {
                        name,
                        namespace: method.method_namespace.to_string(),
                        signature: method.method_signature.to_string(),
                    },
                },
            ))
        }
        EventPipeEvent::MethodLoad(method) |
        EventPipeEvent::MethodDCEnd(method) => {
            let name = if method.method_name.is_empty() {
                format!("JIT[0x{:x}]", method.method_start_address)
            } else {
                method.method_name.to_string()
            };
            let dc_end = match &event {
                EventPipeEvent::MethodDCEnd(_) => true,
                _ => false,
            };
            let tier = (method.method_flags >> 7) & 0x7;
            let tier = match tier {
                1 => super::MethodCompilationTier::MinOptJitted,
                2 => super::MethodCompilationTier::Optimized,
                3 => super::MethodCompilationTier::QuickJitted,
                4 => super::MethodCompilationTier::OptimizedTier1,
                5 => super::MethodCompilationTier::OptimizedTier1OSR,
                6 => super::MethodCompilationTier::InstrumentedTier,
                7 => super::MethodCompilationTier::InstrumentedTierOptimized,
                _ => super::MethodCompilationTier::Unknown,
            };

            Some(CoreClrEvent::MethodLoad(super::MethodLoadEvent {
                common,
                module_id: method.module_id,
                start_address: method.method_start_address,
                size: method.method_size,
                name: CoreClrMethodName {
                    name,
                    namespace: method.method_namespace.to_string(),
                    signature: method.method_signature.to_string(),
                },
                tier,
                dc_end
            }))
        }
        EventPipeEvent::MethodUnload(method) => {
            Some(CoreClrEvent::MethodUnload(super::MethodUnloadEvent {
                common,
                start_address: method.method_start_address,
                size: method.method_size,
            }))
        }
        EventPipeEvent::GcTriggered(gc) => {
            Some(CoreClrEvent::GcTriggered(super::GcTriggeredEvent {
                common,
                reason: gc.reason,
                clr_instance_id: gc.clr_instance_id,
            }))
        }
        EventPipeEvent::GcAllocationTick(tick) => Some(CoreClrEvent::GcAllocationTick(
            super::GcAllocationTickEvent {
                common,
                kind: tick.allocation_kind,
                size: tick.allocation_amount64,
                type_name: Some(format!("Type[{}]", tick.type_id)),
                type_namespace: None,
            },
        )),
        EventPipeEvent::GcSampledObjectAllocation(alloc) => Some(
            CoreClrEvent::GcSampledObjectAllocation(super::GcSampledObjectAllocationEvent {
                common,
                address: alloc.address,
                type_name: Some(format!("Type[{}]", alloc.type_id)),
                type_namespace: None,
                object_count: alloc.object_count_for_type_sample,
                total_size: alloc.total_size_for_type_sample,
            }),
        ),
    }
}
