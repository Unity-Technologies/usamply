use bitflags::bitflags;

use coreclr_tracing::{CoreClrEvent, EventMetadata, GcReason, GcSuspendEeReason, GcType};

use crate::shared::coreclr::*;

use crate::windows::profile_context::{KnownCategory, ProfileContext};

use super::elevated_helper::ElevatedRecordingProps;

pub struct CoreClrContext {
    pub props: CoreClrProviderProps,
}

impl CoreClrContext {
    pub fn new(context: &ProfileContext) -> Self {
        Self {
            props: context.creation_props().coreclr.to_provider_props(),
        }
    }
}

bitflags! {
    #[derive(PartialEq, Eq)]
    pub struct CoreClrMethodFlagsMap: u32 {
        const dynamic = 0x1;
        const generic = 0x2;
        const has_shared_generic_code = 0x4;
        const jitted = 0x8;
        const jit_helper = 0x10;
        const profiler_rejected_precompiled_code = 0x20;
        const ready_to_run_rejected_precompiled_code = 0x40;

        // next three bits are the tiered compilation level
        const opttier_bit0 = 0x80;
        const opttier_bit1 = 0x100;
        const opttier_bit2 = 0x200;

        // extent flags/value (hot/cold)
        const extent_bit_0 = 0x10000000; // 0x1 == cold, 0x0 = hot
        const extent_bit_1 = 0x20000000; // always 0 for now looks like
        const extent_bit_2 = 0x40000000;
        const extent_bit_3 = 0x80000000;

        const _ = !0;
    }
    #[derive(PartialEq, Eq)]
    pub struct TieredCompilationSettingsMap: u32 {
        const None = 0x0;
        const QuickJit = 0x1;
        const QuickJitForLoops = 0x2;
        const TieredPGO = 0x4;
        const ReadyToRun = 0x8;
    }
}

pub fn coreclr_xperf_args(props: &ElevatedRecordingProps) -> Vec<String> {
    if !props.coreclr.any_enabled() {
        return vec![];
    }

    // copy matching property names from props.coreclr into CoreClrProviderProperties
    let coreclr_props = CoreClrProviderProps {
        is_attach: props.is_attach,
        gc_markers: props.coreclr.gc_markers,
        gc_suspensions: props.coreclr.gc_suspensions,
        gc_detailed_allocs: props.coreclr.gc_detailed_allocs,
        event_stacks: props.coreclr.event_stacks,
    };

    coreclr_provider_args(coreclr_props)
}

pub fn handle_coreclr_tracing_event(
    context: &mut ProfileContext,
    coreclr_context: &mut CoreClrContext,
    event_meta: &EventMetadata,
    event_coreclr: &CoreClrEvent,
    is_in_time_range: bool,
) {
    let (gc_markers, gc_suspensions, gc_allocs) = (
        coreclr_context.props.gc_markers,
        coreclr_context.props.gc_suspensions,
        coreclr_context.props.gc_detailed_allocs,
    );

    // Handle events that we need to handle whether in time range or not first

    match event_coreclr {
        CoreClrEvent::MethodLoad(e) => {
            let method_basename = e.method_name.to_string();
            let method_namespace = e.method_namespace.to_string();
            let method_signature = e.method_signature.to_string();
            let method_name = CoreClrMethodName::format(&method_basename, &method_namespace, &method_signature);
            context.handle_coreclr_method_load(
                event_meta.timestamp,
                event_meta.process_id,
                method_name,
                e.method_start_address,
                e.method_size,
            );
        }
        CoreClrEvent::MethodUnload(_e) => {
            // don't care
        }
        CoreClrEvent::GcTriggered(_e) if is_in_time_range && gc_markers => {
            let category = context.known_category(KnownCategory::CoreClrGc);
            let m = context.add_thread_instant_marker(
                event_meta.timestamp,
                event_meta.thread_id,
                CoreClrGcMarker(category));
            if let Some(stack) = event_meta.stack.as_ref() {
                context.handle_coreclr_stack(event_meta.timestamp, event_meta.process_id, stack.iter().map(|v| *v), m);
            }
        }
        CoreClrEvent::GcAllocationTick(e) if is_in_time_range && gc_allocs => {
            let type_name_str = context.intern_profile_string(&e.type_name);
            let category = context.known_category(KnownCategory::CoreClrGc);
            let amount = if e.allocation_amount64 != 0 { e.allocation_amount64 as usize } else { e.allocation_amount as usize };
            let m = context.add_thread_instant_marker(
                event_meta.timestamp,
                event_meta.thread_id,
                CoreClrGcAllocTickMarker(type_name_str, amount, category));
            if let Some(stack) = event_meta.stack.as_ref() {
                context.handle_coreclr_stack(event_meta.timestamp, event_meta.process_id, stack.iter().map(|v| *v), m);
            }
        }
        CoreClrEvent::GcSampledObjectAllocation(e) if is_in_time_range && gc_allocs => {
            let type_name_str = context.intern_profile_string(&format!("type{}", e.type_id));
            let category = context.known_category(KnownCategory::CoreClrGc);
            let m = context.add_thread_instant_marker(
                event_meta.timestamp,
                event_meta.thread_id,
                CoreClrGcAllocMarker(type_name_str, e.total_size_for_type_sample as usize, category));
            if let Some(stack) = event_meta.stack.as_ref() {
                context.handle_coreclr_stack(event_meta.timestamp, event_meta.process_id, stack.iter().map(|v| *v), m);
            }
        }
        CoreClrEvent::GcStart(_e) if is_in_time_range && gc_markers => {
            // TODO: save this start marker, and emit a range when we get a GcEnd
            // TODO: save this as a CoreClrGcDetailedMarker, instead of putting
            // the types, reason, GC# and generation into a string
            /*
            // TODO: use gc_type_str as the name
            coreclr_context.save_gc_marker(
                event_meta.thread_id,
                e.common.timestamp,
                format!(
                    "{}: {} (GC #{}, gen{})",
                    DisplayUnknownIfNone(&e.gc_type),
                    e.reason,
                    e.count,
                    DisplayUnknownIfNone(&e.depth)
                ),
            );
            */
        }
        CoreClrEvent::GcEnd(_e) if is_in_time_range && gc_markers => {
            /*
            if let Some(info) = coreclr_context.remove_gc_marker(event_meta.thread_id, "GC") {
                context.add_thread_interval_marker(
                    info.start_timestamp_raw,
                    e.common.timestamp,
                    event_meta.thread_id,
                    KnownCategory::CoreClrGc,
                    &info.name,
                    CoreClrGcEventMarker(info.description),
                );
            }
            */
        }
        _ => {}
    }
}
