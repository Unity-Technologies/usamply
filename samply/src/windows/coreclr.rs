use bitflags::bitflags;
use std::{collections::HashMap, convert::TryInto, fmt::Display};

use coreclr_tracing::{CoreClrEvent, EventMetadata, GcReason, GcSuspendEeReason, GcType};
use fxprof_processed_profile::*;
use num_traits::FromPrimitive;

use etw_reader::{self, schema::TypedEvent};
use etw_reader::{
    event_properties_to_string,
    parser::{Parser, TryParse},
};

use crate::shared::coreclr::*;
use crate::shared::process_sample_data::SimpleMarker;

use crate::windows::profile_context::{KnownCategory, ProfileContext};

use super::elevated_helper::ElevatedRecordingProps;

pub struct CoreClrContext {
    pub props: CoreClrProviderProps,
    pub unknown_event_markers: bool,

    last_marker_on_thread: HashMap<u32, (ThreadHandle, MarkerHandle)>,
    gc_markers_on_thread: HashMap<u32, HashMap<&'static str, SavedMarkerInfo>>,

    pub last_n: String,
}

impl CoreClrContext {
    pub fn new(context: &ProfileContext) -> Self {
        Self {
            props: context.creation_props().coreclr.to_provider_props(),
            unknown_event_markers: context.creation_props().unknown_event_markers,

            last_marker_on_thread: HashMap::new(),
            gc_markers_on_thread: HashMap::new(),
            last_n: String::new(),
        }
    }

    fn remove_last_event_for_thread(&mut self, tid: u32) -> Option<(ThreadHandle, MarkerHandle)> {
        self.last_marker_on_thread.remove(&tid)
    }

    fn set_last_event_for_thread(&mut self, tid: u32, thread_marker: (ThreadHandle, MarkerHandle)) {
        self.last_marker_on_thread.insert(tid, thread_marker);
    }

    fn save_gc_marker(
        &mut self,
        tid: u32,
        start_timestamp_raw: u64,
        event: &'static str,
        name: String,
        description: String,
    ) {
        self.gc_markers_on_thread.entry(tid).or_default().insert(
            event,
            SavedMarkerInfo {
                start_timestamp_raw,
                name,
                description,
            },
        );
    }

    fn remove_gc_marker(&mut self, tid: u32, event: &str) -> Option<SavedMarkerInfo> {
        self.gc_markers_on_thread
            .get_mut(&tid)
            .and_then(|m| m.remove(event))
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct DisplayUnknownIfNone<'a, T>(pub &'a Option<T>);

impl<'a, T: Display> Display for DisplayUnknownIfNone<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(value) => value.fmt(f),
            None => f.write_str("Unknown"),
        }
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
        CoreClrEvent::GcTriggered(e) if is_in_time_range && gc_markers => {
            let category = context.known_category(KnownCategory::CoreClrGc);
            let mh = context.add_thread_instant_marker(
                event_meta.timestamp,
                event_meta.thread_id,
                CoreClrGcMarker(category));
            coreclr_context.set_last_event_for_thread(event_meta.thread_id, mh);
        }
        CoreClrEvent::GcAllocationTick(e) if is_in_time_range && gc_allocs => {}
        CoreClrEvent::GcSampledObjectAllocation(e) if is_in_time_range && gc_allocs => {
            let type_name_str = context.intern_profile_string(&format!("type{}", e.type_id));
            let category = context.known_category(KnownCategory::CoreClrGc);
            let mh = context.add_thread_instant_marker(
                event_meta.timestamp,
                event_meta.thread_id,
                CoreClrGcAllocMarker(type_name_str, e.total_size_for_type_sample as usize, category));
            coreclr_context.set_last_event_for_thread(event_meta.thread_id, mh);
        }
        CoreClrEvent::GcStart(e) if is_in_time_range && gc_markers => {
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
        CoreClrEvent::GcEnd(e) if is_in_time_range && gc_markers => {
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
