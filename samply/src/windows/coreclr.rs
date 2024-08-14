use bitflags::bitflags;
use std::{collections::HashMap, convert::TryInto, fmt::Display};

use eventpipe::coreclr::{GcSuspendEeReason, GcType};
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

pub fn handle_coreclr_event(
    context: &mut ProfileContext,
    coreclr_context: &mut CoreClrContext,
    s: &TypedEvent,
    parser: &mut Parser,
    is_in_time_range: bool,
) {
    let (gc_markers, gc_suspensions, gc_allocs, event_stacks) = (
        coreclr_context.props.gc_markers,
        coreclr_context.props.gc_suspensions,
        coreclr_context.props.gc_detailed_allocs,
        coreclr_context.props.event_stacks,
    );

    let pid = s.process_id();
    let tid = s.thread_id();

    if !context.is_interesting_process(pid, None, None) {
        return;
    }

    let timestamp_raw = s.timestamp() as u64;

    let mut name_parts = s.name().splitn(3, '/');
    let provider = name_parts.next().unwrap();
    let task = name_parts.next().unwrap();
    let opcode = name_parts.next().unwrap();

    match provider {
        "Microsoft-Windows-DotNETRuntime" | "Microsoft-Windows-DotNETRuntimeRundown" => {}
        _ => {
            panic!("Unexpected event {}", s.name())
        }
    }

    // TODO -- we may need to use the rundown provider if we trace running processes
    // https://learn.microsoft.com/en-us/dotnet/framework/performance/clr-etw-providers

    // We get DbgID_RSDS for ReadyToRun loaded images, along with PDB files. We also get ModuleLoad events for the same:
    // this means we can ignore the ModuleLoadEvents because we'll get dbginfo already mapped properly when the image
    // is loaded.

    let mut handled = false;

    //eprintln!("event: {} [pid: {} tid: {}] {}", timestamp_raw, s.pid(), s.tid(), dotnet_event);

    // If we get a non-stackwalk event followed by a non-stackwalk event for a given thread,
    // clear out any marker that may have been created to make sure the stackwalk doesn't
    // get attached to the wrong thing.
    if (task, opcode) != ("CLRStack", "CLRStackWalk") {
        coreclr_context.remove_last_event_for_thread(tid);
    }

    match (task, opcode) {
        ("CLRMethod" | "CLRMethodRundown", method_event) => {
            match method_event {
            // there's MethodDCStart & MethodDCStartVerbose & MethodLoad
            // difference between *Verbose and not, is Verbose includes the names

            "MethodLoadVerbose" | "MethodDCStartVerbose"
            // | "R2RGetEntryPoint" // not sure we need this? R2R methods should be covered by PDB files
            => {
                // R2RGetEntryPoint shares a lot of fields with MethodLoadVerbose
                let is_r2r = method_event == "R2RGetEntryPoint";

                //let method_id: u64 = parser.parse("MethodID");
                //let clr_instance_id: u32 = parser.parse("ClrInstanceID"); // v1/v2 only

                let method_basename: String = parser.parse("MethodName");
                let method_namespace: String = parser.parse("MethodNamespace");
                let method_signature: String = parser.parse("MethodSignature");

                let method_start_address: u64 = if is_r2r { parser.parse("EntryPoint") } else { parser.parse("MethodStartAddress") };
                let method_size: u32 = parser.parse("MethodSize"); // TODO: R2R doesn't have a size?

                // There's a v0, v1, and v2 version of this event. There are rules in `eventtrace.cpp` in the runtime
                // that describe the rules, but basically:
                // - during a first-JIT, only a v1 (not v0 and not v2+) MethodLoad is emitted.
                // - during a re-jit, a v2 event is emitted.
                // - v2 contains a "NativeCodeId" field which will be nonzero in v2. 
                // - the unique key for a method extent is MethodId + MethodCodeId + extent (hot/cold)

                // there's some stuff in MethodFlags -- might be tiered JIT info?
                // also ClrInstanceID -- we probably won't have more than one runtime, but maybe.

                let method_name = format!("{method_basename} [{method_namespace}] \u{2329}{method_signature}\u{232a}");

                context.handle_coreclr_method_load(timestamp_raw, pid, method_name, method_start_address, method_size);
                handled = true;
            }
            "ModuleLoad" | "ModuleDCStart" |
            "ModuleUnload" | "ModuleDCEnd" => {
                // do we need this for ReadyToRun code?

                //let module_id: u64 = parser.parse("ModuleID");
                //let assembly_id: u64 = parser.parse("AssemblyId");
                //let managed_pdb_signature: u?? = parser.parse("ManagedPdbSignature");
                //let managed_pdb_age: u?? = parser.parse("ManagedPdbAge");
                //let managed_pdb_path: String = parser.parse("ManagedPdbPath");
                //let native_pdb_signature: u?? = parser.parse("NativePdbSignature");
                //let native_pdb_age: u?? = parser.parse("NativePdbAge");
                //let native_pdb_path: String = parser.parse("NativePdbPath");
                handled = true;
            }
            _ => {
                // don't care about any other CLRMethod events
                handled = true;
            }
        }
        }
        ("Type", "BulkType") => {
            //         <template tid="BulkType">
            // <data name="Count" inType="win:UInt32"    />
            // <data name="ClrInstanceID" inType="win:UInt16" />
            // <struct name="Values" count="Count" >
            // <data name="TypeID" inType="win:UInt64" outType="win:HexInt64" />
            // <data name="ModuleID" inType="win:UInt64" outType="win:HexInt64" />
            // <data name="TypeNameID" inType="win:UInt32" />
            // <data name="Flags" inType="win:UInt32" map="TypeFlagsMap"/>
            // <data name="CorElementType"  inType="win:UInt8" />
            // <data name="Name" inType="win:UnicodeString" />
            // <data name="TypeParameterCount" inType="win:UInt32" />
            // <data name="TypeParameters"  count="TypeParameterCount"  inType="win:UInt64" outType="win:HexInt64" />
            // </struct>
            // <UserData>
            // <Type xmlns="myNs">
            // <Count> %1 </Count>
            // <ClrInstanceID> %2 </ClrInstanceID>
            // </Type>
            // </UserData>
            //let count: u32 = parser.parse("Count");

            // uint32 + uint16 at the front (Count and ClrInstanceID), then struct of values. We don't need a Vec<u8> copy.
            //let values: Vec<u8> = parser.parse("Values");
            //let values = &s.user_buffer()[6..];

            //eprintln!("Type/BulkType count: {} user_buffer size: {} values len: {}", count, s.user_buffer().len(), values.len());
        }
        ("CLRStack", "CLRStackWalk") => {
            if !is_in_time_range {
                return;
            }
            // If the STACK keyword is enabled, we get a CLRStackWalk following each CLR event that supports stacks. Not every event
            // does. The info about which does and doesn't is here: https://github.com/dotnet/runtime/blob/main/src/coreclr/vm/ClrEtwAllMeta.lst
            // Current dotnet (8.0.x) seems to have a bug where `MethodJitMemoryAllocatedForCode` events will fire a stackwalk,
            // but the event itself doesn't end up in the trace. (https://github.com/dotnet/runtime/issues/102004)
            if !event_stacks {
                return;
            }

            // if we don't have anything to attach this stack to, just skip it
            let Some(marker) = coreclr_context.remove_last_event_for_thread(tid) else {
                return;
            };

            // "Stack" is explicitly declared as length 2 in the manifest, so the first two addresses are in here, rest
            // are in user data buffer.
            let first_addresses: Vec<u8> = parser.parse("Stack");
            let address_iter = first_addresses
                .chunks_exact(8)
                .chain(parser.buffer.chunks_exact(8))
                .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()));

            context.handle_coreclr_stack(timestamp_raw, tid, address_iter, marker);
            handled = true;
        }
        ("GarbageCollection", gc_event) => {
            // if we're not in the range, or if the thread isn't recorded (because --main-thread-only)
            if !is_in_time_range || !context.has_thread_at_time(tid, timestamp_raw) {
                return;
            }

            match gc_event {
                "GCSampledObjectAllocation" => {
                    if !gc_allocs {
                        return;
                    }

                    // If High/Low flags are set, then we get one of these for every alloc. Otherwise only
                    // when a threshold is hit. (100kb) The count and size are aggregates in that case.
                    // TODO: track whether we're sampling with HIGH/LOW set; if we are, then use GcAllocMarker.
                    // Otherwise, use GcAllocTickMarker
                    let type_id: u64 = parser.parse("TypeID"); // TODO: convert to str, with bulk type data
                                                               //let address: u64 = parser.parse("Address");
                    let _object_count: u32 = parser.parse("ObjectCountForTypeSample");
                    let total_size: u64 = parser.parse("TotalSizeForTypeSample");

                    let category = context.known_category(KnownCategory::CoreClrGc);
                    let clr_type = context.intern_profile_string(&format!("0x{:x}", type_id));
                    let mh = context.add_thread_instant_marker(
                        timestamp_raw,
                        tid,
                        CoreClrGcAllocMarker(clr_type, total_size as usize, category),
                    );
                    coreclr_context.set_last_event_for_thread(tid, mh);
                    handled = true;
                }
                "Triggered" => {
                    if !gc_markers {
                        return;
                    }

                    let reason: u32 = parser.parse("Reason");
                    let reason = GcReason::from_u32(reason).or_else(|| {
                        eprintln!("Unknown CLR GC Triggered reason: {}", reason);
                        None
                    });

                    let category = context.known_category(KnownCategory::CoreClrGc);
                    let name = context.intern_profile_string("GC Trigger");
                    let description = context.intern_profile_string(&format!(
                        "GC Trigger: {}",
                        DisplayUnknownIfNone(&reason)
                    ));
                    let mh = context.add_thread_instant_marker(
                        timestamp_raw,
                        tid,
                        CoreClrGcEventMarker(name, description, category),
                    );
                    coreclr_context.set_last_event_for_thread(tid, mh);
                    handled = true;
                }
                "GCSuspendEEBegin" => {
                    if !gc_suspensions {
                        return;
                    }

                    // Reason, Count
                    let _count: u32 = parser.parse("Count");
                    let reason: u32 = parser.parse("Reason");

                    let reason = GcSuspendEeReason::from_u32(reason).or_else(|| {
                        eprintln!("Unknown CLR GCSuspendEEBegin reason: {}", reason);
                        None
                    });

                    coreclr_context.save_gc_marker(
                        tid,
                        timestamp_raw,
                        "GCSuspendEE",
                        "GC Suspended Thread".to_owned(),
                        format!("Suspended: {}", DisplayUnknownIfNone(&reason)),
                    );
                    handled = true;
                }
                "GCSuspendEEEnd" | "GCRestartEEBegin" => {
                    // don't care -- we only care about SuspendBegin and RestartEnd
                    handled = true;
                }
                "GCRestartEEEnd" => {
                    if !gc_suspensions {
                        return;
                    }

                    if let Some(info) = coreclr_context.remove_gc_marker(tid, "GCSuspendEE") {
                        let category = context.known_category(KnownCategory::CoreClrGc);
                        let name = context.intern_profile_string(&info.name);
                        let description = context.intern_profile_string(&info.description);
                        context.add_thread_interval_marker(
                            info.start_timestamp_raw,
                            timestamp_raw,
                            tid,
                            CoreClrGcEventMarker(name, description, category),
                        );
                    }
                    handled = true;
                }
                "win:Start" => {
                    if !gc_markers {
                        return;
                    }

                    let count: u32 = parser.parse("Count");
                    let depth: u32 = parser.parse("Depth");
                    let reason: u32 = parser.parse("Reason");
                    let gc_type: u32 = parser.parse("Type");

                    let reason = GcReason::from_u32(reason).or_else(|| {
                        eprintln!("Unknown CLR GCStart reason: {}", reason);
                        None
                    });

                    let gc_type = GcType::from_u32(gc_type).or_else(|| {
                        eprintln!("Unknown CLR GCStart type: {}", gc_type);
                        None
                    });

                    // TODO: use gc_type_str as the name
                    coreclr_context.save_gc_marker(
                        tid,
                        timestamp_raw,
                        "GC",
                        "GC".to_owned(),
                        format!(
                            "{}: {} (GC #{}, gen{})",
                            DisplayUnknownIfNone(&gc_type),
                            DisplayUnknownIfNone(&reason),
                            count,
                            depth
                        ),
                    );
                    handled = true;
                }
                "win:Stop" => {
                    if !gc_markers {
                        return;
                    }

                    //let count: u32 = parser.parse("Count");
                    //let depth: u32 = parser.parse("Depth");
                    if let Some(info) = coreclr_context.remove_gc_marker(tid, "GC") {
                        let category = context.known_category(KnownCategory::CoreClrGc);
                        let name = context.intern_profile_string(&info.name);
                        let description = context.intern_profile_string(&info.description);
                        context.add_thread_interval_marker(
                            info.start_timestamp_raw,
                            timestamp_raw,
                            tid,
                            CoreClrGcEventMarker(name, description, category),
                        );
                    }
                    handled = true;
                }
                "SetGCHandle" => {
                    // TODO
                }
                "DestroyGCHandle" => {
                    // TODO
                }
                "GCFinalizersBegin" | "GCFinalizersEnd" | "FinalizeObject" => {
                    // TODO: create an interval
                    handled = true;
                }
                "GCCreateSegment" | "GCFreeSegment" | "GCDynamicEvent" | "GCHeapStats" => {
                    // don't care
                    handled = true;
                }
                _ => {
                    // don't care
                    handled = true;
                }
            }
        }
        ("CLRRuntimeInformation", _) => {
            handled = true;
        }
        ("CLRLoader", _) => {
            // AppDomain, Assembly, Module Load/Unload
            handled = true;
        }
        _ => {}
    }

    if !handled && coreclr_context.unknown_event_markers {
        let name = s.name().split_once('/').unwrap().1;
        let text = event_properties_to_string(s, parser, None);

        let str_handle = context.intern_profile_string(format!("{}: {}", name, text).as_str());

        let marker_handle = context.add_thread_instant_marker(
            timestamp_raw,
            tid,
            SimpleMarker(str_handle)
        );

        coreclr_context.set_last_event_for_thread(tid, marker_handle);
    }
}

pub fn handle_new_coreclr_event(
    context: &mut ProfileContext,
    coreclr_context: &mut CoreClrContext,
    event: &CoreClrEvent,
    is_in_time_range: bool,
) {
    let (gc_markers, gc_suspensions, gc_allocs) = (
        coreclr_context.props.gc_markers,
        coreclr_context.props.gc_suspensions,
        coreclr_context.props.gc_detailed_allocs,
    );

    // Handle events that we need to handle whether in time range or not first

    match event {
        CoreClrEvent::MethodLoad(e) => {
            let method_name = e.name.to_string();
            context.handle_coreclr_method_load(
                e.common.timestamp,
                e.common.process_id,
                method_name,
                e.start_address,
                e.size,
            );
        }
        CoreClrEvent::MethodUnload(e) => {
            // don't care
        }
        CoreClrEvent::GcTriggered(e) if is_in_time_range && gc_markers => {
            let category = context.known_category(KnownCategory::CoreClrGc);
            let mh = context.add_thread_instant_marker(
                e.common.timestamp,
                e.common.thread_id,
                CoreClrGcMarker(category));
            coreclr_context.set_last_event_for_thread(e.common.thread_id, mh);
        }
        CoreClrEvent::GcAllocationTick(e) if is_in_time_range && gc_allocs => {}
        CoreClrEvent::GcSampledObjectAllocation(e) if is_in_time_range && gc_allocs => {
            let type_name_str = context.intern_profile_string(&format!("{}", DisplayUnknownIfNone(&e.type_name)));
            let category = context.known_category(KnownCategory::CoreClrGc);
            let mh = context.add_thread_instant_marker(
                e.common.timestamp,
                e.common.thread_id,
                CoreClrGcAllocMarker(type_name_str, e.total_size as usize, category));
            coreclr_context.set_last_event_for_thread(e.common.thread_id, mh);
        }
        CoreClrEvent::GcStart(e) if is_in_time_range && gc_markers => {
            // TODO: save this as a CoreClrGcDetailedMarker, instead of putting
            // the types, reason, GC# and generation into a string
            /*
            // TODO: use gc_type_str as the name
            coreclr_context.save_gc_marker(
                e.common.thread_id,
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
            if let Some(info) = coreclr_context.remove_gc_marker(e.common.thread_id, "GC") {
                context.add_thread_interval_marker(
                    info.start_timestamp_raw,
                    e.common.timestamp,
                    e.common.thread_id,
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
