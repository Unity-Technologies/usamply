use std::future::pending;
use std::{collections::HashMap, convert::TryInto};

use crate::EventMetadata;
use super::*;
use num_traits::FromPrimitive;

use etw_reader::{self, schema::TypedEvent};
use etw_reader::parser::{Parser, TryParse};

pub struct CoreClrEtwConverter {
    last_event_on_thread: HashMap<u32, (EventMetadata, CoreClrEvent)>,
}

impl CoreClrEtwConverter {
    pub fn new() -> Self {
        Self {
            last_event_on_thread: HashMap::new(),
        }
    }

    pub fn remaining_clr_events_on_threads(
        &mut self,
    ) -> std::collections::hash_map::IntoIter<u32, (EventMetadata, CoreClrEvent)> {
        std::mem::take(&mut self.last_event_on_thread).into_iter()
    }

    pub fn etw_event_to_coreclr_event(
        &mut self,
        s: &TypedEvent,
        parser: &mut Parser,
    ) -> Option<(EventMetadata, CoreClrEvent)> {
        let timestamp_raw = s.timestamp() as u64;

        let mut name_parts = s.name().splitn(3, '/');
        let provider = name_parts.next().unwrap();
        let mut task = name_parts.next().unwrap();
        let mut opcode = name_parts.next().unwrap();

        match provider {
            "Microsoft-Windows-DotNETRuntime" | "Microsoft-Windows-DotNETRuntimeRundown" => {}
            _ => {
                panic!("Unexpected event {}", s.name())
            }
        }

        // When working with merged ETL files, the proper task and opcode names appear here, e.g. "CLRMethod/MethodLoadVerbose" or
        // "CLRMethodRundown/MethodDCStartVerbose". When working with the unmerged user ETL, these show up as e.g. "Method /DCStartVerbose".
        // Not clear where those names come from the Etw .man file in CoreCLR does have entries for e.g. RuntimePublisher.MethodDCStartVerboseOpcodeMessage
        // as "DCStartVerbose", but I'm not sure how/why those are referenced here and not in the merged ETL. xperf -a dumper on the unmerged
        // ETL shows the same (correct) names as the merged ETL.
        //
        // We try to hack around this by converting the unmerged name to the converted one here.
        if task.ends_with(' ') || opcode.ends_with(' ') {
            task = task.trim();
            opcode = opcode.trim();

            // Some of these are technically not correct; e.g. the task should be CLRMethodRundown if it's the
            // rundown provider, but we handle them the same below.
            match task {
                "Method" => {
                    task = "CLRMethod";
                    opcode = match opcode {
                        "LoadVerbose" => "MethodLoadVerbose",
                        "UnloadVerbose" => "MethodUnloadVerbose",
                        "DCStartVerbose" => "MethodDCStartVerbose",
                        "DCEndVerbose" => "MethodDCEndVerbose",
                        "JittingStarted" => "MethodJittingStarted",
                        _ => opcode.trim(),
                    };
                },
                "Loader" => {
                    task = "CLRLoader";
                    opcode = match opcode {
                        "ModuleDCStart" => "ModuleDCStart",
                        _ => opcode.trim(),
                    };
                },
                "Runtime" => {
                    task = "CLRRuntimeInformation";
                    opcode = opcode.trim();
                },
                "GC" => {
                    task = "GarbageCollection";
                    opcode = match opcode {
                        "PerHeapHisory" => opcode,
                        "GCDynamicEvent" => opcode,
                        "Start" => "win:Start",
                        "Stop" => "win:Stop",
                        "RestartEEStart" => "GCRestartEEBegin",
                        "RestartEEStop" => "GCRestartEEEnd",
                        "SuspendEEStart" => "GCSuspendEEBegin",
                        "SuspendEEStop" => "GCSuspendEEEnd",
                        _ => opcode.trim(),
                    };
                },
                "ClrStack" => {
                    task = "CLRStack";
                    opcode = match opcode {
                        "Walk" => "CLRStackWalk",
                        _ => opcode.trim(),
                    };
                },
                _ => {},
            }
        }

        let pid = s.process_id();
        let tid = s.thread_id();

        // ETW CoreCLR stackwalk events are a separate event that comes after the event to which
        // it should be attached. Our cross-platform CoreCLR events have the stack as an optional
        // part of every event. So, if we're recording stacks from ETW, instead of returning
        // non-stackwalk events directly, we store them as the last event for a given thread so
        // that we can attach a stack.
        //
        // If we have a pending event and we get a stackwalk event, we'll attach the stack and
        // return the pending event.
        // If we get a non-stackwalk event, we'll store it, and still return this previous
        // pending event.
        let pending_event = self.last_event_on_thread.remove(&tid);

        // Handle StackWalk events outside of the big match below for cleanliness
        if (task, opcode) == ("CLRStack", "CLRStackWalk") {
            // If the STACK keyword is enabled, we get a CLRStackWalk following each CLR event that supports stacks. Not every event
            // does. The info about which does and doesn't is here: https://github.com/dotnet/runtime/blob/main/src/coreclr/vm/ClrEtwAllMeta.lst
            // Current dotnet (8.0.x) seems to have a bug where `MethodJitMemoryAllocatedForCode` events will fire a stackwalk,
            // but the event itself doesn't end up in the trace. (https://github.com/dotnet/runtime/issues/102004)

            // if we don't have anything to attach this stack to, just skip it
            if pending_event.is_none() {
                return None;
            }

            let pending_event = pending_event.unwrap();

            // "Stack" is explicitly declared as length 2 in the manifest, so the first two addresses are in here, rest
            // are in user data buffer.
            let first_addresses: Vec<u8> = parser.parse("Stack");
            let address_iter = first_addresses
                .chunks_exact(8)
                .chain(parser.buffer.chunks_exact(8))
                .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()));

            return Some((pending_event.0.with_stack(address_iter.collect()), pending_event.1));
        }

        let common = EventMetadata {
            timestamp: timestamp_raw,
            process_id: pid,
            thread_id: tid,
            stack: None,
        };

        let new_event = match (task, opcode) {
            ("CLRMethod" | "CLRMethodRundown", method_event) => match method_event {
                "MethodLoadVerbose" | "MethodDCStartVerbose" | "MethodDCEndVerbose" => {
                    let method_name: String = parser.parse("MethodName");
                    let method_namespace: String = parser.parse("MethodNamespace");
                    let method_signature: String = parser.parse("MethodSignature");
                    let module_id: u64 = parser.parse("ModuleID");
                    let method_id: u64 = parser.parse("MethodID");
                    let method_flags: u32 = parser.parse("MethodFlags");
                    let method_token: u32 = parser.parse("MethodToken");
                    let clr_instance_id: Option<u16> = parser.try_parse("ClrInstanceID").ok();
                    let re_jit_id: Option<u64> = parser.try_parse("ReJITID").ok();

                    let method_start_address: u64 = parser.parse("MethodStartAddress");
                    let method_size: u32 = parser.parse("MethodSize");

                    let dc_end = method_event == "MethodDCEndVerbose";

                    //log::trace!("{}: @ {:x} {}::{} {}", opcode, method_start_address, method_namespace, method_basename, method_signature);

                    Some(CoreClrEvent::MethodLoad(MethodLoadUnloadEvent {
                        module_id,
                        method_start_address,
                        method_size,
                        method_name,
                        method_namespace,
                        method_signature,
                        method_id,
                        method_token,
                        method_flags,
                        clr_instance_id,
                        re_jit_id,
                    }))
                }
                _ => None,
            },
            ("CLRLoader" | "CLRLoaderRundown", loader_event) => match loader_event {
                // AppDomain, Assembly, Module Load/Unload
                "ModuleDCStart" | _ => None,
            },
            ("GarbageCollection", gc_event) => {
                match gc_event {
                    "GCSampledObjectAllocation" => {
                        // If High/Low flags are set, then we get one of these for every alloc. Otherwise only
                        // when a threshold is hit. (100kb) The count and size are aggregates in that case.
                        let type_id: u64 = parser.parse("TypeID"); // TODO: convert to str, with bulk type data
                        let address: u64 = parser.parse("Address");
                        let object_count_for_type_sample: u32 = parser.parse("ObjectCountForTypeSample");
                        let total_size_for_type_sample: u64 = parser.parse("TotalSizeForTypeSample");
                        let clr_instance_id: u16 = parser.parse("ClrInstanceID");

                        Some(CoreClrEvent::GcSampledObjectAllocation(
                            GcSampledObjectAllocationEvent {
                                address,
                                type_id,
                                object_count_for_type_sample,
                                total_size_for_type_sample,
                                clr_instance_id,
                            },
                        ))
                    }
                    "Triggered" => {
                        let reason: u32 = parser.parse("Reason");
                        let reason = GcReason::from_u32(reason).unwrap_or_else(|| {
                            log::warn!("Unknown CLR GC Triggered reason: {}", reason);
                            GcReason::Empty
                        });

                        Some(CoreClrEvent::GcTriggered(GcTriggeredEvent {
                            reason,
                            clr_instance_id: 0,
                        }))
                    }
                    "GCSuspendEEBegin" => {
                        // Reason, Count
                        //let _count: u32 = parser.parse("Count");
                        let reason: u32 = parser.parse("Reason");

                        let _reason = GcSuspendEeReason::from_u32(reason).unwrap_or_else(|| {
                            log::warn!("Unknown CLR GCSuspendEEBegin reason: {}", reason);
                            GcSuspendEeReason::Other
                        });

                        //Some(CoreClrEvent::GcSuspendEeBegin(GcSuspendEeBeginEvent {
                        //    common,
                        //    reason,
                        //}))
                        // TODO
                        None
                    }
                    "GCSuspendEEEnd" => {
                        // TODO
                        None
                    }
                    "GCRestartEEBegin" => {
                        // TODO
                        None
                    }
                    "GCRestartEEEnd" => {
                        // TODO
                        None
                    }
                    "win:Start" => {
                        let count: u32 = parser.parse("Count");
                        let depth: Option<u32> = parser.try_parse("Depth").ok();
                        let reason: u32 = parser.parse("Reason");
                        let gc_type = parser.try_parse("Type").ok().and_then(GcType::from_u32);
                        let clr_instance_id: Option<u16> = parser.try_parse("ClrInstanceID").ok();
                        let client_sequence_number: Option<u64> = parser.try_parse("ClientSequenceNumber").ok();

                        let reason = GcReason::from_u32(reason).unwrap_or_else(|| {
                            log::warn!("Unknown CLR GCStart reason: {}", reason);
                            GcReason::Empty
                        });

                        Some(CoreClrEvent::GcStart(GcStartEvent {
                            count,
                            depth,
                            reason,
                            gc_type,
                            clr_instance_id,
                            client_sequence_number,
                        }))
                    }
                    "win:Stop" => {
                        let count: u32 = parser.parse("Count");
                        let depth: u32 = parser.parse("Depth");
                        let reason = parser.try_parse("Reason").ok().and_then(GcReason::from_u32);
                        Some(CoreClrEvent::GcEnd(GcEndEvent {
                            count,
                            depth,
                            reason,
                        }))
                    }
                    "SetGCHandle" => {
                        // TODO
                        None
                    }
                    "DestroyGCHandle" => {
                        // TODO
                        None
                    }
                    "GCFinalizersBegin" | "GCFinalizersEnd" | "FinalizeObject" => {
                        // TODO: create an interval
                        None
                    }
                    "GCCreateSegment" | "GCFreeSegment" | "GCDynamicEvent" | "GCHeapStats" => {
                        // don't care
                        None
                    }
                    _ => {
                        // don't care
                        None
                    }
                }
            }
            ("CLRRuntimeInformation", _) => None,
            _ => None,
        };

        if new_event.is_some() {
            self.last_event_on_thread.insert(tid, (common, new_event.unwrap()));
        }

        pending_event
    }
}
