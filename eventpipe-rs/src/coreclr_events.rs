// CoreCLR needs from ETW:
//
// DOTNetProvider:
//
// CLRMethod | CLRMethodRundown
//   - MethodLoad_V1 (136), MethodUnLoad_V1 (137), MethodDCStart_V1 (137 -- Rundown), MethodDCEnd_V1 (138 -- Rundown)
//   - MethodLoadVerbose_V1 (143) | MethodDCStartVerbose_V1 (141)
//   - MethodDCEndVerbose (144)
//   - ModuleLoad_V2 (152) | ModuleUnload_V2 (153) | ModuleDCStart_V2 (153) | ModuleDCEnd_V2 (154)
//   - DomainModuleLoad_V1 (151) | DomainModuleDCStart_V1 (151 - rundown) | DomainModuleDCEnd_V1 (152 - rundown)
// Type
//   - BulkType
// CLRStack  (doesn't exist)
//   - CLRStackWalk
// GarbageCollection
//   - GCAllocationTick_V2 (10)
//   - GCSampledObjectAllocation
//   - Triggered
//   - GCSuspendEE (9)
//   - GCSuspendEEEnd (8)
//   - GCRestartEEBegin (7)
//   - GCRestartEEEnd (3)
//   - "win:Start" - GCStart_V1 - 1
//   - "win:Stop" - GCEnd_V1 - 2
//   - SetGCHandle
//   - DestroyGCHandle
//   - GCFinalizersBegin (14) | GCFinalizersEnd (13) | FinalizeObject
//   - GCCreateSegment (5) | GCFreeSegment (6) | GCDynamicEvent | GCHeapStats (4)
// XXX AppDomains
//   - AppDomainLoad_V1 (156) | AppDomainUnLoad_V1 (157)
//   - AppDomainDCStart_V1 (157 -- rundown) | AppDomainDCEnd_V1 (158 -- rundown)
//
// don't need:
//
// CLRRuntimeInformation
// CLRLoader

use bitflags::bitflags;

use std::{
    fmt::Display,
    io::{Cursor, Read, Seek},
};

use crate::coreclr_enums::*;
use crate::{MetadataDefinition, NettraceEvent};
use binrw::{BinRead, BinReaderExt, NullWideString};
use num_derive::{FromPrimitive, ToPrimitive};

#[derive(BinRead, Debug)]
#[br(little, import { version: u32, app_domain: bool })]
pub struct ModuleLoadUnloadEvent {
    pub module_id: u64,
    pub assembly_id: u64,
    #[br(if(app_domain))]
    pub app_domain_id: Option<u64>,
    pub module_flags: u32,
    pub _reserved1: u32,
    pub module_il_path: NullWideString,
    pub module_native_path: NullWideString,
    #[br(if(version >= 1))]
    pub clr_instance_id: Option<u16>,
    #[br(if(version >= 2))]
    pub managed_pdb_signature: [u8; 16],
    #[br(if(version >= 2))]
    pub managed_pdb_age: u32,
    #[br(if(version >= 2))]
    pub managed_pdb_build_path: NullWideString,
    #[br(if(version >= 2))]
    pub native_pdb_signature: [u8; 16],
    #[br(if(version >= 2))]
    pub native_pdb_age: u32,
    #[br(if(version >= 2))]
    pub native_pdb_build_path: NullWideString,
}

#[derive(BinRead, Debug)]
#[br(little, import { version: u32, verbose: bool })]
pub struct MethodLoadUnloadEvent {
    pub method_id: u64,
    pub module_id: u64,
    pub method_start_address: u64,
    pub method_size: u32,
    pub method_token: u32,
    pub method_flags: u32,

    #[br(if(verbose))]
    pub method_namespace: NullWideString,

    #[br(if(verbose))]
    pub method_name: NullWideString,

    #[br(if(verbose))]
    pub method_signature: NullWideString,

    #[br(if(version >= 1, None))]
    pub clr_instance_id: Option<u16>,

    #[br(if(version >= 2, None))]
    pub re_jit_id: Option<u64>,
}

#[derive(BinRead, Debug)]
#[br(little, import { version: u32 })]
pub struct GcTriggeredEvent {
    pub reason: GcReason,
    pub clr_instance_id: u16,
}

#[derive(BinRead, Debug)]
#[br(little, import { version: u32 })]
pub struct GcStartEvent {
    pub count: u32,
    #[br(if(version >= 1, None))]
    pub depth: Option<u32>,
    pub reason: GcReason,
    #[br(if(version >= 1, None))]
    pub gc_type: Option<GcType>,
    #[br(if(version >= 1, None))]
    pub clr_instance_id: Option<u16>,
    #[br(if(version >= 2, None))]
    pub client_sequence_number: Option<u64>,
}

#[derive(BinRead, Debug)]
#[br(little, import { version: u32 })]
pub struct GcEndEvent {
    pub count: u32,
    pub depth: u32,
    #[br(if(version >= 1, None))]
    pub reason: Option<GcReason>,
}

#[derive(BinRead, Debug)]
#[br(little, import { version: u32 })]
pub struct GcAllocationTickEvent {
    pub allocation_amount: u32,
    pub allocation_kind: GcAllocationKind,
    pub clr_instance_id: u16,
    #[br(if(version >= 2))]
    pub allocation_amount64: u64,
    #[br(if(version >= 2))]
    pub type_id: u64, // pointer
    #[br(if(version >= 2))]
    pub type_name: NullWideString,
    #[br(if(version >= 2))]
    pub heap_index: u32,
    #[br(if(version >= 3))]
    pub address: Option<u64>, // pointer
    #[br(if(version >= 4))]
    pub object_size: Option<u64>,
}

#[derive(BinRead, Debug)]
#[br(little, import { version: u32 })]
pub struct GcSampledObjectAllocationEvent {
    pub address: u64, // pointer
    pub type_id: u64, // pointer
    pub object_count_for_type_sample: u32,
    pub total_size_for_type_sample: u64,
    pub clr_instance_id: u16,
}

#[derive(BinRead, Debug)]
#[br(little, import { version: u32 })]
pub struct ReadyToRunGetEntryPointEvent {
    pub method_id: u64,
    pub method_namespace: NullWideString,
    pub method_name: NullWideString,
    pub method_signature: NullWideString,
    pub entry_point: u64,
    pub clr_instance_id: u16,
}

pub enum CoreClrEvent {
    ModuleLoad(ModuleLoadUnloadEvent),
    ModuleUnload(ModuleLoadUnloadEvent),
    MethodLoad(MethodLoadUnloadEvent),
    MethodUnload(MethodLoadUnloadEvent),
    GcTriggered(GcTriggeredEvent),
    GcAllocationTick(GcAllocationTickEvent),
    GcSampledObjectAllocation(GcSampledObjectAllocationEvent),
    ReadyToRunGetEntryPoint(ReadyToRunGetEntryPointEvent),
    MethodDCEnd(MethodLoadUnloadEvent),
}

pub fn decode_coreclr_event(event: &NettraceEvent) -> Option<CoreClrEvent> {
    match event.provider_name.as_str() {
        "Microsoft-Windows-DotNETRuntime" => decode_coreclr_regular_event(event),
        "Microsoft-Windows-DotNETRuntimeRundown" => decode_coreclr_rundown_event(event),
        _ => None,
    }
}

fn decode_coreclr_regular_event(event: &NettraceEvent) -> Option<CoreClrEvent> {
    let mut payload = Cursor::new(&event.payload);
    //eprintln!("Regular: {:?}", event.event_id);

    match event.event_id {
        // 151: DomainModuleLoad
        // 152: ModuleLoad
        // 153: ModuleUnload
        151 => {
            // DomainModuleLoad
            let ev = ModuleLoadUnloadEvent::read_le_args(
                &mut payload,
                binrw::args! { version: event.event_version, app_domain: true },
            )
            .unwrap();
            Some(CoreClrEvent::ModuleLoad(ev))
        }
        152 => {
            // ModuleLoad
            let ev = ModuleLoadUnloadEvent::read_le_args(
                &mut payload,
                binrw::args! { version: event.event_version, app_domain: false },
            )
            .unwrap();
            Some(CoreClrEvent::ModuleLoad(ev))
        }
        153 => {
            // ModuleUnload
            let ev = ModuleLoadUnloadEvent::read_le_args(
                &mut payload,
                binrw::args! { version: event.event_version, app_domain: false },
            )
            .unwrap();
            Some(CoreClrEvent::ModuleUnload(ev))
        }
        159 => {
            // R2RGetEntryPoint
            let ev = ReadyToRunGetEntryPointEvent::read_le_args(
                &mut payload,
                binrw::args! { version: event.event_version },
            )
            .unwrap();
            Some(CoreClrEvent::ReadyToRunGetEntryPoint(ev))
        }
        141 => {
            // MethodLoad
            let ev = MethodLoadUnloadEvent::read_le_args(
                &mut payload,
                binrw::args! { version: event.event_version, verbose: false },
            )
            .unwrap();
            Some(CoreClrEvent::MethodLoad(ev))
        }
        142 => {
            // MethodUnload
            let ev = MethodLoadUnloadEvent::read_le_args(
                &mut payload,
                binrw::args! { version: event.event_version, verbose: false },
            )
            .unwrap();
            Some(CoreClrEvent::MethodUnload(ev))
        }
        143 => {
            // MethodLoadVerbose
            let ev = MethodLoadUnloadEvent::read_le_args(
                &mut payload,
                binrw::args! { version: event.event_version, verbose: true },
            )
            .unwrap();
            Some(CoreClrEvent::MethodLoad(ev))
        }
        144 => {
            // MethodUnloadVerbose
            let ev = MethodLoadUnloadEvent::read_le_args(
                &mut payload,
                binrw::args! { version: event.event_version, verbose: true },
            )
            .unwrap();
            Some(CoreClrEvent::MethodUnload(ev))
        }
        35 => {
            // GCTriggered
            let ev = GcTriggeredEvent::read_le_args(
                &mut payload,
                binrw::args! { version: event.event_version },
            )
            .unwrap();
            Some(CoreClrEvent::GcTriggered(ev))
        }
        1 => {
            // GCStart
            None
        }
        2 => {
            // GCStop
            None
        }
        3 => {
            // GCRestartEEEnd
            None
        }
        7 => {
            // GCRestartEEBegin
            None
        }
        8 => {
            // GCSuspendEEEnd
            None
        }
        9 => {
            // GCSuspendEEBegin
            None
        }
        10 => {
            let ev = GcAllocationTickEvent::read_le_args(
                &mut payload,
                binrw::args! { version: event.event_version },
            )
            .unwrap();
            Some(CoreClrEvent::GcAllocationTick(ev))
        }
        20 | 30 => {
            // High | Low, do we really need both of them?
            let ev = GcSampledObjectAllocationEvent::read_le_args(
                &mut payload,
                binrw::args! { version: event.event_version },
            )
            .unwrap();
            Some(CoreClrEvent::GcSampledObjectAllocation(ev))
        }
        // 13: GCFinalizersEnd
        // 14: GCFinalizersBegin
        // 82: CLRStackWalk (we should never see this I don't think)
        // 83: AppDomainMemAllocated
        // 84: AppDomainMemSurvived
        // 85: ThreadCreated
        // 86: ThreadTerminated
        // 87: ThreadDomainEnter
        // 154: AssemblyLoad
        // 155: AssemblyUnload
        // 156: AppDomainLoad
        // 157: AppDomainUnload
        _ => None,
    }
}

fn decode_coreclr_rundown_event(event: &NettraceEvent) -> Option<CoreClrEvent> {
    let mut payload = Cursor::new(&event.payload);

    //eprintln!("RUNDOWN: {:?}", event.event_id);
    match event.event_id {
        144 => {
            // MethodDCStartVerbose | MethodDCEndVerbose
            let ev = MethodLoadUnloadEvent::read_le_args(
                &mut payload,
                binrw::args! { version: event.event_version, verbose: true },
            )
            .unwrap();
            Some(CoreClrEvent::MethodDCEnd(ev))
        }
        _ => None,
    }
}
