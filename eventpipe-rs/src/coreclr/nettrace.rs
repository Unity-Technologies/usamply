use super::*;
use crate::*;

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
        // 145: MethodJittingStarted
        // 146: MethodJitMemoryAllocatedForCode
        // 154: AssemblyLoad
        // 155: AssemblyUnload
        // 156: AppDomainLoad
        // 157: AppDomainUnload
        // 160: R2RGetEntryPointStart
        // 187: RuntimeInformationStart
        // 190: MethodILToNativeMap
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