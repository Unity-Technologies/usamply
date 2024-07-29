#![allow(unused)]
use std::fs::File;

use eventpipe::*;
use eventpipe::coreclr::CoreClrEvent;

// https://github.com/microsoft/perfview/blob/main/src/TraceEvent/EventPipe/EventPipeFormat.md

fn main() {
    // open file as binary, argv[1]
    let mut file = File::open(std::env::args().nth(1).unwrap()).unwrap();

    let mut reader = EventPipeParser::new(file).expect("Failed to make EventPipeParser");

    loop {
        match reader.next_event() {
            Ok(Some(event)) => {
                //if event.provider_name == "Microsoft-DotNETCore-SampleProfiler" {
                //    continue;
                //}

                match eventpipe::decode_event(&event) {
                    DecodedEvent::CoreClrEvent(coreclr_event) => {
                        match coreclr_event {
                            CoreClrEvent::MethodLoad(event) => {
                                println!(
                                    "MethodLoad: 0x{:16x} -- {}.{}",
                                    event.method_start_address,
                                    event.method_namespace,
                                    event.method_name
                                );
                            }
                            CoreClrEvent::GcTriggered(event) => {
                                println!("GcTriggered: {:?}", event.reason);
                            }
                            CoreClrEvent::GcAllocationTick(event) => {
                                //println!("GcAllocationTick: {:?}", event);
                            }
                            CoreClrEvent::ModuleLoad(event) => {
                                println!("ModuleLoad: {:?}", event);
                            }
                            CoreClrEvent::ModuleUnload(event) => {
                                println!("ModuleUnload: {:?}", event);
                            }
                            CoreClrEvent::MethodUnload(event) => {
                                println!("MethodUnload: {:?}", event);
                            }
                            CoreClrEvent::GcSampledObjectAllocation(event) => {
                                println!("GcSampledObjectAllocation: {:?}", event);
                            }
                            CoreClrEvent::ReadyToRunGetEntryPoint(event) => {
                                println!("ReadyToRunGetEntryPoint: {:?}", event);
                            }
                            CoreClrEvent::MethodDCEnd(event) => {
                                println!("MethodDCEnd: {:?}", event);
                            }
                        }
                    }
                    DecodedEvent::UnknownEvent => {
                        let mut handled = false;

                        if event.provider_name == "Microsoft-Windows-DotNETRuntime" {
                            handled = true;
                            match event.event_id {
                                145 => println!("MethodJittingStarted [Unhandled]"),
                                146 => println!("MemoryAllocatedForJitCode [Unhandled]"),
                                _ => handled = false,
                            }
                        } else if event.provider_name == "Microsoft-Windows-DotNETRuntimeRundown" {
                            handled = true;
                            match event.event_id {
                                10 => println!("Rundown: GCSettingsRundown [Unhandled]"),
                                146 => println!("Rundown: DCEndComplete [Unhandled] @ {}", event.timestamp),
                                148 => println!("Rundown: DCEndInit [Unhandled] @ {}", event.timestamp),
                                150 => println!("Rundown: MethodDCEndILToNativeMap_V1 [Unhandled]"),
                                152 => println!("Rundown: DomainModuleDCEnd [Unhandled]"),
                                154 => println!("Rundown: ModuleDCEnd [Unhandled] @ {}", event.timestamp),
                                156 => println!("Rundown: AssemblyDCEnd [Unhandled]"),
                                158 => println!("Rundown: AppDomainDCEnd [Unhandled]"),
                                187 => println!("Rundown: RuntimeInformationDCStart [Unhandled]"),
                                _ => handled = false,
                            }
                        }

                        if !handled {
                            println!("Unknown: {} / {}", event.provider_name, event.event_id);
                        }
                    }
                }

                //println!("{} -- ({} {}){:?}", name, event);
                //println!("{} -- ({} {})", name, event.provider_name, event.event_id);
            }
            Ok(None) => {
                println!("EOF");
                break;
            }
            Err(e) => {
                println!("Error: {:?}", e);
                break;
            }
        }
    }
}
