#![allow(unused)]
use std::fs::File;

use coreclr_events::CoreClrEvent;
use eventpipe::*;

// https://github.com/microsoft/perfview/blob/main/src/TraceEvent/EventPipe/EventPipeFormat.md

fn main() {
    // open file as binary, argv[1]
    let mut file = File::open(std::env::args().nth(1).unwrap()).unwrap();

    let mut reader = EventPipeParser::new(file).expect("Failed to make EventPipeParser");

    loop {
        match reader.next_event() {
            Ok(Some(event)) => {
                if event.provider_name == "Microsoft-DotNETCore-SampleProfiler" {
                    continue;
                }

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
                        }
                    }
                    DecodedEvent::UnknownEvent => {
                        //println!("Unknown event: {} / {}", event.provider_name, event.event_id);
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
