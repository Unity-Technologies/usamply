#![allow(unused)]

mod helpers;
pub mod eventpipe;

pub mod coreclr;

use binrw::io::TakeSeekExt;
use binrw::{binrw, BinRead, BinReaderExt, BinResult, NullWideString};
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::File;
use std::io::{BufRead, Cursor, Read, Seek, SeekFrom};
use std::mem;

use helpers::*;
use crate::eventpipe::NettraceEvent;

#[derive(Debug)]
pub struct EventMetadata {
    pub timestamp: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub stack: Option<Vec<u64>>,
}

impl EventMetadata {
    fn with_stack(mut self, stack: Vec<u64>) -> Self {
        self.stack = Some(stack);
        self
    }
}

pub trait ReaderTrait: Read + Seek + BinReaderExt {}

pub enum DecodedEvent {
    CoreClrEvent(coreclr::CoreClrEvent),
    UnknownEvent,
}

pub fn decode_event(event: &NettraceEvent) -> DecodedEvent {
    match event.provider_name.as_str() {
        "Microsoft-Windows-DotNETRuntime" | "Microsoft-Windows-DotNETRuntimeRundown" => {
            coreclr::decode_coreclr_event(event)
                .map(|x| DecodedEvent::CoreClrEvent(x))
                .unwrap_or_else(|| DecodedEvent::UnknownEvent)
        }
        _ => DecodedEvent::UnknownEvent,
    }
}
