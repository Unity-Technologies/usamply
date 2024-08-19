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

#[derive(BinRead, Debug)]
#[br(little)]
pub struct StackStack {
    size: u32,

    // TODO -- support 32-bit here
    #[br(count = size / 8)]
    stack: Vec<u64>,
}

#[derive(BinRead, Debug)]
#[br(little)]
pub struct StackBlock {
    #[br(align_after = 4)]
    size: u32,

    first_id: u32,
    count: u32,

    #[br(count = count)]
    stacks: Vec<StackStack>,
}

#[derive(BinRead, Debug)]
#[br(little)]
pub struct ThreadSequenceNumber {
    thread_id: u64,
    sequence_number: u32,
}

#[derive(BinRead, Debug)]
#[br(little)]
pub struct SequencePointBlock {
    #[br(align_after = 4)]
    size: u32,

    timestamp: u64,
    thread_count: u32,

    #[br(count = thread_count)]
    thread_sequence_numbers: Vec<ThreadSequenceNumber>,
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
