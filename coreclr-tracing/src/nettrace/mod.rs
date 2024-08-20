#![allow(unused)]
use binrw::{binrw, BinRead, BinReaderExt, BinResult, NullWideString};
use std::fmt::Display;
use std::io::{BufRead, Cursor, Read, Seek, SeekFrom};

use crate::coreclr;

mod helpers;

pub mod parser;
pub use parser::*;

// https://github.com/microsoft/perfview/blob/main/src/TraceEvent/EventPipe/EventPipeFormat.md

#[derive(BinRead)]
#[br(little)]
pub struct NettraceString {
    length: u32,

    #[br(count = length)]
    bytes: Vec<u8>,
}

impl NettraceString {
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes).unwrap()
    }
}

impl std::fmt::Debug for NettraceString {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "\"{}\"", self.as_str())
    }
}

impl std::fmt::Display for NettraceString {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "\"{}\"", self.as_str())
    }
}

#[derive(BinRead, Debug)]
#[br(little, magic = b"Nettrace")]
pub struct NettraceHeader {
    ident: NettraceString,
}

#[derive(BinRead, Debug, Eq, PartialEq)]
#[br(repr(u8))]
pub enum NettraceTag {
    Invalid = 0,
    NullReference = 1,
    BeginPrivateObject = 5,
    EndObject = 6,
}

// Type objects have a NullReference tag as their type; every object will start with a type object,
// so pull it out into a separate struct instead of as part of the enum
#[derive(BinRead, Debug)]
#[br(little, magic = b"\x05\x01")]
pub struct NettraceTypeObject {
    version: u32,
    minimum_reader_version: u32,
    type_name: NettraceString,
    end_object: NettraceTag,
}

#[derive(BinRead, Debug, Clone, Copy)]
#[br(little)]
pub struct NettraceTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    millisecond: u16,
}

#[derive(BinRead, Debug, Clone, Copy)]
#[br(little)]
pub struct NettraceTraceObject {
    sync_time_utc: NettraceTime,
    sync_time_qpc: u64,
    qpc_frequency: u64,
    pointer_size: u32,
    process_id: u32,
    number_of_processors: u32,
    expected_cpu_sampling_rate: u32,
}

#[derive(BinRead, Debug)]
#[br(little)]
pub struct NettraceEventBlockHeader {
    size: u16,
    flags: u16,
    min_timestamp: u64,
    #[br(pad_after = size - 20)]
    max_timestamp: u64,
}

#[derive(BinRead, Debug)]
#[br(little)]
pub struct NettraceEventBlock {
    #[br(align_after = 4)]
    size: u32,

    header: NettraceEventBlockHeader,
}

// This header can be either compressed or uncompressed.
// The uncompressed header can be parsed directly; the compressed
// header needs manual parsing (see parse_compressed_header below).
#[derive(BinRead, Debug, Default, Clone)]
#[br(little)]
pub struct EventBlobHeader {
    size: u32,
    raw_metadata_id: u32, // high bit is "IsSorted" flag
    sequence_number: u32,
    thread_id: u64,
    capture_thread_id: u64,
    processor_number: u32,
    stack_id: u32,
    timestamp: u64,
    activity_id: [u8; 16],
    related_activity_id: [u8; 16],
    payload_size: u32,

    // at the end to not screw up alignment
    #[br(calc = raw_metadata_id & 0x7fffffff)]
    metadata_id: u32,
    #[br(calc = raw_metadata_id & 0x80000000 != 0)]
    is_sorted: bool,
}

impl Display for EventBlobHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "EventBlobHeader {{ metadata_id: {}, stack: {}, payload_size: {}, seqno: {:?}, thread_id: {} ({}), proc: {:?}, timestamp: {} }}",
            self.metadata_id, self.stack_id, self.payload_size,
            if self.sequence_number == u32::MAX { None } else { Some(self.sequence_number) },
            self.thread_id, self.capture_thread_id,
            if self.processor_number == u32::MAX { None } else { Some(self.processor_number) },
            self.timestamp)
    }
}

#[derive(BinRead, Debug, PartialEq, Default)]
#[br(little, repr=u32)]
pub enum MetadataTypeCode {
    #[default]
    Empty = 0,
    Object = 1,
    DBNull = 2,
    Boolean = 3,
    Char = 4,
    SByte = 5,
    Byte = 6,
    Int16 = 7,
    UInt16 = 8,
    Int32 = 9,
    UInt32 = 10,
    Int64 = 11,
    UInt64 = 12,
    Single = 13,
    Double = 14,
    Decimal = 15,
    DateTime = 16,
    String = 18,
    Array = 19,
}

#[derive(BinRead, Debug)]
#[br(little)]
pub struct MetadataFieldDefinition {
    type_code: MetadataTypeCode,

    #[br(if(type_code == MetadataTypeCode::Array))]
    array_type_code: MetadataTypeCode,

    #[br(if(type_code == MetadataTypeCode::Object || array_type_code == MetadataTypeCode::Object))]
    definition: Option<MetadataPayloadDefinition>,

    field_name: NullWideString,
}

#[derive(BinRead, Debug, Default)]
#[br(little)]
pub struct MetadataPayloadDefinition {
    field_count: u32,
    #[br(count = field_count)]
    fields: Vec<MetadataFieldDefinition>,
}

#[derive(BinRead, Debug)]
#[br(little)]
pub struct MetadataDefinition {
    id: u32,
    provider_name: NullWideString,
    event_id: u32,
    event_name: NullWideString,
    keywords: u64,
    version: u32,
    level: u32,

    // either v1, or replaced with v2 data from tag
    fields: MetadataPayloadDefinition,

    // filled in based on opcode from tag
    #[br(ignore)]
    opcode: Option<u8>,
    // following this, there may be additional tag fields -- based on the size specified
    // in the header. We can't access that in binrw, so it'll have to get handled
    // manually
}

#[derive(BinRead, Debug, PartialEq, Default)]
#[br(little, repr=u8)]
pub enum MetadataTag {
    #[default]
    Invalid = 0,
    OpCode = 1,
    V2Params = 2,
}

#[derive(BinRead, Debug)]
#[br(little)]
pub struct MetadataTaggedData {
    size: u32, // this actually seems to be junk?

    tag: MetadataTag,

    #[br(if(tag == MetadataTag::OpCode))]
    opcode: u8,

    #[br(if(tag == MetadataTag::V2Params))]
    fields_v2: MetadataPayloadDefinition,
}

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

#[derive(Debug)]
pub struct NettraceEvent {
    pub provider_name: String,
    pub event_id: u32,
    pub event_name: Option<String>,
    pub event_keywords: u64,
    pub event_version: u32,
    pub event_level: u32,
    pub event_opcode: Option<u8>,

    pub sequence_number: u32,
    pub thread_id: u64,
    pub capture_thread_id: u64,
    pub processor_number: Option<u32>,
    pub stack: Vec<u64>,
    pub timestamp: u64,
    pub activity_id: [u8; 16],
    pub related_activity_id: [u8; 16],

    pub payload: Vec<u8>,
}

pub trait ReaderTrait: Read + Seek + BinReaderExt {}

pub enum DecodedEvent {
    CoreClrEvent(coreclr::CoreClrEvent),
    UnknownEvent,
}

pub fn decode_event(event: &NettraceEvent) -> DecodedEvent {
    match event.provider_name.as_str() {
        "Microsoft-Windows-DotNETRuntime" | "Microsoft-Windows-DotNETRuntimeRundown" => {
            coreclr::eventpipe::decode_coreclr_event(event)
                .map(|x| DecodedEvent::CoreClrEvent(x))
                .unwrap_or_else(|| DecodedEvent::UnknownEvent)
        }
        _ => DecodedEvent::UnknownEvent,
    }
}