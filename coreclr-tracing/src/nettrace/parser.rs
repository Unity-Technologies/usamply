use binrw::io::TakeSeekExt;
use binrw::{binrw, BinRead, BinReaderExt, BinResult, NullWideString};
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::File;
use std::io::{BufRead, Cursor, Read, Seek, SeekFrom};
use std::mem;

use super::*;
use super::helpers::*;
use crate::*;

trait ReadExactlyExt {
    fn read_exactly(&mut self, len: u64) -> Vec<u8>;
}

impl<T: Read + Seek> ReadExactlyExt for T {
    fn read_exactly(&mut self, len: u64) -> Vec<u8> {
        let mut buf = vec![0; len as usize];
        self.read_exact(&mut buf)
            .expect("Failed to read exact bytes");
        buf
    }
}

pub type EventPipeError = binrw::Error;

struct EventBlobIter {
    data: Cursor<Vec<u8>>,
    header: NettraceEventBlockHeader,
    compressed_headers: bool,
    blob_size: u64,
    prev_header: EventBlobHeader,
}

impl EventBlobIter {
    pub fn new(block: NettraceEventBlock, mut data: Vec<u8>) -> Result<Self, EventPipeError> {
        //eprintln!("EventBlobIter::new: {:?}", block);
        let compressed_headers = (block.header.flags & 1) != 0;
        let blob_size = (block.size - block.header.size as u32) as u64;
        Ok(EventBlobIter {
            data: Cursor::new(data),
            header: block.header,
            compressed_headers,
            blob_size,
            prev_header: Default::default(),
        })
    }

    fn parse_compressed_header<R: BinReaderExt + Read + Seek>(
        reader: &mut R,
        prev_header: &mut EventBlobHeader,
    ) -> BinResult<EventBlobHeader> {
        //eprintln!("\nPREV {:?}", prev_header);
        let flags: u8 = reader.read_le()?;
        fn is_set(flags: u8, bit: u8) -> bool {
            (flags & (1 << bit)) != 0
        }

        //eprintln!("flags: 0b{:b}", flags);

        let mut header = EventBlobHeader::default();
        header.metadata_id = if is_set(flags, 0) {
            parse_varint_u32(reader)?
        } else {
            prev_header.metadata_id
        };
        if is_set(flags, 1) {
            header.sequence_number = prev_header
                .sequence_number
                .wrapping_add_signed(parse_varint_i32(reader)?);
            header.capture_thread_id = parse_varint_u64(reader)?;
            header.processor_number = parse_varint_u32(reader)?;
        } else {
            header.sequence_number = prev_header.sequence_number;
            header.capture_thread_id = prev_header.capture_thread_id;
            header.processor_number = prev_header.processor_number;
        }

        if header.metadata_id != 0 {
            header.sequence_number = header.sequence_number.wrapping_add(1);
        }

        header.thread_id = if is_set(flags, 2) {
            parse_varint_u64(reader)?
        } else {
            prev_header.thread_id
        };
        header.stack_id = if is_set(flags, 3) {
            parse_varint_u32(reader)?
        } else {
            prev_header.stack_id
        };
        header.timestamp = prev_header
            .timestamp
            .wrapping_add_signed(parse_varint_i64(reader)?);
        header.activity_id = if is_set(flags, 4) {
            reader.read_le()?
        } else {
            prev_header.activity_id
        };
        header.related_activity_id = if is_set(flags, 5) {
            reader.read_le()?
        } else {
            prev_header.related_activity_id
        };
        header.is_sorted = is_set(flags, 6);
        header.payload_size = if is_set(flags, 7) {
            parse_varint_u32(reader)?
        } else {
            prev_header.payload_size
        };

        header.raw_metadata_id = if header.is_sorted { (1 << 31) } else { 0 } | header.metadata_id; // set is_sorted bit

        //eprintln!("{} [flags 0b{:b}]", header, flags);

        *prev_header = header.clone();

        Ok(header)
    }

    fn parse_header<R: BinReaderExt + Read + Seek>(
        reader: &mut R,
        prev_header: &mut EventBlobHeader,
        is_compressed: bool,
    ) -> BinResult<EventBlobHeader> {
        if is_compressed {
            Self::parse_compressed_header(reader, prev_header)
        } else {
            eprintln!("parsing uncompressed header");
            reader.read_le()
        }
    }
}

// Assuming block is a
impl Iterator for EventBlobIter {
    type Item = (EventBlobHeader, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.position() >= self.blob_size {
            return None;
        }

        let header = EventBlobIter::parse_header(
            &mut self.data,
            &mut self.prev_header,
            self.compressed_headers,
        )
        .expect("Failed to read EventBlobHeader");
        let payload = self.data.read_exactly(header.payload_size as u64);

        if !self.compressed_headers && header.payload_size & 3 != 0 {
            let alignment_skip = 4 - (header.payload_size & 3);
            self.data
                .seek(SeekFrom::Current(alignment_skip as i64))
                .expect("Seek failed");
        }

        Some((header, payload))
    }
}

pub struct EventPipeParser<R> {
    stream: R,
    metadata_map: HashMap<u32, MetadataDefinition>,
    stack_map: HashMap<u32, Vec<u64>>,
    trace_info: Option<NettraceTraceObject>,
    cur_event_blob_iter: Option<EventBlobIter>,
}

impl<R> EventPipeParser<R>
where
    R: Read + Seek,
{
    pub fn new(mut stream: R) -> Result<Self, EventPipeError> {
        let file_header = NettraceHeader::read(&mut stream)?;
        if file_header.ident.bytes != b"!FastSerialization.1" {
            return Err(EventPipeError::BadMagic {
                found: Box::new(file_header.ident.bytes),
                pos: stream.stream_position().unwrap(),
            });
        }

        Ok(EventPipeParser {
            stream,
            metadata_map: HashMap::new(),
            stack_map: HashMap::new(),
            trace_info: None,
            cur_event_blob_iter: None,
        })
    }

    fn make_err(&mut self, message: &str) -> EventPipeError {
        EventPipeError::AssertFail {
            pos: self.stream.stream_position().unwrap(),
            message: message.to_string(),
        }
    }

    // Return the NettraceTraceObject for this stream, parsing until it's available if necessary.
    // It will be the first thing in the stream, so we won't miss it
    pub fn trace_info(&mut self) -> Result<NettraceTraceObject, EventPipeError> {
        if let Some(trace_info) = self.trace_info {
            return Ok(trace_info);
        }

        // If we don't have it, we're going to assume that it's going to be the first object
        let Some(type_object) = self.advance_to_next_object()? else {
            return Err(self.make_err("Expected NettraceTraceObject"));
        };

        if type_object.type_name.as_str() != "TraceObject" {
            return Err(self.make_err("Expected TraceObject"));
        }

        let trace_info = NettraceTraceObject::read(&mut self.stream)?;
        self.trace_info = Some(trace_info);

        self.read_object_end()?;

        Ok(trace_info)
    }

    fn read_object_end(&mut self) -> Result<(), EventPipeError> {
        let end_tag = NettraceTag::read(&mut self.stream)?;
        if end_tag != NettraceTag::EndObject {
            return Err(self.make_err("Expected EndObject tag"));
        }

        Ok(())
    }

    fn advance_to_next_object(&mut self) -> Result<Option<NettraceTypeObject>, EventPipeError> {
        let start_tag = NettraceTag::read(&mut self.stream)?;
        if start_tag == NettraceTag::NullReference {
            // stream done
            return Ok(None);
        }

        if start_tag != NettraceTag::BeginPrivateObject {
            return Err(self.make_err("Expected BeginPrivateObject tag"));
        }

        // so much effort spent in NettraceTypeObject, when it's just one of 4 things
        let obj_type = NettraceTypeObject::read(&mut self.stream)?;
        Ok(Some(obj_type))
    }

    fn parse_event(
        &mut self,
        header: EventBlobHeader,
        payload: Vec<u8>,
    ) -> Result<Option<NettraceEvent>, EventPipeError> {
        let metadata_id = header.metadata_id;
        let metadata_def =
            self.metadata_map
                .get(&metadata_id)
                .ok_or_else(|| EventPipeError::AssertFail {
                    pos: 0,
                    message: format!("Metadata definition {} not found", metadata_id),
                })?;

        let mut event = NettraceEvent {
            provider_name: metadata_def.provider_name.to_string(),
            event_id: metadata_def.event_id,
            event_name: if metadata_def.event_name.len() > 0 {
                Some(metadata_def.event_name.to_string())
            } else {
                None
            },
            event_keywords: metadata_def.keywords,
            event_version: metadata_def.version,
            event_level: metadata_def.level,
            event_opcode: metadata_def.opcode,

            sequence_number: header.sequence_number,
            thread_id: header.thread_id,
            capture_thread_id: header.capture_thread_id,
            processor_number: if header.processor_number != u32::MAX {
                Some(header.processor_number)
            } else {
                None
            },
            stack: self
                .stack_map
                .get(&header.stack_id)
                .cloned()
                .unwrap_or_default(),
            timestamp: header.timestamp,
            activity_id: header.activity_id,
            related_activity_id: header.related_activity_id,

            payload: payload,
        };

        Ok(Some(event))
    }

    pub fn next_event(&mut self) -> Result<Option<NettraceEvent>, EventPipeError> {
        // If we're inside an event block already, keep iterating through it
        if let Some(cur_event_iter) = self.cur_event_blob_iter.as_mut() {
            if let Some((header, payload)) = cur_event_iter.next() {
                return self.parse_event(header, payload);
            }

            self.cur_event_blob_iter = None;

            // we don't read this when we read the event blob; we could, but we don't
            self.read_object_end()?;
        }

        loop {
            // Keep reading from the data until we get to an EventBlock, in which case we'll
            // jump back out into the above iterator.
            //
            // Anything that's not an EventBlock, we need to parse into internal data structures so we can
            // expose proper events from the EventBlock.

            let obj_type = self.advance_to_next_object()?;
            let Some(obj_type) = obj_type else {
                return Ok(None);
            };

            let obj_type_name = obj_type.type_name.as_str();

            match obj_type_name {
                "Trace" => {
                    let trace_object = NettraceTraceObject::read(&mut self.stream)?;
                    log::trace!("Trace: {:?}", trace_object);
                    self.trace_info = Some(trace_object.clone());
                }
                "MetadataBlock" => {
                    //eprintln!("MetadataBlock");
                    let metadata_block = NettraceEventBlock::read(&mut self.stream)?;
                    let metadata_block_data = self.stream.read_exactly(
                        metadata_block.size as u64 - metadata_block.header.size as u64,
                    );
                    self.handle_metadata_block(EventBlobIter::new(
                        metadata_block,
                        metadata_block_data,
                    )?)?;
                }
                "StackBlock" => {
                    //eprintln!("StackBlock");
                    let stack_block = StackBlock::read(&mut self.stream)?;
                    let mut stack_id = stack_block.first_id;
                    for stack in stack_block.stacks {
                        self.stack_map.insert(stack_id, stack.stack);
                        stack_id += 1;
                    }
                }
                "SPBlock" => {
                    //eprintln!("SPBlock");
                    let sp_block = SequencePointBlock::read(&mut self.stream)?;
                }
                "EventBlock" => {
                    //eprintln!("EventBlock");
                    let event_block = NettraceEventBlock::read(&mut self.stream)?;
                    let event_block_data = self
                        .stream
                        .read_exactly(event_block.size as u64 - event_block.header.size as u64);
                    self.cur_event_blob_iter =
                        Some(EventBlobIter::new(event_block, event_block_data)?);

                    // jump into the iterator at the start of this
                    return self.next_event();
                }
                unknown => {
                    eprintln!("Unknown object type: {}", unknown);
                    return Err(self.make_err("Unknown object type"));
                }
            }

            self.read_object_end()?;
        }
    }

    fn handle_metadata_block(&mut self, mut iter: EventBlobIter) -> Result<(), EventPipeError> {
        while let Some((header, mut data)) = iter.next() {
            let mut payload = Cursor::new(&data);
            let payload_size = header.payload_size as u64;
            let mut metadata_def = MetadataDefinition::read(&mut payload)?;

            while payload.position() < payload_size {
                let tag_data = MetadataTaggedData::read(&mut payload)?;
                if tag_data.tag == MetadataTag::OpCode {
                    metadata_def.opcode = Some(tag_data.opcode);
                } else if tag_data.tag == MetadataTag::V2Params {
                    assert_eq!(
                        metadata_def.fields.field_count, 0,
                        "Found v2 fields, but v1 fields were not empty"
                    );
                    metadata_def.fields = tag_data.fields_v2;
                }
            }

            self.metadata_map.insert(metadata_def.id, metadata_def);
        }

        Ok(())
    }
}
