use std::io::{Read, Seek};

use binrw::{BinReaderExt, BinResult};

pub fn parse_varint_u64<R: BinReaderExt + Read + Seek>(reader: &mut R) -> BinResult<u64> {
    let mut result = 0;
    let mut shift = 0;
    loop {
        let byte: u8 = reader.read_le()?;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(result)
}

pub fn parse_varint_u32<R: BinReaderExt + Read + Seek>(reader: &mut R) -> BinResult<u32> {
    parse_varint_u64(reader).map(|x| x as u32)
}

pub fn parse_varint_i64<R: BinReaderExt + Read + Seek>(reader: &mut R) -> BinResult<i64> {
    parse_varint_u64(reader).map(|x| unsafe { std::mem::transmute(x) })
}

pub fn parse_varint_i32<R: BinReaderExt + Read + Seek>(reader: &mut R) -> BinResult<i32> {
    parse_varint_u64(reader).map(|x| unsafe { std::mem::transmute(x as u32) })
}
