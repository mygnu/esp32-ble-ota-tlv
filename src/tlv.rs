use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    Ok = 0x00,
    BadRequest = 0x01,
    InternalError = 0x02,
}

#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub val: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn parse_one(buf: &'a [u8]) -> Result<(Self, &'a [u8]), ResponseCode> {
        if buf.len() < 2 {
            return Err(ResponseCode::BadRequest);
        }
        let tag = buf[0];
        let len = buf[1] as usize;
        let start: usize = 2;
        let end = start.checked_add(len).ok_or(ResponseCode::BadRequest)?;
        let val = buf.get(start..end).ok_or(ResponseCode::BadRequest)?;
        Ok((Self { tag, val }, &buf[end..]))
    }

    pub fn parse_exact(buf: &'a [u8]) -> Result<Self, ResponseCode> {
        let (tlv, rest) = Self::parse_one(buf)?;
        if !rest.is_empty() {
            return Err(ResponseCode::BadRequest);
        }
        Ok(tlv)
    }
}

pub type RespBuf = heapless::Vec<u8, 128>;

pub struct ResponseWriter {
    buf: RespBuf,
}

impl ResponseWriter {
    pub fn new(code: ResponseCode) -> Self {
        let mut buf = RespBuf::new();
        let _ = buf.push(code as u8);
        Self { buf }
    }

    pub fn push_tlv(&mut self, tag: u8, val: &[u8]) -> Result<(), ResponseCode> {
        if val.len() > 0xff {
            return Err(ResponseCode::BadRequest);
        }
        let needed = 1 + 1 + val.len();
        if self.buf.len() + needed > self.buf.capacity() {
            return Err(ResponseCode::InternalError);
        }
        self.buf.push(tag).ok();
        self.buf.push(val.len() as u8).ok();
        self.buf.extend_from_slice(val).ok();
        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}
