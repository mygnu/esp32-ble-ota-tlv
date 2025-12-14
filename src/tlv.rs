use anyhow::Result;
use std::sync::atomic::{AtomicU32, Ordering};

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

// Command TLV tags
pub const TAG_PING: u8 = 0x01;
pub const TAG_ECHO: u8 = 0x02;
pub const TAG_ACTION: u8 = 0x05;
pub const TAG_SET_CONFIG: u8 = 0x20;

// Nested TLVs inside SET_CONFIG (and echoed back via CONTROL read)
pub const TAG_CFG_NAME: u8 = 0x06;
pub const TAG_CFG_NEAR_FAR_THRESHOLD: u8 = 0x0A;
pub const TAG_CFG_INITIAL_QUIET: u8 = 0x0B;
pub const TAG_CFG_ALARM_ESCALATION_AFTER: u8 = 0x0C;

// Response tags (returned by STATUS read)
pub const TAG_STATUS_PING_COUNT: u8 = 0x10;
pub const TAG_STATUS_LAST_ECHO_LEN: u8 = 0x11;
pub const TAG_STATUS_CONFIG_VERSION: u8 = 0x12;
pub const TAG_STATUS_LAST_ACTION: u8 = 0x13;
pub const TAG_STATUS_OTA_SUCCESS_COUNT: u8 = 0x14;

// Global state for command tracking
pub static PING_COUNT: AtomicU32 = AtomicU32::new(0);
pub static LAST_ECHO_LEN: AtomicU32 = AtomicU32::new(0);
pub static ACTION_COUNT: AtomicU32 = AtomicU32::new(0);
pub static CONFIG_VERSION: AtomicU32 = AtomicU32::new(0);
pub static LAST_ACTION: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub name: heapless::String<20>,
    pub near_far_threshold_dbm: i8,
    pub initial_quiet_s: u8,
    pub alarm_escalation_after_s: u8,
}

impl Default for AppConfig {
    fn default() -> Self {
        let mut name = heapless::String::new();
        let _ = name.push_str("esp32-ble-tlv");

        Self {
            name,
            near_far_threshold_dbm: -60,
            initial_quiet_s: 8,
            alarm_escalation_after_s: 5,
        }
    }
}

impl AppConfig {
    /// Encode the config as a TLV stream
    pub fn encode(&self) -> heapless::Vec<u8, 64> {
        let mut out = heapless::Vec::<u8, 64>::new();

        // Each item is a standard TLV: tag:u8 len:u8 value...
        let _ = out.push(TAG_CFG_NAME);
        let _ = out.push(self.name.len() as u8);
        let _ = out.extend_from_slice(self.name.as_bytes());

        let _ = out.push(TAG_CFG_NEAR_FAR_THRESHOLD);
        let _ = out.push(1);
        let _ = out.push(self.near_far_threshold_dbm as u8);

        let _ = out.push(TAG_CFG_INITIAL_QUIET);
        let _ = out.push(1);
        let _ = out.push(self.initial_quiet_s);

        let _ = out.push(TAG_CFG_ALARM_ESCALATION_AFTER);
        let _ = out.push(1);
        let _ = out.push(self.alarm_escalation_after_s);

        out
    }

    /// Update config from a TLV stream
    pub fn update_from_tlv(&mut self, tlv_data: &[u8]) -> Result<bool, ()> {
        let mut rest = tlv_data;
        let mut changed = false;

        while !rest.is_empty() {
            let (item, next) = Tlv::parse_one(rest).map_err(|_| ())?;
            rest = next;

            match item.tag {
                TAG_CFG_NAME => {
                    if item.val.len() > 20 {
                        log::warn!("NAME too long (max 20)");
                        continue;
                    }
                    match core::str::from_utf8(item.val) {
                        Ok(s) => {
                            self.name.clear();
                            let _ = self.name.push_str(s);
                            changed = true;
                        }
                        Err(_) => {
                            log::warn!("NAME must be UTF-8");
                        }
                    }
                }
                TAG_CFG_NEAR_FAR_THRESHOLD => {
                    if item.val.len() == 1 {
                        self.near_far_threshold_dbm = i8::from_le_bytes([item.val[0]]);
                        changed = true;
                    }
                }
                TAG_CFG_INITIAL_QUIET => {
                    if item.val.len() == 1 {
                        self.initial_quiet_s = item.val[0];
                        changed = true;
                    }
                }
                TAG_CFG_ALARM_ESCALATION_AFTER => {
                    if item.val.len() == 1 {
                        self.alarm_escalation_after_s = item.val[0];
                        changed = true;
                    }
                }
                other => {
                    log::info!("Ignoring unknown config tag=0x{other:02x}");
                }
            }
        }

        Ok(changed)
    }
}

/// Build a status response with all current counters
pub fn build_status_response(ota_success: u32) -> ResponseWriter {
    let ping = PING_COUNT.load(Ordering::Relaxed);
    let echo_len = LAST_ECHO_LEN.load(Ordering::Relaxed);
    let cfg_ver = CONFIG_VERSION.load(Ordering::Relaxed);
    let last_action = LAST_ACTION.load(Ordering::Relaxed) as u8;

    let mut resp = ResponseWriter::new(ResponseCode::Ok);
    let _ = resp.push_tlv(TAG_STATUS_PING_COUNT, &ping.to_le_bytes());
    let _ = resp.push_tlv(TAG_STATUS_LAST_ECHO_LEN, &echo_len.to_le_bytes());
    let _ = resp.push_tlv(TAG_STATUS_CONFIG_VERSION, &cfg_ver.to_le_bytes());
    let _ = resp.push_tlv(TAG_STATUS_LAST_ACTION, &[last_action]);
    let _ = resp.push_tlv(TAG_STATUS_OTA_SUCCESS_COUNT, &ota_success.to_le_bytes());

    resp
}
