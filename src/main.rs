use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use esp32_nimble::utilities::BleUuid;
use esp32_nimble::{BLEAdvertisementData, BLEDevice, NimbleProperties, uuid128};

mod ota;
mod tlv;

const SVC_UUID: BleUuid = uuid128!("01000000-0000-4000-8000-000053564300");
const STATUS_UUID: BleUuid = uuid128!("02000000-0000-4000-8000-000053544154");
const CONTROL_UUID: BleUuid = uuid128!("03000000-0000-4000-8000-00004354524C");
const OTA_UUID: BleUuid = uuid128!("05000000-0000-4000-8000-00004F544100");

// Example TLV commands
const TAG_PING: u8 = 0x01;
const TAG_ECHO: u8 = 0x02;
const TAG_ACTION: u8 = 0x05;
const TAG_SET_CONFIG: u8 = 0x20;

// OTA TLV commands
const TAG_OTA_BEGIN: u8 = ota::TAG_OTA_BEGIN;
const TAG_OTA_CHUNK: u8 = ota::TAG_OTA_CHUNK;
const TAG_OTA_COMMIT: u8 = ota::TAG_OTA_COMMIT;

// Nested TLVs inside SET_CONFIG (and echoed back via CONTROL read)
const TAG_CFG_NAME: u8 = 0x06;
const TAG_CFG_NEAR_FAR_THRESHOLD: u8 = 0x0A;
const TAG_CFG_INITIAL_QUIET: u8 = 0x0B;
const TAG_CFG_ALARM_ESCALATION_AFTER: u8 = 0x0C;

// Response tags (returned by STATUS read)
const TAG_STATUS_PING_COUNT: u8 = 0x10;
const TAG_STATUS_LAST_ECHO_LEN: u8 = 0x11;
const TAG_STATUS_CONFIG_VERSION: u8 = 0x12;
const TAG_STATUS_LAST_ACTION: u8 = 0x13;
const TAG_STATUS_OTA_SUCCESS_COUNT: u8 = 0x14;

static PING_COUNT: AtomicU32 = AtomicU32::new(0);
static LAST_ECHO_LEN: AtomicU32 = AtomicU32::new(0);
static ACTION_COUNT: AtomicU32 = AtomicU32::new(0);
static CONFIG_VERSION: AtomicU32 = AtomicU32::new(0);
static LAST_ACTION: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone)]
struct AppConfig {
    name: heapless::String<20>,
    near_far_threshold_dbm: i8,
    initial_quiet_s: u8,
    alarm_escalation_after_s: u8,
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

fn encode_config(cfg: &AppConfig) -> heapless::Vec<u8, 64> {
    let mut out = heapless::Vec::<u8, 64>::new();

    // Each item is a standard TLV: tag:u8 len:u8 value...
    let _ = out.push(TAG_CFG_NAME);
    let _ = out.push(cfg.name.len() as u8);
    let _ = out.extend_from_slice(cfg.name.as_bytes());

    let _ = out.push(TAG_CFG_NEAR_FAR_THRESHOLD);
    let _ = out.push(1);
    let _ = out.push(cfg.near_far_threshold_dbm as u8);

    let _ = out.push(TAG_CFG_INITIAL_QUIET);
    let _ = out.push(1);
    let _ = out.push(cfg.initial_quiet_s);

    let _ = out.push(TAG_CFG_ALARM_ESCALATION_AFTER);
    let _ = out.push(1);
    let _ = out.push(cfg.alarm_escalation_after_s);

    out
}

fn main() -> anyhow::Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    let device: &'static mut BLEDevice = BLEDevice::take();

    // Prefer large MTU (works best if the client also negotiates it)
    device.set_preferred_mtu(527)?;

    let server = device.get_server();
    let service = server.create_service(SVC_UUID);

    let config = Arc::new(Mutex::new(AppConfig::default()));
    let ota_mgr = Arc::new(Mutex::new(ota::OtaManager::default()));

    // STATUS: READ returns a response frame (status:u8 + TLVs)
    let status_ch = service
        .lock()
        .create_characteristic(STATUS_UUID, NimbleProperties::READ);

    status_ch.lock().on_read(|ch, _| {
        let ping = PING_COUNT.load(Ordering::Relaxed);
        let echo_len = LAST_ECHO_LEN.load(Ordering::Relaxed);
        let cfg_ver = CONFIG_VERSION.load(Ordering::Relaxed);
        let last_action = LAST_ACTION.load(Ordering::Relaxed) as u8;
        let ota_success = ota::OTA_SUCCESS_COUNT.load(Ordering::Relaxed);

        let mut resp = tlv::ResponseWriter::new(tlv::ResponseCode::Ok);
        let _ = resp.push_tlv(TAG_STATUS_PING_COUNT, &ping.to_le_bytes());
        let _ = resp.push_tlv(TAG_STATUS_LAST_ECHO_LEN, &echo_len.to_le_bytes());
        let _ = resp.push_tlv(TAG_STATUS_CONFIG_VERSION, &cfg_ver.to_le_bytes());
        let _ = resp.push_tlv(TAG_STATUS_LAST_ACTION, &[last_action]);
        let _ = resp.push_tlv(TAG_STATUS_OTA_SUCCESS_COUNT, &ota_success.to_le_bytes());

        ch.set_value(resp.as_bytes());
    });

    // CONTROL: READ returns config; WRITE expects exactly one TLV
    let ctrl_ch = service
        .lock()
        .create_characteristic(CONTROL_UUID, NimbleProperties::READ | NimbleProperties::WRITE);

    {
        let config = Arc::clone(&config);
        ctrl_ch.lock().on_read(move |ch, _| {
            let cfg = config.lock().expect("config mutex poisoned");
            let cfg_bytes = encode_config(&cfg);

            let mut resp = tlv::ResponseWriter::new(tlv::ResponseCode::Ok);
            let _ = resp.push_tlv(TAG_SET_CONFIG, &cfg_bytes);
            ch.set_value(resp.as_bytes());
        });
    }

    {
        let config = Arc::clone(&config);
        ctrl_ch.lock().on_write(move |ch| {
            let buf = ch.recv_data();
            match tlv::Tlv::parse_exact(buf) {
                Ok(t) => match t.tag {
                    TAG_PING => {
                        if !t.val.is_empty() {
                            log::warn!("PING expects len=0");
                            return;
                        }
                        let n = PING_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                        log::info!("PING #{n}");
                    }
                    TAG_ECHO => {
                        LAST_ECHO_LEN.store(t.val.len() as u32, Ordering::Relaxed);
                        log::info!("ECHO len={}", t.val.len());
                    }
                    TAG_ACTION => {
                        if t.val.len() != 1 {
                            log::warn!("ACTION expects len=1");
                            return;
                        }
                        let action = t.val[0];
                        let n = ACTION_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                        LAST_ACTION.store(action as u32, Ordering::Relaxed);
                        log::info!("ACTION #{n} code=0x{action:02x}");
                    }
                    TAG_SET_CONFIG => {
                        // Parse nested TLV stream: {tag:u8,len:u8,val...}*
                        let mut rest = t.val;
                        let mut changed = false;

                        while !rest.is_empty() {
                            let (item, next) = match tlv::Tlv::parse_one(rest) {
                                Ok(x) => x,
                                Err(_) => {
                                    log::warn!("Bad nested TLV in SET_CONFIG");
                                    return;
                                }
                            };
                            rest = next;

                            let mut cfg = config.lock().expect("config mutex poisoned");
                            match item.tag {
                                TAG_CFG_NAME => {
                                    if item.val.len() > 20 {
                                        log::warn!("NAME too long (max 20)");
                                        continue;
                                    }
                                    match core::str::from_utf8(item.val) {
                                        Ok(s) => {
                                            cfg.name.clear();
                                            let _ = cfg.name.push_str(s);
                                            changed = true;
                                        }
                                        Err(_) => {
                                            log::warn!("NAME must be UTF-8");
                                        }
                                    }
                                }
                                TAG_CFG_NEAR_FAR_THRESHOLD => {
                                    if item.val.len() == 1 {
                                        cfg.near_far_threshold_dbm = i8::from_le_bytes([item.val[0]]);
                                        changed = true;
                                    }
                                }
                                TAG_CFG_INITIAL_QUIET => {
                                    if item.val.len() == 1 {
                                        cfg.initial_quiet_s = item.val[0];
                                        changed = true;
                                    }
                                }
                                TAG_CFG_ALARM_ESCALATION_AFTER => {
                                    if item.val.len() == 1 {
                                        cfg.alarm_escalation_after_s = item.val[0];
                                        changed = true;
                                    }
                                }
                                other => {
                                    log::info!("Ignoring unknown config tag=0x{other:02x}");
                                }
                            }
                        }

                        if changed {
                            let v = CONFIG_VERSION.fetch_add(1, Ordering::Relaxed) + 1;
                            log::info!("Config updated; version={v}");
                        }
                    }
                    other => {
                        log::warn!("Unknown tag=0x{other:02x} len={}", t.val.len());
                        ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                    }
                },
                Err(_) => {
                    log::warn!("Bad TLV");
                    ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                }
            }
        });
    }

    // OTA: WRITE/WRITE_NO_RSP accepts TLVs; READ exposes progress.
    let ota_ch = service.lock().create_characteristic(
        OTA_UUID,
        NimbleProperties::WRITE | NimbleProperties::WRITE_NO_RSP | NimbleProperties::READ,
    );

    {
        let ota_mgr = Arc::clone(&ota_mgr);
        ota_ch.lock().on_read(move |ch, _| {
            let (received, total) = ota_mgr.lock().expect("ota mutex poisoned").get_progress();

            let mut resp = tlv::ResponseWriter::new(tlv::ResponseCode::Ok);
            let _ = resp.push_tlv(ota::TAG_OTA_PROGRESS, &received.to_le_bytes());
            let _ = resp.push_tlv(ota::TAG_OTA_TOTAL, &total.to_le_bytes());
            ch.set_value(resp.as_bytes());
        });
    }

    {
        let ota_mgr = Arc::clone(&ota_mgr);
        ota_ch.lock().on_write(move |ch| {
            let buf = ch.recv_data();
            if buf.len() < 2 {
                ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                return;
            }

            let tag = buf[0];

            // OTA_CHUNK is special: it uses a u16 LE length field.
            if tag == TAG_OTA_CHUNK {
                if buf.len() < 3 {
                    ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                    return;
                }
                let len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
                let start = 3usize;
                let end = match start.checked_add(len) {
                    Some(x) => x,
                    None => {
                        ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                        return;
                    }
                };
                if end != buf.len() {
                    ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                    return;
                }
                let val = &buf[start..end];
                if val.len() < 4 {
                    ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                    return;
                }
                let offset = u32::from_le_bytes(val[0..4].try_into().unwrap());
                let data = &val[4..];

                match ota_mgr.lock().expect("ota mutex poisoned").chunk(offset, data) {
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("OTA_CHUNK failed: {e:?}");
                        ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                    }
                }

                return;
            }

            // Everything else is a standard u8-length TLV.
            let t = match tlv::Tlv::parse_exact(buf) {
                Ok(x) => x,
                Err(_) => {
                    ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                    return;
                }
            };

            match t.tag {
                TAG_OTA_BEGIN => {
                    if t.val.len() != 36 {
                        ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                        return;
                    }
                    let total_len = u32::from_le_bytes(t.val[0..4].try_into().unwrap());
                    let expected_sha256: [u8; 32] = t.val[4..36].try_into().unwrap();

                    match ota_mgr
                        .lock()
                        .expect("ota mutex poisoned")
                        .begin(total_len, expected_sha256)
                    {
                        Ok(_) => log::info!("OTA_BEGIN ok total_len={total_len}"),
                        Err(e) => {
                            log::warn!("OTA_BEGIN failed: {e:?}");
                            ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                        }
                    }
                }
                TAG_OTA_COMMIT => {
                    if t.val.len() != 64 {
                        ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                        return;
                    }
                    let sig: [u8; 64] = t.val.try_into().unwrap();
                    match ota_mgr.lock().expect("ota mutex poisoned").commit(&sig) {
                        Ok(_) => {
                            ota::record_success();
                            log::info!("OTA_COMMIT ok (boot partition set; reboot to apply)");
                        }
                        Err(e) => {
                            log::warn!("OTA_COMMIT failed: {e:?}");
                            ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                        }
                    }
                }
                other => {
                    log::warn!("Unknown OTA tag=0x{other:02x} len={}", t.val.len());
                    ch.reject_with_error_code(tlv::ResponseCode::BadRequest as u8);
                }
            }
        });
    }

    server.start()?;

    let advertising = device.get_advertising();
    let adv_name = {
        let cfg = config.lock().expect("config mutex poisoned");
        cfg.name.clone()
    };

    advertising
        .lock()
        .set_data(
            BLEAdvertisementData::new()
                .name(adv_name.as_str())
                .add_service_uuid(SVC_UUID),
        )
        .unwrap();

    advertising.lock().start()?;

    log::info!("Advertising started; connect and write TLVs to CONTROL_UUID");

    // Keep the main thread alive.
    loop {
        esp_idf_hal::delay::FreeRtos::delay_ms(1000);
    }
}
