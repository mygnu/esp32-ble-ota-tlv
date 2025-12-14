use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use esp32_nimble::utilities::BleUuid;
use esp32_nimble::{BLEAdvertisementData, BLEDevice, NimbleProperties, uuid128};

mod ota;
mod tlv;

const SVC_UUID: BleUuid = uuid128!("01000000-0000-4000-8000-000053564300");
const STATUS_UUID: BleUuid = uuid128!("02000000-0000-4000-8000-000053544154");
const CONTROL_UUID: BleUuid = uuid128!("03000000-0000-4000-8000-00004354524C");
const OTA_UUID: BleUuid = uuid128!("05000000-0000-4000-8000-00004F544100");

// OTA TLV commands
const TAG_OTA_BEGIN: u8 = ota::TAG_OTA_BEGIN;
const TAG_OTA_CHUNK: u8 = ota::TAG_OTA_CHUNK;
const TAG_OTA_COMMIT: u8 = ota::TAG_OTA_COMMIT;

fn main() -> anyhow::Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    let device: &'static mut BLEDevice = BLEDevice::take();

    // Prefer large MTU (works best if the client also negotiates it)
    device.set_preferred_mtu(527)?;

    let server = device.get_server();
    let service = server.create_service(SVC_UUID);

    let config = Arc::new(Mutex::new(tlv::AppConfig::default()));
    let ota_mgr = Arc::new(Mutex::new(ota::OtaManager::default()));

    // STATUS: READ returns a response frame (status:u8 + TLVs)
    let status_ch = service
        .lock()
        .create_characteristic(STATUS_UUID, NimbleProperties::READ);

    status_ch.lock().on_read(|ch, _| {
        let ota_success = ota::OTA_SUCCESS_COUNT.load(Ordering::Relaxed);
        let resp = tlv::build_status_response(ota_success);
        ch.set_value(resp.as_bytes());
    });

    // CONTROL: READ returns config; WRITE expects exactly one TLV
    let ctrl_ch = service.lock().create_characteristic(
        CONTROL_UUID,
        NimbleProperties::READ | NimbleProperties::WRITE,
    );

    {
        let config = Arc::clone(&config);
        ctrl_ch.lock().on_read(move |ch, _| {
            let cfg = config.lock().expect("config mutex poisoned");
            let cfg_bytes = cfg.encode();

            let mut resp = tlv::ResponseWriter::new(tlv::ResponseCode::Ok);
            let _ = resp.push_tlv(tlv::TAG_SET_CONFIG, &cfg_bytes);
            ch.set_value(resp.as_bytes());
        });
    }

    {
        let config = Arc::clone(&config);
        ctrl_ch.lock().on_write(move |ch| {
            let buf = ch.recv_data();
            match tlv::Tlv::parse_exact(buf) {
                Ok(t) => match t.tag {
                    tlv::TAG_PING => {
                        if !t.val.is_empty() {
                            log::warn!("PING expects len=0");
                            return;
                        }
                        let n = tlv::PING_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                        log::info!("PING #{n}");
                    }
                    tlv::TAG_ECHO => {
                        tlv::LAST_ECHO_LEN.store(t.val.len() as u32, Ordering::Relaxed);
                        log::info!("ECHO len={}", t.val.len());
                    }
                    tlv::TAG_ACTION => {
                        if t.val.len() != 1 {
                            log::warn!("ACTION expects len=1");
                            return;
                        }
                        let action = t.val[0];
                        let n = tlv::ACTION_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                        tlv::LAST_ACTION.store(action as u32, Ordering::Relaxed);
                        log::info!("ACTION #{n} code=0x{action:02x}");
                    }
                    tlv::TAG_SET_CONFIG => {
                        let mut cfg = config.lock().expect("config mutex poisoned");
                        match cfg.update_from_tlv(t.val) {
                            Ok(true) => {
                                let v = tlv::CONFIG_VERSION.fetch_add(1, Ordering::Relaxed) + 1;
                                log::info!("Config updated; version={v}");
                            }
                            Ok(false) => {}
                            Err(_) => {
                                log::warn!("Bad nested TLV in SET_CONFIG");
                            }
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

                match ota_mgr
                    .lock()
                    .expect("ota mutex poisoned")
                    .chunk(offset, data)
                {
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
