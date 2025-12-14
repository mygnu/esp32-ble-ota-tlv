use std::sync::atomic::{AtomicU32, Ordering};

use esp_idf_hal::sys;
use sha2::{Digest, Sha256};

/// OTA TLV tags (match the main firmware’s TLV OTA flow)
pub const TAG_OTA_BEGIN: u8 = 0x30;
pub const TAG_OTA_CHUNK: u8 = 0x31;
pub const TAG_OTA_COMMIT: u8 = 0x32;

/// OTA response tags (returned by OTA read)
pub const TAG_OTA_PROGRESS: u8 = 0x50;
pub const TAG_OTA_TOTAL: u8 = 0x51;

/// Example/demo Ed25519 public key.
///
/// This is a valid Ed25519 public key taken from a published test vector.
/// Replace this with your own public key bytes for a real product.
pub const ED25519_PUBKEY: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
    0xD7, 0x5A, 0x98, 0x01, 0x82, 0xB1, 0x0A, 0xB7, 0xD5, 0x4B, 0xFE, 0xD3, 0xC9, 0x64, 0x07, 0x3A, 0x0E,
    0xE1, 0x72, 0xF3, 0xDA, 0xA6, 0x23, 0x25, 0xAF, 0x02, 0x1A, 0x68, 0xF7, 0x07, 0x51, 0x1A,
];

#[derive(Debug)]
pub enum OtaError {
    BadRequest,
    InvalidState,
    InternalError,
}

pub struct OtaManager {
    state: OtaState,
}

enum OtaState {
    Idle,
    Active {
        handle: sys::esp_ota_handle_t,
        total: u32,
        received: u32,
        expected_sha256: [u8; 32],
        sha: Sha256,
    },
}

impl Default for OtaManager {
    fn default() -> Self {
        Self {
            state: OtaState::Idle,
        }
    }
}

impl OtaManager {
    pub fn reset(&mut self) {
        if let OtaState::Active { handle, .. } = self.state {
            unsafe {
                // # Safety
                // handle is an ESP-IDF OTA handle previously returned by esp_ota_begin.
                let _ = sys::esp_ota_end(handle);
            }
        }
        self.state = OtaState::Idle;
    }

    pub fn get_progress(&self) -> (u32, u32) {
        match &self.state {
            OtaState::Idle => (0, 0),
            OtaState::Active { received, total, .. } => (*received, *total),
        }
    }

    pub fn begin(&mut self, total_len: u32, expected_sha256: [u8; 32]) -> Result<(), OtaError> {
        // Abort any prior session.
        self.reset();

        let part = unsafe {
            // # Safety
            // esp_ota_get_next_update_partition is a pure query. Passing NULL is allowed.
            sys::esp_ota_get_next_update_partition(core::ptr::null())
        };
        if part.is_null() {
            return Err(OtaError::InternalError);
        }

        let part_size = unsafe {
            // # Safety
            // part is checked for null above.
            (*part).size as u32
        };
        if total_len == 0 || total_len > part_size {
            return Err(OtaError::BadRequest);
        }

        let mut handle: sys::esp_ota_handle_t = 0;
        let err = unsafe {
            // # Safety
            // part is valid, and handle is a writable out-parameter.
            sys::esp_ota_begin(part, total_len as usize, &mut handle)
        };
        if err != 0 {
            return Err(OtaError::InternalError);
        }

        self.state = OtaState::Active {
            handle,
            total: total_len,
            received: 0,
            expected_sha256,
            sha: Sha256::new(),
        };

        Ok(())
    }

    pub fn chunk(&mut self, offset: u32, data: &[u8]) -> Result<(), OtaError> {
        let OtaState::Active {
            handle,
            received,
            sha,
            total,
            ..
        } = &mut self.state
        else {
            return Err(OtaError::InvalidState);
        };

        if offset != *received {
            return Err(OtaError::BadRequest);
        }
        if *received + (data.len() as u32) > *total {
            return Err(OtaError::BadRequest);
        }

        let err = unsafe {
            // # Safety
            // handle is a valid OTA handle, data pointer is valid for data.len() bytes.
            sys::esp_ota_write(*handle, data.as_ptr() as *const core::ffi::c_void, data.len())
        };
        if err != 0 {
            return Err(OtaError::InternalError);
        }

        sha.update(data);
        *received += data.len() as u32;

        Ok(())
    }

    pub fn commit(&mut self, sig_ed25519: &[u8; 64]) -> Result<(), OtaError> {
        let OtaState::Active {
            handle,
            total,
            received,
            expected_sha256,
            sha,
        } = &mut self.state
        else {
            return Err(OtaError::InvalidState);
        };

        if *received != *total {
            return Err(OtaError::BadRequest);
        }

        let computed: [u8; 32] = sha.clone().finalize().into();
        if &computed != expected_sha256 {
            return Err(OtaError::BadRequest);
        }

        // Verify Ed25519(sig, expected_sha256)
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(&ED25519_PUBKEY).map_err(|_| OtaError::InternalError)?;
        let sig = ed25519_dalek::Signature::from_bytes(sig_ed25519);
        vk.verify_strict(&expected_sha256[..], &sig)
            .map_err(|_| OtaError::BadRequest)?;

        let handle_copy = *handle;

        let err_end = unsafe {
            // # Safety
            // handle_copy is a valid handle from esp_ota_begin.
            sys::esp_ota_end(handle_copy)
        };
        if err_end != 0 {
            return Err(OtaError::InternalError);
        }

        let part = unsafe {
            // # Safety
            // esp_ota_get_next_update_partition is a pure query. Passing NULL is allowed.
            sys::esp_ota_get_next_update_partition(core::ptr::null())
        };
        if part.is_null() {
            return Err(OtaError::InternalError);
        }

        let err_set = unsafe {
            // # Safety
            // part is the partition returned by esp_ota_get_next_update_partition.
            sys::esp_ota_set_boot_partition(part)
        };
        if err_set != 0 {
            return Err(OtaError::InternalError);
        }

        self.state = OtaState::Idle;
        Ok(())
    }
}

/// A small, cheap metric that can be used in STATUS reads.
///
/// (Kept here so main.rs doesn’t need to depend on OTA state internals.)
pub static OTA_SUCCESS_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn record_success() {
    let _ = OTA_SUCCESS_COUNT.fetch_add(1, Ordering::Relaxed);
}
