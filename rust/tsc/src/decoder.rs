use crate::error::{Result, TSpineError};
use crate::grid::Grid;
use crate::payload::Payload;
use crate::rs::ReedSolomon;
use crate::types::DecodedPayload;

#[derive(Debug, Clone, Default)]
pub struct TSpineDecoder {
    password: Option<String>,
    verify_key: Option<String>,
}

impl TSpineDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn password(mut self, pwd: impl Into<String>) -> Self {
        self.password = Some(pwd.into());
        self
    }

    pub fn verify_key(mut self, key: impl Into<String>) -> Self {
        self.verify_key = Some(key.into());
        self
    }

    pub fn decode_grid(&self, grid: &Grid, is_nano_forced: Option<bool>) -> Result<DecodedPayload> {
        let size = grid.size;
        let is_nano = is_nano_forced.unwrap_or_else(|| Grid::is_nano(size, false));
        let coords = Grid::data_coordinates(size, is_nano);
        let bpc = grid.mode.bits_per_cell();
        let mask_val = (1u8 << bpc) - 1;

        let mut bits = Vec::with_capacity(coords.len() * bpc);
        for (x, y) in coords {
            let mut val = grid.get(x, y);
            if Grid::mask(x, y) {
                val ^= mask_val;
            }
            for shift in (0..bpc).rev() {
                bits.push((val >> shift) & 1);
            }
        }

        let total_cap_bytes = Grid::capacity_bytes(size, grid.mode, is_nano);
        let ecc_candidates: &[usize] = if is_nano {
            &[0, 1, 2, 4]
        } else {
            &[12, 0, 4, 28]
        };

        let mut last_err = None;

        for &ecc_b in ecc_candidates {
            if ecc_b > total_cap_bytes {
                continue;
            }

            let data_cap_bytes = Grid::data_capacity_from_total(total_cap_bytes, ecc_b);
            let encoded_len = if ecc_b == 0 {
                total_cap_bytes
            } else {
                let chunk_cap = 255;
                let chunk_data = 255 - ecc_b;
                let full_chunks = data_cap_bytes / chunk_data;
                let rem = data_cap_bytes % chunk_data;
                (full_chunks * chunk_cap) + if rem > 0 { rem + ecc_b } else { 0 }
            };

            let needed_bits = encoded_len * 8;
            if bits.len() < needed_bits {
                continue;
            }

            let mut byte_array = Vec::with_capacity(encoded_len);
            for chunk in bits[..needed_bits].chunks(8) {
                let mut byte = 0u8;
                for &b in chunk {
                    byte = (byte << 1) | b;
                }
                byte_array.push(byte);
            }

            let rs = ReedSolomon::new(ecc_b);
            match rs.decode(&byte_array) {
                Ok(decoded_block) => {
                    match Payload::unpack(
                        &decoded_block,
                        self.password.as_deref(),
                        self.verify_key.as_deref(),
                    ) {
                        Ok(payload) => return Ok(payload),
                        Err(TSpineError::SignatureMismatch) => {
                            return Err(TSpineError::SignatureMismatch)
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or(TSpineError::InvalidHeader))
    }
}