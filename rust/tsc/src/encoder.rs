use crate::error::{Result, TSpineError};
use crate::grid::Grid;
use crate::payload::Payload;
use crate::rs::ReedSolomon;
use crate::types::{ColorMode, EccLevel, Metadata};

#[derive(Debug, Clone)]
pub struct TSpineEncoder {
    color_mode: ColorMode,
    ecc_level: EccLevel,
    password: Option<String>,
    sign_key: Option<String>,
    forced_size: Option<usize>,
    is_nano: bool,
    min_header: bool,
}

impl Default for TSpineEncoder {
    fn default() -> Self {
        Self {
            color_mode: ColorMode::FourColor,
            ecc_level: EccLevel::Medium,
            password: None,
            sign_key: None,
            forced_size: None,
            is_nano: false,
            min_header: false,
        }
    }
}

impl TSpineEncoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn color_mode(mut self, mode: ColorMode) -> Self {
        self.color_mode = mode;
        self
    }

    pub fn ecc_level(mut self, level: EccLevel) -> Self {
        self.ecc_level = level;
        self
    }

    pub fn password(mut self, pwd: impl Into<String>) -> Self {
        self.password = Some(pwd.into());
        self
    }

    pub fn sign_key(mut self, key: impl Into<String>) -> Self {
        self.sign_key = Some(key.into());
        self
    }

    pub fn forced_size(mut self, size: usize) -> Self {
        self.forced_size = Some(if size % 2 == 0 { size + 1 } else { size });
        self
    }

    pub fn nano(mut self, enable: bool) -> Self {
        self.is_nano = enable;
        self
    }

    pub fn min_header(mut self, enable: bool) -> Self {
        self.min_header = enable;
        self
    }

    fn calculate_size(&self, raw_bytes_len: usize, ecc_b: usize) -> Result<usize> {
        if let Some(forced) = self.forced_size {
            let total_cap = Grid::capacity_bytes(forced, self.color_mode, self.is_nano);
            let data_cap = Grid::data_capacity_from_total(total_cap, ecc_b);
            if data_cap < raw_bytes_len {
                return Err(TSpineError::DataTooLarge {
                    required: raw_bytes_len,
                    capacity: data_cap,
                });
            }
            return Ok(forced);
        }

        let mut size = if self.is_nano || self.min_header { 5 } else { 9 };
        loop {
            let is_nano_grid = Grid::is_nano(size, self.is_nano);
            let total_cap = Grid::capacity_bytes(size, self.color_mode, is_nano_grid);
            let data_cap = Grid::data_capacity_from_total(total_cap, ecc_b);

            if data_cap >= raw_bytes_len {
                return Ok(size);
            }
            size += 2;
            if size > 251 {
                return Err(TSpineError::SizeExceedsLimit { size });
            }
        }
    }

    pub fn encode(&self, data: &[u8]) -> Result<(Grid, Metadata)> {
        let (raw_data, body) = Payload::prepare_single(
            data,
            self.password.as_deref(),
            self.sign_key.as_deref(),
            self.min_header,
        )?;
        self.build_grid(&raw_data, &body, data.len(), false)
    }

    pub fn encode_dual(&self, public_data: &[u8], private_data: &[u8]) -> Result<(Grid, Metadata)> {
        let (raw_data, body) = Payload::prepare_dual(
            public_data,
            private_data,
            self.password.as_deref(),
            self.sign_key.as_deref(),
            self.min_header,
        )?;
        self.build_grid(&raw_data, &body, public_data.len() + private_data.len(), true)
    }

    fn build_grid(
        &self,
        raw_data: &[u8],
        body: &[u8],
        raw_input_len: usize,
        is_dual: bool,
    ) -> Result<(Grid, Metadata)> {
        let mut ecc_b = self.ecc_level.parity_bytes();
        if self.is_nano || matches!(self.forced_size, Some(s) if s <= 5) {
            if let Some(s) = self.forced_size {
                if s <= 5 {
                    ecc_b = ecc_b.min(1);
                } else if s <= 7 {
                    ecc_b = ecc_b.min(2);
                }
            }
        }

        let size = self.calculate_size(raw_data.len(), ecc_b)?;
        let is_nano_grid = Grid::is_nano(size, self.is_nano);
        let total_cap_bytes = Grid::capacity_bytes(size, self.color_mode, is_nano_grid);
        let data_cap_bytes = Grid::data_capacity_from_total(total_cap_bytes, ecc_b);

        let mut padded = raw_data.to_vec();
        padded.resize(data_cap_bytes, 0);

        let rs = ReedSolomon::new(ecc_b);
        let mut encoded = rs.encode(&padded);
        encoded.resize(total_cap_bytes, 0);

        let bpc = self.color_mode.bits_per_cell();
        let mut bits = Vec::with_capacity(encoded.len() * 8);
        for &byte in &encoded {
            for shift in (0..8).rev() {
                bits.push((byte >> shift) & 1);
            }
        }

        let total_grid_bits = if is_nano_grid {
            (size * size - 6) * bpc
        } else {
            (size * size - 2 * size - 1) * bpc
        };
        bits.resize(total_grid_bits, 0);

        let mut grid = Grid::new(size, self.color_mode);
        grid.apply_skeletons(is_nano_grid);

        let coords = Grid::data_coordinates(size, is_nano_grid);
        let mask_val = (1u8 << bpc) - 1;
        let mut bit_idx = 0;

        for (x, y) in coords {
            let mut val = 0u8;
            for _ in 0..bpc {
                val = (val << 1) | bits[bit_idx];
                bit_idx += 1;
            }
            if Grid::mask(x, y) {
                val ^= mask_val;
            }
            grid.set(x, y, val);
        }

        let flags = if self.min_header {
            raw_data[0] & !0x80
        } else {
            raw_data[3]
        };

        let header_bytes_count = (if self.min_header { 1 } else { 4 })
            + (if self.sign_key.is_some() {
                if self.min_header { 16 } else { 32 }
            } else {
                0
            })
            + (if is_dual {
                if self.min_header { 2 } else { 8 }
            } else if self.min_header {
                1
            } else {
                4
            });

        let metadata = Metadata {
            size,
            raw_bytes: raw_input_len,
            packed_bytes: raw_data.len(),
            header_bytes_count,
            data_bytes_count: body.len(),
            ecc_start_byte: data_cap_bytes,
            total_cap_bytes,
            ecc_bytes: ecc_b,
            colors: self.color_mode.num_colors(),
            bits_per_cell: bpc,
            flags,
            is_dual,
            is_binary: (flags & crate::payload::FLAG_BINARY) != 0,
            is_signed: self.sign_key.is_some(),
            is_encrypted: self.password.is_some(),
            is_min_header: self.min_header,
            is_nano: is_nano_grid,
        };

        Ok((grid, metadata))
    }
}