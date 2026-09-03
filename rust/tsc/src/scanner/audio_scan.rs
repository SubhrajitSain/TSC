use hound::WavReader;
use rustfft::{num_complex::Complex, FftPlanner};
use std::path::Path;

use crate::decoder::TSpineDecoder;
use crate::error::{Result, TSpineError};
use crate::export::audio::{FSK_END, FSK_FREQS, FSK_SEP, FSK_SYNC};
use crate::grid::Grid;
use crate::payload::Payload;
use crate::rs::ReedSolomon;
use crate::types::{ColorMode, DecodedPayload};

pub struct AudioScanner;

impl AudioScanner {
    pub fn scan_wav(
        path: impl AsRef<Path>,
        symbol_duration: f32,
        password: Option<&str>,
        verify_key: Option<&str>,
    ) -> Result<DecodedPayload> {
        let mut reader = WavReader::open(path)
            .map_err(|e| TSpineError::Audio(format!("Failed to open WAV: {}", e)))?;
        let spec = reader.spec();
        let rate = spec.sample_rate as f32;

        let samples: Vec<f32> = reader
            .samples::<i16>()
            .filter_map(|s| s.ok())
            .map(|s| s as f32 / 32768.0)
            .collect();

        if samples.len() < (rate * 0.5) as usize {
            return Err(TSpineError::Audio("Audio recording too short".into()));
        }

        let win_len = (rate * 0.2) as usize;
        let step = (rate * 0.05) as usize;
        let mut sep_idx = None;

        for idx in (0..samples.len().saturating_sub(win_len)).step_by(step) {
            let chunk = &samples[idx..idx + win_len];
            let peak = Self::find_peak_freq(chunk, rate);
            if (peak - FSK_SEP).abs() < 45.0 {
                sep_idx = Some(idx);
                break;
            }
        }

        let sep_pos = sep_idx.ok_or_else(|| {
            TSpineError::Audio("Calibration separator tone not found".to_string())
        })?;

        let data_start = sep_pos + (rate * 0.3) as usize;
        let sym_len = (rate * symbol_duration) as usize;

        let mut calib_tones = Vec::new();
        let mut curr_pos = sep_pos as isize - sym_len as isize;

        while curr_pos >= 0 {
            let start = curr_pos as usize + (sym_len as f32 * 0.2) as usize;
            let end = curr_pos as usize + (sym_len as f32 * 0.8) as usize;
            if end >= samples.len() {
                break;
            }
            let peak = Self::find_peak_freq(&samples[start..end], rate);
            if (peak - FSK_SYNC).abs() < 50.0 {
                break;
            }
            calib_tones.push(peak);
            curr_pos -= sym_len as isize;
        }

        calib_tones.reverse();

        let (num_tones, ecc_b) = if calib_tones.len() < 2 {
            (8, 4)
        } else {
            let ecc_freq = *calib_tones.last().unwrap();
            let n_calib = calib_tones.len() - 1;
            let nt = if n_calib >= 8 {
                8
            } else if n_calib >= 4 {
                4
            } else {
                2
            };

            let ecc_idx = FSK_FREQS[..4]
                .iter()
                .enumerate()
                .min_by_key(|(_, &f)| ((f - ecc_freq).abs() * 100.0) as u32)
                .map(|(i, _)| i)
                .unwrap_or(0);

            let eb = match ecc_idx {
                0 => 4,
                1 => 12,
                2 => 28,
                _ => 0,
            };
            (nt, eb)
        };

        let bpc = if num_tones == 8 {
            3
        } else if num_tones == 4 {
            2
        } else {
            1
        };
        let ref_freqs = &FSK_FREQS[..num_tones];

        let mut symbols = Vec::new();
        for idx in (data_start..samples.len().saturating_sub(sym_len)).step_by(sym_len) {
            let mid_start = idx + (sym_len as f32 * 0.15) as usize;
            let mid_end = idx + (sym_len as f32 * 0.85) as usize;
            let peak = Self::find_peak_freq(&samples[mid_start..mid_end], rate);

            if (peak - FSK_END).abs() < 65.0 {
                break;
            }

            let sym = ref_freqs
                .iter()
                .enumerate()
                .min_by_key(|(_, &f)| ((f - peak).abs() * 100.0) as u32)
                .map(|(i, _)| i as u8)
                .unwrap_or(0);

            symbols.push(sym);
        }

        let mut bits = Vec::new();
        for s in symbols {
            for shift in (0..bpc).rev() {
                bits.push((s >> shift) & 1);
            }
        }

        let mut byte_array = Vec::new();
        for chunk in bits.chunks_exact(8) {
            let mut b = 0u8;
            for &bit in chunk {
                b = (b << 1) | bit;
            }
            byte_array.push(b);
        }

        let rs = ReedSolomon::new(ecc_b);
        let decoded_block = rs.decode(&byte_array)?;

        Payload::unpack(&decoded_block, password, verify_key)
    }

    fn find_peak_freq(samples: &[f32], rate: f32) -> f32 {
        let n = samples.len();
        let mut planner = FftPlanner::new();
        let fft = planner.plan_fft_forward(n);

        let mut buffer: Vec<Complex<f32>> = samples.iter().map(|&s| Complex::new(s, 0.0)).collect();
        fft.process(&mut buffer);

        let mut max_mag = 0.0f32;
        let mut max_idx = 0;

        for i in 1..n / 2 {
            let mag = buffer[i].norm_sqr();
            if mag > max_mag {
                max_mag = mag;
                max_idx = i;
            }
        }

        (max_idx as f32 * rate) / (n as f32)
    }
}