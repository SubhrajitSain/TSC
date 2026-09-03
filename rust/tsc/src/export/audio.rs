use hound::{WavSpec, WavWriter};
use std::f32::consts::PI;
use std::path::Path;

use crate::error::Result;
use crate::payload::Payload;
use crate::rs::ReedSolomon;
use crate::types::{ColorMode, EccLevel};

pub const FSK_FREQS: [f32; 8] = [900.0, 1100.0, 1300.0, 1500.0, 1700.0, 1900.0, 2100.0, 2300.0];
pub const FSK_SYNC: f32 = 600.0;
pub const FSK_SEP: f32 = 750.0;
pub const FSK_END: f32 = 2600.0;

pub struct AudioModem;

impl AudioModem {
    fn generate_tone(freq: f32, duration: f32, rate: u32, amp: f32) -> Vec<i16> {
        let total_samples = (rate as f32 * duration) as usize;
        let mut samples = Vec::with_capacity(total_samples);
        let fade_len = (total_samples / 4).min(120);

        for i in 0..total_samples {
            let t = i as f32 / rate as f32;
            let mut val = (2.0 * PI * freq * t).sin() * amp;

            if i < fade_len {
                val *= i as f32 / fade_len as f32;
            } else if i > total_samples - fade_len {
                val *= (total_samples - i) as f32 / fade_len as f32;
            }

            samples.push((val * 32767.0).clamp(-32768.0, 32767.0) as i16);
        }
        samples
    }

    pub fn export_wav(
        data: &[u8],
        path: impl AsRef<Path>,
        mode: ColorMode,
        ecc: EccLevel,
        password: Option<&str>,
        symbol_duration: f32,
    ) -> Result<()> {
        let (raw_data, _) = Payload::prepare_single(data, password, None, false)?;
        let ecc_b = ecc.parity_bytes();
        let rs = ReedSolomon::new(ecc_b);
        let encoded = rs.encode(&raw_data);

        let bpc = mode.bits_per_cell();
        let mut bits = Vec::new();
        for &byte in &encoded {
            for shift in (0..8).rev() {
                bits.push((byte >> shift) & 1);
            }
        }
        while bits.len() % bpc != 0 {
            bits.push(0);
        }

        let mut symbols = Vec::new();
        for chunk in bits.chunks(bpc) {
            let mut val = 0u8;
            for &b in chunk {
                val = (val << 1) | b;
            }
            symbols.push(val);
        }

        let sample_rate = 8000;
        let spec = WavSpec {
            channels: 1,
            sample_rate,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };

        let mut writer = WavWriter::create(path, spec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        for s in Self::generate_tone(FSK_SYNC, 0.5, sample_rate, 0.7) {
            writer.write_sample(s).unwrap();
        }

        let num_tones = mode.num_colors();
        for c in 0..num_tones {
            for s in Self::generate_tone(FSK_FREQS[c], symbol_duration, sample_rate, 0.75) {
                writer.write_sample(s).unwrap();
            }
        }

        let ecc_idx = match ecc_b {
            0 => 3,
            1..=4 => 0,
            5..=12 => 1,
            _ => 2,
        };
        for s in Self::generate_tone(FSK_FREQS[ecc_idx], symbol_duration, sample_rate, 0.75) {
            writer.write_sample(s).unwrap();
        }

        for s in Self::generate_tone(FSK_SEP, 0.3, sample_rate, 0.7) {
            writer.write_sample(s).unwrap();
        }

        for sym in symbols {
            let freq = FSK_FREQS[sym as usize];
            for s in Self::generate_tone(freq, symbol_duration, sample_rate, 0.75) {
                writer.write_sample(s).unwrap();
            }
        }

        for s in Self::generate_tone(FSK_END, 0.5, sample_rate, 0.7) {
            writer.write_sample(s).unwrap();
        }

        writer.finalize().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(())
    }
}