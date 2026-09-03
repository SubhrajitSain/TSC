use image::RgbImage;
use std::path::Path;

use crate::decoder::TSpineDecoder;
use crate::error::{Result, TSpineError};
use crate::grid::Grid;
use crate::types::{ColorMode, DecodedPayload, Rgb};

pub struct ImageScanner;

impl ImageScanner {
    pub fn scan_file(
        path: impl AsRef<Path>,
        password: Option<&str>,
        verify_key: Option<&str>,
        forced_mode: Option<ColorMode>,
    ) -> Result<DecodedPayload> {
        let dyn_img = image::open(path)
            .map_err(|e| TSpineError::ScanFailed(format!("Failed to open image: {}", e)))?;
        let img = dyn_img.to_rgb8();
        Self::scan_image(&img, password, verify_key, forced_mode)
    }

    pub fn scan_image(
        img: &RgbImage,
        password: Option<&str>,
        verify_key: Option<&str>,
        forced_mode: Option<ColorMode>,
    ) -> Result<DecodedPayload> {
        let decoder = TSpineDecoder::new();
        let decoder = if let Some(p) = password {
            decoder.password(p)
        } else {
            decoder
        };
        let decoder = if let Some(vk) = verify_key {
            decoder.verify_key(vk)
        } else {
            decoder
        };

        let modes_to_test = if let Some(m) = forced_mode {
            vec![m]
        } else {
            vec![ColorMode::FourColor, ColorMode::EightColor, ColorMode::Monochrome]
        };

        let (w, h) = img.dimensions();
        for size in (5..=251).step_by(2) {
            let cell_w = w as f32 / size as f32;
            let cell_h = h as f32 / size as f32;
            if cell_w < 1.0 || cell_h < 1.0 {
                continue;
            }

            let mut sample_grid = vec![vec![Rgb(0, 0, 0); size]; size];
            for y in 0..size {
                let cy = ((y as f32 + 0.5) * cell_h) as u32;
                for x in 0..size {
                    let cx = ((x as f32 + 0.5) * cell_w) as u32;
                    let p = img.get_pixel(cx.min(w - 1), cy.min(h - 1));
                    sample_grid[y][x] = Rgb(p[0], p[1], p[2]);
                }
            }

            let bl_dark = sample_grid[size - 1][0].0 < 128;
            let br_bright = sample_grid[size - 1][size - 1].0 >= 128;
            if !bl_dark || !br_bright {
                continue;
            }

            let valid_nano = sample_grid[0][0].0 < 128
                && sample_grid[0][1].0 < 128
                && sample_grid[0][2].0 < 128
                && sample_grid[1][1].0 < 128;

            let spine_x = size / 2;
            let valid_std = (0..size).all(|x| sample_grid[0][x].0 < 128)
                && (0..size.saturating_sub(8).max(1)).all(|y| sample_grid[y][spine_x].0 < 128);

            let mut layouts = Vec::new();
            if valid_nano {
                layouts.push(true);
            }
            if valid_std {
                layouts.push(false);
            }

            for is_nano in layouts {
                for &mode in &modes_to_test {
                    let mut grid = Grid::new(size, mode);
                    let mut palette = Rgb::PALETTE[..mode.num_colors()].to_vec();

                    if !is_nano {
                        for c in 0..mode.num_colors() {
                            let y_pos = size - 1 - c;
                            if y_pos < size {
                                palette[c] = sample_grid[y_pos][spine_x];
                            }
                        }
                    }

                    for y in 0..size {
                        for x in 0..size {
                            let color = sample_grid[y][x];
                            let best_idx = palette
                                .iter()
                                .enumerate()
                                .min_by_key(|(_, p)| color.distance_sq(p))
                                .map(|(i, _)| i as u8)
                                .unwrap_or(0);
                            grid.set(x, y, best_idx);
                        }
                    }

                    if let Ok(res) = decoder.decode_grid(&grid, Some(is_nano)) {
                        return Ok(res);
                    }
                }
            }
        }

        Err(TSpineError::ScanFailed(
            "Could not decode valid T-Spine Code from image".to_string(),
        ))
    }
}