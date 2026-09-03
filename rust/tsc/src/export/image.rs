use image::{ImageBuffer, RgbImage};
use std::path::Path;

use crate::error::Result;
use crate::grid::Grid;

pub struct ImageExporter;

impl ImageExporter {
    pub fn to_image_buffer(grid: &Grid, module_size: u32, quiet_zone: u32) -> RgbImage {
        let total_modules = (grid.size as u32) + 2 * quiet_zone;
        let dim = total_modules * module_size;
        let mut img: RgbImage = ImageBuffer::from_pixel(dim, dim, image::Rgb([255, 255, 255]));

        for y in 0..grid.size {
            for x in 0..grid.size {
                let rgb = grid.get_rgb(x, y);
                let px = ((x as u32) + quiet_zone) * module_size;
                let py = ((y as u32) + quiet_zone) * module_size;

                for dy in 0..module_size {
                    for dx in 0..module_size {
                        img.put_pixel(px + dx, py + dy, image::Rgb([rgb.0, rgb.1, rgb.2]));
                    }
                }
            }
        }

        img
    }

    pub fn save(grid: &Grid, path: impl AsRef<Path>, module_size: u32, quiet_zone: u32) -> Result<()> {
        let img = Self::to_image_buffer(grid, module_size, quiet_zone);
        img.save(path).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(())
    }
}