use crate::types::{ColorMode, Rgb};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grid {
    pub size: usize,
    pub cells: Vec<Vec<u8>>,
    pub mode: ColorMode,
}

impl Grid {
    pub fn new(size: usize, mode: ColorMode) -> Self {
        Self {
            size,
            cells: vec![vec![0; size]; size],
            mode,
        }
    }

    #[inline]
    pub fn get(&self, x: usize, y: usize) -> u8 {
        self.cells[y][x]
    }

    #[inline]
    pub fn set(&mut self, x: usize, y: usize, val: u8) {
        self.cells[y][x] = val;
    }

    #[inline]
    pub fn is_nano(size: usize, force_nano: bool) -> bool {
        force_nano || size <= 7
    }

    #[inline]
    pub fn mask(x: usize, y: usize) -> bool {
        (x + y) % 2 == 0
    }

    pub fn capacity_bytes(size: usize, mode: ColorMode, is_nano: bool) -> usize {
        let bpc = mode.bits_per_cell();
        let bits = if is_nano {
            (size * size - 6) * bpc
        } else {
            (size * size - 2 * size - 1) * bpc
        };
        bits / 8
    }

    pub fn data_capacity_from_total(total_cap: usize, ecc_bytes: usize) -> usize {
        if ecc_bytes == 0 {
            return total_cap;
        }
        let chunk_cap = 255;
        let chunk_data = 255 - ecc_bytes;
        let full_chunks = total_cap / chunk_cap;
        let rem = total_cap % chunk_cap;
        let rem_data = if rem >= ecc_bytes { rem - ecc_bytes } else { 0 };
        (full_chunks * chunk_data) + rem_data
    }

    pub fn data_coordinates(size: usize, is_nano: bool) -> Vec<(usize, usize)> {
        let mut coords = Vec::new();
        if is_nano {
            let t_cells = [(0, 0), (1, 0), (2, 0), (1, 1)];
            for y in 0..size {
                for x in 0..size {
                    if t_cells.contains(&(x, y)) {
                        continue;
                    }
                    if y == size - 1 && (x == 0 || x == size - 1) {
                        continue;
                    }
                    coords.push((x, y));
                }
            }
        } else {
            let spine_x = size / 2;
            for y in 1..size {
                for x in 0..size {
                    if x == spine_x {
                        continue;
                    }
                    if y == size - 1 && (x == 0 || x == size - 1) {
                        continue;
                    }
                    coords.push((x, y));
                }
            }
        }
        coords
    }

    pub fn apply_skeletons(&mut self, is_nano: bool) {
        let size = self.size;
        if is_nano {
            self.set(0, 0, 1);
            self.set(1, 0, 1);
            self.set(2, 0, 1);
            self.set(1, 1, 1);
            self.set(0, size - 1, 1);
            self.set(size - 1, size - 1, 0);
        } else {
            for x in 0..size {
                self.set(x, 0, 1);
            }
            let spine_x = size / 2;
            for y in 0..size {
                self.set(spine_x, y, 1);
            }
            for c in 0..self.mode.num_colors() {
                if size >= 1 + c {
                    self.set(spine_x, size - 1 - c, c as u8);
                }
            }
            self.set(0, size - 1, 1);
            self.set(size - 1, size - 1, 0);
        }
    }

    pub fn get_rgb(&self, x: usize, y: usize) -> Rgb {
        let val = self.get(x, y) as usize;
        if val < Rgb::PALETTE.len() {
            Rgb::PALETTE[val]
        } else {
            Rgb::BLACK
        }
    }
}