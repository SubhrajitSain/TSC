use crate::error::{Result, TSpineError};

const GF_SIZE: usize = 256;
const PRIM_POLY: usize = 0x11d;

#[derive(Clone)]
pub struct ReedSolomon {
    ecc_bytes: usize,
    exp: [u8; GF_SIZE * 2],
    log: [u8; GF_SIZE],
}

impl ReedSolomon {
    pub fn new(ecc_bytes: usize) -> Self {
        let mut exp = [0u8; GF_SIZE * 2];
        let mut log = [0u8; GF_SIZE];

        let mut x = 1;
        for i in 0..255 {
            exp[i] = x as u8;
            exp[i + 255] = x as u8;
            log[x] = i as u8;
            x <<= 1;
            if x >= GF_SIZE {
                x ^= PRIM_POLY;
            }
        }

        Self {
            ecc_bytes,
            exp,
            log,
        }
    }

    #[inline]
    fn gf_mul(&self, x: u8, y: u8) -> u8 {
        if x == 0 || y == 0 {
            0
        } else {
            self.exp[self.log[x as usize] as usize + self.log[y as usize] as usize]
        }
    }

    #[inline]
    fn gf_div(&self, x: u8, y: u8) -> u8 {
        if x == 0 {
            0
        } else if y == 0 {
            panic!("Division by zero in GF(256)");
        } else {
            let idx = (self.log[x as usize] as usize + 255) - self.log[y as usize] as usize;
            self.exp[idx]
        }
    }

    #[inline]
    fn gf_poly_mul(&self, p: &[u8], q: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; p.len() + q.len() - 1];
        for i in 0..p.len() {
            for j in 0..q.len() {
                r[i + j] ^= self.gf_mul(p[i], q[j]);
            }
        }
        r
    }

    fn generator_poly(&self) -> Vec<u8> {
        let mut g = vec![1u8];
        for i in 0..self.ecc_bytes {
            let root = self.exp[i];
            g = self.gf_poly_mul(&g, &[1, root]);
        }
        g
    }

    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        if self.ecc_bytes == 0 {
            return data.to_vec();
        }

        let chunk_data_len = 255 - self.ecc_bytes;
        let mut out = Vec::new();
        let gen = self.generator_poly();

        for chunk in data.chunks(chunk_data_len) {
            let mut msg = chunk.to_vec();
            let mut feedback = vec![0u8; chunk.len() + self.ecc_bytes];
            feedback[..chunk.len()].copy_from_slice(chunk);

            for i in 0..chunk.len() {
                let coef = feedback[i];
                if coef != 0 {
                    for j in 1..gen.len() {
                        feedback[i + j] ^= self.gf_mul(gen[j], coef);
                    }
                }
            }

            msg.extend_from_slice(&feedback[chunk.len()..]);
            out.extend_from_slice(&msg);
        }

        out
    }

    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        if self.ecc_bytes == 0 {
            return Ok(encoded.to_vec());
        }

        let chunk_len = 255;
        let mut decoded = Vec::new();

        for chunk in encoded.chunks(chunk_len) {
            let corrected = self.decode_chunk(chunk)?;
            decoded.extend_from_slice(&corrected);
        }

        Ok(decoded)
    }

    fn decode_chunk(&self, chunk: &[u8]) -> Result<Vec<u8>> {
        let mut msg = chunk.to_vec();
        let mut synd = vec![0u8; self.ecc_bytes];
        let mut has_errors = false;

        for i in 0..self.ecc_bytes {
            let root = self.exp[i];
            let mut eval = 0u8;
            for &byte in &msg {
                eval = self.gf_mul(eval, root) ^ byte;
            }
            synd[i] = eval;
            if eval != 0 {
                has_errors = true;
            }
        }

        if !has_errors {
            let data_len = msg.len() - self.ecc_bytes;
            return Ok(msg[..data_len].to_vec());
        }

        // Berlekamp-Massey Algorithm
        let mut sigma = vec![1u8];
        let mut b = vec![1u8];
        let mut l = 0;
        let mut m = 1;

        for (k, &s_k) in synd.iter().enumerate() {
            let mut d = s_k;
            for i in 1..=l {
                if i < sigma.len() && k >= i {
                    d ^= self.gf_mul(sigma[i], synd[k - i]);
                }
            }

            if d == 0 {
                m += 1;
            } else {
                let temp = sigma.clone();
                let scale = d;
                let mut b_shifted = vec![0u8; m];
                b_shifted.extend_from_slice(&b);

                while sigma.len() < b_shifted.len() {
                    sigma.push(0);
                }
                for i in 0..b_shifted.len() {
                    sigma[i] ^= self.gf_mul(scale, b_shifted[i]);
                }

                if 2 * l <= k {
                    l = k + 1 - l;
                    b = vec![0u8; temp.len()];
                    for i in 0..temp.len() {
                        b[i] = self.gf_div(temp[i], scale);
                    }
                    m = 1;
                } else {
                    m += 1;
                }
            }
        }

        // Chien Search & Forney Algorithm
        let err_count = sigma.len() - 1;
        let mut err_pos = Vec::new();

        for i in 0..msg.len() {
            let x = self.exp[(255 - (i % 255)) % 255];
            let mut eval = 0u8;
            for (j, &c) in sigma.iter().enumerate() {
                eval ^= self.gf_mul(c, self.exp[(self.log[x as usize] as usize * j) % 255]);
            }
            if eval == 0 {
                err_pos.push(msg.len() - 1 - i);
            }
        }

        if err_pos.len() != err_count {
            return Err(TSpineError::ReedSolomon(
                "Uncorrectable error in block".to_string(),
            ));
        }

        let mut omega = self.gf_poly_mul(&synd, &sigma);
        omega.truncate(self.ecc_bytes);

        let msg_len = msg.len();
        for &pos in &err_pos {
            let xi_inv = self.exp[pos % 255];
            let mut num = 0u8;
            for (j, &c) in omega.iter().enumerate() {
                num ^= self.gf_mul(c, self.exp[(self.log[xi_inv as usize] as usize * j) % 255]);
            }

            let mut den = 0u8;
            for j in (1..sigma.len()).step_by(2) {
                den ^= self.gf_mul(
                    sigma[j],
                    self.exp[(self.log[xi_inv as usize] as usize * (j - 1)) % 255],
                );
            }

            let magnitude = self.gf_div(num, den);
            let target_idx = msg_len - 1 - pos;
            msg[target_idx] ^= magnitude;
        }

        let data_len = msg.len() - self.ecc_bytes;
        Ok(msg[..data_len].to_vec())
    }
}