use crate::crypto::Crypto;
use crate::error::{Result, TSpineError};
use crate::types::DecodedPayload;

pub const FLAG_COMPRESSED: u8 = 0x01;
pub const FLAG_ENCRYPTED: u8 = 0x02;
pub const FLAG_SIGNED: u8 = 0x04;
pub const FLAG_DUAL: u8 = 0x08;
pub const FLAG_BINARY: u8 = 0x10;

pub struct Payload;

impl Payload {
    pub fn is_binary(data: &[u8]) -> bool {
        match std::str::from_utf8(data) {
            Ok(s) => s.as_bytes().iter().take(1024).any(|&b| b == 0),
            Err(_) => true,
        }
    }

    pub fn prepare_single(
        data: &[u8],
        password: Option<&str>,
        sign_key: Option<&str>,
        min_header: bool,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut flags = 0u8;
        if Self::is_binary(data) {
            flags |= FLAG_BINARY;
        }

        let compressed = zstd::bulk::compress(data, 22).unwrap_or_else(|_| data.to_vec());
        let (payload_bytes, is_comp) = if compressed.len() < data.len() {
            (compressed, true)
        } else {
            (data.to_vec(), false)
        };

        if is_comp {
            flags |= FLAG_COMPRESSED;
        }

        let encrypted = if let Some(pwd) = password {
            flags |= FLAG_ENCRYPTED;
            Crypto::encrypt_fernet(pwd, &payload_bytes)
        } else {
            payload_bytes
        };

        let body = if min_header {
            let mut b = Vec::with_capacity(1 + encrypted.len());
            b.push((encrypted.len() & 0xFF) as u8);
            b.extend_from_slice(&encrypted);
            b
        } else {
            let mut b = Vec::with_capacity(4 + encrypted.len());
            b.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
            b.extend_from_slice(&encrypted);
            b
        };

        let mut sig_block = Vec::new();
        if let Some(key) = sign_key {
            flags |= FLAG_SIGNED;
            let full_sig = Crypto::sign_hmac(key, &body);
            if min_header {
                sig_block.extend_from_slice(&full_sig[..16]);
            } else {
                sig_block.extend_from_slice(&full_sig);
            }
        }

        let raw_data = if min_header {
            let mut r = Vec::with_capacity(1 + sig_block.len() + body.len());
            r.push(flags | 0x80);
            r.extend_from_slice(&sig_block);
            r.extend_from_slice(&body);
            r
        } else {
            let mut r = Vec::with_capacity(4 + sig_block.len() + body.len());
            r.extend_from_slice(b"TSC");
            r.push(flags);
            r.extend_from_slice(&sig_block);
            r.extend_from_slice(&body);
            r
        };

        Ok((raw_data, body))
    }

    pub fn prepare_dual(
        public_data: &[u8],
        private_data: &[u8],
        password: Option<&str>,
        sign_key: Option<&str>,
        min_header: bool,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut flags = FLAG_DUAL;

        let compressed_priv =
            zstd::bulk::compress(private_data, 22).unwrap_or_else(|_| private_data.to_vec());
        let mut priv_payload = Vec::new();
        if compressed_priv.len() < private_data.len() {
            priv_payload.push(1u8);
            priv_payload.extend_from_slice(&compressed_priv);
        } else {
            priv_payload.push(0u8);
            priv_payload.extend_from_slice(private_data);
        }

        if let Some(pwd) = password {
            flags |= FLAG_ENCRYPTED;
            priv_payload = Crypto::encrypt_fernet(pwd, &priv_payload);
        }

        let body = if min_header {
            let mut b = Vec::new();
            b.push((public_data.len() & 0xFF) as u8);
            b.extend_from_slice(public_data);
            b.push((priv_payload.len() & 0xFF) as u8);
            b.extend_from_slice(&priv_payload);
            b
        } else {
            let mut b = Vec::new();
            b.extend_from_slice(&(public_data.len() as u32).to_be_bytes());
            b.extend_from_slice(public_data);
            b.extend_from_slice(&(priv_payload.len() as u32).to_be_bytes());
            b.extend_from_slice(&priv_payload);
            b
        };

        let mut sig_block = Vec::new();
        if let Some(key) = sign_key {
            flags |= FLAG_SIGNED;
            let full_sig = Crypto::sign_hmac(key, &body);
            if min_header {
                sig_block.extend_from_slice(&full_sig[..16]);
            } else {
                sig_block.extend_from_slice(&full_sig);
            }
        }

        let raw_data = if min_header {
            let mut r = Vec::new();
            r.push(flags | 0x80);
            r.extend_from_slice(&sig_block);
            r.extend_from_slice(&body);
            r
        } else {
            let mut r = Vec::new();
            r.extend_from_slice(b"TSC");
            r.push(flags);
            r.extend_from_slice(&sig_block);
            r.extend_from_slice(&body);
            r
        };

        Ok((raw_data, body))
    }

    pub fn unpack(
        block: &[u8],
        password: Option<&str>,
        verify_key: Option<&str>,
    ) -> Result<DecodedPayload> {
        if block.len() < 2 {
            return Err(TSpineError::CorruptedBlock(block.len()));
        }

        let (is_min, flags, mut idx) = if (block[0] & 0x80) != 0 {
            (true, block[0] & !0x80, 1usize)
        } else if block.len() >= 4 && &block[..3] == b"TSC" {
            (false, block[3], 4usize)
        } else {
            return Err(TSpineError::InvalidHeader);
        };

        let has_compression = (flags & FLAG_COMPRESSED) != 0;
        let has_encryption = (flags & FLAG_ENCRYPTED) != 0;
        let has_signature = (flags & FLAG_SIGNED) != 0;
        let is_dual = (flags & FLAG_DUAL) != 0;
        let is_binary = (flags & FLAG_BINARY) != 0;

        if has_signature {
            let sig_size = if is_min { 16 } else { 32 };
            if block.len() < idx + sig_size {
                return Err(TSpineError::CorruptedSignature);
            }
            let sig = &block[idx..idx + sig_size];
            idx += sig_size;

            let body_start = idx;
            let body_len = if is_dual {
                if is_min {
                    let pub_len = block[idx] as usize;
                    let pr_pos = idx + 1 + pub_len;
                    let pr_len = block[pr_pos] as usize;
                    1 + pub_len + 1 + pr_len
                } else {
                    let pub_len = u32::from_be_bytes(block[idx..idx + 4].try_into().unwrap()) as usize;
                    let pr_pos = idx + 4 + pub_len;
                    let pr_len = u32::from_be_bytes(block[pr_pos..pr_pos + 4].try_into().unwrap()) as usize;
                    4 + pub_len + 4 + pr_len
                }
            } else if is_min {
                let p_len = block[idx] as usize;
                1 + p_len
            } else {
                let p_len = u32::from_be_bytes(block[idx..idx + 4].try_into().unwrap()) as usize;
                4 + p_len
            };

            let body_to_verify = &block[body_start..body_start + body_len];
            if let Some(vk) = verify_key {
                if !Crypto::verify_hmac(vk, body_to_verify, sig) {
                    return Err(TSpineError::SignatureMismatch);
                }
            }
        }

        if is_dual {
            let (pub_bytes, priv_payload) = if is_min {
                let pub_len = block[idx] as usize;
                idx += 1;
                let pub_b = &block[idx..idx + pub_len];
                idx += pub_len;
                let priv_len = block[idx] as usize;
                idx += 1;
                let priv_p = &block[idx..idx + priv_len];
                (pub_b, priv_p)
            } else {
                let pub_len = u32::from_be_bytes(block[idx..idx + 4].try_into().unwrap()) as usize;
                idx += 4;
                let pub_b = &block[idx..idx + pub_len];
                idx += pub_len;
                let priv_len = u32::from_be_bytes(block[idx..idx + 4].try_into().unwrap()) as usize;
                idx += 4;
                let priv_p = &block[idx..idx + priv_len];
                (pub_b, priv_p)
            };

            let pub_text = String::from_utf8_lossy(pub_bytes).to_string();
            let priv_text = if has_encryption {
                if let Some(pwd) = password {
                    match Crypto::decrypt_fernet(pwd, priv_payload) {
                        Ok(decrypted) if !decrypted.is_empty() => {
                            let comp_flag = decrypted[0];
                            let raw_p = &decrypted[1..];
                            if comp_flag == 1 {
                                zstd::bulk::decompress(raw_p, 10 * 1024 * 1024)
                                    .map(|b| String::from_utf8_lossy(&b).to_string())
                                    .unwrap_or_else(|_| "[Corrupted private data]".to_string())
                            } else {
                                String::from_utf8_lossy(raw_p).to_string()
                            }
                        }
                        _ => "[Incorrect password]".to_string(),
                    }
                } else {
                    "[Pass password to decrypt]".to_string()
                }
            } else if !priv_payload.is_empty() {
                let comp_flag = priv_payload[0];
                let raw_p = &priv_payload[1..];
                if comp_flag == 1 {
                    zstd::bulk::decompress(raw_p, 10 * 1024 * 1024)
                        .map(|b| String::from_utf8_lossy(&b).to_string())
                        .unwrap_or_else(|_| "[Corrupted private data]".to_string())
                } else {
                    String::from_utf8_lossy(raw_p).to_string()
                }
            } else {
                String::new()
            };

            Ok(DecodedPayload::Dual {
                public_data: pub_text,
                private_data: priv_text,
            })
        } else {
            let payload_bytes = if is_min {
                let p_len = block[idx] as usize;
                idx += 1;
                &block[idx..idx + p_len]
            } else {
                let p_len = u32::from_be_bytes(block[idx..idx + 4].try_into().unwrap()) as usize;
                idx += 4;
                &block[idx..idx + p_len]
            };

            let decrypted = if has_encryption {
                let pwd = password.ok_or(TSpineError::PasswordRequired)?;
                Crypto::decrypt_fernet(pwd, payload_bytes)?
            } else {
                payload_bytes.to_vec()
            };

            let decompressed = if has_compression {
                zstd::bulk::decompress(&decrypted, 100 * 1024 * 1024)?
            } else {
                decrypted
            };

            if is_binary {
                Ok(DecodedPayload::Binary(decompressed))
            } else {
                Ok(DecodedPayload::Text(String::from_utf8(decompressed)?))
            }
        }
    }
}