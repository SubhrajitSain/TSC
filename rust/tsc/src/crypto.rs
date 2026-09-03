use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes128;
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use cbc::{Decryptor, Encryptor};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, TSpineError};

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

pub struct Crypto;

impl Crypto {
    pub fn derive_keys(password: &str) -> ([u8; 16], [u8; 16]) {
        let hash = Sha256::digest(password.as_bytes());
        let mut sign_key = [0u8; 16];
        let mut enc_key = [0u8; 16];
        sign_key.copy_from_slice(&hash[..16]);
        enc_key.copy_from_slice(&hash[16..32]);
        (sign_key, enc_key)
    }

    pub fn encrypt_fernet(password: &str, data: &[u8]) -> Vec<u8> {
        let (sign_key, enc_key) = Self::derive_keys(password);

        let version = 0x80u8;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        let encryptor = Aes128CbcEnc::new(&enc_key.into(), &iv.into());
        let ciphertext = encryptor.encrypt_padded_vec_mut::<Pkcs7>(data);

        let mut raw_token = Vec::with_capacity(1 + 8 + 16 + ciphertext.len() + 32);
        raw_token.push(version);
        raw_token.extend_from_slice(&timestamp.to_be_bytes());
        raw_token.extend_from_slice(&iv);
        raw_token.extend_from_slice(&ciphertext);

        let mut mac = HmacSha256::new_from_slice(&sign_key).expect("Valid HMAC key");
        mac.update(&raw_token);
        let hmac_res = mac.finalize().into_bytes();

        raw_token.extend_from_slice(&hmac_res);

        URL_SAFE.encode(raw_token).into_bytes()
    }

    pub fn decrypt_fernet(password: &str, token: &[u8]) -> Result<Vec<u8>> {
        let (sign_key, enc_key) = Self::derive_keys(password);

        let raw = URL_SAFE
            .decode(token)
            .or_else(|_| Ok::<Vec<u8>, base64::DecodeError>(token.to_vec()))
            .map_err(|_| TSpineError::DecryptionFailed)?;

        if raw.len() < 1 + 8 + 16 + 16 + 32 || raw[0] != 0x80 {
            return Err(TSpineError::DecryptionFailed);
        }

        let payload_len = raw.len() - 32;
        let msg = &raw[..payload_len];
        let sig = &raw[payload_len..];

        let mut mac = HmacSha256::new_from_slice(&sign_key).map_err(|_| TSpineError::DecryptionFailed)?;
        mac.update(msg);
        mac.verify_slice(sig).map_err(|_| TSpineError::DecryptionFailed)?;

        let iv = &raw[9..25];
        let ciphertext = &raw[25..payload_len];

        let decryptor = Aes128CbcDec::new(&enc_key.into(), iv.into());
        decryptor
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| TSpineError::DecryptionFailed)
    }

    pub fn sign_hmac(key: &str, data: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("Valid HMAC key");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    pub fn verify_hmac(key: &str, data: &[u8], signature: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("Valid HMAC key");
        mac.update(data);
        let full_sig = mac.finalize().into_bytes();
        if signature.len() == 16 {
            &full_sig[..16] == signature
        } else if signature.len() == 32 {
            &full_sig[..] == signature
        } else {
            false
        }
    }
}