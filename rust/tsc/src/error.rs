use thiserror::Error;

#[derive(Error, Debug)]
pub enum TSpineError {
    #[error("Data too large: requires {required} bytes, but maximum capacity is {capacity} bytes")]
    DataTooLarge { required: usize, capacity: usize },

    #[error("Data too large for single TSC: grid size {size} exceeds limit of 251x251")]
    SizeExceedsLimit { size: usize },

    #[error("Corrupted payload block: expected at least 2 bytes, got {0}")]
    CorruptedBlock(usize),

    #[error("Invalid T-Spine Code header")]
    InvalidHeader,

    #[error("Data is encrypted: provide password to decrypt")]
    PasswordRequired,

    #[error("Failed to decrypt payload: invalid password or corrupted data")]
    DecryptionFailed,

    #[error("Signature verification failed: signature does not match")]
    SignatureMismatch,

    #[error("Corrupted signature in header")]
    CorruptedSignature,

    #[error("Reed-Solomon decoding error: {0}")]
    ReedSolomon(String),

    #[error("Compression error: {0}")]
    Compression(#[from] std::io::Error),

    #[error("Audio decoding error: {0}")]
    Audio(String),

    #[error("Image scanning error: {0}")]
    ScanFailed(String),

    #[error("Invalid UTF-8 payload")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}

pub type Result<T> = std::result::Result<T, TSpineError>;