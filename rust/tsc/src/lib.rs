//! # T-Spine Code (TSC) Library
//!
//! High-density 2D matrix barcode format featuring central spine and roof alignment,
//! 2/4/8-color high density modulation, Zstandard compression, Fernet AES-CBC encryption,
//! HMAC-SHA256 digital signatures, interactive SVG/HTML matrix diagnostics, and acoustic FSK transmission.

pub mod crypto;
pub mod decoder;
pub mod encoder;
pub mod error;
pub mod export;
pub mod grid;
pub mod payload;
pub mod rs;
pub mod scanner;
pub mod types;

pub use decoder::TSpineDecoder;
pub use encoder::TSpineEncoder;
pub use error::{Result, TSpineError};
pub use grid::Grid;
pub use types::{ColorMode, DecodedPayload, EccLevel, Metadata, Rgb};

/// High-level shortcut: Encode a byte payload into a TSC PNG image.
pub fn encode_to_png_file(
    data: &[u8],
    path: impl AsRef<std::path::Path>,
    mode: ColorMode,
    ecc: EccLevel,
) -> Result<Metadata> {
    let (grid, meta) = TSpineEncoder::new()
        .color_mode(mode)
        .ecc_level(ecc)
        .encode(data)?;
    export::image::ImageExporter::save(&grid, path, 15, 2)?;
    Ok(meta)
}

/// High-level shortcut: Scan and decode a TSC image file directly.
pub fn scan_image_file(path: impl AsRef<std::path::Path>) -> Result<DecodedPayload> {
    scanner::image_scan::ImageScanner::scan_file(path, None, None, None)
}