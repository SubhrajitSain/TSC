## Quickstart

### 1. Encode Data to an Image

```rust
use tspine::{TSpineEncoder, ColorMode, EccLevel};
use tspine::export::image::ImageExporter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payload = b"https://github.com/SubhrajitSain/IDFCPL";

    let (grid, meta) = TSpineEncoder::new()
        .color_mode(ColorMode::FourColor)
        .ecc_level(EccLevel::Medium)
        .encode(payload)?;

    println!("Generated {}x{} TSC grid with {} colors", meta.size, meta.colors);

    // Save as PNG
    ImageExporter::save(&grid, "tspine.png", 15 /* module size */, 2 /* quiet zone */)?;

    Ok(())
}
```

---

### 2. Encrypted & Signed TSC

```rust
use tspine::TSpineEncoder;
use tspine::export::image::ImageExporter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret_payload = b"Top secret cryptographic payload";

    let (grid, _) = TSpineEncoder::new()
        .password("strong-vault-passphrase")
        .sign_key("hmac-signing-key")
        .encode(secret_payload)?;

    ImageExporter::save(&grid, "secure.png", 15, 2)?;
    Ok(())
}
```

---

### 3. Dual-Layer Steganographic Matrix

```rust
use tspine::TSpineEncoder;
use tspine::export::image::ImageExporter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let public_note = b"Public asset tracking tag #1042";
    let private_keys = b"PRIVATE: seed-phrase-data-inside-vault";

    let (grid, _) = TSpineEncoder::new()
        .password("admin-passphrase")
        .encode_dual(public_note, private_keys)?;

    ImageExporter::save(&grid, "dual.png", 15, 2)?;
    Ok(())
}
```

---

### 4. Decode an Image

```rust
use tspine::scanner::image_scan::ImageScanner;
use tspine::DecodedPayload;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result = ImageScanner::scan_file("secure.png", Some("strong-vault-passphrase"), Some("hmac-signing-key"), None)?;

    match result {
        DecodedPayload::Text(text) => println!("Decoded Text: {}", text),
        DecodedPayload::Binary(bytes) => println!("Decoded {} bytes", bytes.len()),
        DecodedPayload::Dual { public_data, private_data } => {
            println!("Public: {}\nPrivate: {}", public_data, private_data);
        }
    }

    Ok(())
}
```

---

### 5. Interactive HTML Diagnostics & Vector SVG

```rust
use tspine::TSpineEncoder;
use tspine::export::html::HtmlExporter;
use tspine::export::svg::SvgExporter;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (grid, meta) = TSpineEncoder::new().encode(b"Diagnostic Data")?;

    // Export interactive HTML Inspector
    let html = HtmlExporter::to_html_string(&grid, Some(&meta), 16, 2);
    fs::write("inspector.html", html)?;

    // Export scalable SVG
    let svg = SvgExporter::to_svg_string(&grid, 15, 2);
    fs::write("output.svg", svg)?;

    Ok(())
}
```

---

### 6. Acoustic Modem (Audio FSK Modulation)

```rust
use tspine::{ColorMode, EccLevel};
use tspine::export::audio::AudioModem;
use tspine::scanner::audio_scan::AudioScanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = b"Acoustic Packet 001";

    // Modulate to WAV
    AudioModem::export_wav(data, "signal.wav", ColorMode::FourColor, EccLevel::Medium, None, 0.5)?;

    // Demodulate from WAV
    let decoded = AudioScanner::scan_wav("signal.wav", 0.5, None, None)?;
    println!("Received audio packet: {:?}", decoded);

    Ok(())
}
```

---