# T-Spine Code (TSC) for Rust



**T-Spine Code (TSC)** is a next-generation 2D matrix barcode and acoustic data transmission format. It utilizes an asymmetric **Roof-and-Spine** finder structure, chromatic modulation (up to 3 bits/cell), Reed-Solomon forward error correction, built-in Zstandard compression, Fernet AES encryption, and HMAC-SHA256 digital signatures.

---

## Features

- **Chromatic Capacity Modulation**:
  - `Monochrome` (2 colors / 1 bit per cell)
  - `FourColor` (4 colors: W/K/R/B / 2 bits per cell)
  - `EightColor` (8 colors: W/K/R/B/G/C/M/Y / 3 bits per cell)
- **Standard & Nano Layouts**: Dynamically scales from compact $5\times 5$ grids up to $251\times 251$ matrices.
- **Dual-Layer Steganography**: Public payload visible to standard scanners alongside encrypted private data.
- **Built-in Cryptography & Integrity**:
  - Symmetric Fernet (AES-128-CBC + HMAC-SHA256) encryption.
  - HMAC-SHA256 authentication signatures.
- **Acoustic Modem (Audio FSK)**: Encode and decode TSC data packets to and from `.wav` audio signals.
- **Multi-Format Exporting**:
  - Raster Images (`PNG`, `BMP`, `JPEG`)
  - Scalable Vector Graphics (`SVG`)
  - Interactive HTML Diagnostic Inspector
  - ANSI Colored Terminal Matrix Preview
  - Acoustic WAV Signals

---

## Installation

Add `tspine` to your `Cargo.toml`:

```toml
[dependencies]
tspine = "1.0.0"