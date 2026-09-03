use std::fmt;

/// Color mode determining grid density and cell bit capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorMode {
    /// 2 colors: Black and White (1 bit per cell).
    #[default]
    Monochrome = 2,
    /// 4 colors: White, Black, Red, Blue (2 bits per cell).
    FourColor = 4,
    /// 8 colors: White, Black, Red, Blue, Green, Cyan, Magenta, Yellow (3 bits per cell).
    EightColor = 8,
}

impl ColorMode {
    #[inline]
    pub fn num_colors(&self) -> usize {
        *self as usize
    }

    #[inline]
    pub fn bits_per_cell(&self) -> usize {
        match self {
            ColorMode::Monochrome => 1,
            ColorMode::FourColor => 2,
            ColorMode::EightColor => 3,
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        let clean = s.trim().to_lowercase();
        match clean.as_str() {
            "0" | "no" | "none" | "bw" | "wk" | "mono" | "2" | "b/w" | "false" | "off" => {
                Some(ColorMode::Monochrome)
            }
            "4" | "default" | "min" | "wkrb" => Some(ColorMode::FourColor),
            "8" | "all" | "max" | "wkrbgcmy" => Some(ColorMode::EightColor),
            _ => None,
        }
    }
}

/// Reed-Solomon Error Correction Level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EccLevel {
    None,
    Low,
    #[default]
    Medium,
    High,
    Custom(u8),
}

impl EccLevel {
    #[inline]
    pub fn parity_bytes(&self) -> usize {
        match self {
            EccLevel::None => 0,
            EccLevel::Low => 4,
            EccLevel::Medium => 12,
            EccLevel::High => 28,
            EccLevel::Custom(b) => *b as usize,
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "0" | "no" | "none" | "off" | "false" => EccLevel::None,
            "1" | "low" => EccLevel::Low,
            "2" | "mid" | "med" | "normal" => EccLevel::Medium,
            "3" | "high" | "max" => EccLevel::High,
            other => other
                .parse::<u8>()
                .map(EccLevel::Custom)
                .unwrap_or(EccLevel::Medium),
        }
    }
}

/// 24-bit RGB Color Tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    pub const WHITE: Rgb = Rgb(255, 255, 255);
    pub const BLACK: Rgb = Rgb(0, 0, 0);
    pub const RED: Rgb = Rgb(255, 0, 0);
    pub const BLUE: Rgb = Rgb(0, 0, 255);
    pub const GREEN: Rgb = Rgb(0, 255, 0);
    pub const CYAN: Rgb = Rgb(0, 255, 255);
    pub const MAGENTA: Rgb = Rgb(255, 0, 255);
    pub const YELLOW: Rgb = Rgb(255, 255, 0);

    pub const PALETTE: [Rgb; 8] = [
        Self::WHITE,
        Self::BLACK,
        Self::RED,
        Self::BLUE,
        Self::GREEN,
        Self::CYAN,
        Self::MAGENTA,
        Self::YELLOW,
    ];

    #[inline]
    pub fn distance_sq(&self, other: &Rgb) -> u32 {
        let dr = self.0 as i32 - other.0 as i32;
        let dg = self.1 as i32 - other.1 as i32;
        let db = self.2 as i32 - other.2 as i32;
        (dr * dr + dg * dg + db * db) as u32
    }
}

impl fmt::Display for Rgb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rgb({},{},{})", self.0, self.1, self.2)
    }
}

/// Metadata summary of an encoded or decoded TSC instance.
#[derive(Debug, Clone, Default)]
pub struct Metadata {
    pub size: usize,
    pub raw_bytes: usize,
    pub packed_bytes: usize,
    pub header_bytes_count: usize,
    pub data_bytes_count: usize,
    pub ecc_start_byte: usize,
    pub total_cap_bytes: usize,
    pub ecc_bytes: usize,
    pub colors: usize,
    pub bits_per_cell: usize,
    pub flags: u8,
    pub is_dual: bool,
    pub is_binary: bool,
    pub is_signed: bool,
    pub is_encrypted: bool,
    pub is_min_header: bool,
    pub is_nano: bool,
}

/// Decoded result container for Single and Dual mode payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedPayload {
    Text(String),
    Binary(Vec<u8>),
    Dual {
        public_data: String,
        private_data: String,
    },
}