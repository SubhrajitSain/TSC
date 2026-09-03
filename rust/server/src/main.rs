use axum::{
    extract::{Multipart, Query},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::net::SocketAddr;
use tempfile::NamedTempFile;
use tower_http::cors::{Any, CorsLayer};

use tspine::export::{
    audio::AudioModem,
    html::HtmlExporter,
    image::ImageExporter,
    svg::SvgExporter,
    terminal::TerminalExporter,
};
use tspine::scanner::image_scan::ImageScanner;
use tspine::{ColorMode, DecodedPayload, EccLevel, TSpineEncoder};

#[derive(Deserialize, Debug)]
pub struct GenerateParams {
    pub text: Option<String>,
    pub public: Option<String>,
    pub private: Option<String>,
    pub format: Option<String>,
    pub colors: Option<String>,
    pub ecc: Option<String>,
    pub nano: Option<bool>,
    pub size: Option<usize>,
    pub min_header: Option<bool>,
    pub password: Option<String>,
    pub sign: Option<String>,
    pub mod_size: Option<u32>,
    pub margin: Option<u32>,
}

#[derive(Serialize)]
pub struct MetadataResponse {
    pub size: usize,
    pub raw_bytes: usize,
    pub packed_bytes: usize,
    pub total_cap_bytes: usize,
    pub ecc_bytes: usize,
    pub colors: usize,
    pub bits_per_cell: usize,
    pub is_dual: bool,
    pub is_encrypted: bool,
    pub is_signed: bool,
    pub is_nano: bool,
}

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(handle_generate))
        .route("/generate", get(handle_generate))
        .route("/decode", post(handle_decode))
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], 9999));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_generate(Query(params): Query<GenerateParams>) -> Response {
    let mode = params
        .colors
        .as_deref()
        .and_then(ColorMode::from_str_loose)
        .unwrap_or(ColorMode::FourColor);

    let ecc = params
        .ecc
        .as_deref()
        .map(EccLevel::from_str_loose)
        .unwrap_or(EccLevel::Medium);

    let format_str = params
        .format
        .as_deref()
        .unwrap_or("png")
        .to_lowercase();

    let mod_size = params.mod_size.unwrap_or(15).max(1);
    let margin = params.margin.unwrap_or(2);

    if format_str == "wav" {
        let text_data = params
            .text
            .unwrap_or_else(|| "T-Spine Audio Packet".to_string());
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        if let Err(e) = AudioModem::export_wav(
            text_data.as_bytes(),
            path,
            mode,
            ecc,
            params.password.as_deref(),
            0.5,
        ) {
            return (StatusCode::BAD_REQUEST, format!("Audio generation error: {}", e)).into_response();
        }

        let audio_bytes = std::fs::read(path).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("audio/wav"));
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("inline; filename=\"tspine.wav\""),
        );
        return (headers, audio_bytes).into_response();
    }

    let mut encoder = TSpineEncoder::new()
        .color_mode(mode)
        .ecc_level(ecc)
        .nano(params.nano.unwrap_or(false))
        .min_header(params.min_header.unwrap_or(false));

    if let Some(pwd) = params.password.as_deref() {
        encoder = encoder.password(pwd);
    }
    if let Some(key) = params.sign.as_deref() {
        encoder = encoder.sign_key(key);
    }
    if let Some(size) = params.size {
        encoder = encoder.forced_size(size);
    }

    let encode_result = if let (Some(pub_data), Some(priv_data)) =
        (params.public.as_deref(), params.private.as_deref())
    {
        encoder.encode_dual(pub_data.as_bytes(), priv_data.as_bytes())
    } else {
        let default_text = "Hello from T-Spine Code (TSC)!".to_string();
        let text_data = params.text.as_ref().unwrap_or(&default_text);
        encoder.encode(text_data.as_bytes())
    };

    let (grid, meta) = match encode_result {
        Ok(res) => res,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    match format_str.as_str() {
        "svg" => {
            let svg = SvgExporter::to_svg_string(&grid, mod_size, margin);
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/svg+xml"));
            (headers, svg).into_response()
        }
        "html" => {
            let html = HtmlExporter::to_html_string(&grid, Some(&meta), mod_size.max(14), margin);
            Html(html).into_response()
        }
        "term" | "terminal" | "ansi" => {
            let term = TerminalExporter::render(&grid);
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            (headers, term).into_response()
        }
        "json" => {
            let resp = MetadataResponse {
                size: meta.size,
                raw_bytes: meta.raw_bytes,
                packed_bytes: meta.packed_bytes,
                total_cap_bytes: meta.total_cap_bytes,
                ecc_bytes: meta.ecc_bytes,
                colors: meta.colors,
                bits_per_cell: meta.bits_per_cell,
                is_dual: meta.is_dual,
                is_encrypted: meta.is_encrypted,
                is_signed: meta.is_signed,
                is_nano: meta.is_nano,
            };
            Json(resp).into_response()
        }
        _ => {
            let img = ImageExporter::to_image_buffer(&grid, mod_size, margin);
            let mut png_bytes = Cursor::new(Vec::new());
            img.write_to(&mut png_bytes, image::ImageFormat::Png).unwrap();

            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
            headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("inline; filename=\"tspine.png\""),
            );
            (headers, png_bytes.into_inner()).into_response()
        }
    }
}

async fn handle_decode(mut multipart: Multipart) -> Response {
    let mut file_bytes = Vec::new();
    let mut password = None;
    let mut verify_key = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or_default().to_string();
        if name == "file" || name == "image" {
            if let Ok(bytes) = field.bytes().await {
                file_bytes = bytes.to_vec();
            }
        } else if name == "password" {
            if let Ok(txt) = field.text().await {
                if !txt.is_empty() {
                    password = Some(txt);
                }
            }
        } else if name == "verify" {
            if let Ok(txt) = field.text().await {
                if !txt.is_empty() {
                    verify_key = Some(txt);
                }
            }
        }
    }

    if file_bytes.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No file uploaded" })),
        )
            .into_response();
    }

    if let Ok(dyn_img) = image::load_from_memory(&file_bytes) {
        let rgb_img = dyn_img.to_rgb8();
        return match ImageScanner::scan_image(
            &rgb_img,
            password.as_deref(),
            verify_key.as_deref(),
            None,
        ) {
            Ok(DecodedPayload::Text(t)) => Json(serde_json::json!({ "type": "text", "data": t })).into_response(),
            Ok(DecodedPayload::Binary(b)) => {
                Json(serde_json::json!({ "type": "binary", "size": b.len(), "hex": hex_encode(&b) }))
                    .into_response()
            }
            Ok(DecodedPayload::Dual { public_data, private_data }) => Json(serde_json::json!({
                "type": "dual",
                "public": public_data,
                "private": private_data
            }))
            .into_response(),
            Err(e) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        };
    }

    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": "Unsupported image format" })),
    )
        .into_response()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}