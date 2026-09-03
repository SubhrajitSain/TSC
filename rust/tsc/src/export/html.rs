use crate::grid::Grid;
use crate::types::Metadata;

pub struct HtmlExporter;

impl HtmlExporter {
    pub fn to_html_string(
        grid: &Grid,
        meta: Option<&Metadata>,
        module_size: u32,
        quiet_zone: u32,
    ) -> String {
        let size = grid.size;
        let is_nano = Grid::is_nano(size, false);
        let total_dim = ((size as u32) + 2 * quiet_zone) * module_size;
        let coords_list = Grid::data_coordinates(size, is_nano);

        let header_bytes = meta.map(|m| m.header_bytes_count).unwrap_or(4);
        let data_bytes = meta.map(|m| m.data_bytes_count).unwrap_or(10);
        let ecc_start = meta.map(|m| m.ecc_start_byte).unwrap_or(20);
        let bpc = grid.mode.bits_per_cell();

        let mut svg_cells = Vec::new();
        svg_cells.push(format!(
            r##"<rect width="{}" height="{}" fill="#ffffff"/>"##,
            total_dim, total_dim
        ));

        for y in 0..size {
            for x in 0..size {
                let val = grid.get(x, y);
                let px = ((x as u32) + quiet_zone) * module_size;
                let py = ((y as u32) + quiet_zone) * module_size;

                let role = if let Some(idx) = coords_list.iter().position(|&c| c == (x, y)) {
                    let byte_offset = (idx * bpc) / 8;
                    if byte_offset < header_bytes {
                        "Header / Metadata"
                    } else if byte_offset < header_bytes + data_bytes {
                        "Data Payload"
                    } else if byte_offset >= ecc_start {
                        "Error Correction Code"
                    } else {
                        "Padding"
                    }
                } else if is_nano && [(0, 0), (1, 0), (2, 0), (1, 1)].contains(&(x, y)) {
                    "TSC Nano T-Finder"
                } else if !is_nano && y == 0 {
                    "T-Finder Roof"
                } else if !is_nano && x == size / 2 {
                    if y >= size - grid.mode.num_colors() {
                        "Color Calibration"
                    } else {
                        "T-Finder Spine"
                    }
                } else if y == size - 1 && x == 0 {
                    "Left Notch (Black)"
                } else if y == size - 1 && x == size - 1 {
                    "Right Notch (White)"
                } else {
                    "Skeleton"
                };

                let rgb = grid.get_rgb(x, y);
                let fill = format!("rgb({},{},{})", rgb.0, rgb.1, rgb.2);
                let bin = format!("{:0width$b}", val, width = bpc);

                svg_cells.push(format!(
                    r#"<rect class="cell" x="{}" y="{}" width="{}" height="{}" fill="{}" data-x="{}" data-y="{}" data-val="{}" data-bin="{}" data-role="{}" data-rgb="{}"/>"#,
                    px, py, module_size, module_size, fill, x, y, val, bin, role, fill
                ));
            }
        }

        let svg_content = svg_cells.join("\n");
        let default_meta = Metadata::default();
        let m = meta.unwrap_or(&default_meta);

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>T-Spine Code (TSC) Inspector</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
body {{ background: #000000; color: #e2e8f0; display: flex; flex-direction: column; align-items: center; min-height: 100vh; padding: 2rem; }}
h1 {{ color: #38bdf8; font-size: 1.5rem; margin-bottom: 0.5rem; }}
.subtitle {{ color: #64748b; font-size: 0.85rem; margin-bottom: 2rem; }}
.wrapper {{ display: flex; gap: 2rem; flex-wrap: wrap; justify-content: center; max-width: 1100px; width: 100%; }}
.matrix-card {{ background: #090d16; border: 1px solid #1e293b; border-radius: 8px; padding: 1.5rem; }}
svg {{ border: 2px solid #334155; border-radius: 4px; cursor: crosshair; }}
.cell:hover {{ stroke: #38bdf8; stroke-width: 2px; }}
.panel {{ flex: 1; min-width: 320px; display: flex; flex-direction: column; gap: 1.5rem; }}
.card {{ background: #090d16; border: 1px solid #1e293b; border-radius: 8px; padding: 1.25rem; }}
.card h2 {{ font-size: 1rem; color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 0.5rem; margin-bottom: 1rem; }}
table {{ width: 100%; font-size: 0.85rem; border-collapse: collapse; }}
td {{ padding: 0.4rem 0; }}
td.label {{ color: #64748b; width: 45%; }}
td.val {{ color: #f8fafc; font-weight: bold; }}
.swatch {{ display: inline-block; width: 12px; height: 12px; border-radius: 2px; vertical-align: middle; margin-left: 6px; }}
</style>
</head>
<body>
<h1>T-Spine Code (TSC) Inspector</h1>
<p class="subtitle">Interactive Module Inspection & Diagnostic Tool</p>
<div class="wrapper">
  <div class="matrix-card">
    <svg width="{total_dim}" height="{total_dim}" viewBox="0 0 {total_dim} {total_dim}">
      {svg_content}
    </svg>
  </div>
  <div class="panel">
    <div class="card">
      <h2>Cell Inspector</h2>
      <table>
        <tr><td class="label">Coordinates:</td><td class="val" id="ins-coord">(Hover over a module...)</td></tr>
        <tr><td class="label">Cell Role:</td><td class="val" id="ins-role">-</td></tr>
        <tr><td class="label">Raw Value (DEC):</td><td class="val" id="ins-val">-</td></tr>
        <tr><td class="label">Raw Value (BIN):</td><td class="val" id="ins-bin">-</td></tr>
        <tr><td class="label">Color (RGB):</td><td class="val" id="ins-rgb">- <span id="ins-swatch" class="swatch"></span></td></tr>
      </table>
    </div>
    <div class="card">
      <h2>Metadata</h2>
      <table>
        <tr><td class="label">Dimensions:</td><td class="val">{size} &times; {size} modules</td></tr>
        <tr><td class="label">Color Mode:</td><td class="val">{} colors ({} bits/cell)</td></tr>
        <tr><td class="label">ECC Parity:</td><td class="val">{} bytes</td></tr>
        <tr><td class="label">Data Payload:</td><td class="val">{} bytes</td></tr>
        <tr><td class="label">Encrypted:</td><td class="val">{}</td></tr>
        <tr><td class="label">HMAC Signed:</td><td class="val">{}</td></tr>
      </table>
    </div>
  </div>
</div>
<script>
document.querySelectorAll('.cell').forEach(cell => {{
  cell.addEventListener('mouseenter', () => {{
    document.getElementById('ins-coord').textContent = `X: ${{cell.dataset.x}}, Y: ${{cell.dataset.y}}`;
    document.getElementById('ins-role').textContent = cell.dataset.role;
    document.getElementById('ins-val').textContent = cell.dataset.val;
    document.getElementById('ins-bin').textContent = cell.dataset.bin;
    document.getElementById('ins-rgb').textContent = cell.dataset.rgb;
    const swatch = document.getElementById('ins-swatch');
    swatch.style.background = cell.dataset.rgb;
  }});
}});
</script>
</body>
</html>"#,
            grid.mode.num_colors(),
            bpc,
            m.ecc_bytes,
            m.packed_bytes,
            if m.is_encrypted { "Yes" } else { "No" },
            if m.is_signed { "Yes" } else { "No" }
        )
    }
}