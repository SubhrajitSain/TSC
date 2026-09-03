use crate::grid::Grid;

pub struct SvgExporter;

impl SvgExporter {
    pub fn to_svg_string(grid: &Grid, module_size: u32, quiet_zone: u32) -> String {
        let total_dim = ((grid.size as u32) + 2 * quiet_zone) * module_size;
        let mut svg = Vec::new();

        svg.push(format!(
            r#"<svg width="{}" height="{}" xmlns="http://www.w3.org/2000/svg">"#,
            total_dim, total_dim
        ));
        svg.push(format!(
            r##"<rect width="{}" height="{}" fill="#ffffff"/>"##,
            total_dim, total_dim
        ));

        for y in 0..grid.size {
            for x in 0..grid.size {
                let val = grid.get(x, y);
                if val != 0 {
                    let rgb = grid.get_rgb(x, y);
                    let px = ((x as u32) + quiet_zone) * module_size;
                    let py = ((y as u32) + quiet_zone) * module_size;
                    svg.push(format!(
                        r#"<rect x="{}" y="{}" width="{}" height="{}" fill="rgb({},{},{})"/>"#,
                        px, py, module_size, module_size, rgb.0, rgb.1, rgb.2
                    ));
                }
            }
        }

        svg.push("</svg>".to_string());
        svg.join("\n")
    }
}