use colored::Colorize;
use crate::grid::Grid;

pub struct TerminalExporter;

impl TerminalExporter {
    pub fn render(grid: &Grid) -> String {
        let mut out = String::new();
        let size = grid.size;

        let white_block = "  ".on_white();
        let black_block = "  ".on_black();

        let border = white_block.to_string().repeat(size + 2);
        out.push_str(&format!("{}\n", border));

        for y in 0..size {
            out.push_str(&format!("{}", white_block));
            for x in 0..size {
                let val = grid.get(x, y);
                let cell_str = match val {
                    0 => "  ".on_white(),
                    1 => "  ".on_black(),
                    2 => "  ".on_red(),
                    3 => "  ".on_blue(),
                    4 => "  ".on_green(),
                    5 => "  ".on_cyan(),
                    6 => "  ".on_magenta(),
                    7 => "  ".on_yellow(),
                    _ => black_block.clone(),
                };
                out.push_str(&format!("{}", cell_str));
            }
            out.push_str(&format!("{}\n", white_block));
        }

        out.push_str(&format!("{}\n", border));
        out
    }
}