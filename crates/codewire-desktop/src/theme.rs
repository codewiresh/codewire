//! Theme re-export + terminal-specific color helpers
pub use codewire_ui::theme::Theme;

use gpui::{Hsla, hsla};

/// Convert an alacritty_terminal ANSI color to an Hsla value.
pub fn ansi_color_to_hsla(color: &alacritty_terminal::vte::ansi::Color, theme: &Theme) -> Hsla {
    use alacritty_terminal::vte::ansi::{Color, NamedColor};
    match color {
        Color::Named(named) => match named {
            NamedColor::Black => theme.term_black,
            NamedColor::Red => theme.term_red,
            NamedColor::Green => theme.term_green,
            NamedColor::Yellow => theme.term_yellow,
            NamedColor::Blue => theme.term_blue,
            NamedColor::Magenta => theme.term_magenta,
            NamedColor::Cyan => theme.term_cyan,
            NamedColor::White => theme.term_white,
            NamedColor::BrightBlack => theme.term_bright_black,
            NamedColor::BrightRed => theme.term_bright_red,
            NamedColor::BrightGreen => theme.term_bright_green,
            NamedColor::BrightYellow => theme.term_bright_yellow,
            NamedColor::BrightBlue => theme.term_bright_blue,
            NamedColor::BrightMagenta => theme.term_bright_magenta,
            NamedColor::BrightCyan => theme.term_bright_cyan,
            NamedColor::BrightWhite => theme.term_bright_white,
            NamedColor::Foreground | NamedColor::BrightForeground => theme.foreground,
            NamedColor::Background => theme.background,
            NamedColor::Cursor => theme.term_cursor,
            NamedColor::DimBlack => theme.term_black,
            NamedColor::DimRed => theme.term_red,
            NamedColor::DimGreen => theme.term_green,
            NamedColor::DimYellow => theme.term_yellow,
            NamedColor::DimBlue => theme.term_blue,
            NamedColor::DimMagenta => theme.term_magenta,
            NamedColor::DimCyan => theme.term_cyan,
            NamedColor::DimWhite => theme.term_white,
            NamedColor::DimForeground => theme.muted,
        },
        Color::Spec(rgb) => {
            let r = rgb.r as f32 / 255.0;
            let g = rgb.g as f32 / 255.0;
            let b = rgb.b as f32 / 255.0;
            let max = r.max(g).max(b);
            let min = r.min(g).min(b);
            let l = (max + min) / 2.0;
            if (max - min).abs() < f32::EPSILON {
                hsla(0.0, 0.0, l, 1.0)
            } else {
                let d = max - min;
                let s = if l > 0.5 {
                    d / (2.0 - max - min)
                } else {
                    d / (max + min)
                };
                let h = if (max - r).abs() < f32::EPSILON {
                    ((g - b) / d + if g < b { 6.0 } else { 0.0 }) / 6.0
                } else if (max - g).abs() < f32::EPSILON {
                    ((b - r) / d + 2.0) / 6.0
                } else {
                    ((r - g) / d + 4.0) / 6.0
                };
                hsla(h, s, l, 1.0)
            }
        }
        Color::Indexed(idx) => match idx {
            0 => theme.term_black,
            1 => theme.term_red,
            2 => theme.term_green,
            3 => theme.term_yellow,
            4 => theme.term_blue,
            5 => theme.term_magenta,
            6 => theme.term_cyan,
            7 => theme.term_white,
            8 => theme.term_bright_black,
            9 => theme.term_bright_red,
            10 => theme.term_bright_green,
            11 => theme.term_bright_yellow,
            12 => theme.term_bright_blue,
            13 => theme.term_bright_magenta,
            14 => theme.term_bright_cyan,
            15 => theme.term_bright_white,
            16..=231 => {
                let i = idx - 16;
                let r = (i / 36) as f32 / 5.0;
                let g = ((i % 36) / 6) as f32 / 5.0;
                let b = (i % 6) as f32 / 5.0;
                let l = (r + g + b) / 3.0;
                hsla(0.0, 0.0, l, 1.0)
            }
            232..=255 => {
                let l = ((*idx as f32 - 232.0) * 10.0 + 8.0) / 256.0;
                hsla(0.0, 0.0, l, 1.0)
            }
            _ => theme.foreground,
        },
    }
}
