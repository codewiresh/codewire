//! The Codewire wordmark `cw upgrade` draws above the wire: the full
//! wordmark on a terminal 80 columns wide or more, the cw mark on a narrower
//! one, nothing on one narrower still.
//!
//! The art is plain ASCII, so it draws on every charset. Each cell has a
//! tone, from the dim edge of a letter to its bright core, painted in
//! Codewire purple: exact on a 24-bit terminal, the nearest 256-colour
//! entries elsewhere, and not at all without colour.

use super::style::Style;

/// One piece of art: its rows, and a tone per cell (`0` edge to `3` core,
/// a space where the art has one).
struct Art {
    text: &'static [&'static str],
    tones: &'static [&'static str],
}

const WORDMARK: Art = Art {
    text: &[
        r#"                           _,                            _g_"#,
        r#"                         -BBBB;                          PMF"#,
        r#" _ggg,q@g  .ggggg_     .__,"7BB    _gg@gg  gg@@g,   g@g  ggg. ig@g_ q@g  .gg@@g,"#,
        r#"qB" '0BBR qBBF   0@. gBBFTP0@@F  .@P" .BB` 7PTgP.g@g"0BL 7BB  QBF"T@/BB gBF` JBD"#,
        r#"[@    ._. [BE    BBL BB    .gg_  @Bgm4P"   _gP^.B`'B 'BL .B    Q@  '""`iB@g*PT^"#,
        r#" 0@gg@BBB  0@,,_@BB` 0Bg__gBFJB@ QB_.gBBB qBB_gB` !B_gB` @B@; gBB@     'B&,_@BBp"#,
        r#"  '"TPP"`   '"PPF"    '"PPT` TP^  '7PPF"`  "PP"    "PP^  TPF` "PF^       "PPP"""#,
    ],
    tones: &[
        "                           00                            121",
        "                         032221                          222",
        " 13321132  0333220     01111222    133321  333220   332  3220 13321 332  0333220",
        "321 02222 1322   220 3322222222  0320 0220 2222212221222 222  222122222 3220 222",
        "22    110 222    322 22    0321  3222221   132002012 022 02    22  011012222220",
        " 22333322  220013220 22211322222 22102222 2222220 121220 3220 3322     022013222",
        "  0122210   012220    012220 220  0222210  1221    1220  2220 1220       122210",
    ],
};

const MARK: Art = Art {
    text: &[
        r#" ._g_ _g,   _gg_,   _g_"#,
        r#"qBF"7@@BB  4BBTBt_g_7BBL"#,
        r#"dB   '""    _gF`@F"B 'BD"#,
        r#"'Bg__gBB@  @BL_@F  B,_B^"#,
        r#"  "PMRPF`  7MRP^   7RRF"#,
    ],
    tones: &[
        " 0131 120   13310   131",
        "122022222  2222221313222",
        "22   011    12202212 022",
        "022013322  322022  21121",
        "  0222220  22220   2222",
    ],
};

/// Each tone's 24-bit colour, its 256-colour stand-in, and whether it is
/// bold. The body tone is the brand accent purple, `#B98BBA`.
const TONES: [Tone; 4] = [
    Tone::new([0x60, 0x37, 0x62], 53, false),
    Tone::new([0x92, 0x65, 0x93], 96, false),
    Tone::new([0xB9, 0x8B, 0xBA], 139, true),
    Tone::new([0xC6, 0x9A, 0xC7], 182, true),
];

struct Tone {
    rgb: [u8; 3],
    index: u8,
    bold: bool,
}

impl Tone {
    const fn new(rgb: [u8; 3], index: u8, bold: bool) -> Self {
        Self { rgb, index, bold }
    }

    fn sgr(&self, true_color: bool) -> String {
        let weight = if self.bold { 1 } else { 22 };
        let [red, green, blue] = self.rgb;
        if true_color {
            format!("\x1b[{weight};38;2;{red};{green};{blue}m")
        } else {
            format!("\x1b[{weight};38;5;{}m", self.index)
        }
    }
}

const RESET: &str = "\x1b[0m";

/// The widest art that fits in `columns`, rendered for `style`, one row per
/// line, or `None` when not even the cw mark fits.
pub(super) fn wordmark(columns: u16, style: Style, true_color: bool) -> Option<String> {
    let art = [&WORDMARK, &MARK]
        .into_iter()
        // Narrower than the terminal: art filling the last column wraps.
        .find(|art| art.width() < usize::from(columns))?;
    Some(art.render(style.color().then_some(true_color)))
}

impl Art {
    fn width(&self) -> usize {
        self.text
            .iter()
            .map(|row| row.chars().count())
            .max()
            .unwrap_or(0)
    }

    /// `color` is `None` for plain text, or whether to use 24-bit colour.
    fn render(&self, color: Option<bool>) -> String {
        let mut out = String::new();
        for (row, tones) in self.text.iter().zip(self.tones) {
            let Some(true_color) = color else {
                out.push_str(row);
                out.push('\n');
                continue;
            };
            // A space keeps the tone before it, so a run needs one sequence.
            let mut current = None;
            for (cell, tone) in row.chars().zip(tones.chars()) {
                let tone = tone
                    .to_digit(10)
                    .and_then(|tone| usize::try_from(tone).ok());
                if let Some(index) = tone
                    && current != Some(index)
                    && let Some(tone) = TONES.get(index)
                {
                    out.push_str(&tone.sgr(true_color));
                    current = Some(index);
                }
                out.push(cell);
            }
            out.push_str(RESET);
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Charset;

    const PLAIN: Style = Style::new(false, Charset::Unicode);
    const COLOR: Style = Style::new(true, Charset::Unicode);

    #[test]
    fn every_cell_of_the_art_has_a_tone_and_every_space_none() {
        for art in [&WORDMARK, &MARK] {
            assert_eq!(art.text.len(), art.tones.len());
            for (row, tones) in art.text.iter().zip(art.tones) {
                assert!(row.is_ascii(), "{row}");
                assert_eq!(row.len(), tones.len(), "{row}");
                for (cell, tone) in row.chars().zip(tones.chars()) {
                    assert_eq!(cell == ' ', tone == ' ', "{row}");
                    assert!(tone == ' ' || ('0'..='3').contains(&tone), "{tones}");
                }
            }
        }
    }

    #[test]
    fn the_widest_art_that_fits_is_drawn() {
        let rows = |columns| wordmark(columns, PLAIN, false).map(|art| art.lines().count());
        assert_eq!(WORDMARK.width(), 80);
        assert_eq!(MARK.width(), 24);
        // Art is narrower than the terminal, so it never fills the last
        // column, where a terminal would wrap it.
        assert_eq!(rows(120), Some(7));
        assert_eq!(rows(81), Some(7));
        assert_eq!(rows(80), Some(5));
        assert_eq!(rows(25), Some(5));
        assert_eq!(rows(24), None);
    }

    #[test]
    fn without_colour_the_art_is_plain_text() {
        let art = wordmark(81, PLAIN, true).unwrap();
        assert!(!art.contains('\x1b'));
        assert_eq!(art, format!("{}\n", WORDMARK.text.join("\n")));
    }

    #[test]
    fn colour_paints_each_tone_once_per_run_and_resets_each_row() {
        let art = wordmark(40, COLOR, true).unwrap();
        let first = art.lines().next().unwrap();
        // " ._g_": an edge `.`, soft `_`, core `g`, soft `_`.
        assert!(first.starts_with(
            " \x1b[22;38;2;96;55;98m.\x1b[22;38;2;146;101;147m_\
             \x1b[1;38;2;198;154;199mg\x1b[22;38;2;146;101;147m_ "
        ));
        assert!(art.lines().all(|row| row.ends_with(RESET)));
        let second = art.lines().nth(1).unwrap();
        // "qBF": soft, then body twice under one sequence.
        assert!(second.starts_with("\x1b[22;38;2;146;101;147mq\x1b[1;38;2;185;139;186mBF"));
    }

    #[test]
    fn a_terminal_without_true_colour_gets_the_256_colour_purples() {
        let art = wordmark(40, COLOR, false).unwrap();
        assert!(art.starts_with(" \x1b[22;38;5;53m.\x1b[22;38;5;96m_\x1b[1;38;5;182mg"));
        assert!(!art.contains(";38;2;"));
    }
}
