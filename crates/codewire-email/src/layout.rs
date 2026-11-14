//! One plain layout for every Codewire email (#4553).
//!
//! A template describes its email as a heading and a few blocks; this module
//! renders the HTML part and the plain-text part from the same words. The
//! HTML is a centred column at most 640 px wide on a white page, in the
//! system font with left-aligned text, a dark button at most, a thin rule and
//! a small grey footer that says why the email was sent. There are no
//! images, no tracking pixels, no remote fonts and no dark-mode styles.
//! Every string is escaped here, so a template passes raw values.

use std::fmt::Write as _;

const FONT: &str =
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
const TEXT: &str = "#171717";
const MUTED: &str = "#6b7280";
const RULE: &str = "#e5e7eb";

/// One block of an email's body, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// A paragraph.
    Paragraph(String),
    /// A paragraph with one inline link: `before`, the linked `label`, then
    /// `after`. The plain-text part writes the URL out after the label
    /// unless the label is the URL itself.
    LinkedParagraph {
        before: String,
        label: String,
        url: String,
        after: String,
    },
    /// Smaller grey text, such as when a link expires.
    Note(String),
    /// The email's one dark button. The plain-text part writes the link out.
    Button { label: String, url: String },
    /// A link set as ordinary underlined text, for a second action.
    Link { label: String, url: String },
    /// A heading for the list or details that follow.
    Subheading(String),
    /// A bulleted list.
    List(Vec<String>),
    /// Commands to type, one per line, in a monospace box.
    Code(Vec<String>),
    /// Label and value rows, such as an invoice's amount and date.
    Details(Vec<(String, String)>),
}

/// An email in the Codewire layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    pub subject: String,
    pub heading: String,
    pub blocks: Vec<Block>,
    /// Why the recipient got this email, shown in the footer.
    pub reason: String,
}

impl Email {
    pub fn new(subject: impl Into<String>, heading: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            heading: heading.into(),
            blocks: Vec::new(),
            reason: String::new(),
        }
    }

    pub fn paragraph(mut self, text: impl Into<String>) -> Self {
        self.blocks.push(Block::Paragraph(text.into()));
        self
    }

    pub fn linked_paragraph(
        mut self,
        before: impl Into<String>,
        label: impl Into<String>,
        url: impl Into<String>,
        after: impl Into<String>,
    ) -> Self {
        self.blocks.push(Block::LinkedParagraph {
            before: before.into(),
            label: label.into(),
            url: url.into(),
            after: after.into(),
        });
        self
    }

    pub fn note(mut self, text: impl Into<String>) -> Self {
        self.blocks.push(Block::Note(text.into()));
        self
    }

    pub fn button(mut self, label: impl Into<String>, url: impl Into<String>) -> Self {
        self.blocks.push(Block::Button {
            label: label.into(),
            url: url.into(),
        });
        self
    }

    pub fn link(mut self, label: impl Into<String>, url: impl Into<String>) -> Self {
        self.blocks.push(Block::Link {
            label: label.into(),
            url: url.into(),
        });
        self
    }

    pub fn subheading(mut self, text: impl Into<String>) -> Self {
        self.blocks.push(Block::Subheading(text.into()));
        self
    }

    pub fn list(mut self, items: impl IntoIterator<Item = String>) -> Self {
        self.blocks.push(Block::List(items.into_iter().collect()));
        self
    }

    pub fn code(mut self, lines: impl IntoIterator<Item = String>) -> Self {
        self.blocks.push(Block::Code(lines.into_iter().collect()));
        self
    }

    pub fn details(mut self, rows: impl IntoIterator<Item = (String, String)>) -> Self {
        self.blocks.push(Block::Details(rows.into_iter().collect()));
        self
    }

    pub fn reason(mut self, text: impl Into<String>) -> Self {
        self.reason = text.into();
        self
    }

    /// The HTML part.
    pub fn html(&self) -> String {
        let mut body = String::new();
        let _ = write!(
            body,
            r#"<h1 style="margin:0 0 24px;font-size:24px;line-height:32px;font-weight:700;color:{TEXT};">{}</h1>"#,
            escape(&self.heading)
        );
        for block in &self.blocks {
            block_html(&mut body, block);
        }
        let mut footer = String::from("Codewire");
        if !self.reason.is_empty() {
            let _ = write!(footer, "<br>{}", escape(&self.reason));
        }
        format!(
            r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>{subject}</title>
</head>
<body style="margin:0;padding:0;background:#ffffff;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff;">
<tr><td align="center" style="padding:32px 16px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:640px;width:100%;">
<tr><td style="text-align:left;font-family:{FONT};font-size:16px;line-height:24px;color:{TEXT};">
{body}
<hr style="border:0;border-top:1px solid {RULE};margin:32px 0 16px;">
<p style="margin:0;font-size:13px;line-height:20px;color:{MUTED};">{footer}</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
"#,
            subject = escape(&self.subject),
        )
    }

    /// The plain-text part: the same words, with every link written out.
    pub fn text(&self) -> String {
        let mut text = format!("{}\n", self.heading);
        for block in &self.blocks {
            text.push('\n');
            match block {
                Block::Paragraph(line) | Block::Note(line) | Block::Subheading(line) => {
                    text.push_str(line);
                    text.push('\n');
                }
                Block::LinkedParagraph {
                    before,
                    label,
                    url,
                    after,
                } => {
                    if label == url {
                        let _ = writeln!(text, "{before}{label}{after}");
                    } else {
                        let _ = writeln!(text, "{before}{label} ({url}){after}");
                    }
                }
                Block::Button { label, url } | Block::Link { label, url } => {
                    let _ = writeln!(text, "{label}: {url}");
                }
                Block::List(items) => {
                    for item in items {
                        let _ = writeln!(text, "- {item}");
                    }
                }
                Block::Code(lines) => {
                    for line in lines {
                        let _ = writeln!(text, "    {line}");
                    }
                }
                Block::Details(rows) => {
                    for (label, value) in rows {
                        let _ = writeln!(text, "{label}: {value}");
                    }
                }
            }
        }
        text.push_str("\n--\nCodewire\n");
        if !self.reason.is_empty() {
            text.push_str(&self.reason);
            text.push('\n');
        }
        text
    }
}

fn block_html(body: &mut String, block: &Block) {
    match block {
        Block::Paragraph(text) => {
            let _ = write!(body, r#"<p style="margin:0 0 16px;">{}</p>"#, escape(text));
        }
        Block::LinkedParagraph {
            before,
            label,
            url,
            after,
        } => {
            let _ = write!(
                body,
                r#"<p style="margin:0 0 16px;">{}<a href="{}" style="color:{TEXT};text-decoration:underline;">{}</a>{}</p>"#,
                escape(before),
                escape(url),
                escape(label),
                escape(after)
            );
        }
        Block::Note(text) => {
            let _ = write!(
                body,
                r#"<p style="margin:0 0 16px;font-size:14px;line-height:20px;color:{MUTED};">{}</p>"#,
                escape(text)
            );
        }
        Block::Button { label, url } => {
            // A pill, as the site's `cw-button--pill`. The cell carries the
            // fill and the radius too, so a client that ignores padding or
            // radius on links (desktop Outlook) still shows a dark block.
            let _ = write!(
                body,
                r#"<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0;border-collapse:separate;"><tr><td style="border-radius:999px;background:{TEXT};"><a href="{}" style="display:inline-block;padding:12px 24px;border-radius:999px;background:{TEXT};color:#ffffff;text-decoration:none;font-weight:600;line-height:20px;">{}</a></td></tr></table>"#,
                escape(url),
                escape(label)
            );
        }
        Block::Link { label, url } => {
            let _ = write!(
                body,
                r#"<p style="margin:0 0 16px;"><a href="{}" style="color:{TEXT};text-decoration:underline;">{}</a></p>"#,
                escape(url),
                escape(label)
            );
        }
        Block::Subheading(text) => {
            let _ = write!(
                body,
                r#"<p style="margin:24px 0 8px;font-weight:600;">{}</p>"#,
                escape(text)
            );
        }
        Block::List(items) => {
            body.push_str(r#"<ul style="margin:0 0 16px;padding-left:20px;">"#);
            for item in items {
                let _ = write!(body, r#"<li style="margin:0 0 4px;">{}</li>"#, escape(item));
            }
            body.push_str("</ul>");
        }
        Block::Code(lines) => {
            let joined: Vec<String> = lines.iter().map(|line| escape(line)).collect();
            let _ = write!(
                body,
                r#"<pre style="margin:0 0 16px;padding:12px 16px;background:#f5f5f5;border-radius:6px;font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;font-size:14px;line-height:20px;white-space:pre-wrap;">{}</pre>"#,
                joined.join("\n")
            );
        }
        Block::Details(rows) => {
            body.push_str(r#"<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 16px;border-collapse:collapse;">"#);
            for (label, value) in rows {
                let _ = write!(
                    body,
                    r#"<tr><td style="padding:2px 16px 2px 0;color:{MUTED};vertical-align:top;">{}</td><td style="padding:2px 0;vertical-align:top;">{}</td></tr>"#,
                    escape(label),
                    escape(value)
                );
            }
            body.push_str("</table>");
        }
    }
}

/// Escape text for HTML element content and quoted attribute values.
pub fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Email {
        Email::new("Reset your Codewire password", "Reset your password")
            .paragraph("We received a request to reset your Codewire password.")
            .button(
                "Reset password",
                "https://codewire.test/reset-password?token=a&b",
            )
            .note("This link expires in 1 hour.")
            .reason(
                "You got this email because someone asked to reset the password for this address.",
            )
    }

    #[test]
    fn the_layout_is_a_centred_640_px_column_with_left_aligned_system_text() {
        let html = sample().html();
        assert!(html.contains("max-width:640px;width:100%"));
        assert!(html.contains(r#"<td align="center""#));
        assert!(html.contains("text-align:left"));
        assert!(html.contains("font-size:16px;line-height:24px"));
        assert!(html.contains(r#"<meta name="color-scheme" content="light">"#));
        assert!(html.contains("Codewire<br>You got this email"));
    }

    #[test]
    fn the_button_is_a_dark_pill_that_degrades_to_a_dark_block() {
        let html = sample().html();
        assert!(html.contains(r#"<td style="border-radius:999px;background:#171717;">"#));
        assert!(
            html.contains("padding:12px 24px;border-radius:999px;background:#171717;color:#ffffff")
        );
    }

    #[test]
    fn the_layout_loads_nothing_remote() {
        let html = sample().html();
        for forbidden in [
            "<img",
            "<link",
            "@import",
            "url(",
            "<script",
            "prefers-color-scheme",
        ] {
            assert!(!html.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn every_value_is_escaped() {
        let email = Email::new("<s>", "<h> & \"q\"")
            .paragraph("<script>alert(1)</script>")
            .button("Go", "https://x.test/?a=1&b=\"2\"")
            .list(["<li>".to_owned()])
            .details([("<k>".to_owned(), "'v'".to_owned())]);
        let html = email.html();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains(r#"href="https://x.test/?a=1&amp;b=&quot;2&quot;""#));
        assert!(html.contains("&lt;h&gt; &amp; &quot;q&quot;"));
        assert!(html.contains("&#39;v&#39;"));
    }

    #[test]
    fn a_linked_paragraph_links_its_label_inline() {
        let email = Email::new("s", "h").linked_paragraph(
            "Sign in at ",
            "https://codewire.test",
            "https://codewire.test",
            " with this address.",
        );
        assert!(email.html().contains(
            r#"<p style="margin:0 0 16px;">Sign in at <a href="https://codewire.test" style="color:#171717;text-decoration:underline;">https://codewire.test</a> with this address.</p>"#
        ));
        assert!(
            email
                .text()
                .contains("\nSign in at https://codewire.test with this address.\n")
        );
    }

    #[test]
    fn a_linked_paragraph_writes_a_different_url_out_in_the_text_part() {
        let email = Email::new("s", "h").linked_paragraph(
            "Open ",
            "the Billing page",
            "https://codewire.test/acme/billing/",
            " to pay.",
        );
        assert!(email.html().contains(
            r#"Open <a href="https://codewire.test/acme/billing/" style="color:#171717;text-decoration:underline;">the Billing page</a> to pay."#
        ));
        assert!(
            email.text().contains(
                "\nOpen the Billing page (https://codewire.test/acme/billing/) to pay.\n"
            )
        );
    }

    #[test]
    fn a_linked_paragraph_is_escaped() {
        let html = Email::new("s", "h")
            .linked_paragraph("<b>", "<i>&", "https://x.test/?a=1&b=\"2\"", "</p><script>")
            .html();
        assert!(html.contains(
            r#"<p style="margin:0 0 16px;">&lt;b&gt;<a href="https://x.test/?a=1&amp;b=&quot;2&quot;" style="color:#171717;text-decoration:underline;">&lt;i&gt;&amp;</a>&lt;/p&gt;&lt;script&gt;</p>"#
        ));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn the_text_part_has_the_same_words_and_writes_links_out() {
        let text = sample().text();
        assert_eq!(
            text,
            "Reset your password\n\n\
             We received a request to reset your Codewire password.\n\n\
             Reset password: https://codewire.test/reset-password?token=a&b\n\n\
             This link expires in 1 hour.\n\n\
             --\nCodewire\n\
             You got this email because someone asked to reset the password for this address.\n"
        );
    }
}
