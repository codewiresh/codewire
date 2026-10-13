//! The skill that tells a noel lead how to delegate work with `cw`.
//!
//! A host conversation the host user launched is given its own identity
//! ([`ConversationIdentity::Own`]), so its `bash` tool can already launch
//! workers under itself. noel lists the `SKILL.md` of every `--skill`
//! directory in its system prompt, by name, description and file, and its
//! model reads the file when a task matches. This skill holds the commands.
//! It lives in the conversation's own driver directory and is written again
//! at every launch, so it always names the `cw` that runs the conversation:
//! the path its driver resolved when it started.
use super::*;

/// The skill's name: its frontmatter's and its directory's.
pub(super) const NAME: &str = "codewire-delegation";
/// The skill as checked in. [`CW`] stands for the running `cw`.
pub(super) const SKILL: &str = include_str!("delegation/SKILL.md");
const CW: &str = "{{cw}}";

/// `path` as one word of a shell command, quoted only if it needs it.
fn shell_word(path: &str) -> String {
    let plain = |byte: u8| byte.is_ascii_alphanumeric() || b"/._-+@%,:=".contains(&byte);
    if !path.is_empty() && path.bytes().all(plain) {
        path.to_owned()
    } else {
        format!("'{}'", path.replace('\'', "'\\''"))
    }
}

/// The skill's text, with `cw` named by its absolute path.
pub(super) fn text(cw: &Path) -> anyhow::Result<String> {
    let cw = cw.to_str().context("the cw executable path is not UTF-8")?;
    Ok(SKILL.replace(CW, &shell_word(cw)))
}

/// Writes the skill for a conversation with its own identity and returns its
/// directory, which is noel's `--skill`. Any other conversation is given
/// none. The directories and the file are the owner's alone, and a symlink in
/// their place is refused or replaced, never followed.
pub(super) fn prepare(
    identity: &ConversationIdentity,
    driver_dir: &Path,
    cw: &Path,
) -> anyhow::Result<Option<String>> {
    if !matches!(identity, ConversationIdentity::Own(_)) {
        return Ok(None);
    }
    let text = text(cw)?;
    let skills = driver_dir.join("skills");
    let dir = skills.join(NAME);
    let argument = dir
        .to_str()
        .context("the conversation's directory is not UTF-8")?
        .to_owned();
    private_directory(&skills)?;
    private_directory(&dir)?;
    write_private(&dir.join("SKILL.md"), text.as_bytes())?;
    Ok(Some(argument))
}
