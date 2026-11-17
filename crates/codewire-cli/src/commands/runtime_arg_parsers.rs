//! Value parsers for the `cw runtime` arguments.

pub(super) fn parse_runtime_sha256(value: &str) -> Result<String, String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(value.to_owned())
    } else {
        Err("runtime SHA256 must be exactly 64 lowercase hexadecimal characters".into())
    }
}

pub(super) fn parse_runtime_revision(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|revision| *revision > 0)
        .ok_or_else(|| "runtime selection revision must be a nonzero integer".into())
}

pub(super) fn parse_runtime_generation(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|number| number.to_string() == value)
        .ok_or_else(|| "runtime Store generation must be a canonical unsigned integer".into())
}

pub(super) fn parse_runtime_request_id(value: &str) -> Result<uuid::Uuid, String> {
    uuid::Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or_else(|| "runtime request ID must be a non-nil UUID".into())
}
