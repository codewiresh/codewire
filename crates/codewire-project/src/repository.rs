use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    MAX_REPOSITORY_KNOWN_HOST_LINE_BYTES, MAX_REPOSITORY_KNOWN_HOSTS,
    MAX_REPOSITORY_KNOWN_HOSTS_BYTES, ProjectError,
};

const DEFAULT_SSH_PORT: u16 = 22;
const MAX_SSH_HOST_BYTES: usize = 253;
const GITHUB_HTTPS_PREFIX: &str = "https://github.com/";
const MAX_GITHUB_PATH_SEGMENT_BYTES: usize = 128;

/// GitHub's published SSH host keys (`ssh_keys` at
/// <https://api.github.com/meta>), as canonical `known_hosts` lines in the
/// order [`canonical_repository_known_hosts`] returns them. A test binds each
/// key to the SHA256 fingerprint GitHub documents, so this is trust from a
/// published channel, never from a first connection.
pub const GITHUB_SSH_KNOWN_HOSTS: [&str; 3] = [
    "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
    "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
    "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
];

/// The SSH form of a GitHub HTTPS repository source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitHubSshSource {
    /// `git@github.com:<owner>/<repository>`, with the HTTPS path verbatim.
    pub source: String,
    /// [`GITHUB_SSH_KNOWN_HOSTS`], already canonical for `source`.
    pub known_hosts: Vec<String>,
}

/// Map a canonical `https://github.com/<owner>/<repository>` source to its SSH
/// form, so a checkout can use a selected SSH key instead of a GitHub
/// connection. Anything else, including other hosts, extra path segments,
/// userinfo, queries and fragments, returns `None`.
pub fn github_ssh_source(source: &str) -> Option<GitHubSshSource> {
    let path = source.strip_prefix(GITHUB_HTTPS_PREFIX)?;
    let (owner, repository) = path.split_once('/')?;
    let canonical = [owner, repository].iter().all(|part| {
        !part.is_empty()
            && part.len() <= MAX_GITHUB_PATH_SEGMENT_BYTES
            && !matches!(*part, "." | ".." | ".git")
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    });
    canonical.then(|| GitHubSshSource {
        source: format!("git@github.com:{owner}/{repository}"),
        known_hosts: GITHUB_SSH_KNOWN_HOSTS.map(str::to_owned).to_vec(),
    })
}

/// Canonical host identity selected by an SSH repository source.
///
/// This is public trust-routing metadata. It contains no username, repository
/// path, credential selector, or protected material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositorySshHost {
    host: String,
    port: u16,
}

impl RepositorySshHost {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Exact first field required in every admitted known_hosts line.
    ///
    /// Checkout must use the value returned by this method as OpenSSH's fixed
    /// `HostKeyAlias`, and [`Self::port`] as its fixed port. OpenSSH uses the
    /// alias verbatim, so this includes `[host]:port` for a non-default port.
    pub fn known_hosts_name(&self) -> String {
        if self.port == DEFAULT_SSH_PORT {
            self.host.clone()
        } else {
            format!("[{}]:{}", self.host, self.port)
        }
    }
}

/// Parse the canonical host/port identity of an SSH repository source.
///
/// `Ok(None)` means the source is not SSH. Invalid or ambiguous SSH authority
/// syntax fails closed rather than being interpreted differently by native and
/// hosted checkout implementations.
pub fn parse_repository_ssh_host(source: &str) -> Result<Option<RepositorySshHost>, ProjectError> {
    if source.starts_with('-') || source.chars().any(char::is_whitespace) {
        return invalid("contains an option-leading or control-bearing source");
    }
    if let Some((scheme, remainder)) = source.split_once("://") {
        if scheme.eq_ignore_ascii_case("ssh") && scheme != "ssh" {
            return invalid("must use the canonical lowercase ssh scheme");
        }
        if scheme != "ssh" {
            return Ok(None);
        }
        let (authority, path) = remainder
            .split_once('/')
            .ok_or_else(|| source_error("must include an SSH repository path"))?;
        validate_path(path, false)?;
        let authority = strip_user(authority)?;
        return parse_host_port(authority).map(Some);
    }

    let separator = scp_separator(source);
    let Some(separator) = separator else {
        if source.contains(':') {
            return invalid("contains an ambiguous SSH scp authority");
        }
        return Ok(None);
    };
    let (authority, path) = source.split_at(separator);
    let path = &path[1..];
    validate_path(path, true)?;
    let authority = strip_user(authority)?;
    let host = if authority.starts_with('[') && authority.ends_with(']') {
        parse_ipv6(&authority[1..authority.len() - 1])?
    } else {
        parse_host(authority)?
    };
    Ok(Some(RepositorySshHost {
        host,
        port: DEFAULT_SSH_PORT,
    }))
}

/// Return canonical direct host-key lines for one repository source.
///
/// SSH requires at least one exact host pin. Every other transport rejects
/// host trust input so a downstream checkout cannot silently ignore it.
/// Adapters receiving an already-canonical typed or RPC value must additionally
/// require the returned vector to equal their input vector.
pub fn canonical_repository_known_hosts(
    source: &str,
    lines: Vec<String>,
) -> Result<Vec<String>, ProjectError> {
    if lines.len() > MAX_REPOSITORY_KNOWN_HOSTS {
        return Err(ProjectError::TooManyEntries {
            field: "repositories.known_hosts",
            maximum: MAX_REPOSITORY_KNOWN_HOSTS,
        });
    }
    let Some(ssh_host) = parse_repository_ssh_host(source)? else {
        if lines.is_empty() {
            return Ok(lines);
        }
        return trust_invalid("is only valid for an SSH repository source");
    };
    if lines.is_empty() {
        return trust_invalid("must pin at least one SSH host key");
    }
    let expected_host = ssh_host.known_hosts_name();
    let mut normalized = Vec::with_capacity(lines.len());
    let mut aggregate = 0usize;
    for line in lines {
        let line = normalize_known_host_line(&line, &expected_host)?;
        aggregate = aggregate
            .checked_add(line.len())
            .and_then(|size| size.checked_add(1))
            .ok_or_else(|| trust_error("exceeds the aggregate size limit"))?;
        if aggregate > MAX_REPOSITORY_KNOWN_HOSTS_BYTES {
            return trust_invalid("exceeds the aggregate size limit");
        }
        normalized.push(line);
    }
    normalized.sort();
    if normalized.windows(2).any(|pair| pair[0] == pair[1]) {
        return trust_invalid("contains a duplicate host key");
    }
    Ok(normalized)
}

fn normalize_known_host_line(line: &str, expected_host: &str) -> Result<String, ProjectError> {
    if line.is_empty()
        || line.len() > MAX_REPOSITORY_KNOWN_HOST_LINE_BYTES
        || !line.is_ascii()
        || line
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
    {
        return trust_invalid("contains an invalid or oversized host-key line");
    }
    let fields: Vec<_> = line.split_ascii_whitespace().collect();
    let [host, algorithm, key, rest @ ..] = fields.as_slice() else {
        return trust_invalid("must contain a standard public host-key line");
    };
    if *host != expected_host
        || host.contains([',', '*', '?', '!', '|'])
        || host.starts_with('@')
        || !valid_ssh_algorithm(algorithm)
        || !valid_base64(key)
    {
        return trust_invalid("does not pin the exact SSH source host");
    }
    let mut canonical = format!("{host} {algorithm} {key}");
    if !rest.is_empty() {
        canonical.push(' ');
        canonical.push_str(&rest.join(" "));
    }
    Ok(canonical)
}

fn valid_ssh_algorithm(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && !value.contains("-cert-")
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+' | b'@')
        })
}

fn valid_base64(value: &str) -> bool {
    if value.len() < 4 || value.len() % 4 == 1 {
        return false;
    }
    let padding = value.bytes().rev().take_while(|byte| *byte == b'=').count();
    padding <= 2
        && (padding == 0 || value.len().is_multiple_of(4))
        && value[..value.len() - padding]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
        && value[value.len() - padding..]
            .bytes()
            .all(|byte| byte == b'=')
}

fn trust_invalid<T>(detail: impl Into<String>) -> Result<T, ProjectError> {
    Err(trust_error(detail))
}

fn trust_error(detail: impl Into<String>) -> ProjectError {
    ProjectError::InvalidField {
        field: "repositories.known_hosts",
        detail: detail.into(),
    }
}

fn scp_separator(source: &str) -> Option<usize> {
    let mut bracketed = false;
    for (index, byte) in source.bytes().enumerate() {
        match byte {
            b'[' if !bracketed => bracketed = true,
            b']' if bracketed => bracketed = false,
            b':' if !bracketed => return Some(index),
            _ => {}
        }
    }
    None
}

fn validate_path(path: &str, allow_leading_slashes: bool) -> Result<(), ProjectError> {
    let path = if allow_leading_slashes {
        path.trim_start_matches('/')
    } else {
        path
    };
    if path.is_empty()
        || path.ends_with('/')
        || path.contains(['?', '#', '\\'])
        || path
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return invalid("must include a normalized SSH repository path");
    }
    Ok(())
}

fn strip_user(authority: &str) -> Result<&str, ProjectError> {
    if authority.contains('%') {
        return invalid("must not contain percent-encoded SSH authority delimiters");
    }
    let Some((user, host)) = authority.rsplit_once('@') else {
        return Ok(authority);
    };
    if user.is_empty()
        || user.starts_with('-')
        || !user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
        || host.is_empty()
        || host.contains('@')
    {
        return invalid("contains an invalid SSH username or host");
    }
    Ok(host)
}

fn parse_host_port(authority: &str) -> Result<RepositorySshHost, ProjectError> {
    if authority.starts_with('[') {
        let close = authority
            .find(']')
            .ok_or_else(|| source_error("contains an unterminated IPv6 host"))?;
        let host = parse_ipv6(&authority[1..close])?;
        let suffix = &authority[close + 1..];
        let port = if suffix.is_empty() {
            DEFAULT_SSH_PORT
        } else {
            parse_port(
                suffix
                    .strip_prefix(':')
                    .ok_or_else(|| source_error("contains an invalid SSH host suffix"))?,
            )?
        };
        return Ok(RepositorySshHost { host, port });
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) if !port.contains(':') => (host, parse_port(port)?),
        Some(_) => return invalid("must bracket an IPv6 SSH host"),
        None => (authority, DEFAULT_SSH_PORT),
    };
    Ok(RepositorySshHost {
        host: parse_host(host)?,
        port,
    })
}

fn parse_port(value: &str) -> Result<u16, ProjectError> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return invalid("contains an invalid or noncanonical SSH port");
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| source_error("contains an invalid or noncanonical SSH port"))
}

fn parse_host(value: &str) -> Result<String, ProjectError> {
    if value.is_empty() || value.len() > MAX_SSH_HOST_BYTES || value.starts_with('-') {
        return invalid("contains an invalid SSH host");
    }
    if let Ok(address) = value.parse::<Ipv4Addr>() {
        return Ok(address.to_string());
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return invalid("contains an invalid IPv4 SSH host");
    }
    if value.contains(':') {
        return parse_ipv6(value);
    }
    if !value.is_ascii() || value.ends_with('.') {
        return invalid("contains a noncanonical SSH host");
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return invalid("contains an invalid SSH host");
        }
    }
    Ok(value.to_ascii_lowercase())
}

fn parse_ipv6(value: &str) -> Result<String, ProjectError> {
    value
        .parse::<Ipv6Addr>()
        .map(|address| address.to_string())
        .map_err(|_| source_error("contains an invalid IPv6 SSH host"))
}

fn invalid<T>(detail: impl Into<String>) -> Result<T, ProjectError> {
    Err(source_error(detail))
}

fn source_error(detail: impl Into<String>) -> ProjectError {
    ProjectError::InvalidField {
        field: "repositories.source",
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_sources_share_one_canonical_host_identity() {
        for (source, host, port, known_host) in [
            (
                "git@Example.COM:org/app.git",
                "example.com",
                22,
                "example.com",
            ),
            (
                "ssh://git@example.com/org/app.git",
                "example.com",
                22,
                "example.com",
            ),
            (
                "ssh://git@example.com:2222/org/app.git",
                "example.com",
                2222,
                "[example.com]:2222",
            ),
            (
                "ssh://git@[2001:0db8::1]/org/app.git",
                "2001:db8::1",
                22,
                "2001:db8::1",
            ),
            (
                "git@[2001:db8::1]:org/app.git",
                "2001:db8::1",
                22,
                "2001:db8::1",
            ),
            (
                "git@example.com:org/user@app.git",
                "example.com",
                22,
                "example.com",
            ),
        ] {
            let parsed = parse_repository_ssh_host(source).unwrap().unwrap();
            assert_eq!((parsed.host(), parsed.port()), (host, port));
            assert_eq!(parsed.known_hosts_name(), known_host);
        }
        assert!(
            parse_repository_ssh_host("https://example.com/org/app.git")
                .unwrap()
                .is_none()
        );
    }

    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn base64_decode(text: &str) -> Vec<u8> {
        let mut bits = 0_u32;
        let mut count = 0;
        let mut bytes = Vec::new();
        for byte in text.trim_end_matches('=').bytes() {
            let value = BASE64.iter().position(|digit| *digit == byte).unwrap();
            bits = (bits << 6) | value as u32;
            count += 6;
            if count >= 8 {
                count -= 8;
                bytes.push((bits >> count) as u8);
                bits &= (1 << count) - 1;
            }
        }
        bytes
    }

    fn base64_encode_unpadded(bytes: &[u8]) -> String {
        let mut text = String::new();
        for chunk in bytes.chunks(3) {
            let mut block = [0_u8; 3];
            block[..chunk.len()].copy_from_slice(chunk);
            let bits = u32::from_be_bytes([0, block[0], block[1], block[2]]);
            for index in 0..=chunk.len() {
                text.push(BASE64[((bits >> (18 - 6 * index)) & 63) as usize] as char);
            }
        }
        text
    }

    #[test]
    fn github_pins_match_the_fingerprints_github_publishes() {
        use sha2::{Digest as _, Sha256};
        // "GitHub's SSH key fingerprints" (docs.github.com) and
        // `ssh_key_fingerprints` at https://api.github.com/meta.
        let published = [
            "p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
            "+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
            "uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
        ];
        for (line, fingerprint) in GITHUB_SSH_KNOWN_HOSTS.iter().zip(published) {
            let key = line.split(' ').nth(2).unwrap();
            let digest = Sha256::digest(base64_decode(key));
            assert_eq!(base64_encode_unpadded(&digest), fingerprint, "{line}");
        }
    }

    #[test]
    fn github_https_sources_map_to_ssh_with_canonical_pins() {
        for (source, expected) in [
            ("https://github.com/org/app", "git@github.com:org/app"),
            (
                "https://github.com/org/app.git",
                "git@github.com:org/app.git",
            ),
            (
                "https://github.com/My-Org/my_app.v2",
                "git@github.com:My-Org/my_app.v2",
            ),
        ] {
            let mapped = github_ssh_source(source).unwrap();
            assert_eq!(mapped.source, expected);
            let host = parse_repository_ssh_host(&mapped.source).unwrap().unwrap();
            assert_eq!((host.host(), host.port()), ("github.com", 22));
            assert_eq!(
                canonical_repository_known_hosts(&mapped.source, mapped.known_hosts.clone())
                    .unwrap(),
                mapped.known_hosts
            );
        }
        for source in [
            "http://github.com/org/app",
            "https://GitHub.com/org/app",
            "https://github.com./org/app",
            "https://github.com:443/org/app",
            "https://user@github.com/org/app",
            "https://gitlab.com/org/app",
            "https://github.com/org",
            "https://github.com/org/",
            "https://github.com//app",
            "https://github.com/org/app/",
            "https://github.com/org/app/tree/main",
            "https://github.com/org/app?x=1",
            "https://github.com/org/app#main",
            "https://github.com/org/.git",
            "https://github.com/../app",
            "https://github.com/org/a%20pp",
            "git@github.com:org/app.git",
        ] {
            assert!(github_ssh_source(source).is_none(), "mapped {source:?}");
        }
    }

    #[test]
    fn ambiguous_ssh_authorities_fail_closed() {
        for source in [
            "-oProxyCommand=x:repo",
            "ssh://-host/repo",
            "ssh://git%40evil@example.com/repo",
            "ssh://git@example.com:022/repo",
            "ssh://git@example.com:0/repo",
            "ssh://git@example.com:65536/repo",
            "ssh://git@2001:db8::1/repo",
            "ssh://git@example..com/repo",
            "ssh://git@example.com./repo",
            "ssh://bad user@example.com/repo",
            "ssh://git@example.com/org/../repo",
            "SSH://git@example.com/org/repo",
            "git@example.com:org//repo",
            "git@example.com:org/repo/",
            "git@[2001:db8::1:repo",
            "git@host\n.invalid:repo",
        ] {
            assert!(
                parse_repository_ssh_host(source).is_err(),
                "accepted {source:?}"
            );
        }
    }
}
