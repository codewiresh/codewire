use codewire_types::CoreError;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::Mutex;

/// SSH client backed by the `russh` crate
pub struct RusshClient {
    config: Arc<russh::client::Config>,
}

impl RusshClient {
    pub fn new() -> Self {
        let config = russh::client::Config {
            ..Default::default()
        };
        Self {
            config: Arc::new(config),
        }
    }
}

impl Default for RusshClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Handler for russh client events
struct ClientHandler;

/// Wrapper error to satisfy russh's `From<crate::Error>` bound on Handler::Error
#[derive(Debug)]
enum SshError {
    Russh(russh::Error),
}

impl From<russh::Error> for SshError {
    fn from(e: russh::Error) -> Self {
        SshError::Russh(e)
    }
}

impl std::fmt::Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshError::Russh(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SshError {}

impl russh::client::Handler for ClientHandler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept all keys (trust-on-first-use model, like ssh -o StrictHostKeyChecking=no)
        // Remote environments are ephemeral and don't have stable host keys.
        Ok(true)
    }
}

// ============================================================================
// ProxyCommand Support
// ============================================================================

/// Combines a child process's stdout (read) and stdin (write) into a single
/// `AsyncRead + AsyncWrite` stream for use with `russh::client::connect_stream`.
struct ChildStream {
    stdout: ChildStdout,
    stdin: ChildStdin,
}

impl AsyncRead for ChildStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChildStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

/// Replace SSH config tokens in a ProxyCommand string.
/// Supports: %h (hostname), %p (port), %r (remote user), %n (hostname), %% (literal %)
fn substitute_proxy_tokens(cmd: &str, hostname: &str, port: u16, user: &str) -> String {
    let mut result = String::with_capacity(cmd.len());
    let mut chars = cmd.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            match chars.peek() {
                Some('h') => {
                    result.push_str(hostname);
                    chars.next();
                }
                Some('n') => {
                    result.push_str(hostname);
                    chars.next();
                }
                Some('p') => {
                    result.push_str(&port.to_string());
                    chars.next();
                }
                Some('r') => {
                    result.push_str(user);
                    chars.next();
                }
                Some('%') => {
                    result.push('%');
                    chars.next();
                }
                _ => {
                    result.push('%');
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}

/// Spawn a ProxyCommand subprocess, returning the combined stream and child handle.
fn spawn_proxy_command(cmd: &str) -> Result<(ChildStream, Child), CoreError> {
    let mut child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| CoreError::Ssh {
            message: format!("Failed to spawn ProxyCommand `{cmd}`: {e}"),
        })?;

    let stdout = child.stdout.take().ok_or_else(|| CoreError::Ssh {
        message: "ProxyCommand: failed to capture stdout".to_string(),
    })?;
    let stdin = child.stdin.take().ok_or_else(|| CoreError::Ssh {
        message: "ProxyCommand: failed to capture stdin".to_string(),
    })?;

    Ok((ChildStream { stdout, stdin }, child))
}

impl RusshClient {
    /// Connect to an SSH host using the user's native SSH configuration.
    pub async fn connect(&self, host: &str) -> Result<RusshSession, CoreError> {
        // Parse host:port, default to port 22
        let (hostname, port) = if let Some((h, p)) = host.rsplit_once(':') {
            let port = p.parse::<u16>().unwrap_or(22);
            (h, port)
        } else {
            (host, 22)
        };

        // Parse SSH config for the host to get user, port overrides, identity file, etc.
        let ssh_config = parse_ssh_config(hostname);

        let actual_host = ssh_config.hostname.as_deref().unwrap_or(hostname);
        let actual_port = ssh_config.port.unwrap_or(port);
        let user = ssh_config.user.as_deref().unwrap_or("root");

        let (mut handle, proxy_child) = if let Some(ref proxy_cmd) = ssh_config.proxy_command {
            // ProxyCommand path: spawn subprocess and connect over its stdio
            let expanded = substitute_proxy_tokens(proxy_cmd, hostname, actual_port, user);
            let (stream, child) = spawn_proxy_command(&expanded)?;
            let handle = russh::client::connect_stream(self.config.clone(), stream, ClientHandler)
                .await
                .map_err(|e| CoreError::Ssh {
                    message: format!("Failed to connect via ProxyCommand `{expanded}`: {e}"),
                })?;
            (handle, Some(child))
        } else {
            // Direct TCP connection
            let handle = russh::client::connect(
                self.config.clone(),
                (actual_host, actual_port),
                ClientHandler,
            )
            .await
            .map_err(|e| CoreError::Ssh {
                message: format!("Failed to connect to {actual_host}:{actual_port}: {e}"),
            })?;
            (handle, None)
        };

        // Try "none" auth first (works for proxied remote environments
        // where the proxy already handles authentication)
        let none_result = handle
            .authenticate_none(user)
            .await
            .map(|r| matches!(r, russh::client::AuthResult::Success))
            .unwrap_or(false);

        if !none_result {
            // Fall back to key-based auth
            let authenticated = try_key_auth(&mut handle, user, &ssh_config).await;

            if !authenticated {
                return Err(CoreError::Ssh {
                    message: format!(
                        "Authentication failed for {user}@{actual_host}:{actual_port}"
                    ),
                });
            }
        }

        Ok(RusshSession {
            handle: Arc::new(Mutex::new(handle)),
            host: host.to_string(),
            _proxy_child: proxy_child,
        })
    }
}

/// An active SSH session backed by russh
pub struct RusshSession {
    handle: Arc<Mutex<russh::client::Handle<ClientHandler>>>,
    host: String,
    /// Keeps the ProxyCommand subprocess alive for the duration of the session.
    /// Dropped when the session is dropped, which kills the child (kill_on_drop).
    _proxy_child: Option<Child>,
}

impl RusshSession {
    /// Execute a command and return its standard output.
    pub async fn exec(&self, command: &str) -> Result<String, CoreError> {
        let handle = self.handle.lock().await;
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| CoreError::Ssh {
                message: format!("Failed to open channel: {e}"),
            })?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| CoreError::Ssh {
                message: format!("Failed to exec command: {e}"),
            })?;

        let mut output = Vec::new();
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data, .. }) => {
                    output.extend_from_slice(&data);
                }
                Some(russh::ChannelMsg::Eof) | None => break,
                _ => {}
            }
        }

        String::from_utf8(output).map_err(|e| CoreError::Ssh {
            message: format!("Invalid UTF-8 in command output: {e}"),
        })
    }

    /// Return the host this session connected to.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Check whether a new channel can be opened on this session.
    pub async fn is_alive(&self) -> bool {
        let handle = self.handle.lock().await;
        handle.channel_open_session().await.is_ok()
    }

    /// Open a new SSH channel with PTY allocation and shell.
    ///
    /// Returns the raw russh Channel for bidirectional byte I/O.
    /// Used by the terminal backend for interactive sessions.
    pub async fn open_pty_channel(
        &self,
        cols: u32,
        rows: u32,
    ) -> Result<russh::Channel<russh::client::Msg>, CoreError> {
        let handle = self.handle.lock().await;
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| CoreError::Ssh {
                message: format!("Failed to open session channel: {e}"),
            })?;

        channel
            .request_pty(true, "xterm-256color", cols, rows, 0, 0, &[])
            .await
            .map_err(|e| CoreError::Ssh {
                message: format!("Failed to request PTY: {e}"),
            })?;

        channel
            .request_shell(true)
            .await
            .map_err(|e| CoreError::Ssh {
                message: format!("Failed to request shell: {e}"),
            })?;

        Ok(channel)
    }
}

// ============================================================================
// SSH Config Parsing
// ============================================================================

/// Parsed SSH config entry for a host
#[derive(Debug, Default)]
pub struct SshHostConfig {
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub identity_file: Option<String>,
    pub proxy_command: Option<String>,
}

/// Parse `~/.ssh/config` for a given host pattern
pub fn parse_ssh_config(host: &str) -> SshHostConfig {
    let config_path = dirs::home_dir()
        .map(|h| h.join(".ssh").join("config"))
        .unwrap_or_default();

    let content = match std::fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return SshHostConfig::default(),
    };

    parse_ssh_config_content(&content, host)
}

/// Parse SSH config content (extracted for testing)
pub fn parse_ssh_config_content(content: &str, host: &str) -> SshHostConfig {
    let mut result = SshHostConfig::default();
    let mut in_matching_block = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split on first whitespace or '='
        let (key, value) = if let Some(eq_pos) = line.find('=') {
            let (k, v) = line.split_at(eq_pos);
            (k.trim(), v[1..].trim())
        } else if let Some((k, v)) = line.split_once(char::is_whitespace) {
            (k.trim(), v.trim())
        } else {
            continue;
        };

        match key.to_lowercase().as_str() {
            "host" => {
                in_matching_block = value.split_whitespace().any(|pattern| {
                    if pattern == "*" {
                        true
                    } else if let Some(prefix) = pattern.strip_suffix('*') {
                        host.starts_with(prefix)
                    } else if let Some(suffix) = pattern.strip_prefix('*') {
                        host.ends_with(suffix)
                    } else {
                        pattern == host
                    }
                });
            }
            "hostname" if in_matching_block => {
                result.hostname = Some(value.to_string());
            }
            "port" if in_matching_block => {
                result.port = value.parse().ok();
            }
            "user" if in_matching_block => {
                result.user = Some(value.to_string());
            }
            "identityfile" if in_matching_block => {
                let expanded = if let Some(rest) = value.strip_prefix("~/") {
                    dirs::home_dir()
                        .map(|h| h.join(rest).to_string_lossy().to_string())
                        .unwrap_or_else(|| value.to_string())
                } else {
                    value.to_string()
                };
                result.identity_file = Some(expanded);
            }
            "proxycommand" if in_matching_block => {
                if value.eq_ignore_ascii_case("none") {
                    result.proxy_command = None;
                } else {
                    result.proxy_command = Some(value.to_string());
                }
            }
            _ => {}
        }
    }

    result
}

/// Try to authenticate with SSH keys
async fn try_key_auth(
    handle: &mut russh::client::Handle<ClientHandler>,
    user: &str,
    config: &SshHostConfig,
) -> bool {
    // Try identity file from config first
    if let Some(ref identity_file) = config.identity_file {
        if let Ok(true) = try_key_file(handle, user, identity_file).await {
            return true;
        }
    }

    // Try default key locations
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return false,
    };

    let default_keys = [
        home.join(".ssh/id_ed25519"),
        home.join(".ssh/id_rsa"),
        home.join(".ssh/id_ecdsa"),
    ];

    for key_path in &default_keys {
        if key_path.exists() {
            if let Ok(true) = try_key_file(handle, user, &key_path.to_string_lossy()).await {
                return true;
            }
        }
    }

    false
}

/// Try to authenticate with a specific key file
async fn try_key_file(
    handle: &mut russh::client::Handle<ClientHandler>,
    user: &str,
    key_path: &str,
) -> Result<bool, CoreError> {
    let key_data = std::fs::read_to_string(key_path).map_err(|e| CoreError::Ssh {
        message: format!("Failed to read key file {key_path}: {e}"),
    })?;

    let key_pair =
        russh::keys::PrivateKey::from_openssh(&key_data).map_err(|e| CoreError::Ssh {
            message: format!("Failed to parse key {key_path}: {e}"),
        })?;

    // Wrap in PrivateKeyWithHashAlg (None hash_alg = use default for the key type)
    let key_with_alg = russh::keys::key::PrivateKeyWithHashAlg::new(Arc::new(key_pair), None);

    let auth_result = handle
        .authenticate_publickey(user, key_with_alg)
        .await
        .map_err(|e| CoreError::Ssh {
            message: format!("Key auth failed: {e}"),
        })?;

    Ok(matches!(auth_result, russh::client::AuthResult::Success))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_config_basic() {
        let config = r#"
Host myserver
    HostName 192.168.1.100
    Port 2222
    User admin
    IdentityFile ~/.ssh/id_myserver

Host *.example.com
    User deploy
    Port 22
"#;

        let result = parse_ssh_config_content(config, "myserver");
        assert_eq!(result.hostname, Some("192.168.1.100".to_string()));
        assert_eq!(result.port, Some(2222));
        assert_eq!(result.user, Some("admin".to_string()));
        assert!(result.identity_file.is_some());
    }

    #[test]
    fn test_parse_ssh_config_wildcard() {
        let config = r#"
Host *.example.com
    User deploy
    Port 2200
"#;

        let result = parse_ssh_config_content(config, "app.example.com");
        assert_eq!(result.user, Some("deploy".to_string()));
        assert_eq!(result.port, Some(2200));
    }

    #[test]
    fn test_parse_ssh_config_prefix_wildcard() {
        let config = r#"
Host env.*
    User codewire
    HostName 10.0.0.1
"#;

        let result = parse_ssh_config_content(config, "env.workspace-1");
        assert_eq!(result.user, Some("codewire".to_string()));
        assert_eq!(result.hostname, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_parse_ssh_config_no_match() {
        let config = r#"
Host production
    HostName prod.example.com
    User admin
"#;

        let result = parse_ssh_config_content(config, "staging");
        assert_eq!(result.hostname, None);
        assert_eq!(result.user, None);
    }

    #[test]
    fn test_parse_ssh_config_equals_syntax() {
        let config = r#"
Host myhost
    HostName=10.0.0.5
    Port=3022
    User=testuser
"#;

        let result = parse_ssh_config_content(config, "myhost");
        assert_eq!(result.hostname, Some("10.0.0.5".to_string()));
        assert_eq!(result.port, Some(3022));
        assert_eq!(result.user, Some("testuser".to_string()));
    }

    #[test]
    fn test_parse_ssh_config_star_matches_all() {
        let config = r#"
Host *
    User default
    Port 22
"#;

        let result = parse_ssh_config_content(config, "anything");
        assert_eq!(result.user, Some("default".to_string()));
        assert_eq!(result.port, Some(22));
    }

    #[test]
    fn test_parse_ssh_config_proxy_command() {
        let config = r#"
Host env.*
    ProxyCommand /usr/local/bin/codewire ssh --stdio --ssh-host-prefix env. %h
    User codewire
    StrictHostKeyChecking no
"#;

        let result = parse_ssh_config_content(config, "env.admin-codewire");
        assert_eq!(
            result.proxy_command,
            Some("/usr/local/bin/codewire ssh --stdio --ssh-host-prefix env. %h".to_string())
        );
        assert_eq!(result.user, Some("codewire".to_string()));
    }

    #[test]
    fn test_parse_ssh_config_proxy_command_none() {
        let config = r#"
Host env.*
    ProxyCommand /usr/local/bin/codewire ssh --stdio %h

Host env.special
    ProxyCommand none
    HostName 10.0.0.5
"#;

        // "env.special" matches both blocks; last ProxyCommand wins
        let result = parse_ssh_config_content(config, "env.special");
        assert_eq!(result.proxy_command, None);
        assert_eq!(result.hostname, Some("10.0.0.5".to_string()));
    }

    #[test]
    fn test_substitute_proxy_tokens() {
        let cmd = "/usr/local/bin/codewire ssh --stdio --ssh-host-prefix env. %h";
        let result = substitute_proxy_tokens(cmd, "env.admin-codewire", 22, "codewire");
        assert_eq!(
            result,
            "/usr/local/bin/codewire ssh --stdio --ssh-host-prefix env. env.admin-codewire"
        );
    }

    #[test]
    fn test_substitute_proxy_tokens_all() {
        let cmd = "connect %h %p %r %n %%";
        let result = substitute_proxy_tokens(cmd, "myhost", 2222, "admin");
        assert_eq!(result, "connect myhost 2222 admin myhost %");
    }

    #[test]
    fn test_parse_host_port() {
        let host = "myhost:2222";
        let (hostname, port) = if let Some((h, p)) = host.rsplit_once(':') {
            let port = p.parse::<u16>().unwrap_or(22);
            (h, port)
        } else {
            (host, 22)
        };
        assert_eq!(hostname, "myhost");
        assert_eq!(port, 2222);

        let host2 = "myhost";
        let (hostname2, port2) = if let Some((h, p)) = host2.rsplit_once(':') {
            let port = p.parse::<u16>().unwrap_or(22);
            (h, port)
        } else {
            (host2, 22)
        };
        assert_eq!(hostname2, "myhost");
        assert_eq!(port2, 22);
    }
}
