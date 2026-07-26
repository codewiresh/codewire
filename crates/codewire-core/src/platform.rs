//! Platform abstraction traits
//!
//! These traits define the I/O boundaries for codewire-core. By making all
//! business logic generic over these traits, the core crate remains free of
//! I/O dependencies and can compile for native, WASM, and server targets.
//!
//! Implementations live in platform-specific crates:
//! - `codewire-platform-native` (reqwest, russh, keyring, tokio::fs)
//! - `codewire-platform-wasm` (web_sys::fetch, localStorage)

use crate::CoreError;

// ============================================================================
// HTTP Client
// ============================================================================

/// HTTP response from a platform HTTP client
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Check if the status code indicates success (2xx)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Get the body as a UTF-8 string
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// Deserialize the body from JSON
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, CoreError> {
        serde_json::from_slice(&self.body).map_err(|e| CoreError::Serialization {
            message: format!("Failed to parse JSON response: {}", e),
        })
    }
}

/// A streaming byte chunk from an HTTP response
#[cfg(not(target_arch = "wasm32"))]
pub type ByteChunk = Result<Vec<u8>, CoreError>;

/// Platform-specific HTTP client (native: Send + Sync, streaming support)
#[cfg(not(target_arch = "wasm32"))]
pub trait HttpClient: Send + Sync {
    /// Send a GET request with headers
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> impl std::future::Future<Output = Result<HttpResponse, CoreError>> + Send;

    /// Send a POST request with a JSON body
    fn post_json(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> impl std::future::Future<Output = Result<HttpResponse, CoreError>> + Send;

    /// Send a POST request with form-encoded body
    fn post_form(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        form_data: &[(&str, &str)],
    ) -> impl std::future::Future<Output = Result<HttpResponse, CoreError>> + Send;

    /// Send a POST request and return a streaming response.
    ///
    /// The returned receiver yields byte chunks as they arrive.
    /// Used for SSE streaming from AI providers.
    fn post_streaming(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> impl std::future::Future<
        Output = Result<(u16, tokio::sync::mpsc::Receiver<ByteChunk>), CoreError>,
    > + Send;
}

/// Platform-specific HTTP client (WASM: no Send/Sync, no streaming)
#[cfg(target_arch = "wasm32")]
pub trait HttpClient {
    /// Send a GET request with headers
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> impl std::future::Future<Output = Result<HttpResponse, CoreError>>;

    /// Send a POST request with a JSON body
    fn post_json(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> impl std::future::Future<Output = Result<HttpResponse, CoreError>>;

    /// Send a POST request with form-encoded body
    fn post_form(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        form_data: &[(&str, &str)],
    ) -> impl std::future::Future<Output = Result<HttpResponse, CoreError>>;
}

// ============================================================================
// Persistent Storage (synchronous, for config files)
// ============================================================================

/// Synchronous key-value storage for configuration data
///
/// Implementations:
/// - Native: `std::fs` read/write to `~/.codewire/`
/// - WASM: `localStorage`
#[cfg(not(target_arch = "wasm32"))]
pub trait PersistentStorage: Send + Sync {
    /// Read a file's contents as a string. Returns None if not found.
    fn read(&self, key: &str) -> Result<Option<String>, CoreError>;

    /// Write a string to storage
    fn write(&self, key: &str, value: &str) -> Result<(), CoreError>;

    /// Delete a key from storage
    fn delete(&self, key: &str) -> Result<(), CoreError>;

    /// Check if a key exists
    fn exists(&self, key: &str) -> bool;
}

#[cfg(target_arch = "wasm32")]
pub trait PersistentStorage {
    fn read(&self, key: &str) -> Result<Option<String>, CoreError>;
    fn write(&self, key: &str, value: &str) -> Result<(), CoreError>;
    fn delete(&self, key: &str) -> Result<(), CoreError>;
    fn exists(&self, key: &str) -> bool;
}

// ============================================================================
// Async Storage (for chat history / append-only files)
// ============================================================================

/// Async storage for append-only data like chat history
///
/// Implementations:
/// - Native: `tokio::fs` with JSONL files
/// - WASM: IndexedDB or localStorage
#[cfg(not(target_arch = "wasm32"))]
pub trait AsyncStorage: Send + Sync {
    /// Read all lines from a storage key
    fn read_lines(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, CoreError>> + Send;

    /// Append a line to storage
    fn append(
        &self,
        key: &str,
        line: &str,
    ) -> impl std::future::Future<Output = Result<(), CoreError>> + Send;

    /// Append multiple lines to storage
    fn append_lines(
        &self,
        key: &str,
        lines: &[String],
    ) -> impl std::future::Future<Output = Result<(), CoreError>> + Send;

    /// Delete all data for a key
    fn delete(&self, key: &str) -> impl std::future::Future<Output = Result<(), CoreError>> + Send;

    /// Check if a key exists
    fn exists(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<bool, CoreError>> + Send;
}

#[cfg(target_arch = "wasm32")]
pub trait AsyncStorage {
    fn read_lines(
        &self,
        key: &str,
    ) -> impl std::future::Future<Output = Result<Vec<String>, CoreError>>;

    fn append(
        &self,
        key: &str,
        line: &str,
    ) -> impl std::future::Future<Output = Result<(), CoreError>>;

    fn append_lines(
        &self,
        key: &str,
        lines: &[String],
    ) -> impl std::future::Future<Output = Result<(), CoreError>>;

    fn delete(&self, key: &str) -> impl std::future::Future<Output = Result<(), CoreError>>;

    fn exists(&self, key: &str) -> impl std::future::Future<Output = Result<bool, CoreError>>;
}

// ============================================================================
// Secure Storage (for credentials)
// ============================================================================

/// Secure credential storage (keychain, keyring, etc.)
///
/// Implementations:
/// - Native: system keychain via `keyring` crate
/// - WASM: not available (use token-based auth only)
#[cfg(not(target_arch = "wasm32"))]
pub trait SecureStorage: Send + Sync {
    /// Store a credential
    fn store(&self, key: &str, value: &str) -> Result<(), CoreError>;

    /// Retrieve a credential. Returns None if not found.
    fn retrieve(&self, key: &str) -> Result<Option<String>, CoreError>;

    /// Delete a credential
    fn delete(&self, key: &str) -> Result<(), CoreError>;
}

#[cfg(target_arch = "wasm32")]
pub trait SecureStorage {
    fn store(&self, key: &str, value: &str) -> Result<(), CoreError>;
    fn retrieve(&self, key: &str) -> Result<Option<String>, CoreError>;
    fn delete(&self, key: &str) -> Result<(), CoreError>;
}

// ============================================================================
// OAuth Callback Handler
// ============================================================================

/// Handles the browser-based OAuth flow
///
/// Implementations:
/// - Native: `open` crate + `tiny_http` local server
/// - WASM: browser redirect flow
#[cfg(not(target_arch = "wasm32"))]
pub trait OAuthCallbackHandler: Send + Sync {
    /// Open the given URL in the user's browser
    fn open_browser(&self, url: &str) -> Result<(), CoreError>;

    /// Start listening for an OAuth callback and return the authorization code.
    /// This blocks until a callback is received or times out.
    fn wait_for_callback(
        &self,
    ) -> impl std::future::Future<Output = Result<String, CoreError>> + Send;
}

#[cfg(target_arch = "wasm32")]
pub trait OAuthCallbackHandler {
    fn open_browser(&self, url: &str) -> Result<(), CoreError>;

    fn wait_for_callback(&self) -> impl std::future::Future<Output = Result<String, CoreError>>;
}

// ============================================================================
// SSH Client (native only)
// ============================================================================

/// SSH client for remote command execution
///
/// Implementations:
/// - Native: `russh` crate
/// - WASM: not available
#[cfg(not(target_arch = "wasm32"))]
pub trait SshClient: Send + Sync {
    type Session: SshSession;

    /// Connect to an SSH host
    fn connect(
        &self,
        host: &str,
    ) -> impl std::future::Future<Output = Result<Self::Session, CoreError>> + Send;
}

/// An active SSH session
#[cfg(not(target_arch = "wasm32"))]
pub trait SshSession: Send + Sync {
    /// Execute a command and return stdout
    fn exec(
        &self,
        command: &str,
    ) -> impl std::future::Future<Output = Result<String, CoreError>> + Send;

    /// Get the host this session is connected to
    fn host(&self) -> &str;

    /// Check if the session is still alive
    fn is_alive(&self) -> impl std::future::Future<Output = bool> + Send;
}
