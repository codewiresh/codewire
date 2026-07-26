pub mod auth;
pub mod config;
pub mod server;
pub mod store;

pub use auth::{AuthIdentity, SESSION_COOKIE_NAME, SESSION_TOKEN_PREFIX, authenticate_headers};
pub use codewire_network_auth as network_auth;
pub use config::{
    AUTH_MODE_ENV, AUTH_TOKEN_ENV, AuthMode, Config, ConfigError, DATABASE_URL_ENV,
    DEFAULT_LISTEN_ADDR, LISTEN_ADDR_ENV, MESH_URL_ENV, OIDC_ALLOWED_GROUPS_ENV,
    OIDC_CLIENT_ID_ENV, OIDC_CLIENT_SECRET_ENV, OIDC_ISSUER_ENV,
};
pub use server::{router, router_with_store, serve};
pub use store::{
    AccessGrant, AccessGrantFilter, GROUP_DEBUG_FULL, GROUP_DEBUG_NONE, GROUP_DEBUG_OBSERVE_ONLY,
    GROUP_MESSAGES_INTERNAL_ONLY, GROUP_MESSAGES_OPEN, Group, GroupBinding, GroupMember,
    GroupPolicy, Invite, KVEntry, LatestTaskValue, MemoryStore, MeshStore, NETWORK_ROLE_MEMBER,
    NETWORK_ROLE_OWNER, Network, NetworkMember, OidcUser, PostgresMeshStore, SessionIdentity,
    SharedStore, StoreError, TaskEvent, TaskFilter, TaskWatchEvent, User, store_from_config,
};
