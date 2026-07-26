# codewire-oidc

A standalone, transport-agnostic **OpenID Connect / OAuth 2.0 provider (OP)**
library for Rust.

`codewire-oidc` implements the OAuth/OIDC *protocol mechanics* and delegates
all state and deployment policy to a small set of storage traits. It is
deliberately self-contained — **zero Codewire-internal dependencies** — so it
can be extracted and published on its own, and is dual-licensed `MIT OR
Apache-2.0`.

## Scope

Implemented or in progress:

- OpenID Connect Discovery (`/.well-known/openid-configuration`)
- JWKS publication (EdDSA / Ed25519 id_token signing)
- Authorization Code flow with **mandatory PKCE (S256)**
- **Opaque Bearer** access tokens (not JWTs)
- EdDSA-signed `id_token`s
- Refresh-token rotation, token revocation (RFC 7009), introspection (RFC 7662)
- UserInfo endpoint
- RP-initiated logout (`end_session`)

Out of scope (by design): implicit/hybrid flows, the device authorization
grant, dynamic client registration, and `client_secret_jwt`/`private_key_jwt`.

## Design

The library owns the mechanics; the host owns the state. A deployment
implements six traits (see [`src/store.rs`](src/store.rs)):

| Trait | Responsibility |
|-------|----------------|
| `AuthorizationStore` | In-flight `/authorize` requests |
| `TokenStore` | Codes, opaque access tokens, refresh tokens (single-use consume) |
| `ClientStore` | Relying-party lookup + constant-time secret verification |
| `KeyStore` | Active Ed25519 signer + published JWKS |
| `UserAuthenticator` | Bridge to the host's session/login + policy gate |
| `TokenCustomizer` | Deployment-specific extra claims (optional) |

Wire them into a [`Provider`] via its builder:

```rust,ignore
let provider = Provider::builder(ProviderConfig {
        issuer: Issuer("https://idp.example".into()),
        paths: Default::default(),
        scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
    })
    .auth_requests(auth_store)
    .tokens(token_store)
    .clients(client_store)
    .keys(key_store)
    .authenticator(authenticator)
    .build()?;

let discovery = provider.discovery();
let jwks = provider.jwks().await?;
```

See [`examples/in_memory.rs`](examples/in_memory.rs) for a complete,
dependency-free backing:

```sh
cargo run -p codewire-oidc --example in_memory
```

## Features

- `axum` *(off by default)* — an optional axum router that mounts the
  endpoints; non-axum hosts pay nothing for it.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)
at your option.
