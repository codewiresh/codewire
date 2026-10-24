# Go/Tailscale interoperability harness

This module proves the Rust DERP service remains interoperable with real
Tailscale Go clients. It is not a general product-correctness driver or a
former-implementation oracle. Rust service correctness belongs in the owning
Rust black-box tests; browser behavior belongs in connect-es/Playwright.

Go remains here only where the behavior is genuinely Go- or Tailscale-client
interoperability. The former Go product implementation is not a contract oracle.
See `docs/dev/CONTRACT-TESTING.md` for the binding ownership policy.

## Running

The suite is skipped unless `DERP_BASE_URL` is set, so `go test ./...` is safe
everywhere:

```sh
DERP_BASE_URL=http://127.0.0.1:8080 \
  GOWORK=off go test ./derp/...
```

Set `DERP_WEBSOCKET=1` to run the WebSocket fallback case as well as the raw
HTTP upgrade case.

## Tailscale wire-format golden

`tailscalegolden` records the Tailscale wire formats the Rust
`codewire-tailnet` port reimplements (DERP frames and constants, disco
messages, STUN, UDP-relay Geneve headers, key encodings), produced by
Tailscale's own Go packages at the `tailscale.com` version in `go.mod`. It
needs no service and always runs:

```sh
GOWORK=off go test ./tailscalegolden/
```

It fails when the pinned Tailscale produces different bytes than
`tests/fixtures/tailnet/tailscale_golden.json`. After a `tailscale.com` bump,
regenerate with `UPDATE_TAILSCALE_GOLDEN=1`, review the diff, and make
`cargo test -p codewire-tailnet golden_tests` pass.

## Writing a suite

- Do not add another general Rust-service suite here.
- Implementation packages remain forbidden.
- A retained Go test must name the Go consumer or external Tailscale protocol
  promise it proves. Otherwise, put the assertion in the Rust owner.
