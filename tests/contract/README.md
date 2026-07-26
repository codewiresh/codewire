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

## Writing a suite

- Do not add another general Rust-service suite here.
- Implementation packages remain forbidden.
- A retained Go test must name the Go consumer or external Tailscale protocol
  promise it proves. Otherwise, put the assertion in the Rust owner.
