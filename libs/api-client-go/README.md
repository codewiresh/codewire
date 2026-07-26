# codewire api-client-go

Fully generated Go client for the Codewire API. `client_gen.go` is produced
by oapi-codegen (pinned in `oapi-codegen.yaml` + `make api-client-tools`)
from the canonical `openapi.json` at the repo root — every operation,
parameter, and response type derives from the spec.

Regenerate after API changes:

```sh
make api-client-generate-go
```

The hand-written SDK in `libs/sdk-go` layers ergonomics (auth bootstrap,
fluent environment handles, retries) over this client.
