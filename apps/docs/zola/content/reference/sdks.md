---
title: SDKs
description: Install the Go SDK with go get, then list your environments from a Go program.
updated: 2026-11-23
weight: 11
---

The Go SDK calls the same API as `cw`. Its module is `codewire.sh/sdk-go`,
and it needs Go 1.27.3 or later.

## Go

Add it to your module:

```sh
go get codewire.sh/sdk-go@v0.1.0
```

```text
go: downloading codewire.sh/sdk-go v0.1.0
go: downloading connectrpc.com/connect v1.18.1
go: downloading google.golang.org/protobuf v1.36.11
go: downloading github.com/codewiresh/codewire/libs/gen-go v0.1.0
go: added codewire.sh/sdk-go v0.1.0
go: added connectrpc.com/connect v1.18.1
go: added github.com/codewiresh/codewire/libs/gen-go v0.1.0
go: added google.golang.org/protobuf v1.36.11
```

`codewire.New` takes an API key; pass `""` to read `CODEWIRE_API_KEY`. It
calls `https://codewire.sh` unless `CODEWIRE_API_URL` names another server.
Requests about environments also need your organization's ID: pass
`codewire.WithOrganizationID(id)` to `codewire.New`, or set
`CODEWIRE_ORGANIZATION_ID`. `cw org list` shows the ID. This program lists
your environments:

```go
package main

import (
	"context"
	"fmt"
	"log"

	codewire "codewire.sh/sdk-go"
)

func main() {
	// An empty key reads CODEWIRE_API_KEY.
	client := codewire.New("")
	envs, err := client.Environments.List(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, env := range envs {
		name := "-"
		if env.Name != nil {
			name = *env.Name
		}
		fmt.Println(env.Id, name, env.State)
	}
	fmt.Println(len(envs), "environments")
}
```

```sh
export CODEWIRE_API_KEY=…           # an API key; see below
export CODEWIRE_ORGANIZATION_ID=…   # from cw org list
go build -o list-environments . && ./list-environments
```

```text
8abd20bb-9cff-4d10-8ba7-26f7a7a3aaf6 sdk-example running
1 environments
```

Without an organization ID, `List` returns the error
`codewire: organization ID is required — use WithOrganizationID or set CODEWIRE_ORGANIZATION_ID`.
Without an API key, every call returns `codewire.ErrNoCredentials` before
sending anything.

`CODEWIRE_ORG_ID`, `WithOrgID` and `WithBaseURL` still work as older names.
The Go SDK reads no `.env` file.

Create an API key with `cw api-keys create`; see
[API keys](@/organizations/api-keys.md).
