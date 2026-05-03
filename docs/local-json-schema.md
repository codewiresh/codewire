# `cw local` JSON output schema

The `cw local` subcommands emit machine-readable JSON when `--output json` is passed.
The SDKs (Go, Python, TypeScript) consume this output directly, so the schema
below is a public contract — **any breaking change here is also a breaking
change to the SDK**.

## Global flag

`-o, --output` is a persistent flag on `cw local`; use `--output json` for
machine-readable output:

```bash
cw local list --output json
cw local info <name> --output json
cw local create --backend docker --spec - --output json
cw local start <name> --output json
cw local stop <name> --output json
cw local rm --output json
cw local ports --output json <name>
cw local files list --output json <name> [remote-path]
```

`cw exec` accepts `--output json`, which captures stdout/stderr into a
buffered result (see below).

---

## `LocalInstance`

Produced by `list`, `info`, `create`, `start`, `stop`, and `ports --publish`.
`list` emits an array; the others emit a single object.

```jsonc
{
  "name": "my-repo",                 // instance name
  "backend": "docker",               // one of: docker, lima, incus, firecracker
  "status": "running",               // running | stopped | error | missing | unknown
  "runtime_name": "cw-my-repo",      // backend-native name (docker container, lima VM, etc.)
  "repo_path": "/home/user/code/my-repo",
  "workdir": "/workspace",           // default workdir inside the VM
  "image": "ghcr.io/…/python",       // OCI image ref
  "preset": "python",                // preset slug (optional)
  "install": "…",                    // install script (optional)
  "startup": "…",                    // startup script (optional)
  "secrets": "…",                    // secret project (optional)
  "agent": "claude",                 // primary agent (optional)
  "env": { "KEY": "VALUE" },          // env overrides (optional)
  "ports": [                          // published ports (optional)
    { "host_port": 8080, "guest_port": 3000, "label": "api" }
  ],
  "mounts": [                         // bind mounts (optional)
    { "source": "/host/path", "target": "/vm/path", "readonly": false }
  ],
  "cpu": 2000,                        // millicores (optional)
  "memory": 2048,                     // MB (optional)
  "disk": 20,                         // GB (optional)
  "created_at": "2026-04-23T12:00:00Z",
  "last_used_at": "2026-04-23T12:00:00Z",
  "lima": {                           // present only when backend == "lima"
    "instance_name": "cw-my-repo",
    "mount_type": "virtiofs",
    "vm_type": "vz"
  }
}
```

Fields are snake_case. Empty / zero values are omitted from the JSON output
to keep it compact. Consumers must treat unknown fields as valid future
additions — **do not** fail on unknown keys.

---

## `LocalSpec` (create input)

`cw local create --spec <file-or-stdin>` accepts this document. Fields mirror
`codewire.yaml` with snake_case keys:

```jsonc
{
  "preset": "python",
  "image": "python:3.12",
  "install": "pip install -r requirements.txt",
  "startup": "pytest",
  "env": { "API_URL": "https://…" },
  "ports": [
    { "host_port": 8080, "guest_port": 3000, "label": "app" },
    { "port": 5432 }                    // shorthand: host_port == guest_port
  ],
  "mounts": [
    { "source": "/host/path", "target": "/vm/path", "readonly": true }
  ],
  "cpu": 2000,
  "memory": 2048,
  "disk": 20,
  "agent": "claude",
  "secret_project": "prod-keys",
  "include_org_secrets": false,
  "include_user_secrets": true
}
```

The `--spec` flag takes precedence over `codewire.yaml`. Pass `--spec -` to
read JSON from stdin (this is what the SDK shell-out uses).

---

## `cw local files list --output json`

Returns an array of file entries at the given path:

```jsonc
[
  {
    "name": "README.md",
    "size": 1024,
    "is_dir": false,
    "mode": "-rw-r--r--",
    "mtime": "2026-04-23 12:00:00.000000000 +0000"
  }
]
```

Parsed from `ls -la --time-style=full-iso` inside the VM. Only supported for
the `docker` and `lima` backends today; `firecracker` and `incus` return an
error.

---

## `cw local rm --output json`

```jsonc
{ "name": "my-repo", "removed": true }
```

---

## `cw local ports --output json`

- With no `--publish`: emits the instance's configured ports array (the
  `ports` field of `LocalInstance`).
- With `--publish host:guest`: reconciles and emits the full
  updated `LocalInstance`.

---

## `cw exec --output json`

Buffers stdout/stderr and emits:

```jsonc
{ "exit_code": 0, "stdout": "…", "stderr": "…" }
```

The subprocess itself always exits 0 when it successfully emitted the buffered
result — the caller inspects `exit_code` to see whether the remote command
succeeded. Non-zero CLI exit indicates a CLI-level failure (instance not
found, backend unreachable, etc.).

`cw exec --target <ref> --output json --workdir <dir> -- <cmd>` is the shape the
SDKs use. `<ref>` may be a local instance name or an environment id.

Supported backends for local exec + `--output json`: docker, lima, incus. Firecracker
is not yet wired for buffered JSON output.

---

## Versioning

Schema changes are coordinated with SDK releases. Additive changes (new fields,
new commands) are considered backwards-compatible. Removing or renaming a
field is a breaking change and requires a major SDK version bump.
