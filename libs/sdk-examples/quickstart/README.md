# Quickstart

Creates an environment from the `python:3.12-slim` image and waits until it is
ready. Then it runs `python3 --version` in it, writes `/workspace/hello.txt`,
lists `/workspace` and reads the file back. Last, it deletes the environment,
whether or not those steps succeeded.

Each program reads an API key and its organization from the environment:

```sh
export CODEWIRE_API_KEY=cw_...
export CODEWIRE_ORG_ID=...
```

For a server other than the hosted one, set `CODEWIRE_API_URL` to its URL.

| Language | Run it |
| --- | --- |
| Go | `cd go && go run .` |
| Python | `python python/quickstart.py`, with the SDK installed |
| TypeScript | `cd typescript && npm ci --install-links && npm start`, after `npm run build` in `libs/sdk-ts` |
| Rust | `cargo run -p codewire --example quickstart` |

The Go program's output against Dev on 2026-11-20. The other languages print
the same lines, each with its own environment ID:

```text
created 53609b38-41fc-45e7-a5eb-fe298b4924a8
ready
Python 3.12.13
wrote and read back /workspace/hello.txt
deleted 53609b38-41fc-45e7-a5eb-fe298b4924a8
```
