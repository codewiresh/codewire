# A durable pi agent in a Codewire environment

A [pi-durable](https://www.npmjs.com/package/@earendil-works/pi-durable) agent
whose tools run in a Codewire environment, and a turn that survives its host
process being killed. TypeScript only, since pi-durable is a TypeScript
library.

`npm start` runs the demo:

1. The Codewire SDK creates an environment from `python:3.12-slim`.
2. A child process opens pi-durable's SQLite storage and starts a turn. The
   agent's `bash` call writes `/workspace/notes.txt` in the environment, then
   sleeps.
3. The demo kills that process in the middle of the call.
4. A new process reopens the same storage and resumes the turn. pi-durable
   gives the cut-off call an `interrupted` result, and the agent reads
   `/workspace/notes.txt` back from the same environment and answers.
5. The demo checks the file with the SDK, then deletes the environment and the
   storage, whether or not the turn succeeded.

The agent's tools reach the environment through
[pi-env](https://www.npmjs.com/package/@earendil-works/pi-env)'s
`RemoteExecutionEnv` over SSH. The SSH session goes through
`cw --cloud shell --stdio`, and the environment's host key comes from
`cw --cloud ssh known-hosts`, the route `cw setup ssh` writes. The demo writes
it into an SSH config file of its own for the one host, so your
`~/.ssh/config` is untouched, and there is no fingerprint to accept.

## Running it

You need `cw`, signed in or with an API key, OpenSSH 9.6 or later, and
Node 22.19 or later.

```sh
export CODEWIRE_API_KEY=cw_...
export CODEWIRE_ORG_ID=...
export CODEWIRE_API_URL=...         # only for a server other than the hosted one
cd libs/sdk-ts && npm ci --install-links && npm run build && cd -
cd typescript && npm ci --install-links && npm start
```

With `ANTHROPIC_API_KEY` set, the agent is Claude (`PI_DURABLE_MODEL`, default
`claude-sonnet-5-5`). Without it, a scripted model plays the same turn,
deciding each step from the transcript, so the resumed process carries on
where the killed one stopped. CI runs it that way, with no model key.

The scripted model's run against Dev on 2026-11-20:

```text
created 4ea42578-654c-49aa-a35d-b25066231718 (pi-durable-451c2221)
killed the host process in the middle of the turn
answer: notes.txt says: written before the restart
resumed against the same environment: /workspace/notes.txt is still there
deleted 4ea42578-654c-49aa-a35d-b25066231718
```
