# SDK examples

Runnable programs, one task each, for the Codewire SDKs. Until the SDKs are
installed from their releases (#3512), each example builds from this
repository.

| Example | Go | Python | TypeScript | Rust |
| --- | --- | --- | --- | --- |
| [Quickstart](quickstart/): create an environment, run a command, write and read back a file, delete it | [go](quickstart/go/main.go) | [python](quickstart/python/quickstart.py) | [typescript](quickstart/typescript/quickstart.ts) | [rust](../../crates/codewire/examples/quickstart.rs) |
| [Run a coding agent](run-agent/): upload a project, run an agent on it without a terminal, print its change | [go](run-agent/go/main.go) | [python](run-agent/python/run_agent.py) | [typescript](run-agent/typescript/run_agent.ts) | [rust](../../crates/codewire/examples/run_agent.rs) |
| [A durable pi agent](pi-durable/): a pi-durable agent whose tools run in an environment, and a turn that survives its host process being killed | | | [typescript](pi-durable/typescript/durable.ts) | |

The Rust examples live with the crate, as Cargo expects
(`cargo run -p codewire --example quickstart`).

Every example deletes the environment it creates, even when a step fails.
`make test-sdk-examples` builds and typechecks them all without a server, and
`make sdk-e2e` runs them against one with the SDK end-to-end suites.
