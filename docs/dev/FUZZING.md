# Fuzzing

`fuzz/` holds [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html)
targets for the parsers that read bytes Codewire does not control.

| Target | Parser | Input comes from |
|---|---|---|
| `disco_message` | `codewire_tailnet::disco::Message::parse` | a peer, after the disco box opens |
| `udp_relay_packet` | `codewire_tailnet::udp_relay::decode_packet` | any host that can reach the UDP relay |
| `netstack_ipv4_tcp` | `codewire_netstack::parse_canonical_ipv4_tcp_packet`, `parse_initial_ipv4_tcp_syn`, `build_ipv4_tcp_refusal` | the guest |
| `netstack_dns_question` | `codewire_netstack::parse_ipv4_dns_question`, `build_ipv4_dns_response` | the guest |

Each target asserts that its parser never panics, plus a property of what it
accepts, written in the target's header comment.

## How it runs

`.github/workflows/fuzz.yml` runs every target for ten minutes a day on the
public GitHub mirror, and on manual dispatch. It keeps each target's corpus in
the GitHub Actions cache between runs. A crash fails the job and uploads the
crashing input as the `fuzz-artifacts-<target>` artifact. The private mirror
skips the job, and Forgejo CI does not build the targets: they need a nightly
toolchain.

`fuzz/Cargo.toml` is its own workspace, so the root workspace's builds and
checks never see it. The job copies the root `Cargo.lock` to
`fuzz/Cargo.lock` first, so every crate the targets share with Codewire
resolves to `main`'s version; only `libfuzzer-sys` and `arbitrary` are added.
`fuzz/Cargo.lock` is not committed.

## Run a target locally

```sh
rustup toolchain install nightly-2026-11-01 --profile minimal
cargo +nightly-2026-11-01 install cargo-fuzz --locked --version 0.13.2
cp Cargo.lock fuzz/Cargo.lock
cd fuzz
cargo +nightly-2026-11-01 fuzz run -O disco_message -- -max_total_time=60
```

To reproduce a crash from the job, download its artifact and pass the input
file: `cargo +nightly-2026-11-01 fuzz run -O <target> <file>`. Fix the parser,
then add the input as a regression test in the parser's crate.

## Add a target

Add `fuzz/fuzz_targets/<name>.rs` and a `[[bin]]` entry in `fuzz/Cargo.toml`,
and add `<name>` to the workflow's matrix; `scripts/ci/tests/test-fuzz-workflow.py`
fails until the two lists match. Fuzz a parser of untrusted input, and state in
the header comment where its input comes from and what the target asserts.
