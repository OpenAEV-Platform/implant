# AGENTS.md

OpenAEV implant: a short-lived Rust binary started by an orchestrator (OpenAEV agent, Tanium, Caldera...) for one inject. It fetches the inject payload from the platform, runs it, reports the results and exits. Targets Linux, macOS and Windows, on x86_64 and arm64.

## Layout

- `src/main.rs`: CLI arguments (platform URL, token, inject, agent and tenant ids), logger, payload directory, then runs the payload.
- `src/api/`: HTTP client (blocking `reqwest`, rustls, proxy and certificate options), payload fetch and result reporting.
- `src/handle/`: one handler per payload type (command, DNS resolution, file drop, file execution).
- `src/process/`: process execution and output capture.
- `src/common/`: logger, constants, error and execution result models.
- `src/tests/`: tests, mirroring the `src/` layout.

## Commands

```bash
cargo fmtcheck          # cargo fmt -- --check
cargo lint              # cargo clippy -- -D warnings
cargo test --locked
cargo audit
cargo run -- --help
```

Logs go next to the executable. Payload files go to `../../payloads/<folder>` relative to the executable, where `<folder>` is the executable's parent folder name.

## CI

`.github/workflows/implant-ci.yml`: fmt and audit, clippy per target, tests and release builds per OS and arch, coverage.

## Rules

- Code must build on every target: put OS-specific code behind `cfg` attributes.
- Windows builds link the C runtime statically through `.cargo/config.toml`: do not set `RUSTFLAGS` in CI.
- Commit, PR and issue titles follow Conventional Commits with an issue reference, see `CONTRIBUTING.md`.
