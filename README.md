# OpenAEV Implant

[![Website](https://img.shields.io/badge/website-openaev.io-blue.svg)](https://openaev.io)
[![CircleCI](https://circleci.com/gh/OpenAEV-Platform/implant.svg?style=shield)](https://circleci.com/gh/OpenAEV-Platform/implant/tree/main)
[![GitHub release](https://img.shields.io/github/release/OpenAEV-Platform/implant.svg)](https://github.com/OpenAEV-Platform/implant/releases/latest)
[![Slack Status](https://img.shields.io/badge/slack-3K%2B%20members-4A154B)](https://community.filigran.io)
[![codecov](https://codecov.io/gh/OpenAEV-Platform/implant/graph/badge.svg)](https://codecov.io/gh/OpenAEV-Platform/implant)

The following repository is used to store the OpenAEV implant for the platform. For performance and low level access, the agent is written in Rust. Please start your journey with https://doc.rust-lang.org/book.

---

## 🚀 Installation

There is **no direct installation** required for the implant.

Instead, it is executed by a neutral orchestrator such as:

- **OpenAEV Agent**
- **Tanium**
- **Caldera**
- Or any other compatible execution engine

Execution is fully managed by the orchestrator via OpenAEV scenarios.

---

## 🛠 Development

This project is written in [Rust](https://rust-lang.org/). If you're new to Rust, we recommend starting
with [The Rust Book](https://doc.rust-lang.org/book).

### Prerequisites

- [Rust](https://rustup.rs/)
- [Cargo](https://doc.rust-lang.org/cargo/)
- Linux, macOS, or Windows

### Build

To build the implant locally:

```bash
cargo build
```

---

## ✅ Running Tests

Run all tests:

```bash
cargo test
```

Run a specific test:

```bash
cargo test test_name
```

---

## 📊 Code Coverage

You can generate coverage reports using [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov):

```bash
cargo install cargo-llvm-cov
cargo llvm-cov --html
```

---

## 🧹 Code Quality

### 🧠 Clippy – Linting

```bash
cargo clippy -- -D warnings
```

Auto-fix warnings:

```bash
cargo fix --clippy
```

Clippy runs in CI and must pass.

---

### 🎨 Rustfmt – Formatting

Check formatting:

```bash
cargo fmt -- --check
```

Auto-format:

```bash
cargo fmt
```

Rustfmt also runs in CI.

---

### 🔒 Cargo Audit – Vulnerabilities

Check for known issues in dependencies:

```bash
cargo audit
```

Fix with:

```bash
cargo update
```

---

## 🐞 Troubleshooting in Development Mode

When running the implant locally (e.g., using `cargo run`), logs are written to:

```
target/debug/openaev-implant.log
```

Check this file to investigate errors or debug behavior during development.

---

## 🧬 About

OpenAEV is developed by [Filigran](https://filigran.io), a company building open-source security tooling.

<a href="https://filigran.io" alt="Filigran"><img src="https://github.com/OpenCTI-Platform/opencti/raw/master/.github/img/logo_filigran.png" width="300" /></a>
