# AGENTS.md — Wicket

Guidelines for AI coding agents working in this Rust workspace.

## Project Overview

Wicket is a reverse proxy and Kubernetes Gateway API implementation built on [Pingora](https://github.com/cloudflare/pingora). It's a multi-crate workspace:

| Crate | Purpose |
|-------|---------|
| `wicket` | Main binary, CLI, telemetry bootstrap |
| `wicket-config` | TOML configuration parsing and validation |
| `wicket-core` | Pingora proxy service, request routing |

## Build Commands

```bash
# Build all crates
cargo build

# Build release
cargo build --release

# Build specific crate
cargo build -p wicket-core

# Check all (fast type checking)
cargo check --workspace

# Check specific crate
cargo check -p wicket-config
```

## Test Commands

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p wicket-core
cargo test -p wicket-config

# Run a single test by name
cargo test -p wicket-core test_request_id_generation
cargo test -p wicket-core routing::tests::test_exact_host_match

# Run tests matching a pattern
cargo test -p wicket-core routing

# Run tests with output shown
cargo test --workspace -- --nocapture

# Run only doc tests
cargo test --workspace --doc
```

## Lint Commands

```bash
# Clippy (required before commits)
cargo clippy --workspace -- -D warnings

# Clippy with all targets
cargo clippy --workspace --all-targets -- -D warnings

# Format check
cargo fmt --all --check

# Format (fix)
cargo fmt --all

# Full verification (run before PR)
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

## Run Commands

```bash
# Run with default config (wicket.toml)
cargo run -p wicket

# Run with specific config
cargo run -p wicket -- -c /path/to/config.toml

# Validate config only
cargo run -p wicket -- --validate

# Debug log level
cargo run -p wicket -- -l debug
```

## Code Style

### Imports

Order (rustfmt handles this):
1. `crate::` imports
2. External crates
3. `std::` imports

Group by crate, one `use` per line for clarity in complex modules:

```rust
use crate::routing::{RouteMatch, Router};
use anyhow::Result;
use async_trait::async_trait;
use pingora_core::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
```

### Error Handling

- Use `anyhow::Result` for application-level errors (main.rs, tests)
- Use `thiserror` for library error types in crates
- **Never use `.unwrap()` in production code** — use `?` or explicit error handling
- Use `.with_context()` to add context to errors:

```rust
let config = Config::load(&args.config)
    .with_context(|| format!("Failed to load config from {}", args.config.display()))?;
```

### Types and Naming

- Structs: `PascalCase` (e.g., `WicketProxy`, `RouteConfig`)
- Functions: `snake_case` (e.g., `match_request`, `build_upstreams`)
- Constants: `SCREAMING_SNAKE_CASE`
- Prefer `&str` over `&String`, `&[T]` over `&Vec<T>` in function params
- Use `#[must_use]` on builders or functions with important returns

### Async

- Use `async_trait` for async trait methods
- Pingora's proxy uses `PingoraResult` (not `anyhow::Result`)
- The workspace uses Tokio runtime

### Documentation

- Module-level `//!` doc comments on each `lib.rs` and significant modules
- Doc comments (`///`) on public items
- Keep docs concise — code should be self-explanatory

```rust
//! Core proxy and routing logic for Wicket.
//!
//! This crate provides the Pingora-based proxy service and request routing.

/// A compiled router that matches requests to upstream names.
#[derive(Debug)]
pub struct Router {
    routes: Vec<CompiledRoute>,
}
```

### Struct Organization

Use this order in structs/impls:
1. Public fields/methods
2. Private fields/methods
3. Trait implementations last

### Tracing/Logging

Use `tracing` macros with structured fields:

```rust
use tracing::{debug, info, warn, error};

info!(
    request_id = %ctx.request_id,
    method = %method,
    path = %path,
    status = status,
    "Request completed"
);
```

## Key Dependencies

- **pingora** — Core proxy framework
- **foundations** — Cloudflare's telemetry/settings framework
- **arc-swap** — Lock-free atomic pointer swaps (for hot reload)
- **serde + toml** — Configuration parsing

## Architecture Notes

### Configuration Flow
1. `Config::load()` reads TOML → validates → returns `Config`
2. `WicketProxy::new(&config)` builds router + upstream clusters
3. Hot reload via `WicketProxy::reload()` using `ArcSwap`

### Request Flow
1. `request_filter` — Match route, populate context
2. `upstream_peer` — Select backend from matched upstream
3. `logging` — Log request completion

### Testing Patterns

Tests use helper functions to construct test data:

```rust
fn make_route(
    name: Option<&str>,
    upstream: &str,
    host: Option<&str>,
    path_prefix: Option<&str>,
    path: Option<&str>,
    methods: Vec<&str>,
) -> RouteConfig { ... }

#[test]
fn test_exact_host_match() {
    let routes = vec![make_route(...)];
    let router = Router::build(&routes);
    assert!(router.match_request(...).is_some());
}
```

## Workspace Dependencies

Dependencies are centralized in root `Cargo.toml`:

```toml
[workspace.dependencies]
anyhow = "1"
thiserror = "1"
# ...
```

Crates reference them with:

```toml
[dependencies]
anyhow = { workspace = true }
```

## PR Checklist

1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. Add tests for new functionality
5. Update doc comments if public API changes
