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

<!-- BEGIN BEADS INTEGRATION -->
## Issue Tracking with bd (beads)

**IMPORTANT**: This project uses **bd (beads)** for ALL issue tracking. Do NOT use markdown TODOs, task lists, or other tracking methods.

### Why bd?

- Dependency-aware: Track blockers and relationships between issues
- Git-friendly: Auto-syncs to JSONL for version control
- Agent-optimized: JSON output, ready work detection, discovered-from links
- Prevents duplicate tracking systems and confusion

### Quick Start

**Check for ready work:**

```bash
bd ready --json
```

**Create new issues:**

```bash
bd create "Issue title" --description="Detailed context" -t bug|feature|task -p 0-4 --json
bd create "Issue title" --description="What this issue is about" -p 1 --deps discovered-from:bd-123 --json
```

**Claim and update:**

```bash
bd update bd-42 --status in_progress --json
bd update bd-42 --priority 1 --json
```

**Complete work:**

```bash
bd close bd-42 --reason "Completed" --json
```

### Issue Types

- `bug` - Something broken
- `feature` - New functionality
- `task` - Work item (tests, docs, refactoring)
- `epic` - Large feature with subtasks
- `chore` - Maintenance (dependencies, tooling)

### Priorities

- `0` - Critical (security, data loss, broken builds)
- `1` - High (major features, important bugs)
- `2` - Medium (default, nice-to-have)
- `3` - Low (polish, optimization)
- `4` - Backlog (future ideas)

### Workflow for AI Agents

1. **Check ready work**: `bd ready` shows unblocked issues
2. **Claim your task**: `bd update <id> --status in_progress`
3. **Work on it**: Implement, test, document
4. **Discover new work?** Create linked issue:
   - `bd create "Found bug" --description="Details about what was found" -p 1 --deps discovered-from:<parent-id>`
5. **Complete**: `bd close <id> --reason "Done"`

### Auto-Sync

bd automatically syncs with git:

- Exports to `.beads/issues.jsonl` after changes (5s debounce)
- Imports from JSONL when newer (e.g., after `git pull`)
- No manual export/import needed!

### Important Rules

- ✅ Use bd for ALL task tracking
- ✅ Always use `--json` flag for programmatic use
- ✅ Link discovered work with `discovered-from` dependencies
- ✅ Check `bd ready` before asking "what should I work on?"
- ❌ Do NOT create markdown TODO lists
- ❌ Do NOT use external issue trackers
- ❌ Do NOT duplicate tracking systems

For more details, see README.md and docs/QUICKSTART.md.

<!-- END BEADS INTEGRATION -->

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
