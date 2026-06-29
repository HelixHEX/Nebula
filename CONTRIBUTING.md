# Contributing to Nebula

Nebula is currently pre-alpha. Contributions are welcome, but the public contract is still being shaped and maintainers may change APIs, storage formats, and CLI behavior before a stable release.

## Before You Start

- Open an issue or discussion for large design changes.
- Keep changes narrowly scoped and covered by tests when behavior changes.
- Do not submit secrets, private repository data, generated `target/` output, local `.nebula/` state, or dependency directories.

## Development Setup

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For production-path validation:

```bash
NEBULA_TEST_PROFILE=fast ./tests/production/validate-production.sh
```

Full production validation may require Postgres, object storage, and k6. See `docs/production-sprint-runbook.md`.

## Pull Request Expectations

- Explain the user-facing behavior change.
- Include tests or explain why the change is docs/config only.
- Update relevant docs when changing CLI commands, environment variables, registry routes, or operational behavior.
- Keep placeholder or experimental behavior clearly labeled as pre-alpha.

## Code Style

- Prefer simple, explicit Rust over clever abstractions.
- Keep security-sensitive logic fail-closed.
- Avoid broad authorization shortcuts; route and token behavior should be specific and testable.
- Split large modules when a change makes ownership or review harder.
