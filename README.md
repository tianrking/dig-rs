# dig-rs

`dig-rs` is a modern, cross-platform DNS inspection tool written in Rust.

It is designed for both:
- interactive terminal usage (human-friendly),
- and agent/automation workflows (machine-friendly).

## Why dig-rs

- Cross-platform first: Linux, macOS, Windows parity.
- Safer implementation: Rust memory safety.
- Structured output: JSON-first automation support.
- Multi-mode diagnostics: query, health, compare, trace, batch.
- Versioned machine envelope for compare/trace JSON (`schema_version`).
- Backward compatibility: supports legacy dig-style positional usage.

## Installation

```bash
cargo install dig-rs
```

Or download binaries from GitHub Releases.

## Command Model

`dig-rs` supports two invocation styles.

### 1) Subcommand style (recommended)

```bash
dig-rs query @8.8.8.8 example.com A --json
dig-rs health example.com --json
dig-rs compare example.com A --resolvers system google cloudflare
dig-rs compare example.com A --resolvers google cloudflare --json --allow-inconsistent
dig-rs trace example.com
dig-rs trace example.com --json --output-file trace.json
dig-rs batch --file queries.txt
```

### 2) Legacy compatible style

```bash
dig-rs @8.8.8.8 example.com A --short
dig-rs example.com --health
dig-rs example.com --compare system google cloudflare
dig-rs example.com --trace --json
dig-rs --file queries.txt
```

## Subcommands

### `query`

Run standard DNS query.

```bash
dig-rs query [@SERVER] NAME [TYPE] [OPTIONS]
```

Examples:

```bash
dig-rs query example.com
dig-rs query @1.1.1.1 example.com AAAA
dig-rs query example.com MX --short
dig-rs query example.com A --json
```

### `health`

Run DNS health diagnostics.

```bash
dig-rs health NAME [--json]
```

Examples:

```bash
dig-rs health example.com
dig-rs health example.com --json
```

### `compare`

Compare consistency and latency across resolvers.

```bash
dig-rs compare NAME [TYPE] --resolvers RESOLVER...
```

Resolver aliases:
- `system` (current OS resolver),
- `google` (`8.8.8.8`),
- `cloudflare` (`1.1.1.1`),
- `opendns` (`208.67.222.222`),
- `quad9` (`9.9.9.9`).

Examples:

```bash
dig-rs compare example.com A --resolvers system google cloudflare
dig-rs compare example.com AAAA --resolvers 8.8.8.8 1.1.1.1 9.9.9.9
dig-rs compare example.com A --resolvers google cloudflare --json --allow-inconsistent
```

### `trace`

Trace DNS delegation from root to final answer.

```bash
dig-rs trace [@SERVER] NAME [TYPE] [OPTIONS]
```

Examples:

```bash
dig-rs trace example.com
dig-rs trace @8.8.8.8 example.com A
dig-rs trace example.com --json --output-file trace.json
```

### `batch`

Run queries from file.

```bash
dig-rs batch --file FILE [OPTIONS]
```

Example:

```bash
dig-rs batch --file queries.txt --json
```

## Common Options

Most query-like modes support:

- `-J, --json` structured output.
- `--short` short output.
- `--table` table output.
- `-c, --class IN|CH|HS`.
- `-p, --port PORT`.
- `-x, --reverse IP`.
- `-4, --ipv4` / `-6, --ipv6`.
- `--tcp` / `--dot` / `--doh`.
- `--dnssec`.
- `--norecurse`.
- `--timeout SECONDS`.
- `--retries COUNT`.
- `--output-file FILE` write output to file (while still printing stdout).
- `--no-comments`.
- `--no-stats`.
- `-v, --verbose`.
- `-d, --debug`.

Compare-specific:
- `--allow-inconsistent` keeps exit code `0` even if compare finds resolver inconsistency.

## JSON Contracts

`compare --json` and `trace --json` output a versioned envelope:

```json
{
  "schema_version": "dig-rs/v1",
  "mode": "compare or trace",
  "generated_at_unix_ms": 1774233148357,
  "data": { "...mode specific payload..." }
}
```

This is designed for long-term agent compatibility and explicit schema evolution.

## AI/Agent-Friendly Usage

`dig-rs` is intentionally designed for LLM/agent pipelines:

- Prefer deterministic command shapes (`query`, `health`, `compare`, `trace`, `batch`).
- Prefer `--json` for machine parsing and downstream automation.
- Use resolver aliases in scripts (`system`, `google`, `cloudflare`, etc.).
- Keep output mode explicit in prompts or tools.
- Persist artifacts with `--output-file`.
- Use `--allow-inconsistent` when you want compare output but do not want hard-fail behavior.

Recommended patterns:

```bash
# Parse-ready query
dig-rs query example.com A --json

# Programmatic health check
dig-rs health example.com --json

# Consistency verification before production rollout
dig-rs compare api.example.com A --resolvers system google cloudflare

# Artifact-friendly compare output
dig-rs compare api.example.com A --resolvers system google cloudflare --json --allow-inconsistent --output-file compare.json
```

## Architecture

See:
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/AGENT_GUIDE.md](docs/AGENT_GUIDE.md)
- [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)
- [docs/JSON_SCHEMA.md](docs/JSON_SCHEMA.md)

Workspace crates:

```text
dig-rs/
|- crates/dig         # CLI
|- crates/dig-core    # DNS logic
`- crates/dig-output  # formatters
```

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

## License

Dual-licensed:
- MIT
- Apache-2.0
