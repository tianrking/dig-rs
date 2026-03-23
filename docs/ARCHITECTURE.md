# dig-rs Architecture

This document describes the current architecture and the practical roadmap for making `dig-rs` a cross-platform, automation-native DNS tool.

## Goals

- Match and exceed classic `dig` for daily debugging workflows.
- Keep Linux, macOS, and Windows behavior consistent.
- Provide stable command contracts for scripts and AI agents.
- Preserve compatibility with legacy dig-like invocation habits.

## Workspace Structure

- `crates/dig`
  - CLI entrypoint and command orchestration.
  - Supports both subcommand mode and legacy positional mode.
- `crates/dig-core`
  - Query execution, resolver handling, diagnostics, metrics, trace logic, batch processor.
- `crates/dig-output`
  - Formatters for standard dig-like, JSON, short, and table outputs.

## Command Architecture

`dig-rs` now exposes explicit subcommands:

- `query`
- `health`
- `compare`
- `trace`
- `batch`

And still supports legacy usage:

- `dig-rs [@SERVER] NAME [TYPE] [OPTIONS]`
- `dig-rs --health ...`
- `dig-rs --compare ...`
- `dig-rs --file ...`

This dual-mode architecture gives users migration safety while giving automation systems deterministic command shapes.

## Runtime Flow

1. CLI parses arguments and mode.
2. Arguments are normalized into `DigConfig` where applicable.
3. Execution is delegated to `dig-core`:
   - `lookup` for query,
   - `diagnostic` for health/compare,
   - `trace` for delegation path,
   - `batch` for file workloads.
4. Results are rendered via `dig-output` or mode-specific reports.

## Cross-Platform Design Notes

- Resolver discovery:
  - Unix reads `/etc/resolv.conf`.
  - Windows uses PowerShell DNS APIs, with robust `ipconfig /all` fallback parsing.
- CI baseline:
  - stable Rust on `ubuntu-latest`, `macos-latest`, `windows-latest`.
  - required checks: `fmt`, `clippy -D warnings`, `test`, `release build`.
- Output choices avoid platform-specific assumptions in core paths.

## Agent-Oriented Design Notes

- Subcommands provide strict intent boundaries (query vs health vs compare).
- `--json` is available for machine consumption.
- Resolver aliases (`system`, `google`, `cloudflare`, `opendns`, `quad9`) reduce hardcoded resolver management in automation.
- `compare/trace --json` now use a versioned envelope with `schema_version`.
- `--output-file` supports artifact-first workflows in CI and agent pipelines.
- `compare --allow-inconsistent` supports soft-fail automation paths.
- Legacy mode remains for compatibility, but subcommand mode is preferred for tool-calling reliability.

## Current Tradeoffs

- Some modes still use direct structured payloads (without envelope) while compare/trace use schema envelopes.
- Integration tests still depend partly on external DNS reachability.

## Next Priorities

- Add resolver profile option (`--resolver`) with presets and policy bundles.
- Unify JSON contract shape across all modes while maintaining backward compatibility.
- Expand cross-platform integration tests with deterministic fixtures where possible.
- Add richer policy controls for automation (strict/soft fail at mode granularity).
