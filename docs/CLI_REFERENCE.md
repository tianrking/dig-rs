# CLI Reference

This reference documents all currently supported user-facing CLI behaviors.

## Invocation Styles

## Subcommand style (recommended)

```bash
dig-rs <subcommand> [options]
```

Subcommands:
- `query`
- `health`
- `compare`
- `trace`
- `batch`

## Legacy compatible style

```bash
dig-rs [@SERVER] NAME [TYPE] [OPTIONS]
dig-rs --health ...
dig-rs --compare ...
dig-rs --file ...
```

## Global Options

- `-v, --verbose`
- `-d, --debug`

## Common Query-like Options

Used by `query`, `trace`, `batch`, and legacy query flows:

- `-J, --json`
- `-c, --class <CLASS>` (default: `IN`)
- `-p, --port <PORT>` (default: `53`)
- `-x, --reverse <IP>`
- `-4, --ipv4`
- `-6, --ipv6`
- `--tcp`
- `--dot`
- `--doh`
- `--short`
- `--table`
- `--no-comments`
- `--no-stats`
- `--trace`
- `--dnssec`
- `--norecurse`
- `--timeout <SECONDS>` (default: `5`)
- `--retries <COUNT>` (default: `3`)
- `--output-file <FILE>`

## `query`

```bash
dig-rs query [@SERVER] NAME [TYPE] [OPTIONS]
```

Examples:

```bash
dig-rs query example.com
dig-rs query @1.1.1.1 example.com AAAA --json
dig-rs query example.com MX --short
```

## `health`

```bash
dig-rs health NAME [--json] [--output-file FILE]
```

Examples:

```bash
dig-rs health example.com
dig-rs health example.com --json --output-file health.json
```

## `compare`

```bash
dig-rs compare NAME [TYPE] --resolvers RESOLVER... [--json] [--allow-inconsistent] [--output-file FILE]
```

Options:
- `--resolvers <RESOLVERS>...` (required)
- `-J, --json`
- `--allow-inconsistent`
- `--output-file <FILE>`

Resolver aliases:
- `system`
- `google`
- `cloudflare`
- `opendns`
- `quad9`

Behavior notes:
- Default behavior: inconsistency returns non-zero exit code.
- With `--allow-inconsistent`: still outputs result, returns exit code `0`.
- If all resolvers fail, compare is treated as failed/inconsistent.

## `trace`

```bash
dig-rs trace [@SERVER] NAME [TYPE] [OPTIONS]
```

Behavior notes:
- Text report by default.
- `--json` emits versioned machine envelope.
- `--output-file` stores output artifact for pipelines.

## `batch`

```bash
dig-rs batch --file FILE [OPTIONS]
```

Options:
- `-f, --file <FILE>` (required)
- Optional query-like flags for output and transport defaults.

## Legacy Flags (Root Command)

- `--health`
- `--compare <RESOLVERS>...`
- `--allow-inconsistent` (legacy compare only)
- `-f, --file <FILE>`

These map to subcommand behavior and remain for migration compatibility.
