# dig-rs Agent Guide

This guide explains how to call `dig-rs` safely and predictably from AI agents, automation runners, or orchestration tools.

Related references:
- `docs/CLI_REFERENCE.md`
- `docs/JSON_SCHEMA.md`

## 1. Prefer Subcommands

Use explicit subcommands instead of legacy positional mode.

Recommended:

```bash
dig-rs query example.com A --json
dig-rs health example.com --json
dig-rs compare example.com A --resolvers system google cloudflare --json
dig-rs trace example.com --json
dig-rs batch --file queries.txt --json
```

Avoid for new integrations:

```bash
dig-rs example.com --health
dig-rs @8.8.8.8 example.com A
```

Legacy mode is supported for compatibility, not as primary contract for agents.

## 2. Use JSON for Parsing

For machine workflows, prefer `--json` wherever available.

- `query --json`: structured record output.
- `health --json`: structured diagnostic object.
- `compare --json`: versioned envelope output.
- `trace --json`: versioned envelope output.

For compare and trace, validate:
- `schema_version`
- `mode`
- `data`

## 3. Resolver Strategy

Use aliases to avoid hardcoding raw IPs in every prompt or pipeline:

- `system`
- `google`
- `cloudflare`
- `opendns`
- `quad9`

Example:

```bash
dig-rs compare api.example.com A --resolvers system google cloudflare
```

## 4. Error Handling Contract

Agents should treat non-zero exit code as failure and inspect stderr.

Typical failure categories:
- argument/validation errors,
- network/transport errors,
- DNS response failures,
- compare inconsistency (unless `--allow-inconsistent` is set).

## 5. Suggested Prompt/Tool Patterns

### Query then evaluate

```bash
dig-rs query example.com A --json
```

Then:
- check `status`,
- verify returned answer set,
- branch to `compare` if mismatch suspected.

### Health-gate deployment

```bash
dig-rs health service.example.com --json
```

Then:
- allow deploy on healthy/warning by policy,
- block on critical/failed statuses.

### Resolve disagreement before change rollout

```bash
dig-rs compare service.example.com A --resolvers system google cloudflare
```

Then:
- if inconsistent, alert and pause rollout.

If you need output for decisioning but not a hard fail in that step:

```bash
dig-rs compare service.example.com A --resolvers system google cloudflare --json --allow-inconsistent --output-file compare.json
```

## 6. CI Integration Recommendations

- Pin execution through subcommands.
- Capture stdout and stderr separately.
- Store JSON outputs as build artifacts.
- Keep a fixed resolver set for reproducibility.
- Run on all three supported OSes if behavior parity matters.
- Prefer `--output-file` for deterministic artifact paths.
- For compare/trace, validate envelope `schema_version`.

## 7. Stability Notes

`dig-rs` aims for stable command behavior across platforms. For agent tooling:
- lock binary version for critical production flows,
- validate command output in tests before upgrading.
