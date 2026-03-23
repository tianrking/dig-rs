# JSON Schema Contract

This document describes the machine-facing JSON contract for `dig-rs`.

## Versioning

- Current schema version: `dig-rs/v1`.
- Version field: `schema_version`.
- Consumers should validate `schema_version` before strict parsing.

## Envelope (compare/trace)

`compare --json` and `trace --json` return:

```json
{
  "schema_version": "dig-rs/v1",
  "mode": "compare or trace",
  "generated_at_unix_ms": 1774233148357,
  "data": {}
}
```

Fields:
- `schema_version`: contract version.
- `mode`: operation mode (`compare` or `trace`).
- `generated_at_unix_ms`: generation timestamp in milliseconds since Unix epoch.
- `data`: mode-specific payload.

## Compare Payload (`mode = compare`)

`data` mirrors `ComparisonResult`:

- `domain`: queried domain.
- `query_type`: DNS record type.
- `resolver_results`: array of per-resolver result objects.
- `consistent`: boolean.
- `inconsistencies`: array.
- `timestamp`: local timestamp string from core diagnostic layer.

Each `resolver_results` item:
- `resolver`
- `success`
- `latency_ms`
- `answers`
- `rcode`
- `error`

## Trace Payload (`mode = trace`)

`data` mirrors `TraceResult`:

- `query_name`
- `query_type`
- `steps`
- `final_answer` (nullable)
- `total_time_ms`

Each trace step:
- `server`
- `query`
- `response`
- `query_time_ms`
- `zone`
- `server_type`

## Other JSON Outputs

- `query --json` and `health --json` currently return structured JSON payloads without the envelope above.
- Automation consumers should parse these by command context.

## Compatibility Guidance

- Pin `dig-rs` versions in production automation.
- Check `schema_version` for compare/trace JSON.
- Preserve unknown fields to stay forward-compatible.
- Prefer subcommand style in all machine integrations.
