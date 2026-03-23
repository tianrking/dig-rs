# dig-rs（中文）

`dig-rs` 是一个现代化、跨平台、面向自动化与 AI Agent 的 DNS 工具。

## 项目定位

- 跨平台一致：Windows / Linux / macOS。
- 人机双友好：终端可读 + 结构化 JSON 可解析。
- 模式完整：`query`、`health`、`compare`、`trace`、`batch`。
- 兼容旧习惯：保留 `dig` 风格位置参数调用。
- Agent 契约：`compare/trace --json` 带 `schema_version`。

## 安装

```bash
cargo install dig-rs
```

## 命令模型

### 推荐：子命令模式

```bash
dig-rs query @8.8.8.8 example.com A --json
dig-rs health example.com --json
dig-rs compare example.com A --resolvers system google cloudflare --json
dig-rs trace example.com --json --output-file trace.json
dig-rs batch --file queries.txt
```

### 兼容：传统 dig 风格

```bash
dig-rs @8.8.8.8 example.com A --short
dig-rs example.com --health --json
dig-rs example.com --compare system google cloudflare --json --allow-inconsistent
dig-rs example.com --trace --json
dig-rs --file queries.txt
```

## 子命令说明

### `query`

标准 DNS 查询。

```bash
dig-rs query [@SERVER] NAME [TYPE] [OPTIONS]
```

### `health`

DNS 健康诊断。

```bash
dig-rs health NAME [--json] [--output-file FILE]
```

### `compare`

多解析器对比（结果一致性 + 延迟）。

```bash
dig-rs compare NAME [TYPE] --resolvers RESOLVER... [--json] [--allow-inconsistent] [--output-file FILE]
```

解析器别名：
- `system`
- `google`（8.8.8.8）
- `cloudflare`（1.1.1.1）
- `opendns`（208.67.222.222）
- `quad9`（9.9.9.9）

实用增强：
- `--allow-inconsistent`：不一致时仍返回 0（便于流水线继续处理结果）。
- 现在“全部 resolver 都失败”会判定为不一致/失败，不再误判为一致。

### `trace`

从根开始追踪 DNS 委派路径。

```bash
dig-rs trace [@SERVER] NAME [TYPE] [OPTIONS]
```

实用增强：
- `--json`：输出结构化 envelope。
- `--output-file FILE`：结果同时落盘，方便 CI/Agent 存档。

### `batch`

批量查询文件。

```bash
dig-rs batch --file FILE [OPTIONS]
```

## 常用参数

- `-J, --json`
- `--short`
- `--table`
- `-c, --class IN|CH|HS`
- `-p, --port`
- `-x, --reverse`
- `-4 / -6`
- `--tcp / --dot / --doh`
- `--dnssec`
- `--norecurse`
- `--timeout`
- `--retries`
- `--output-file FILE`
- `-v, --verbose`
- `-d, --debug`

## JSON 契约（Agent 关键）

`compare --json` 与 `trace --json` 输出统一 envelope：

```json
{
  "schema_version": "dig-rs/v1",
  "mode": "compare or trace",
  "generated_at_unix_ms": 1774233148357,
  "data": { "...模式具体数据..." }
}
```

这样可以保证 agent 侧长期稳定解析，并支持后续 schema 演进。

## 文档导航

- [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)
- [docs/JSON_SCHEMA.md](docs/JSON_SCHEMA.md)
- [docs/AGENT_GUIDE.md](docs/AGENT_GUIDE.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## 开发命令

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```
