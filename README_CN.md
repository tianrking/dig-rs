# dig-rs

[![CI](https://github.com/dig-rs/dig-rs/workflows/CI/badge.svg)](https://github.com/dig-rs/dig-rs/actions)
[![Crates.io](https://img.shields.io/crates/v/dig-rs)](https://crates.io/crates/dig-rs)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Security Audit](https://github.com/dig-rs/dig-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/dig-rs/dig-rs/actions)

**dig-rs** 是一个用 Rust 编写的现代化、跨平台 DNS 查询工具。它重新构想了经典的 BIND9 `dig` 工具，专注于性能、安全性和用户体验。

## 特性

- **全面的 DNS 支持**：包括 DNSSEC 在内的所有主要 DNS 记录类型
- **多种传输协议**：UDP、TCP、DNS-over-TLS (DoT)、DNS-over-HTTPS (DoH)
- **现代输出格式**：经典 dig、JSON、YAML、表格、简洁输出等
- **跨平台**：原生支持 Linux、macOS 和 Windows
- **高性能**：基于 Tokio 异步运行时，实现最优性能
- **DNSSEC**：完整的 DNSSEC 验证和支持
- **批处理**：从文件处理多个查询
- **灵活配置**：与 BIND9 dig 匹配的丰富 CLI 选项

## 安装

### Cargo

```bash
cargo install dig-rs
```

### 预编译二进制文件

从 [GitHub Releases](https://github.com/dig-rs/dig-rs/releases) 下载最新版本。

### Homebrew (macOS/Linux)

```bash
brew install dig-rs
```

### 从源码编译

```bash
git clone https://github.com/dig-rs/dig-rs.git
cd dig-rs
cargo install --path .
```

## 快速开始

### 基本用法

```bash
# 简单的 A 记录查询
dig example.com

# 查询特定记录类型
dig example.com MX

# 查询特定 DNS 服务器
dig @8.8.8.8 example.com

# 反向 DNS 查询
dig -x 8.8.8.8

# 从根服务器追踪
dig +trace example.com

# 简洁输出
dig example.com +short

# JSON 输出
dig example.com +json
```

### 高级用法

```bash
# DNS-over-TLS
dig @1.1.1.1 example.com +tls

# DNS-over-HTTPS
dig @1.1.1.1 example.com +https

# DNSSEC 验证
dig example.com +dnssec

# 批处理模式
dig -f queries.txt

# EDNS 选项
dig example.com +edns=0 +bufsize=4096

# TSIG 认证
dig -k tsig.key example.com AXFR
```

## 输出格式

dig-rs 支持多种输出格式：

| 格式 | 标志 | 描述 |
|------|------|------|
| 经典 dig | `+dig` | BIND9 兼容输出（默认） |
| JSON | `+json` | 机器可读的 JSON |
| YAML | `+yaml` | 人类可读的 YAML |
| 表格 | `+table` | 格式化的表格视图 |
| 简洁 | `+short` | 仅回答数据 |
| XML | `+xml` | XML 格式 |

## CLI 选项

### 基本选项

| 选项 | 描述 |
|------|------|
| `-4` / `-6` | 强制 IPv4/IPv6 传输 |
| `-b address` | 绑定源地址 |
| `-c class` | 设置查询类（IN、CH、HS） |
| `-f file` | 从文件读取查询 |
| `-p port` | 设置端口号 |
| `-q name` | 指定查询名称 |
| `-t type` | 指定查询类型 |
| `-x addr` | 反向查询 |
| `-k file` | TSIG 密钥文件 |

### 查询标志

| 标志 | 描述 |
|------|------|
| `+tcp` / `+notcp` | 使用 TCP 代替 UDP |
| `+tls` / `+notls` | 使用 DNS-over-TLS |
| `+https` / `+nohttps` | 使用 DNS-over-HTTPS |
| `+short` / `+noshort` | 简洁输出格式 |
| `+json` / `+nojson` | JSON 输出格式 |
| `+yaml` / `+noyaml` | YAML 输出格式 |
| `+trace` / `+notrace` | 追踪授权路径 |
| `+dnssec` / `+nodnssec` | 启用 DNSSEC |
| `+recurse` / `+norecurse` | 设置递归期望标志 |
| `+adflag` / `+noadflag` | 设置认证数据标志 |
| `+cdflag` / `+nocdflag` | 设置检查禁用标志 |

### 显示选项

| 标志 | 描述 |
|------|------|
| `+comments` / `+nocomments` | 显示注释 |
| `+question` / `+noquestion` | 显示问题部分 |
| `+answer` / `+noanswer` | 显示回答部分 |
| `+authority` / `+noauthority` | 显示授权部分 |
| `+additional` / `+noadditional` | 显示附加部分 |
| `+stats` / `+nostats` | 显示统计信息 |
| `+ttlid` / `+nottlid` | 显示 TTL |
| `+class` / `+noclass` | 显示类 |

### EDNS 选项

| 标志 | 描述 |
|------|------|
| `+edns[=#]` | 设置 EDNS 版本 |
| `+noedns` | 禁用 EDNS |
| `+bufsize=B` | 设置 UDP 缓冲区大小 |
| `+nsid` / `+nonsid` | 请求名称服务器 ID |
| `+cookie[=#]` | 发送 DNS COOKIE |

### 时间和重试选项

| 标志 | 描述 |
|------|------|
| `+timeout=T` | 设置查询超时（秒） |
| `+retry=T` | 设置重试次数 |
| `+tries=T` | 设置总尝试次数 |

## 支持的记录类型

dig-rs 支持所有主要的 DNS 记录类型：

- **标准类型**：A、AAAA、NS、CNAME、SOA、MX、TXT、PTR、SRV
- **DNSSEC 类型**：DNSKEY、DS、RRSIG、NSEC、NSEC3、NSEC3PARAM
- **安全类型**：TLSA、CAA、SSHFP、IPSECKEY
- **现代类型**：SVCB、HTTPS、OPENPGPKEY
- **区域传输**：AXFR、IXFR
- **以及 60+ 更多类型**

## 架构

dig-rs 组织为一个包含三个 crate 的工作空间：

```
dig-rs/
├── dig/           # CLI 二进制文件
├── dig-core/      # 核心 DNS 库
└── dig-output/    # 输出格式化
```

### dig-core

核心 DNS 库提供：
- DNS 协议实现
- 查询执行
- 记录类型定义
- 传输层抽象
- 配置管理

### dig-output

输出格式化库包含：
- 多种格式实现
- 用于扩展的格式化器 trait
- 彩色终端输出
- 机器可读格式

## 开发

### 构建

```bash
cargo build --release
```

### 测试

```bash
# 运行所有测试
cargo test

# 运行覆盖率测试
cargo tarpaulin --all-features

# 运行基准测试
cargo bench
```

### 代码检查

```bash
# 格式化代码
cargo fmt

# 运行 clippy
cargo clippy --all-targets --all-features
```

## 贡献

我们欢迎贡献！详情请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

### 开发设置

```bash
# Fork 并克隆仓库
git clone https://github.com/your-username/dig-rs.git
cd dig-rs

# 安装开发依赖
cargo install cargo-watch cargo-tarpaulin cargo-audit

# 运行带热重载的开发服务器
cargo watch -x test
```

## 安全

请负责任地报告安全漏洞。详情请参阅 [SECURITY.md](SECURITY.md)。

## 性能

dig-rs 经过了性能优化：

- 使用 Tokio 的异步 I/O
- 尽可能零拷贝解析
- 高效的内存使用
- 批处理模式的并行查询执行

基准测试显示，dig-rs 在提供更好的跨平台支持的同时，性能与 BIND9 dig 相当。

## 与 BIND9 dig 的比较

| 特性 | dig-rs | BIND9 dig |
|------|--------|-----------|
| 跨平台 | ✅ 原生支持 | ✅ 原生支持 |
| 现代输出格式 | ✅ JSON/YAML | ❌ |
| 内存安全 | ✅ Rust 保证 | ❌ C |
| 异步 I/O | ✅ Tokio | ❌ |
| 易于安装 | ✅ 一条命令 | ❌ 复杂 |
| 活跃开发 | ✅ | ⚠️ 缓慢 |

## 许可证

您可以选择以下任一许可证：

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) 或 http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) 或 http://opensource.org/licenses/MIT)

## 致谢

- 基于 [hickory-dns](https://github.com/hickory-dns/hickory-dns) 构建
- 灵感来自 [BIND9](https://www.isc.org/bind/)

## 联系方式

- **作者**：tianrking <tian.r.king@gmail.com>
- **问题反馈**：[GitHub Issues](https://github.com/dig-rs/dig-rs/issues)
- **讨论**：[GitHub Discussions](https://github.com/dig-rs/dig-rs/discussions)
