# dig-rs

[![CI](https://github.com/dig-rs/dig-rs/workflows/CI/badge.svg)](https://github.com/dig-rs/dig-rs/actions)
[![Crates.io](https://img.shields.io/crates/v/dig-rs)](https://crates.io/crates/dig-rs)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Security Audit](https://github.com/dig-rs/dig-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/dig-rs/dig-rs/actions)

**dig-rs** is a modern, cross-platform DNS lookup utility written in Rust. It reimagines the classic BIND9 `dig` tool with a focus on performance, security, and user experience.

## Features

- **Comprehensive DNS Support**: All major DNS record types including DNSSEC
- **Multiple Transports**: UDP, TCP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH)
- **Modern Output Formats**: Classic dig, JSON, YAML, Table, Short, and more
- **Cross-Platform**: Native support for Linux, macOS, and Windows
- **High Performance**: Built on Tokio async runtime for optimal performance
- **DNSSEC**: Full DNSSEC validation and support
- **Batch Processing**: Process multiple queries from a file
- **Flexible Configuration**: Extensive CLI options matching BIND9 dig

## Installation

### Cargo

```bash
cargo install dig-rs
```

### Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/dig-rs/dig-rs/releases).

### Homebrew (macOS/Linux)

```bash
brew install dig-rs
```

### From Source

```bash
git clone https://github.com/dig-rs/dig-rs.git
cd dig-rs
cargo install --path .
```

## Quick Start

### Basic Usage

```bash
# Simple A record lookup
dig example.com

# Lookup specific record type
dig example.com MX

# Query a specific DNS server
dig @8.8.8.8 example.com

# Reverse DNS lookup
dig -x 8.8.8.8

# DNS trace from root servers
dig +trace example.com

# Short output
dig example.com +short

# JSON output
dig example.com +json
```

### Advanced Usage

```bash
# DNS-over-TLS
dig @1.1.1.1 example.com +tls

# DNS-over-HTTPS
dig @1.1.1.1 example.com +https

# DNSSEC validation
dig example.com +dnssec

# Batch mode
dig -f queries.txt

# EDNS options
dig example.com +edns=0 +bufsize=4096

# TSIG authentication
dig -k tsig.key example.com AXFR
```

## Output Formats

dig-rs supports multiple output formats:

| Format | Flag | Description |
|--------|------|-------------|
| Classic dig | `+dig` | BIND9 compatible output (default) |
| JSON | `+json` | Machine-readable JSON |
| YAML | `+yaml` | Human-readable YAML |
| Table | `+table` | Formatted table view |
| Short | `+short` | Only the answer data |
| XML | `+xml` | XML format |

## CLI Options

### Basic Options

| Option | Description |
|--------|-------------|
| `-4` / `-6` | Force IPv4/IPv6 transport |
| `-b address` | Bind to source address |
| `-c class` | Set query class (IN, CH, HS) |
| `-f file` | Read queries from file |
| `-p port` | Set port number |
| `-q name` | Specify query name |
| `-t type` | Specify query type |
| `-x addr` | Reverse lookup |
| `-k file` | TSIG key file |

### Query Flags

| Flag | Description |
|------|-------------|
| `+tcp` / `+notcp` | Use TCP instead of UDP |
| `+tls` / `+notls` | Use DNS-over-TLS |
| `+https` / `+nohttps` | Use DNS-over-HTTPS |
| `+short` / `+noshort` | Short output format |
| `+json` / `+nojson` | JSON output format |
| `+yaml` / `+noyaml` | YAML output format |
| `+trace` / `+notrace` | Trace delegation path |
| `+dnssec` / `+nodnssec` | Enable DNSSEC |
| `+recurse` / `+norecurse` | Set recursion desired flag |
| `+adflag` / `+noadflag` | Set authentic data flag |
| `+cdflag` / `+nocdflag` | Set checking disabled flag |

### Display Options

| Flag | Description |
|------|-------------|
| `+comments` / `+nocomments` | Display comments |
| `+question` / `+noquestion` | Show question section |
| `+answer` / `+noanswer` | Show answer section |
| `+authority` / `+noauthority` | Show authority section |
| `+additional` / `+noadditional` | Show additional section |
| `+stats` / `+nostats` | Display statistics |
| `+ttlid` / `+nottlid` | Display TTL |
| `+class` / `+noclass` | Display class |

### EDNS Options

| Flag | Description |
|------|-------------|
| `+edns[=#]` | Set EDNS version |
| `+noedns` | Disable EDNS |
| `+bufsize=B` | Set UDP buffer size |
| `+nsid` / `+nonsid` | Request name server ID |
| `+cookie[=#]` | Send DNS COOKIE |

### Timing and Retry Options

| Flag | Description |
|------|-------------|
| `+timeout=T` | Set query timeout (seconds) |
| `+retry=T` | Set retry count |
| `+tries=T` | Set total tries |

## Record Types Supported

dig-rs supports all major DNS record types:

- **Standard**: A, AAAA, NS, CNAME, SOA, MX, TXT, PTR, SRV
- **DNSSEC**: DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM
- **Security**: TLSA, CAA, SSHFP, IPSECKEY
- **Modern**: SVCB, HTTPS, OPENPGPKEY
- **Zone Transfer**: AXFR, IXFR
- **And 60+ more types**

## Architecture

dig-rs is organized as a workspace with three crates:

```
dig-rs/
├── dig/           # CLI binary
├── dig-core/      # Core DNS library
└── dig-output/    # Output formatting
```

### dig-core

The core DNS library providing:
- DNS protocol implementation
- Query execution
- Record type definitions
- Transport layer abstraction
- Configuration management

### dig-output

Output formatting library with:
- Multiple format implementations
- Formatter trait for extensibility
- Colorized terminal output
- Machine-readable formats

## Development

### Building

```bash
cargo build --release
```

### Testing

```bash
# Run all tests
cargo test

# Run with coverage
cargo tarpaulin --all-features

# Run benchmarks
cargo bench
```

### Linting

```bash
# Format code
cargo fmt

# Run clippy
cargo clippy --all-targets --all-features
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/your-username/dig-rs.git
cd dig-rs

# Install development dependencies
cargo install cargo-watch cargo-tarpaulin cargo-audit

# Run development server with hot reload
cargo watch -x test
```

## Security

Please report security vulnerabilities responsibly. See [SECURITY.md](SECURITY.md) for details.

## Performance

dig-rs is optimized for performance:

- Async I/O with Tokio
- Zero-copy parsing where possible
- Efficient memory usage
- Parallel query execution for batch mode

Benchmarks show dig-rs is competitive with BIND9 dig while providing better cross-platform support.

## Comparison with BIND9 dig

| Feature | dig-rs | BIND9 dig |
|---------|--------|-----------|
| Cross-platform | ✅ Native | ✅ Native |
| Modern output formats | ✅ JSON/YAML | ❌ |
| Memory safety | ✅ Rust guarantees | ❌ C |
| Async I/O | ✅ Tokio | ❌ |
| Easy installation | ✅ One command | ❌ Complex |
| Active development | ✅ | ⚠️ Slow |

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

## Acknowledgments

- Built on [hickory-dns](https://github.com/hickory-dns/hickory-dns)
- Inspired by [BIND9](https://www.isc.org/bind/)

## Contact

- **Author**: tianrking <tian.r.king@gmail.com>
- **Issues**: [GitHub Issues](https://github.com/dig-rs/dig-rs/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dig-rs/dig-rs/discussions)
