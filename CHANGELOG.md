# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of dig-rs
- Comprehensive DNS query support for all major record types
- Multiple transport protocols: UDP, TCP, DNS-over-TLS, DNS-over-HTTPS
- Multiple output formats: Classic dig, JSON, YAML, Table, Short
- Cross-platform support for Linux, macOS, and Windows
- DNSSEC validation and support
- EDNS(0) support with configurable options
- DNS trace mode from root servers
- Reverse DNS lookups
- Batch processing mode
- TSIG authentication framework
- Comprehensive CI/CD pipeline
- Security auditing with cargo-audit and cargo-deny
- Code coverage reporting

### Changed
- N/A (initial release)

### Deprecated
- N/A

### Removed
- N/A

### Fixed
- N/A

### Security
- Initial security review completed

## [0.1.0] - 2025-03-21

### Added
- Initial commit
- Project scaffolding with workspace structure
- Core DNS library implementation
- Output formatting library
- CLI binary with clap argument parsing
- Basic DNS query functionality
- Cross-platform DNS resolver detection

[Unreleased]: https://github.com/dig-rs/dig-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dig-rs/dig-rs/releases/tag/v0.1.0
