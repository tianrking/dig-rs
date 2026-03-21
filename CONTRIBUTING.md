# Contributing to dig-rs

Thank you for your interest in contributing to dig-rs! We welcome contributions from the community.

## Getting Started

### Prerequisites

- Rust 1.75 or later
- Git
- A code editor (VS Code, IntelliJ IDEA, etc.)

### Setting Up Your Development Environment

1. **Fork the repository**
   ```bash
   # Fork the repository on GitHub
   # Then clone your fork
   git clone https://github.com/your-username/dig-rs.git
   cd dig-rs
   ```

2. **Install development dependencies**
   ```bash
   cargo install cargo-watch cargo-tarpaulin cargo-audit
   ```

3. **Build the project**
   ```bash
   cargo build --release
   ```

4. **Run tests**
   ```bash
   cargo test --all-features
   ```

## Development Workflow

### Making Changes

1. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clear, concise code
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**
   ```bash
   # Run all tests
   cargo test --all-features

   # Run with coverage
   cargo tarpaulin --all-features

   # Run benchmarks
   cargo bench

   # Check formatting
   cargo fmt --all -- --check

   # Run linter
   cargo clippy --all-targets --all-features -- -D warnings
   ```

4. **Run development server with hot reload**
   ```bash
   cargo watch -x test
   ```

### Code Style

We follow standard Rust conventions:

- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Follow the Rust API guidelines
- Write documentation for public APIs
- Include examples in documentation

### Commit Messages

Follow these guidelines for commit messages:

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor" not "Moves cursor")
- Limit to 72 characters for the first line
- Reference issues and pull requests liberally

Example:
```
Add support for DNS-over-QUIC transport

Implement DoQ as specified in RFC 9250.
This provides better performance than DoT/DoH.

Closes #123
```

### Pull Requests

1. **Update your branch**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Create a Pull Request**
   - Provide a clear description of the changes
   - Reference related issues
   - Ensure CI checks pass
   - Request review from maintainers

### PR Review Process

- All PRs must be reviewed by at least one maintainer
- Address review comments promptly
- Keep the PR focused and atomic
- Squash commits if needed before merging

## Project Structure

```
dig-rs/
├── crates/
│   ├── dig/           # CLI binary
│   ├── dig-core/      # Core DNS library
│   └── dig-output/    # Output formatting
├── tests/             # Integration tests
├── benches/           # Benchmarks
├── docs/              # Additional documentation
└── examples/          # Example code
```

## Testing

### Writing Tests

- Unit tests go in the same module as the code
- Integration tests go in `tests/`
- Use descriptive test names
- Test both success and failure cases

```rust
#[test]
fn test_feature_x_returns_valid_result() {
    let result = feature_x();
    assert!(result.is_valid());
}
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_feature_x

# Run tests with output
cargo test -- --nocapture

# Run tests in release mode
cargo test --release
```

## Documentation

### Code Documentation

```rust
/// Performs a DNS lookup for the given domain.
///
/// # Arguments
///
/// * `domain` - The domain name to lookup
/// * `record_type` - The DNS record type to query
///
/// # Returns
///
/// A `Result` containing the lookup result or an error.
///
/// # Examples
///
/// ```
/// use dig_core::DigLookup;
///
/// let result = DigLookup::lookup("example.com", "A").await?;
/// ```
pub async fn lookup(domain: &str, record_type: &str) -> Result<LookupResult> {
    // ...
}
```

### Documentation Updates

- Update README.md for user-facing changes
- Update CHANGELOG.md for version changes
- Add inline documentation for API changes

## Release Process

Releases are handled by maintainers:

1. Update version in Cargo.toml
2. Update CHANGELOG.md
3. Create a git tag
4. Push to crates.io
5. Create GitHub release

## Community Guidelines

### Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Assume good intentions

### Getting Help

- GitHub Issues: For bug reports and feature requests
- GitHub Discussions: For questions and ideas
- Email: tian.r.king@gmail.com (for sensitive matters)

## Recognition

Contributors will be:
- Listed in the CONTRIBUTORS file
- Credited in release notes
- Mentioned in related issues/PRs (with permission)

## License

By contributing, you agree that your contributions will be licensed under the MIT OR Apache-2.0 license.

Thank you for contributing to dig-rs!
