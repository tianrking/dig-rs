//! dig-core: Core DNS query library for dig-rs
//!
//! This library provides DNS query capabilities with:
//! - Full DNS record type support
//! - TCP and UDP transport
//! - DNSSEC validation support
//! - EDNS(0) support
//! - Structured error handling
//! - Cross-platform support (Windows, Linux, macOS)

pub mod config;
pub mod error;
pub mod lookup;
pub mod record;
pub mod resolver;
pub mod trace;

pub use config::DigConfig;
pub use error::{DigError, Result};
pub use lookup::{DigLookup, LookupResult};
pub use record::RecordType;
pub use resolver::DigResolver;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
