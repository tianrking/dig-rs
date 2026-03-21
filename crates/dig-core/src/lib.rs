//! dig-core: Core DNS query library for dig-rs
//!
//! This library provides DNS query capabilities with:
//! - Full DNS record type support
//! - TCP and UDP transport
//! - DNSSEC validation support
//! - EDNS(0) support
//! - Structured error handling
//! - Cross-platform support (Windows, Linux, macOS)

pub mod batch;
pub mod config;
pub mod diagnostic;
pub mod edns;
pub mod error;
pub mod lookup;
pub mod metrics;
pub mod record;
pub mod resolver;
pub mod trace;
pub mod tsig;
pub mod zonetransfer;

pub use batch::{BatchConfig, BatchProcessor, BatchQuery, BatchResult};
pub use config::DigConfig;
pub use diagnostic::{
    compare_resolvers, CheckResult, CheckStatus, ComparisonResult, DnsDiagnostic, HealthCheck,
    HealthStatus, ResolverResult,
};
pub use edns::{CookieOption, EdnsOption, EdnsOptionCode, NsidOption, SubnetOption};
pub use error::{DigError, Result};
pub use lookup::{DigLookup, LookupResult};
pub use metrics::{AggregatedMetrics, MetricsCollector, QueryMetrics, Timing};
pub use record::RecordType;
pub use resolver::DigResolver;
pub use tsig::{TsigAlgorithm, TsigConfig, TsigKey, TsigSigner};
pub use zonetransfer::{ZoneTransfer, ZoneTransferResult, ZoneTransferType};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
