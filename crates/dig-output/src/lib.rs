//! Output formatting library for dig-rs
//!
//! Provides multiple output formats:
//! - Standard dig format (BIND9 compatible)
//! - Structured JSON format (modern, machine-readable)
//! - Short format (+short)
//! - Table format
//! - YAML format

pub mod dig_format;
pub mod format;
pub mod json_format;
pub mod short_format;
pub mod structured;
pub mod table_format;

pub use dig_format::DigFormatter;
pub use format::{OutputFormat, OutputFormatter};
pub use json_format::JsonFormatter;
pub use short_format::ShortFormatter;
pub use structured::{
    ComparisonResponse, HealthCheckResponse, RecordsByType, ResponseStatus, StructuredDnsResponse,
    StructuredFormatter,
};
pub use table_format::TableFormatter;

// Re-export dig-core types needed for formatting
pub use dig_core::lookup::{DnsFlags, DnsMessage, DnsQuestion, DnsRecord, LookupResult};
