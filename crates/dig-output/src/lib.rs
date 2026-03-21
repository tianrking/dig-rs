//! Output formatting library for dig-rs
//!
//! Provides multiple output formats:
//! - Standard dig format
//! - JSON format
//! - Short format (+short)
//! - Table format

pub mod format;
pub mod dig_format;
pub mod json_format;
pub mod short_format;
pub mod table_format;

pub use format::{OutputFormat, OutputFormatter};
pub use dig_format::DigFormatter;
pub use json_format::JsonFormatter;
pub use short_format::ShortFormatter;
pub use table_format::TableFormatter;

// Re-export dig-core types needed for formatting
pub use dig_core::lookup::{DnsMessage, DnsRecord, DnsQuestion, DnsFlags, LookupResult};
