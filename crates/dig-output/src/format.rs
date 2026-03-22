//! Output format traits and types

use std::io;

use dig_core::lookup::LookupResult;

/// Output format enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Standard dig output format
    #[default]
    Standard,
    /// JSON output
    Json,
    /// Short output (just RDATA)
    Short,
    /// Table format
    Table,
    /// YAML output
    Yaml,
    /// XML output
    Xml,
}

/// Trait for output formatters
pub trait OutputFormatter {
    /// Format the complete output
    fn format(&self, result: &LookupResult) -> io::Result<String>;

    /// Format just the header
    fn format_header(&self, result: &LookupResult) -> io::Result<String>;

    /// Format the question section
    fn format_question(&self, result: &LookupResult) -> io::Result<String>;

    /// Format the answer section
    fn format_answer(&self, result: &LookupResult) -> io::Result<String>;

    /// Format the authority section
    fn format_authority(&self, result: &LookupResult) -> io::Result<String>;

    /// Format the additional section
    fn format_additional(&self, result: &LookupResult) -> io::Result<String>;

    /// Format statistics
    fn format_stats(&self, result: &LookupResult) -> io::Result<String>;
}

/// Configuration for output formatting
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// Show comments
    pub comments: bool,
    /// Show question section
    pub question: bool,
    /// Show answer section
    pub answer: bool,
    /// Show authority section
    pub authority: bool,
    /// Show additional section
    pub additional: bool,
    /// Show statistics
    pub stats: bool,
    /// Show TTL in human-readable format
    pub ttl_units: bool,
    /// Use colors
    pub color: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            comments: true,
            question: true,
            answer: true,
            authority: true,
            additional: true,
            stats: true,
            ttl_units: false,
            color: false,
        }
    }
}

impl OutputConfig {
    /// Create config for short output
    pub fn short() -> Self {
        Self {
            comments: false,
            question: false,
            answer: true,
            authority: false,
            additional: false,
            stats: false,
            ttl_units: false,
            color: false,
        }
    }

    /// Create config for JSON output
    pub fn json() -> Self {
        Self {
            comments: false,
            question: true,
            answer: true,
            authority: true,
            additional: true,
            stats: true,
            ttl_units: false,
            color: false,
        }
    }
}

/// Format TTL in human-readable format
pub fn format_ttl(ttl: u32, human_readable: bool) -> String {
    if !human_readable {
        return ttl.to_string();
    }

    if ttl < 60 {
        format!("{}s", ttl)
    } else if ttl < 3600 {
        format!("{}m{}s", ttl / 60, ttl % 60)
    } else if ttl < 86400 {
        format!("{}h{}m", ttl / 3600, (ttl % 3600) / 60)
    } else {
        format!("{}d{}h", ttl / 86400, (ttl % 86400) / 3600)
    }
}

/// Pad a string to a specific width
pub fn pad_right(s: &str, width: usize) -> String {
    if s.len() >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - s.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_ttl() {
        assert_eq!(format_ttl(30, false), "30");
        assert_eq!(format_ttl(30, true), "30s");
        assert_eq!(format_ttl(90, true), "1m30s");
        assert_eq!(format_ttl(3661, true), "1h1m");
        assert_eq!(format_ttl(90061, true), "1d1h");
    }
}
