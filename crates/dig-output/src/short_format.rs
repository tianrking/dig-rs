//! Short output format (+short)
//!
//! Only outputs the RDATA portion of answer records

use std::io;

use dig_core::lookup::LookupResult;

use crate::format::{OutputConfig, OutputFormatter};

/// Short formatter - only outputs RDATA
pub struct ShortFormatter {
    _config: OutputConfig,
}

impl ShortFormatter {
    /// Create a new short formatter
    pub fn new(config: OutputConfig) -> Self {
        Self { _config: config }
    }

    /// Create with default short config
    pub fn default() -> Self {
        Self::new(OutputConfig::short())
    }
}

impl OutputFormatter for ShortFormatter {
    fn format(&self, result: &LookupResult) -> io::Result<String> {
        let mut output = String::new();

        for record in &result.message.answer {
            output.push_str(&record.rdata);
            output.push('\n');
        }

        Ok(output)
    }

    fn format_header(&self, _result: &LookupResult) -> io::Result<String> {
        Ok(String::new())
    }

    fn format_question(&self, _result: &LookupResult) -> io::Result<String> {
        Ok(String::new())
    }

    fn format_answer(&self, result: &LookupResult) -> io::Result<String> {
        self.format(result)
    }

    fn format_authority(&self, _result: &LookupResult) -> io::Result<String> {
        Ok(String::new())
    }

    fn format_additional(&self, _result: &LookupResult) -> io::Result<String> {
        Ok(String::new())
    }

    fn format_stats(&self, _result: &LookupResult) -> io::Result<String> {
        Ok(String::new())
    }
}
