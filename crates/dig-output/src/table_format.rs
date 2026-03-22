//! Table output format
//!
//! Outputs DNS results in a formatted table

use std::io;

use dig_core::lookup::LookupResult;

use crate::format::{OutputConfig, OutputFormatter};

/// Table formatter
pub struct TableFormatter {
    config: OutputConfig,
}

impl TableFormatter {
    /// Create a new table formatter
    pub fn new(config: OutputConfig) -> Self {
        Self { config }
    }

    /// Create with default config
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self::new(OutputConfig::default())
    }

    /// Create records table
    fn create_records_table(&self, records: &[dig_core::lookup::DnsRecord]) -> String {
        if records.is_empty() {
            return String::new();
        }

        let mut output = String::new();
        for r in records {
            output.push_str(&format!(
                "{:<30} {:>8} {:<4} {:<8} {}\n",
                r.name, r.ttl, r.class, r.rtype, r.rdata
            ));
        }
        output
    }
}

impl OutputFormatter for TableFormatter {
    fn format(&self, result: &LookupResult) -> io::Result<String> {
        let mut output = String::new();

        if self.config.comments {
            output.push_str(&format!(
                "Query: {} {} {}\n\n",
                result.query_name, result.query_type, result.query_class
            ));
        }

        if self.config.question && !result.message.question.is_empty() {
            if self.config.comments {
                output.push_str("Question:\n");
            }
            for q in &result.message.question {
                output.push_str(&format!("  {} {} {}\n", q.name, q.qclass, q.qtype));
            }
            output.push('\n');
        }

        if self.config.answer && !result.message.answer.is_empty() {
            if self.config.comments {
                output.push_str("Answer:\n");
            }
            output.push_str(&self.create_records_table(&result.message.answer));
            output.push('\n');
        }

        if self.config.authority && !result.message.authority.is_empty() {
            if self.config.comments {
                output.push_str("Authority:\n");
            }
            output.push_str(&self.create_records_table(&result.message.authority));
            output.push('\n');
        }

        if self.config.additional && !result.message.additional.is_empty() {
            if self.config.comments {
                output.push_str("Additional:\n");
            }
            output.push_str(&self.create_records_table(&result.message.additional));
            output.push('\n');
        }

        if self.config.stats {
            output.push_str(&format!(
                "\nQuery time: {}ms | Server: {} | Size: {} bytes\n",
                result.query_time_ms, result.server, result.message_size
            ));
        }

        Ok(output)
    }

    fn format_header(&self, result: &LookupResult) -> io::Result<String> {
        Ok(format!(
            "Response: {} (id: {})\nFlags: qr={} aa={} tc={} rd={} ra={} ad={} cd={}",
            result.message.rcode,
            result.message.id,
            result.message.flags.qr,
            result.message.flags.aa,
            result.message.flags.tc,
            result.message.flags.rd,
            result.message.flags.ra,
            result.message.flags.ad,
            result.message.flags.cd,
        ))
    }

    fn format_question(&self, result: &LookupResult) -> io::Result<String> {
        let mut output = String::new();
        for q in &result.message.question {
            output.push_str(&format!("{} {} {}\n", q.name, q.qclass, q.qtype));
        }
        Ok(output)
    }

    fn format_answer(&self, result: &LookupResult) -> io::Result<String> {
        Ok(self.create_records_table(&result.message.answer))
    }

    fn format_authority(&self, result: &LookupResult) -> io::Result<String> {
        Ok(self.create_records_table(&result.message.authority))
    }

    fn format_additional(&self, result: &LookupResult) -> io::Result<String> {
        Ok(self.create_records_table(&result.message.additional))
    }

    fn format_stats(&self, result: &LookupResult) -> io::Result<String> {
        Ok(format!(
            "Query time: {}ms\nServer: {}\nSize: {} bytes\nWhen: {}",
            result.query_time_ms, result.server, result.message_size, result.timestamp
        ))
    }
}
