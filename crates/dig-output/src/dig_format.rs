//! Classic dig output format
//!
//! Mimics the output format of BIND9 dig

use std::io;

use dig_core::lookup::LookupResult;

use crate::format::{OutputConfig, OutputFormatter, format_ttl, pad_right};

/// Classic dig-style formatter
pub struct DigFormatter {
    config: OutputConfig,
}

impl DigFormatter {
    /// Create a new dig formatter
    pub fn new(config: OutputConfig) -> Self {
        Self { config }
    }

    /// Create with default config
    pub fn default() -> Self {
        Self::new(OutputConfig::default())
    }

    /// Format flags
    fn format_flags(&self, flags: &dig_core::lookup::DnsFlags) -> String {
        let mut parts = Vec::new();

        if flags.qr { parts.push("qr"); }
        if flags.aa { parts.push("aa"); }
        if flags.tc { parts.push("tc"); }
        if flags.rd { parts.push("rd"); }
        if flags.ra { parts.push("ra"); }
        if flags.ad { parts.push("ad"); }
        if flags.cd { parts.push("cd"); }

        parts.join(" ")
    }

    /// Format a single record
    fn format_record(&self, record: &dig_core::lookup::DnsRecord) -> String {
        let name = pad_right(&record.name, 30);
        let ttl = format_ttl(record.ttl, self.config.ttl_units);
        let ttl_padded = pad_right(&ttl, 8);
        let class = pad_right(&record.class, 4);
        let rtype = pad_right(&record.rtype, 6);

        format!("{}\t{}\t{}\t{}\t{}", name, ttl_padded, class, rtype, record.rdata)
    }
}

impl OutputFormatter for DigFormatter {
    fn format(&self, result: &LookupResult) -> io::Result<String> {
        let mut output = String::new();

        if self.config.comments {
            output.push_str(&self.format_header(result)?);
        }

        if self.config.question {
            output.push_str(&self.format_question(result)?);
        }

        if self.config.answer && !result.message.answer.is_empty() {
            output.push_str(&self.format_answer(result)?);
        }

        if self.config.authority && !result.message.authority.is_empty() {
            output.push_str(&self.format_authority(result)?);
        }

        if self.config.additional && !result.message.additional.is_empty() {
            output.push_str(&self.format_additional(result)?);
        }

        if self.config.stats {
            output.push_str(&self.format_stats(result)?);
        }

        Ok(output)
    }

    fn format_header(&self, result: &LookupResult) -> io::Result<String> {
        let msg = &result.message;

        // Header line
        let header = format!(
            "\n;; ->>HEADER<<- opcode: {}, status: {}, id: {}\n",
            msg.opcode, msg.rcode, msg.id
        );

        // Flags line
        let flags = self.format_flags(&msg.flags);
        let flag_line = format!(
            ";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n",
            flags,
            msg.question.len(),
            msg.answer.len(),
            msg.authority.len(),
            msg.additional.len()
        );

        // EDNS line (if applicable)
        let edns_line = String::new(); // TODO: Add EDNS info

        // Opt pseudo section
        let opt_line = String::new(); // TODO: Add OPT info

        Ok(format!("{}{}{}{}", header, flag_line, edns_line, opt_line))
    }

    fn format_question(&self, result: &LookupResult) -> io::Result<String> {
        let mut output = String::new();

        if self.config.comments {
            output.push_str(";; QUESTION SECTION:\n");
        }

        for q in &result.message.question {
            let name = pad_right(&q.name, 30);
            output.push_str(&format!(";{}\t\t{}\t{}\n", name, q.qclass, q.qtype));
        }

        if self.config.comments {
            output.push('\n');
        }

        Ok(output)
    }

    fn format_answer(&self, result: &LookupResult) -> io::Result<String> {
        let mut output = String::new();

        if self.config.comments {
            output.push_str(";; ANSWER SECTION:\n");
        }

        for record in &result.message.answer {
            output.push_str(&self.format_record(record));
            output.push('\n');
        }

        if self.config.comments {
            output.push('\n');
        }

        Ok(output)
    }

    fn format_authority(&self, result: &LookupResult) -> io::Result<String> {
        let mut output = String::new();

        if self.config.comments {
            output.push_str(";; AUTHORITY SECTION:\n");
        }

        for record in &result.message.authority {
            output.push_str(&self.format_record(record));
            output.push('\n');
        }

        if self.config.comments {
            output.push('\n');
        }

        Ok(output)
    }

    fn format_additional(&self, result: &LookupResult) -> io::Result<String> {
        let mut output = String::new();

        if self.config.comments {
            output.push_str(";; ADDITIONAL SECTION:\n");
        }

        for record in &result.message.additional {
            output.push_str(&self.format_record(record));
            output.push('\n');
        }

        if self.config.comments {
            output.push('\n');
        }

        Ok(output)
    }

    fn format_stats(&self, result: &LookupResult) -> io::Result<String> {
        let stats = format!(
            ";; Query time: {} msec\n;; SERVER: {}\n;; WHEN: {}\n;; MSG SIZE  rcvd: {}\n",
            result.query_time_ms,
            result.server,
            result.timestamp,
            result.message_size
        );

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_flags() {
        let formatter = DigFormatter::default();
        let flags = dig_core::lookup::DnsFlags {
            qr: true,
            aa: false,
            tc: false,
            rd: true,
            ra: true,
            ad: false,
            cd: false,
        };
        assert_eq!(formatter.format_flags(&flags), "qr rd ra");
    }
}
