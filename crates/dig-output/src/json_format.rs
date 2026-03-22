//! JSON output format
//!
//! Provides structured JSON output for programmatic consumption

use std::io;

use dig_core::lookup::LookupResult;
use serde_json::{json, to_string_pretty, Value};

use crate::format::{OutputConfig, OutputFormatter};

/// JSON formatter
pub struct JsonFormatter {
    _config: OutputConfig,
    pretty: bool,
}

impl JsonFormatter {
    /// Create a new JSON formatter
    pub fn new(config: OutputConfig) -> Self {
        Self {
            _config: config,
            pretty: true,
        }
    }

    /// Create with default config
    pub fn default() -> Self {
        Self::new(OutputConfig::default())
    }

    /// Set pretty printing
    pub fn with_pretty(mut self, pretty: bool) -> Self {
        self.pretty = pretty;
        self
    }

    /// Convert lookup result to JSON
    fn result_to_json(&self, result: &LookupResult) -> Value {
        let msg = &result.message;

        json!({
            "query": {
                "name": result.query_name,
                "type": result.query_type,
                "class": result.query_class,
            },
            "response": {
                "id": msg.id,
                "rcode": msg.rcode,
                "opcode": msg.opcode,
                "flags": {
                    "qr": msg.flags.qr,
                    "aa": msg.flags.aa,
                    "tc": msg.flags.tc,
                    "rd": msg.flags.rd,
                    "ra": msg.flags.ra,
                    "ad": msg.flags.ad,
                    "cd": msg.flags.cd,
                },
            },
            "question": msg.question.iter().map(|q| json!({
                "name": q.name,
                "type": q.qtype,
                "class": q.qclass,
            })).collect::<Vec<_>>(),
            "answer": msg.answer.iter().map(|r| self.record_to_json(r)).collect::<Vec<_>>(),
            "authority": msg.authority.iter().map(|r| self.record_to_json(r)).collect::<Vec<_>>(),
            "additional": msg.additional.iter().map(|r| self.record_to_json(r)).collect::<Vec<_>>(),
            "stats": {
                "query_time_ms": result.query_time_ms,
                "server": result.server,
                "message_size": result.message_size,
                "timestamp": result.timestamp,
            },
        })
    }

    /// Convert a record to JSON
    fn record_to_json(&self, record: &dig_core::lookup::DnsRecord) -> Value {
        json!({
            "name": record.name,
            "ttl": record.ttl,
            "class": record.class,
            "type": record.rtype,
            "data": record.rdata,
        })
    }
}

impl OutputFormatter for JsonFormatter {
    fn format(&self, result: &LookupResult) -> io::Result<String> {
        let json = self.result_to_json(result);

        if self.pretty {
            to_string_pretty(&json).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        } else {
            serde_json::to_string(&json).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        }
    }

    fn format_header(&self, result: &LookupResult) -> io::Result<String> {
        let header = json!({
            "response": {
                "id": result.message.id,
                "rcode": result.message.rcode,
                "opcode": result.message.opcode,
                "flags": {
                    "qr": result.message.flags.qr,
                    "aa": result.message.flags.aa,
                    "tc": result.message.flags.tc,
                    "rd": result.message.flags.rd,
                    "ra": result.message.flags.ra,
                    "ad": result.message.flags.ad,
                    "cd": result.message.flags.cd,
                },
            },
        });

        serde_json::to_string(&header).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn format_question(&self, result: &LookupResult) -> io::Result<String> {
        let questions: Vec<Value> = result
            .message
            .question
            .iter()
            .map(|q| {
                json!({
                    "name": q.name,
                    "type": q.qtype,
                    "class": q.qclass,
                })
            })
            .collect();

        serde_json::to_string(&questions).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn format_answer(&self, result: &LookupResult) -> io::Result<String> {
        let answers: Vec<Value> = result
            .message
            .answer
            .iter()
            .map(|r| self.record_to_json(r))
            .collect();

        serde_json::to_string(&answers).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn format_authority(&self, result: &LookupResult) -> io::Result<String> {
        let authority: Vec<Value> = result
            .message
            .authority
            .iter()
            .map(|r| self.record_to_json(r))
            .collect();

        serde_json::to_string(&authority).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn format_additional(&self, result: &LookupResult) -> io::Result<String> {
        let additional: Vec<Value> = result
            .message
            .additional
            .iter()
            .map(|r| self.record_to_json(r))
            .collect();

        serde_json::to_string(&additional).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn format_stats(&self, result: &LookupResult) -> io::Result<String> {
        let stats = json!({
            "query_time_ms": result.query_time_ms,
            "server": result.server,
            "message_size": result.message_size,
            "timestamp": result.timestamp,
        });

        serde_json::to_string(&stats).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}
