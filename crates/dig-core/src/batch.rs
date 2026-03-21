//! Batch mode processing for multiple DNS queries
//!
//! This module provides support for reading and processing multiple
//! DNS queries from a file, similar to BIND9 dig's -f option.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tracing::{debug, info, warn};

use crate::config::DigConfig;
use crate::error::{DigError, Result};
use crate::lookup::{DigLookup, LookupResult};

/// Batch query configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    /// Continue on errors
    pub continue_on_error: bool,
    /// Show query details
    pub show_query: bool,
    /// Display results sequentially
    pub sequential: bool,
    /// Number of parallel queries
    pub parallel: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            continue_on_error: true,
            show_query: false,
            sequential: true,
            parallel: 1,
        }
    }
}

/// A single query in a batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchQuery {
    /// Original query string
    pub raw: String,
    /// Domain name
    pub domain: String,
    /// Query type
    pub qtype: String,
    /// Query class
    pub qclass: Option<String>,
    /// Server to use (optional)
    pub server: Option<String>,
    /// Line number in file
    pub line_number: usize,
}

/// Batch query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    /// The query that was executed
    pub query: BatchQuery,
    /// The lookup result
    pub result: Result<LookupResult>,
    /// Query execution time in milliseconds
    pub exec_time_ms: u64,
}

/// Batch processor for multiple DNS queries
pub struct BatchProcessor {
    config: BatchConfig,
    base_config: DigConfig,
    runtime: Runtime,
}

impl BatchProcessor {
    /// Create a new batch processor
    pub fn new(base_config: DigConfig, batch_config: BatchConfig) -> Result<Self> {
        let runtime = Runtime::new()
            .map_err(|e| DigError::ConfigError(format!("Failed to create runtime: {}", e)))?;

        Ok(Self {
            config: batch_config,
            base_config,
            runtime,
        })
    }

    /// Process queries from a file
    pub fn process_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<BatchResult>> {
        let file = File::open(path.as_ref())
            .map_err(|e| DigError::IoError(format!("Failed to open batch file: {}", e)))?;

        let queries = self.parse_batch_file(file)?;
        info!("Loaded {} queries from batch file", queries.len());

        self.process_queries(queries)
    }

    /// Process a list of query strings
    pub fn process_strings(&self, query_strings: Vec<String>) -> Result<Vec<BatchResult>> {
        let queries = self.parse_query_strings(query_strings)?;
        self.process_queries(queries)
    }

    /// Parse queries from a batch file
    fn parse_batch_file(&self, file: File) -> Result<Vec<BatchQuery>> {
        let reader = BufReader::new(file);
        let mut queries = Vec::new();
        let mut line_number = 0;

        for line in reader.lines() {
            line_number += 1;
            let line = line.map_err(|e| DigError::IoError(format!("Failed to read line: {}", e)))?;

            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            // Parse the query line
            match self.parse_query_line(line, line_number) {
                Ok(query) => queries.push(query),
                Err(e) => {
                    if self.config.continue_on_error {
                        warn!("Failed to parse line {}: {}", line_number, e);
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Ok(queries)
    }

    /// Parse query strings
    fn parse_query_strings(&self, strings: Vec<String>) -> Result<Vec<BatchQuery>> {
        strings
            .into_iter()
            .enumerate()
            .map(|(i, s)| self.parse_query_line(&s, i + 1))
            .collect()
    }

    /// Parse a single query line
    fn parse_query_line(&self, line: &str, line_number: usize) -> Result<BatchQuery> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.is_empty() {
            return Err(DigError::InvalidDomain("Empty query line".into()));
        }

        let mut domain = String::new();
        let mut qtype = "A".to_string();
        let mut qclass = None;
        let mut server = None;

        let mut i = 0;
        while i < parts.len() {
            match parts[i] {
                s if s.starts_with('@') => {
                    server = Some(s[1..].to_string());
                }
                s if s.parse::<QueryOption>().is_ok() => {
                    // Skip options for now
                    // In full implementation, would parse these
                }
                s if domain.is_empty() => {
                    domain = s.to_string();
                }
                s if qtype == "A" && self.is_record_type(s) => {
                    qtype = s.to_uppercase();
                }
                s if qclass.is_none() && self.is_query_class(s) => {
                    qclass = Some(s.to_uppercase());
                }
                _ => {
                    // Unknown part, treat as domain if not set
                    if domain.is_empty() {
                        domain = s.to_string();
                    }
                }
            }
            i += 1;
        }

        if domain.is_empty() {
            return Err(DigError::InvalidDomain("No domain specified in query".into()));
        }

        Ok(BatchQuery {
            raw: line.to_string(),
            domain,
            qtype,
            qclass,
            server,
            line_number,
        })
    }

    /// Check if a string is a record type
    fn is_record_type(&self, s: &str) -> bool {
        matches!(
            s.to_uppercase().as_str(),
            "A" | "AAAA" | "NS" | "CNAME" | "MX" | "TXT" | "PTR" | "SOA" |
            "SRV" | "DNSKEY" | "DS" | "RRSIG" | "NSEC" | "NSEC3" | "TLSA" |
            "CAA" | "SSHFP" | "ANY" | "AXFR" | "IXFR"
        )
    }

    /// Check if a string is a query class
    fn is_query_class(&self, s: &str) -> bool {
        matches!(s.to_uppercase().as_str(), "IN" | "CH" | "HS" | "ANY")
    }

    /// Process a list of queries
    fn process_queries(&self, queries: Vec<BatchQuery>) -> Result<Vec<BatchResult>> {
        if self.config.sequential || self.config.parallel == 1 {
            self.process_sequential(queries)
        } else {
            self.process_parallel(queries)
        }
    }

    /// Process queries sequentially
    fn process_sequential(&self, queries: Vec<BatchQuery>) -> Result<Vec<BatchResult>> {
        let mut results = Vec::new();

        for query in queries {
            let start = std::time::Instant::now();
            let result = self.execute_query(&query);
            let exec_time = start.elapsed().as_millis() as u64;

            results.push(BatchResult {
                query: query.clone(),
                result,
                exec_time_ms: exec_time,
            });

            if !self.config.continue_on_error {
                if results.last().unwrap().result.is_err() {
                    break;
                }
            }
        }

        Ok(results)
    }

    /// Process queries in parallel
    fn process_parallel(&self, queries: Vec<BatchQuery>) -> Result<Vec<BatchResult>> {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let results = Arc::new(Mutex::new(Vec::new()));
        let chunk_size = (queries.len() + self.config.parallel - 1) / self.config.parallel;
        let mut handles = Vec::new();

        for chunk in queries.chunks(chunk_size) {
            let chunk_queries = chunk.to_vec();
            let results_clone = Arc::clone(&results);
            let base_config = self.base_config.clone();
            let continue_on_error = self.config.continue_on_error;

            let handle = thread::spawn(move || {
                let rt = Runtime::new().unwrap();
                let mut local_results = Vec::new();

                for query in chunk_queries {
                    let start = std::time::Instant::now();
                    let result = rt.block_on(execute_query_async(&query, &base_config));
                    let exec_time = start.elapsed().as_millis() as u64;

                    local_results.push(BatchResult {
                        query: query.clone(),
                        result,
                        exec_time_ms: exec_time,
                    });

                    if !continue_on_error && result.is_err() {
                        break;
                    }
                }

                let mut results = results_clone.lock().unwrap();
                results.extend(local_results);
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join()
                .map_err(|e| DigError::ConfigError(format!("Thread join failed: {:?}", e)))?;
        }

        // Convert Arc result
        let results = Arc::try_unwrap(results)
            .map_err(|_| DigError::ConfigError("Failed to unwrap Arc".into()))?
            .into_inner()
            .map_err(|_| DigError::ConfigError("Failed to get Mutex result".into()))?;

        Ok(results)
    }

    /// Execute a single query
    fn execute_query(&self, query: &BatchQuery) -> Result<LookupResult> {
        self.runtime.block_on(execute_query_async(query, &self.base_config))
    }
}

/// Execute a query asynchronously
async fn execute_query_async(query: &BatchQuery, base_config: &DigConfig) -> Result<LookupResult> {
    use crate::config::{QueryClass, ServerConfig};

    let mut config = base_config.clone();
    config.name = query.domain.clone();
    config.query_type = query.qtype.clone();

    if let Some(ref server) = query.server {
        if let Some(server_config) = ServerConfig::parse(server) {
            config.servers = vec![server_config];
        }
    }

    if let Some(ref qclass) = query.qclass {
        config.query_class = qclass.parse()
            .unwrap_or(QueryClass::IN);
    }

    let lookup = DigLookup::new(config);
    lookup.lookup().await
}

/// Query option for parsing
#[derive(Debug)]
enum QueryOption {
    Short,
    Tcp,
    Tls,
    Https,
    Trace,
    Dnssec,
    Json,
    Yaml,
}

impl std::str::FromStr for QueryOption {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "+short" => Ok(QueryOption::Short),
            "+tcp" => Ok(QueryOption::Tcp),
            "+tls" => Ok(QueryOption::Tls),
            "+https" => Ok(QueryOption::Https),
            "+trace" => Ok(QueryOption::Trace),
            "+dnssec" => Ok(QueryOption::Dnssec),
            "+json" => Ok(QueryOption::Json),
            "+yaml" => Ok(QueryOption::Yaml),
            _ => Err(format!("Unknown option: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_query_line() {
        let processor = BatchProcessor::new(
            DigConfig::default(),
            BatchConfig::default(),
        ).unwrap();

        let query = processor.parse_query_line("example.com", 1).unwrap();
        assert_eq!(query.domain, "example.com");
        assert_eq!(query.qtype, "A");
        assert!(query.server.is_none());

        let query = processor.parse_query_line("example.com MX", 2).unwrap();
        assert_eq!(query.domain, "example.com");
        assert_eq!(query.qtype, "MX");

        let query = processor.parse_query_line("@8.8.8.8 example.com", 3).unwrap();
        assert_eq!(query.domain, "example.com");
        assert_eq!(query.server, Some("8.8.8.8".to_string()));
    }

    #[test]
    fn test_is_record_type() {
        let processor = BatchProcessor::new(
            DigConfig::default(),
            BatchConfig::default(),
        ).unwrap();

        assert!(processor.is_record_type("A"));
        assert!(processor.is_record_type("MX"));
        assert!(processor.is_record_type("txt"));
        assert!(!processor.is_record_type("example.com"));
    }

    #[test]
    fn test_is_query_class() {
        let processor = BatchProcessor::new(
            DigConfig::default(),
            BatchConfig::default(),
        ).unwrap();

        assert!(processor.is_query_class("IN"));
        assert!(processor.is_query_class("ch"));
        assert!(!processor.is_query_class("A"));
    }
}
