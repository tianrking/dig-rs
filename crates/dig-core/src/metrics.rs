//! Performance metrics and monitoring for DNS operations
//!
//! This module provides metrics collection and reporting capabilities.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// DNS query metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryMetrics {
    /// Query name
    pub query_name: String,
    /// Query type
    pub query_type: String,
    /// Server address
    pub server: String,
    /// Query duration
    pub duration: Duration,
    /// Response size in bytes
    pub response_size: usize,
    /// Number of answers
    pub answer_count: usize,
    /// Number of authority records
    pub authority_count: usize,
    /// Number of additional records
    pub additional_count: usize,
    /// Response code
    pub response_code: String,
    /// Whether the query was successful
    pub success: bool,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Local>,
}

/// Aggregated metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedMetrics {
    /// Total queries
    pub total_queries: u64,
    /// Successful queries
    pub successful_queries: u64,
    /// Failed queries
    pub failed_queries: u64,
    /// Average query time in milliseconds
    pub avg_query_time_ms: f64,
    /// Minimum query time in milliseconds
    pub min_query_time_ms: u64,
    /// Maximum query time in milliseconds
    pub max_query_time_ms: u64,
    /// Total bytes received
    pub total_bytes: u64,
    /// Average response size in bytes
    pub avg_response_size: f64,
    /// Queries by type
    pub queries_by_type: HashMap<String, u64>,
    /// Queries by server
    pub queries_by_server: HashMap<String, u64>,
    /// Queries by response code
    pub queries_by_rcode: HashMap<String, u64>,
}

impl Default for AggregatedMetrics {
    fn default() -> Self {
        Self {
            total_queries: 0,
            successful_queries: 0,
            failed_queries: 0,
            avg_query_time_ms: 0.0,
            min_query_time_ms: u64::MAX,
            max_query_time_ms: 0,
            total_bytes: 0,
            avg_response_size: 0.0,
            queries_by_type: HashMap::new(),
            queries_by_server: HashMap::new(),
            queries_by_rcode: HashMap::new(),
        }
    }
}

impl AggregatedMetrics {
    /// Update metrics with a new query
    pub fn update(&mut self, metrics: &QueryMetrics) {
        self.total_queries += 1;

        if metrics.success {
            self.successful_queries += 1;
        } else {
            self.failed_queries += 1;
        }

        let query_time_ms = metrics.duration.as_millis() as u64;
        self.min_query_time_ms = self.min_query_time_ms.min(query_time_ms);
        self.max_query_time_ms = self.max_query_time_ms.max(query_time_ms);

        // Update average query time
        let total_time = self.avg_query_time_ms * (self.total_queries - 1) as f64;
        self.avg_query_time_ms = (total_time + query_time_ms as f64) / self.total_queries as f64;

        // Update response size stats
        self.total_bytes += metrics.response_size as u64;
        self.avg_response_size = self.total_bytes as f64 / self.total_queries as f64;

        // Update counts
        *self
            .queries_by_type
            .entry(metrics.query_type.clone())
            .or_insert(0) += 1;
        *self
            .queries_by_server
            .entry(metrics.server.clone())
            .or_insert(0) += 1;
        *self
            .queries_by_rcode
            .entry(metrics.response_code.clone())
            .or_insert(0) += 1;
    }

    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.total_queries == 0 {
            return 0.0;
        }
        (self.successful_queries as f64 / self.total_queries as f64) * 100.0
    }

    /// Format metrics as a string
    pub fn format(&self) -> String {
        let mut output = String::new();
        output.push_str("DNS Query Metrics:\n");
        output.push_str(&format!("  Total queries: {}\n", self.total_queries));
        output.push_str(&format!(
            "  Successful: {} ({:.1}%)\n",
            self.successful_queries,
            self.success_rate()
        ));
        output.push_str(&format!("  Failed: {}\n", self.failed_queries));
        output.push_str(&format!(
            "  Avg query time: {:.2} ms\n",
            self.avg_query_time_ms
        ));
        output.push_str(&format!(
            "  Min query time: {} ms\n",
            self.min_query_time_ms
        ));
        output.push_str(&format!(
            "  Max query time: {} ms\n",
            self.max_query_time_ms
        ));
        output.push_str(&format!(
            "  Avg response size: {:.2} bytes\n",
            self.avg_response_size
        ));
        output.push_str(&format!("  Total bytes: {} bytes\n", self.total_bytes));
        output
    }
}

/// Metrics collector
#[derive(Debug, Clone)]
pub struct MetricsCollector {
    metrics: Arc<RwLock<Vec<QueryMetrics>>>,
    aggregated: Arc<RwLock<AggregatedMetrics>>,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(Vec::new())),
            aggregated: Arc::new(RwLock::new(AggregatedMetrics::default())),
        }
    }
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a query metric
    pub fn record(&self, metric: QueryMetrics) {
        // Store individual metric
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.push(metric.clone());
        }

        // Update aggregated metrics
        if let Ok(mut aggregated) = self.aggregated.write() {
            aggregated.update(&metric);
        }
    }

    /// Get all collected metrics
    pub fn get_metrics(&self) -> Vec<QueryMetrics> {
        self.metrics.read().map(|m| m.clone()).unwrap_or_default()
    }

    /// Get aggregated metrics
    pub fn get_aggregated(&self) -> AggregatedMetrics {
        self.aggregated
            .read()
            .map(|a| a.clone())
            .unwrap_or_default()
    }

    /// Clear all metrics
    pub fn clear(&self) {
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.clear();
        }
        if let Ok(mut aggregated) = self.aggregated.write() {
            *aggregated = AggregatedMetrics::default();
        }
    }

    /// Get metrics count
    pub fn count(&self) -> usize {
        self.metrics.read().map(|m| m.len()).unwrap_or(0)
    }

    /// Export metrics as JSON
    pub fn export_json(&self) -> String {
        let aggregated = self.get_aggregated();
        serde_json::to_string_pretty(&aggregated).unwrap_or_default()
    }

    /// Export metrics as CSV
    pub fn export_csv(&self) -> String {
        let metrics = self.get_metrics();
        let mut output = String::from("timestamp,query_name,query_type,server,duration_ms,response_size,answer_count,success,response_code\n");

        for metric in metrics {
            output.push_str(&format!(
                "{},{},{},{},{},{},{},{},{}\n",
                metric.timestamp.format("%Y-%m-%d %H:%M:%S"),
                metric.query_name,
                metric.query_type,
                metric.server,
                metric.duration.as_millis(),
                metric.response_size,
                metric.answer_count,
                metric.success,
                metric.response_code,
            ));
        }

        output
    }
}

/// Timing helper for measuring query duration
pub struct Timing {
    start: Instant,
}

impl Timing {
    /// Start a new timing measurement
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Get the elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Get elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Get elapsed time in microseconds
    pub fn elapsed_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregated_metrics_update() {
        let mut metrics = AggregatedMetrics::default();

        let metric1 = QueryMetrics {
            query_name: "example.com".to_string(),
            query_type: "A".to_string(),
            server: "8.8.8.8:53".to_string(),
            duration: Duration::from_millis(100),
            response_size: 64,
            answer_count: 1,
            authority_count: 0,
            additional_count: 0,
            response_code: "NOERROR".to_string(),
            success: true,
            timestamp: chrono::Local::now(),
        };

        metrics.update(&metric1);

        assert_eq!(metrics.total_queries, 1);
        assert_eq!(metrics.successful_queries, 1);
        assert_eq!(metrics.avg_query_time_ms, 100.0);
    }

    #[test]
    fn test_metrics_collector() {
        let collector = MetricsCollector::new();

        let metric = QueryMetrics {
            query_name: "example.com".to_string(),
            query_type: "A".to_string(),
            server: "8.8.8.8:53".to_string(),
            duration: Duration::from_millis(100),
            response_size: 64,
            answer_count: 1,
            authority_count: 0,
            additional_count: 0,
            response_code: "NOERROR".to_string(),
            success: true,
            timestamp: chrono::Local::now(),
        };

        collector.record(metric);

        assert_eq!(collector.count(), 1);
        assert_eq!(collector.get_metrics().len(), 1);
    }

    #[test]
    fn test_timing() {
        let timing = Timing::start();
        std::thread::sleep(Duration::from_millis(10));
        assert!(timing.elapsed_ms() >= 10);
    }

    #[test]
    fn test_metrics_format() {
        let metrics = AggregatedMetrics::default();
        let formatted = metrics.format();
        assert!(formatted.contains("DNS Query Metrics"));
        assert!(formatted.contains("Total queries"));
    }

    #[test]
    fn test_success_rate() {
        let mut metrics = AggregatedMetrics::default();

        let metric1 = QueryMetrics {
            query_name: "example.com".to_string(),
            query_type: "A".to_string(),
            server: "8.8.8.8:53".to_string(),
            duration: Duration::from_millis(100),
            response_size: 64,
            answer_count: 1,
            authority_count: 0,
            additional_count: 0,
            response_code: "NOERROR".to_string(),
            success: true,
            timestamp: chrono::Local::now(),
        };

        let metric2 = QueryMetrics {
            success: false,
            response_code: "NXDOMAIN".to_string(),
            ..metric1.clone()
        };

        metrics.update(&metric1);
        metrics.update(&metric2);

        assert_eq!(metrics.success_rate(), 50.0);
    }

    #[test]
    fn test_export_json() {
        let collector = MetricsCollector::new();
        let json = collector.export_json();
        assert!(json.contains("total_queries"));
    }

    #[test]
    fn test_export_csv() {
        let collector = MetricsCollector::new();
        let csv = collector.export_csv();
        assert!(csv.contains("timestamp,query_name,query_type"));
    }
}
