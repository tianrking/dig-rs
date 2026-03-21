//! DNS diagnostic and health check capabilities
//!
//! This module provides intelligent DNS diagnostics that go beyond
//! simple lookups to identify and explain DNS issues.

use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::config::DigConfig;
use crate::error::{DigError, Result};
use crate::lookup::{DigLookup, LookupResult};
use crate::metrics::QueryMetrics;

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Domain checked
    pub domain: String,
    /// Overall health status
    pub status: HealthStatus,
    /// Individual checks performed
    pub checks: Vec<CheckResult>,
    /// Issues found
    pub issues: Vec<HealthIssue>,
    /// Recommendations
    pub recommendations: Vec<String>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Local>,
}

/// Health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// All checks passed
    Healthy,
    /// Minor issues found
    Warning,
    /// Significant problems detected
    Critical,
    /// DNS resolution failed
    Failed,
}

/// Individual check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Check name
    pub name: String,
    /// Check description
    pub description: String,
    /// Check status
    pub status: CheckStatus,
    /// Check value (if applicable)
    pub value: Option<String>,
    /// Expected range/value
    pub expected: Option<String>,
}

/// Check status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    Pass,
    Warning,
    Fail,
    Skip,
}

/// Health issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthIssue {
    /// Issue severity
    pub severity: IssueSeverity,
    /// Issue category
    pub category: IssueCategory,
    /// Issue description
    pub description: String,
    /// Details
    pub details: Option<String>,
}

/// Issue severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Issue category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueCategory {
    Resolution,
    Performance,
    Consistency,
    Security,
    Configuration,
}

/// DNS diagnostic engine
pub struct DnsDiagnostic {
    config: DiagnosticConfig,
}

/// Diagnostic configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticConfig {
    /// Test resolvers
    pub test_resolvers: Vec<String>,
    /// Performance thresholds (ms)
    pub latency_thresholds: LatencyThresholds,
    /// Enable consistency checks
    pub check_consistency: bool,
    /// Enable security checks
    pub check_security: bool,
    /// Enable CDN detection
    pub detect_cdn: bool,
}

/// Performance thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyThresholds {
    /// Fast threshold (ms)
    pub fast: u64,
    /// Acceptable threshold (ms)
    pub acceptable: u64,
    /// Slow threshold (ms)
    pub slow: u64,
}

impl Default for LatencyThresholds {
    fn default() -> Self {
        Self {
            fast: 50,      // < 50ms is fast
            acceptable: 200, // < 200ms is acceptable
            slow: 500,    // > 500ms is slow
        }
    }
}

impl Default for DiagnosticConfig {
    fn default() -> Self {
        Self {
            test_resolvers: vec![
                "8.8.8.8".to_string(),      // Google
                "1.1.1.1".to_string(),      // Cloudflare
                "208.67.222.222".to_string(), // OpenDNS
            ],
            latency_thresholds: LatencyThresholds::default(),
            check_consistency: true,
            check_security: true,
            detect_cdn: true,
        }
    }
}

impl DnsDiagnostic {
    /// Create a new diagnostic engine
    pub fn new(config: DiagnosticConfig) -> Self {
        Self { config }
    }

    /// Run a comprehensive health check
    pub async fn health_check(&self, domain: &str) -> Result<HealthCheck> {
        let mut checks = Vec::new();
        let mut issues = Vec::new();
        let mut recommendations = Vec::new();

        // 1. Basic resolution check
        let resolution_result = self.check_resolution(domain).await?;
        checks.push(resolution_result.check);
        issues.extend(resolution_result.issues);
        recommendations.extend(resolution_result.recommendations);

        // 2. Performance check
        let perf_result = self.check_performance(domain).await?;
        checks.push(perf_result.check);
        issues.extend(perf_result.issues);
        recommendations.extend(perf_result.recommendations);

        // 3. Consistency check
        if self.config.check_consistency {
            let consistency_result = self.check_consistency(domain).await?;
            checks.push(consistency_result.check);
            issues.extend(consistency_result.issues);
            recommendations.extend(consistency_result.recommendations);
        }

        // 4. Security check
        if self.config.check_security {
            let security_result = self.check_security(domain).await?;
            checks.push(security_result.check);
            issues.extend(security_result.issues);
            recommendations.extend(security_result.recommendations);
        }

        // 5. CDN detection
        if self.config.detect_cdn {
            let cdn_result = self.detect_cdn(domain).await?;
            checks.push(cdn_result.check);
        }

        // Determine overall status
        let status = self.determine_overall_status(&checks);

        Ok(HealthCheck {
            domain: domain.to_string(),
            status,
            checks,
            issues,
            recommendations,
            timestamp: chrono::Local::now(),
        })
    }

    /// Check basic DNS resolution
    async fn check_resolution(&self, domain: &str) -> Result<CheckWithIssues> {
        let config = DigConfig::new(domain);
        let lookup = DigLookup::new(config);

        let mut issues = Vec::new();
        let mut recommendations = Vec::new();

        match lookup.lookup().await {
            Ok(result) => {
                let answer_count = result.message.answer.len();

                let status = if answer_count > 0 {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Warning
                };

                let check = CheckResult {
                    name: "DNS Resolution".to_string(),
                    description: "Domain can be resolved".to_string(),
                    status,
                    value: Some(format!("{} answers", answer_count)),
                    expected: Some(">= 1 answer".to_string()),
                };

                if answer_count == 0 {
                    issues.push(HealthIssue {
                        severity: IssueSeverity::Warning,
                        category: IssueCategory::Resolution,
                        description: "No DNS records found".to_string(),
                        details: Some("The domain exists but returned no answers".to_string()),
                    });
                }

                Ok(CheckWithIssues { check, issues, recommendations })
            }
            Err(e) => {
                let check = CheckResult {
                    name: "DNS Resolution".to_string(),
                    description: "Domain can be resolved".to_string(),
                    status: CheckStatus::Fail,
                    value: None,
                    expected: Some("Successful resolution".to_string()),
                };

                issues.push(HealthIssue {
                    severity: IssueSeverity::Critical,
                    category: IssueCategory::Resolution,
                    description: format!("DNS resolution failed: {}", e),
                    details: None,
                });

                recommendations.push("Check if the domain name is correct".to_string());
                recommendations.push("Verify network connectivity".to_string());

                Ok(CheckWithIssues { check, issues, recommendations })
            }
        }
    }

    /// Check DNS performance
    async fn check_performance(&self, domain: &str) -> Result<CheckWithIssues> {
        let start = Instant::now();
        let config = DigConfig::new(domain);
        let lookup = DigLookup::new(config);

        let mut issues = Vec::new();
        let mut recommendations = Vec::new();

        let result = lookup.lookup().await;
        let latency = start.elapsed().as_millis() as u64;

        let (status, status_text) = if latency <= self.config.latency_thresholds.fast {
            (CheckStatus::Pass, "Fast")
        } else if latency <= self.config.latency_thresholds.acceptable {
            (CheckStatus::Pass, "Acceptable")
        } else if latency <= self.config.latency_thresholds.slow {
            (CheckStatus::Warning, "Slow")
        } else {
            (CheckStatus::Fail, "Very Slow")
        };

        let check = CheckResult {
            name: "DNS Performance".to_string(),
            description: "Query response time".to_string(),
            status,
            value: Some(format!("{}ms", latency)),
            expected: Some(format!("<={}ms", self.config.latency_thresholds.acceptable)),
        };

        if latency > self.config.latency_thresholds.slow {
            issues.push(HealthIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::Performance,
                description: "High DNS latency detected".to_string(),
                details: Some(format!("{}ms is above the slow threshold of {}ms",
                    latency, self.config.latency_thresholds.slow)),
            });

            recommendations.push("Consider using a closer DNS resolver".to_string());
            recommendations.push("Check for network congestion".to_string());
        }

        Ok(CheckWithIssues { check, issues, recommendations })
    }

    /// Check consistency across resolvers
    async fn check_consistency(&self, domain: &str) -> Result<CheckWithIssues> {
        let mut issues = Vec::new();
        let mut recommendations = Vec::new();

        let mut results = Vec::new();
        for resolver in &self.config.test_resolvers {
            let config = DigConfig::new(domain).with_server(
                crate::config::ServerConfig::new(resolver)
            );
            let lookup = DigLookup::new(config);

            match lookup.lookup().await {
                Ok(result) => {
                    let answers: Vec<String> = result.message.answer
                        .iter()
                        .map(|a| a.rdata.clone())
                        .collect();
                    results.push((resolver.clone(), answers));
                }
                Err(_) => {
                    results.push((resolver.clone(), Vec::new()));
                }
            }
        }

        // Check for consistency
        let unique_answer_sets: HashSet<_> = results.iter()
            .map(|(_, answers)| answers.clone())
            .collect();

        let status = if unique_answer_sets.len() == 1 {
            CheckStatus::Pass
        } else if unique_answer_sets.len() == results.len() {
            CheckStatus::Fail
        } else {
            CheckStatus::Warning
        };

        let check = CheckResult {
            name: "Resolver Consistency".to_string(),
            description: "Consistent results across resolvers".to_string(),
            status,
            value: Some(format!("{} unique result(s)", unique_answer_sets.len())),
            expected: Some("Consistent results".to_string()),
        };

        if unique_answer_sets.len() > 1 {
            issues.push(HealthIssue {
                severity: IssueSeverity::Warning,
                category: IssueCategory::Consistency,
                description: "Inconsistent results across resolvers".to_string(),
                details: Some(format!("Got {} different result sets from {} resolvers",
                    unique_answer_sets.len(), results.len())),
            });

            recommendations.push("DNS propagation may be in progress".to_string());
            recommendations.push("Some resolvers may be returning cached data".to_string());
        }

        Ok(CheckWithIssues { check, issues, recommendations })
    }

    /// Check DNS security
    async fn check_security(&self, domain: &str) -> Result<CheckWithIssues> {
        let mut issues = Vec::new();
        let mut recommendations = Vec::new();

        // Check for DNSSEC
        let config = DigConfig::new(domain).with_dnssec(true);
        let lookup = DigLookup::new(config);

        let check = match lookup.lookup().await {
            Ok(result) => {
                let has_dnssec = result.message.answer.iter()
                    .any(|a| a.rtype.contains("DNSKEY") || a.rtype.contains("RRSIG"));

                if has_dnssec {
                    CheckResult {
                        name: "DNS Security".to_string(),
                        description: "DNSSEC support".to_string(),
                        status: CheckStatus::Pass,
                        value: Some("DNSSEC signed".to_string()),
                        expected: None,
                    }
                } else {
                    CheckResult {
                        name: "DNS Security".to_string(),
                        description: "DNSSEC support".to_string(),
                        status: CheckStatus::Skip,
                        value: Some("Not signed".to_string()),
                        expected: None,
                    }
                }
            }
            Err(_) => {
                CheckResult {
                    name: "DNS Security".to_string(),
                    description: "DNSSEC support".to_string(),
                    status: CheckStatus::Skip,
                    value: None,
                    expected: None,
                }
            }
        };

        Ok(CheckWithIssues { check, issues, recommendations })
    }

    /// Detect CDN usage
    async fn detect_cdn(&self, domain: &str) -> Result<CheckWithIssues> {
        let config = DigConfig::new(domain);
        let lookup = DigLookup::new(config);

        let check = match lookup.lookup().await {
            Ok(result) => {
                let cdn_info = self.detect_cdn_from_result(&result);

                CheckResult {
                    name: "CDN Detection".to_string(),
                    description: "Content Delivery Network detection".to_string(),
                    status: CheckStatus::Pass,
                    value: Some(cdn_info),
                    expected: None,
                }
            }
            Err(_) => {
                CheckResult {
                    name: "CDN Detection".to_string(),
                    description: "Content Delivery Network detection".to_string(),
                    status: CheckStatus::Skip,
                    value: None,
                    expected: None,
                }
            }
        };

        Ok(CheckWithIssues {
            check,
            issues: Vec::new(),
            recommendations: Vec::new(),
        })
    }

    /// Detect CDN from lookup result
    fn detect_cdn_from_result(&self, result: &LookupResult) -> String {
        let cdns = [
            ("Cloudflare", vec!["cloudflare", "cf-", "1.1.1.1", "104.16."]),
            ("Akamai", vec!["akamai", "akamaiedge", "akamaitech"]),
            ("Fastly", vec!["fastly", "fastlylb"]),
            ("AWS CloudFront", vec!["cloudfront", "aws"]),
            ("Azure CDN", vec!["azureedge", "azurefd"]),
            ("Google Cloud", vec!["cloudflare", "googleusercontent"]),
            ("Incapsula", vec!["incapula"]),
        ];

        for answer in &result.message.answer {
            let answer_lower = answer.rdata.to_lowercase();

            for (cdn_name, patterns) in &cdns {
                for pattern in patterns {
                    if answer_lower.contains(pattern) {
                        return cdn_name.to_string();
                    }
                }
            }
        }

        "Not detected".to_string()
    }

    /// Determine overall health status
    fn determine_overall_status(&self, checks: &[CheckResult]) -> HealthStatus {
        if checks.iter().any(|c| c.status == CheckStatus::Fail) {
            return HealthStatus::Failed;
        }

        if checks.iter().any(|c| c.status == CheckStatus::Warning) {
            return HealthStatus::Warning;
        }

        if checks.iter().all(|c| c.status == CheckStatus::Pass || c.status == CheckStatus::Skip) {
            return HealthStatus::Healthy;
        }

        HealthStatus::Warning
    }
}

/// Helper struct for check results with issues
struct CheckWithIssues {
    check: CheckResult,
    issues: Vec<HealthIssue>,
    recommendations: Vec<String>,
}

/// Comparison result for multiple resolvers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    /// Domain queried
    pub domain: String,
    /// Query type
    pub query_type: String,
    /// Results from each resolver
    pub resolver_results: Vec<ResolverResult>,
    /// Whether all results match
    pub consistent: bool,
    /// Inconsistencies found
    pub inconsistencies: Vec<Inconsistency>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Local>,
}

/// Result from a single resolver
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverResult {
    /// Resolver address
    pub resolver: String,
    /// Query was successful
    pub success: bool,
    /// Response time in milliseconds
    pub latency_ms: u64,
    /// Answers received
    pub answers: Vec<String>,
    /// Response code
    pub rcode: String,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Inconsistency between resolvers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inconsistency {
    /// Type of inconsistency
    pub inconsistency_type: InconsistencyType,
    /// Description
    pub description: String,
    /// Affected resolvers
    pub resolvers: Vec<String>,
    /// Details
    pub details: Option<String>,
}

/// Type of inconsistency
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InconsistencyType {
    /// Different answers
    DifferentAnswers,
    /// Some resolvers failed
    PartialFailure,
    /// Different response codes
    DifferentRcode,
    /// Timing anomaly
    TimingAnomaly,
}

/// Compare results across multiple resolvers
pub async fn compare_resolvers(
    domain: &str,
    resolvers: &[String],
    query_type: Option<&str>,
) -> Result<ComparisonResult> {
    let mut resolver_results = Vec::new();
    let mut inconsistencies = Vec::new();

    let query_type = query_type.unwrap_or("A");

    for resolver in resolvers {
        let start = Instant::now();

        let config = DigConfig::new(domain)
            .with_server(crate::config::ServerConfig::new(resolver))
            .with_query_type(query_type);

        let lookup = DigLookup::new(config);

        match lookup.lookup().await {
            Ok(result) => {
                let latency = start.elapsed().as_millis() as u64;
                let answers: Vec<String> = result.message.answer
                    .iter()
                    .map(|a| a.rdata.clone())
                    .collect();

                resolver_results.push(ResolverResult {
                    resolver: resolver.clone(),
                    success: true,
                    latency_ms: latency,
                    answers,
                    rcode: result.message.rcode,
                    error: None,
                });
            }
            Err(e) => {
                let latency = start.elapsed().as_millis() as u64;
                resolver_results.push(ResolverResult {
                    resolver: resolver.clone(),
                    success: false,
                    latency_ms: latency,
                    answers: Vec::new(),
                    rcode: "FAILED".to_string(),
                    error: Some(e.to_string()),
                });
            }
        }
    }

    // Check for inconsistencies
    let consistent = check_consistency(&resolver_results, &mut inconsistencies);

    Ok(ComparisonResult {
        domain: domain.to_string(),
        query_type: query_type.to_string(),
        resolver_results,
        consistent,
        inconsistencies,
        timestamp: chrono::Local::now(),
    })
}

/// Check consistency across resolver results
fn check_consistency(
    results: &[ResolverResult],
    inconsistencies: &mut Vec<Inconsistency>,
) -> bool {
    // Check if any failed
    let failed_resolvers: Vec<_> = results.iter()
        .filter(|r| !r.success)
        .map(|r| r.resolver.clone())
        .collect();

    if !failed_resolvers.is_empty() && failed_resolvers.len() < results.len() {
        inconsistencies.push(Inconsistency {
            inconsistency_type: InconsistencyType::PartialFailure,
            description: format!("{} resolvers failed", failed_resolvers.len()),
            resolvers: failed_resolvers,
            details: None,
        });
        return false;
    }

    // Check answer consistency
    let answer_sets: Vec<_> = results.iter()
        .map(|r| r.answers.clone())
        .collect();

    let unique_sets: HashSet<_> = answer_sets.iter().collect();

    if unique_sets.len() > 1 {
        let inconsistent_resolvers: Vec<_> = results.iter()
            .map(|r| r.resolver.clone())
            .collect();

        inconsistencies.push(Inconsistency {
            inconsistency_type: InconsistencyType::DifferentAnswers,
            description: format!("Got {} different result sets", unique_sets.len()),
            resolvers: inconsistent_resolvers,
            details: None,
        });
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status() {
        let diagnostic = DnsDiagnostic::new(DiagnosticConfig::default());

        // Basic sanity check - structure is correct
        assert_eq!(diagnostic.config.test_resolvers.len(), 3);
    }

    #[test]
    fn test_latency_thresholds() {
        let thresholds = LatencyThresholds::default();
        assert_eq!(thresholds.fast, 50);
        assert_eq!(thresholds.acceptable, 200);
        assert_eq!(thresholds.slow, 500);
    }

    #[test]
    fn test_inconsistency_type() {
        let inconsistency = Inconsistency {
            inconsistency_type: InconsistencyType::DifferentAnswers,
            description: "Test".to_string(),
            resolvers: vec!["8.8.8.8".to_string()],
            details: None,
        };

        assert_eq!(inconsistency.inconsistency_type, InconsistencyType::DifferentAnswers);
    }
}
