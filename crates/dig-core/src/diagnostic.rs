//! DNS diagnostic and health check capabilities
//!
//! This module provides intelligent DNS diagnostics that go beyond
//! simple lookups to identify and explain DNS issues.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Instant;

use crate::config::DigConfig;
use crate::error::Result;
use crate::lookup::{DigLookup, LookupResult};

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
            fast: 50,        // < 50ms is fast
            acceptable: 200, // < 200ms is acceptable
            slow: 500,       // > 500ms is slow
        }
    }
}

impl Default for DiagnosticConfig {
    fn default() -> Self {
        Self {
            test_resolvers: vec![
                "8.8.8.8".to_string(),        // Google
                "1.1.1.1".to_string(),        // Cloudflare
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

                Ok(CheckWithIssues {
                    check,
                    issues,
                    recommendations,
                })
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

                Ok(CheckWithIssues {
                    check,
                    issues,
                    recommendations,
                })
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

        let _result = lookup.lookup().await;
        let latency = start.elapsed().as_millis() as u64;

        let (status, _status_text) = if latency <= self.config.latency_thresholds.fast {
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
                details: Some(format!(
                    "{}ms is above the slow threshold of {}ms",
                    latency, self.config.latency_thresholds.slow
                )),
            });

            recommendations.push("Consider using a closer DNS resolver".to_string());
            recommendations.push("Check for network congestion".to_string());
        }

        Ok(CheckWithIssues {
            check,
            issues,
            recommendations,
        })
    }

    /// Check consistency across resolvers
    async fn check_consistency(&self, domain: &str) -> Result<CheckWithIssues> {
        let mut issues = Vec::new();
        let mut recommendations = Vec::new();

        let mut results = Vec::new();
        for resolver in &self.config.test_resolvers {
            let config =
                DigConfig::new(domain).with_server(crate::config::ServerConfig::new(resolver));
            let lookup = DigLookup::new(config);

            match lookup.lookup().await {
                Ok(result) => {
                    let answers: Vec<String> = result
                        .message
                        .answer
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
        let unique_answer_sets: HashSet<_> =
            results.iter().map(|(_, answers)| answers.clone()).collect();

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
                details: Some(format!(
                    "Got {} different result sets from {} resolvers",
                    unique_answer_sets.len(),
                    results.len()
                )),
            });

            recommendations.push("DNS propagation may be in progress".to_string());
            recommendations.push("Some resolvers may be returning cached data".to_string());
        }

        Ok(CheckWithIssues {
            check,
            issues,
            recommendations,
        })
    }

    /// Check DNS security
    async fn check_security(&self, domain: &str) -> Result<CheckWithIssues> {
        let issues = Vec::new();
        let recommendations = Vec::new();

        // Check for DNSSEC
        let config = DigConfig::new(domain).with_dnssec(true);
        let lookup = DigLookup::new(config);

        let check = match lookup.lookup().await {
            Ok(result) => {
                let has_dnssec = result
                    .message
                    .answer
                    .iter()
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
            Err(_) => CheckResult {
                name: "DNS Security".to_string(),
                description: "DNSSEC support".to_string(),
                status: CheckStatus::Skip,
                value: None,
                expected: None,
            },
        };

        Ok(CheckWithIssues {
            check,
            issues,
            recommendations,
        })
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
            Err(_) => CheckResult {
                name: "CDN Detection".to_string(),
                description: "Content Delivery Network detection".to_string(),
                status: CheckStatus::Skip,
                value: None,
                expected: None,
            },
        };

        Ok(CheckWithIssues {
            check,
            issues: Vec::new(),
            recommendations: Vec::new(),
        })
    }

    /// Detect CDN from lookup result
    pub fn detect_cdn_from_result(&self, result: &LookupResult) -> String {
        // Enhanced CDN detection with more providers and patterns
        let cdns = [
            (
                "Cloudflare",
                vec![
                    "cloudflare",
                    "cf-",
                    "cloudflareinsights",
                    "104.16.",
                    "104.17.",
                    "104.18.",
                    "104.19.",
                    "104.20.",
                    "172.64.",
                    "162.159.",
                    "188.114.",
                ],
            ),
            (
                "Akamai",
                vec![
                    "akamai",
                    "akamaiedge",
                    "akamaitech",
                    "akamaihd",
                    "23.32.",
                    "23.33.",
                    "23.44.",
                    "23.50.",
                    "23.60.",
                    "104.80.",
                    "104.85.",
                    "104.86.",
                ],
            ),
            (
                "Fastly",
                vec!["fastly", "fastlylb", "fastly-ssl", "151.101.", "199.27."],
            ),
            (
                "AWS CloudFront",
                vec![
                    "cloudfront",
                    "aws",
                    "cloudfront.net",
                    "13.32.",
                    "13.33.",
                    "13.34.",
                    "13.35.",
                ],
            ),
            (
                "Azure CDN",
                vec![
                    "azureedge",
                    "azurefd",
                    "azure.microsoft",
                    "azure-trafficmanager",
                ],
            ),
            (
                "Google Cloud CDN",
                vec![
                    "cloud.google",
                    "googleusercontent",
                    "gcp",
                    "gslb.",
                    "l.googleusercontent",
                ],
            ),
            ("Incapsula", vec!["incapula", "incapsula", "inscname"]),
            ("StackPath", vec!["stackpath", "stackpathdns"]),
            ("BunnyCDN", vec!["bunnycdn", "bunny.net"]),
            ("KeyCDN", vec!["keycdn", "kxcdn"]),
            ("CDN77", vec!["cdn77", "cdn77.org"]),
            ("QUIC.cloud", vec!["quic.cloud", "qc."]),
        ];

        // Check answer records
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

        // Check NS records for CDN-hosted domains
        for auth in &result.message.authority {
            if auth.rtype == "NS" {
                let ns_lower = auth.rdata.to_lowercase();

                // Cloudflare NS
                if ns_lower.contains("ns.cloudflare") || ns_lower.contains("cloudflare") {
                    return "Cloudflare (NS)".to_string();
                }
                // AWS Route53 NS
                if ns_lower.contains("awsdns") || ns_lower.contains("route53") {
                    return "AWS Route53".to_string();
                }
                // Akamai NS
                if ns_lower.contains("akamai") || ns_lower.contains("akamaiedge") {
                    return "Akamai (NS)".to_string();
                }
                // Fastly NS
                if ns_lower.contains("fastly") || ns_lower.contains("fastlylb") {
                    return "Fastly (NS)".to_string();
                }
                // Azure NS
                if ns_lower.contains("azure") || ns_lower.contains("azure-dns") {
                    return "Azure DNS".to_string();
                }
                // Google NS
                if ns_lower.contains("google") || ns_lower.contains("googledomains") {
                    return "Google Cloud (NS)".to_string();
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

        if checks
            .iter()
            .all(|c| c.status == CheckStatus::Pass || c.status == CheckStatus::Skip)
        {
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
                let answers: Vec<String> = result
                    .message
                    .answer
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
fn check_consistency(results: &[ResolverResult], inconsistencies: &mut Vec<Inconsistency>) -> bool {
    // Check if any failed
    let failed_resolvers: Vec<_> = results
        .iter()
        .filter(|r| !r.success)
        .map(|r| r.resolver.clone())
        .collect();

    // If all resolvers failed, this is an outright failure and cannot be considered consistent.
    if !failed_resolvers.is_empty() && failed_resolvers.len() == results.len() {
        inconsistencies.push(Inconsistency {
            inconsistency_type: InconsistencyType::PartialFailure,
            description: "All resolvers failed".to_string(),
            resolvers: failed_resolvers,
            details: None,
        });
        return false;
    }

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
    let answer_sets: Vec<_> = results.iter().map(|r| r.answers.clone()).collect();

    let unique_sets: HashSet<_> = answer_sets.iter().collect();

    if unique_sets.len() > 1 {
        let inconsistent_resolvers: Vec<_> = results.iter().map(|r| r.resolver.clone()).collect();

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

/// DNS pollution detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollutionDetectionResult {
    /// Domain checked
    pub domain: String,
    /// Whether pollution is suspected
    pub polluted: bool,
    /// Pollution type detected (if any)
    pub pollution_type: Option<PollutionType>,
    /// Results from trusted resolvers
    pub trusted_results: Vec<ResolverResult>,
    /// Results from suspicious resolvers
    pub suspicious_results: Vec<ResolverResult>,
    /// Analysis details
    pub analysis: PollutionAnalysis,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Local>,
}

/// Type of DNS pollution detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PollutionType {
    /// DNS hijacking (different IP returned)
    Hijacking,
    /// DNS blocking (NXDOMAIN or refused)
    Blocking,
    /// DNS redirection (wrong IP pointing to block page)
    Redirection,
    /// DNS injection (fake records injected)
    Injection,
}

/// Detailed pollution analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollutionAnalysis {
    /// Number of resolvers checked
    pub total_resolvers: usize,
    /// Number of trusted resolvers
    pub trusted_count: usize,
    /// Number of suspicious resolvers
    pub suspicious_count: usize,
    /// Description of what was found
    pub description: String,
    /// Confidence level (0-100)
    pub confidence: u8,
}

/// Detect DNS pollution by comparing trusted vs suspicious resolvers
pub async fn detect_pollution(
    domain: &str,
    query_type: Option<&str>,
) -> Result<PollutionDetectionResult> {
    // Trusted international resolvers
    let trusted_resolvers = vec![
        "8.8.8.8",        // Google
        "1.1.1.1",        // Cloudflare
        "208.67.222.222", // OpenDNS
    ];

    // Resolvers that might be polluted (region-specific)
    // In practice, users would configure these based on their location
    let suspicious_resolvers: Vec<String> = vec![
        // User can add specific resolvers to test
    ];

    // Save lengths for later use
    let trusted_count = trusted_resolvers.len();
    let suspicious_count = suspicious_resolvers.len();

    // Query trusted resolvers
    let mut trusted_results = Vec::new();
    for resolver in trusted_resolvers {
        let config = DigConfig::new(domain)
            .with_server(crate::config::ServerConfig::new(resolver.to_string()))
            .with_query_type(query_type.unwrap_or("A"));

        let lookup = DigLookup::new(config);

        match lookup.lookup().await {
            Ok(result) => {
                let answers: Vec<String> = result
                    .message
                    .answer
                    .iter()
                    .map(|a| a.rdata.clone())
                    .collect();

                trusted_results.push(ResolverResult {
                    resolver: resolver.to_string(),
                    success: true,
                    latency_ms: 0,
                    answers,
                    rcode: result.message.rcode,
                    error: None,
                });
            }
            Err(_) => {
                trusted_results.push(ResolverResult {
                    resolver: resolver.to_string(),
                    success: false,
                    latency_ms: 0,
                    answers: Vec::new(),
                    rcode: "FAILED".to_string(),
                    error: Some("Query failed".to_string()),
                });
            }
        }
    }

    // Query suspicious resolvers (if any provided)
    let mut suspicious_results = Vec::new();
    for resolver in suspicious_resolvers {
        let config = DigConfig::new(domain)
            .with_server(crate::config::ServerConfig::new(resolver.as_str()))
            .with_query_type(query_type.unwrap_or("A"));

        let lookup = DigLookup::new(config);

        match lookup.lookup().await {
            Ok(result) => {
                let answers: Vec<String> = result
                    .message
                    .answer
                    .iter()
                    .map(|a| a.rdata.clone())
                    .collect();

                suspicious_results.push(ResolverResult {
                    resolver: resolver.clone(),
                    success: true,
                    latency_ms: 0,
                    answers,
                    rcode: result.message.rcode,
                    error: None,
                });
            }
            Err(_) => {
                suspicious_results.push(ResolverResult {
                    resolver: resolver.clone(),
                    success: false,
                    latency_ms: 0,
                    answers: Vec::new(),
                    rcode: "FAILED".to_string(),
                    error: Some("Query failed".to_string()),
                });
            }
        }
    }

    // Analyze results for pollution
    let analysis = analyze_pollution(&trusted_results, &suspicious_results);

    Ok(PollutionDetectionResult {
        domain: domain.to_string(),
        polluted: analysis.polluted,
        pollution_type: analysis.pollution_type,
        trusted_results,
        suspicious_results,
        analysis: PollutionAnalysis {
            total_resolvers: trusted_count + suspicious_count,
            trusted_count,
            suspicious_count,
            description: analysis.description,
            confidence: analysis.confidence,
        },
        timestamp: chrono::Local::now(),
    })
}

/// Internal analysis result
struct PollutionAnalysisInternal {
    polluted: bool,
    pollution_type: Option<PollutionType>,
    description: String,
    confidence: u8,
}

/// Analyze trusted vs suspicious results for pollution patterns
fn analyze_pollution(
    trusted: &[ResolverResult],
    suspicious: &[ResolverResult],
) -> PollutionAnalysisInternal {
    // Get reference answers from trusted resolvers
    let trusted_answers: Vec<_> = trusted
        .iter()
        .filter(|r| r.success)
        .flat_map(|r| r.answers.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if trusted_answers.is_empty() {
        return PollutionAnalysisInternal {
            polluted: false,
            pollution_type: None,
            description: "No trusted answers to compare".to_string(),
            confidence: 0,
        };
    }

    // Check each suspicious resolver
    for susp in suspicious {
        if !susp.success {
            // Blocking detected
            if susp.rcode == "NXDOMAIN" || susp.rcode == "REFUSED" {
                return PollutionAnalysisInternal {
                    polluted: true,
                    pollution_type: Some(PollutionType::Blocking),
                    description: format!(
                        "{} returned {} instead of valid answers",
                        susp.resolver, susp.rcode
                    ),
                    confidence: 80,
                };
            }
        } else {
            // Check for hijacking or redirection
            let susp_answers: Vec<_> = susp.answers.clone();
            let common = trusted_answers
                .iter()
                .filter(|t| susp_answers.contains(t))
                .count();

            // No common answers suggests hijacking
            if common == 0 && !susp_answers.is_empty() {
                return PollutionAnalysisInternal {
                    polluted: true,
                    pollution_type: Some(PollutionType::Hijacking),
                    description: format!(
                        "{} returned completely different answers: {:?}",
                        susp.resolver, susp_answers
                    ),
                    confidence: 90,
                };
            }

            // Partial overlap might indicate redirection
            if common < susp_answers.len() && common < trusted_answers.len() {
                return PollutionAnalysisInternal {
                    polluted: true,
                    pollution_type: Some(PollutionType::Redirection),
                    description: format!(
                        "{} returned different answers than trusted resolvers",
                        susp.resolver
                    ),
                    confidence: 60,
                };
            }
        }
    }

    PollutionAnalysisInternal {
        polluted: false,
        pollution_type: None,
        description: "No pollution detected".to_string(),
        confidence: 70,
    }
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

        assert_eq!(
            inconsistency.inconsistency_type,
            InconsistencyType::DifferentAnswers
        );
    }

    #[test]
    fn test_check_consistency_all_failed_is_not_consistent() {
        let mut inconsistencies = Vec::new();
        let results = vec![
            ResolverResult {
                resolver: "8.8.8.8".to_string(),
                success: false,
                latency_ms: 100,
                answers: Vec::new(),
                rcode: "FAILED".to_string(),
                error: Some("timeout".to_string()),
            },
            ResolverResult {
                resolver: "1.1.1.1".to_string(),
                success: false,
                latency_ms: 120,
                answers: Vec::new(),
                rcode: "FAILED".to_string(),
                error: Some("timeout".to_string()),
            },
        ];

        let consistent = check_consistency(&results, &mut inconsistencies);
        assert!(!consistent);
        assert!(!inconsistencies.is_empty());
    }
}
