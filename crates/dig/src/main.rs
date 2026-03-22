//! dig-rs - A modern, cross-platform DNS inspection tool
//!
//! Core differentiators:
//! - JSON-first output for automation
//! - Compare-first: multi-resolver comparison
//! - Diagnose-first: intelligent DNS health checks
//! - Cross-platform consistency

use std::process::ExitCode;
use std::time::Duration;

use clap::{Arg, ArgAction, Command};
use colored::Colorize;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use dig_core::config::{DigConfig, OutputFormat, ServerConfig, Transport};
use dig_core::diagnostic::{compare_resolvers, DiagnosticConfig, DnsDiagnostic};
use dig_core::error::DigError;
use dig_core::lookup::DigLookup;
use dig_core::trace::DnsTrace;
use dig_output::{
    DigFormatter, JsonFormatter, OutputFormatter, ShortFormatter, StructuredFormatter,
    TableFormatter,
};

/// Program version
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let matches = build_cli().get_matches();

    // Initialize logging
    if matches.get_flag("debug") {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::DEBUG)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set tracing subscriber");
    } else if matches.get_flag("verbose") {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set tracing subscriber");
    }

    // Run the main logic
    match run(&matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {}", "error:".red(), e);
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

/// Build the CLI command with modern, focused interface
fn build_cli() -> Command {
    Command::new("dig-rs")
        .about("A modern, cross-platform DNS inspection tool")
        .version(VERSION)
        .author("tianrking <tian.r.king@gmail.com>")
        .long_about(
            "dig-rs is a structured DNS inspection tool with built-in diagnostics.\n\
             \n\
             Core differentiators:\n\
             • JSON-first: Machine-readable output for automation\n\
             • Compare-first: Multi-resolver comparison in one command\n\
             • Diagnose-first: Intelligent DNS health analysis\n\
             • Cross-platform: Consistent on Linux, macOS, Windows\n\
             \n\
             Examples:\n\
               dig-rs example.com                    -- Basic query\n\
               dig-rs example.com --json             -- Structured JSON output\n\
               dig-rs example.com --health           -- Health check with diagnostics\n\
               dig-rs example.com --compare 8.8.8.8 1.1.1.1  -- Compare resolvers"
        )
        // Positional arguments (dig-compatible)
        // We collect all remaining arguments and parse them manually
        // to handle the @server, name, and type in any order
        .arg(Arg::new("args")
            .help("Arguments: [@SERVER] [NAME] [TYPE]")
            .value_name("ARGS")
            .num_args(1..))
        // ===== CORE DIFFERENTIATORS =====
        .arg(Arg::new("json")
            .long("json")
            .short('J')
            .help("Structured JSON output (machine-readable)")
            .action(ArgAction::SetTrue)
            .long_help(
                "Output in structured JSON format designed for automation and API integration.\n\
                 \n\
                 Schema includes:\n\
                 • HTTP-style status codes (200, 404, 500)\n\
                 • Records grouped by type\n\
                 • Performance metrics (latency, size)\n\
                 • Resolver information\n\
                 • DNS flags and metadata"
            ))
        .arg(Arg::new("health")
            .long("health")
            .short('H')
            .help("Run DNS health check with diagnostics")
            .action(ArgAction::SetTrue)
            .long_help(
                "Perform comprehensive DNS health analysis:\n\
                 • Resolution check\n\
                 • Performance analysis\n\
                 • Consistency across resolvers\n\
                 • Security (DNSSEC) check\n\
                 • CDN detection\n\
                 • Actionable recommendations"
            ))
        .arg(Arg::new("compare")
            .long("compare")
            .short('C')
            .help("Compare results across multiple resolvers")
            .value_name("RESOLVERS")
            .value_delimiter(' ')
            .num_args(1..)
            .long_help(
                "Query the same domain from multiple resolvers and compare results.\n\
                 \n\
                 Resolvers can be:\n\
                 • IP addresses: 8.8.8.8 1.1.1.1\n\
                 • 'system' to use system resolver\n\
                 • 'google' 'cloudflare' 'opendns' for presets\n\
                 \n\
                 Detects inconsistencies, latency differences, and failures."
            ))
        // ===== QUERY OPTIONS =====
        .arg(Arg::new("class")
            .short('c')
            .long("class")
            .help("Query class (IN, CH, HS)")
            .value_name("CLASS")
            .default_value("IN"))
        .arg(Arg::new("port")
            .short('p')
            .long("port")
            .help("Query port")
            .value_name("PORT")
            .default_value("53"))
        .arg(Arg::new("reverse")
            .short('x')
            .long("reverse")
            .help("Reverse lookup (PTR)")
            .value_name("IP"))
        // ===== TRANSPORT OPTIONS =====
        .arg(Arg::new("ipv4")
            .short('4')
            .long("ipv4")
            .help("Use IPv4 only")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("ipv6")
            .short('6')
            .long("ipv6")
            .help("Use IPv6 only")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("tcp")
            .long("tcp")
            .help("Use TCP")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("dot")
            .long("dot")
            .help("DNS-over-TLS")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("doh")
            .long("doh")
            .short('H')
            .help("DNS-over-HTTPS")
            .action(ArgAction::SetTrue))
        // ===== OUTPUT OPTIONS =====
        .arg(Arg::new("short")
            .long("short")
            .help("Short output (answers only)")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("table")
            .long("table")
            .help("Table format")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("no-comments")
            .long("no-comments")
            .help("Hide comments")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("no-stats")
            .long("no-stats")
            .help("Hide statistics")
            .action(ArgAction::SetTrue))
        // ===== DNS OPTIONS =====
        .arg(Arg::new("trace")
            .long("trace")
            .help("Trace delegation from root")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("dnssec")
            .long("dnssec")
            .help("Request DNSSEC records")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("norecurse")
            .long("norecurse")
            .help("Disable recursion")
            .action(ArgAction::SetTrue))
        // ===== TIMING OPTIONS =====
        .arg(Arg::new("timeout")
            .long("timeout")
            .help("Query timeout in seconds")
            .value_name("SECONDS")
            .default_value("5"))
        .arg(Arg::new("retries")
            .long("retries")
            .help("Number of retries")
            .value_name("COUNT")
            .default_value("3"))
        // ===== BATCH MODE =====
        .arg(Arg::new("file")
            .short('f')
            .long("file")
            .help("Read queries from file (batch mode)")
            .value_name("FILE"))
        // ===== DEBUG OPTIONS =====
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .help("Verbose output")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("debug")
            .short('d')
            .long("debug")
            .help("Debug output")
            .action(ArgAction::SetTrue))
}

/// Main program logic
fn run(matches: &clap::ArgMatches) -> Result<(), DigError> {
    // Check for batch mode first (doesn't require args)
    if matches.contains_id("file") {
        if let Some(file) = matches.get_one::<String>("file") {
            // Build minimal config for batch mode
            let config = if let Some(_args) = matches.get_many::<String>("args") {
                build_config(matches)?
            } else {
                DigConfig::default()
            };
            return run_batch(file, &config);
        }
    }

    // Build configuration for other modes
    let config = build_config(matches)?;

    // Health check mode
    if matches.get_flag("health") {
        return run_health_check(&config, matches);
    }

    // Compare mode
    if let Some(resolvers) = matches.get_many::<String>("compare") {
        return run_compare(&config, resolvers);
    }

    // Trace mode
    if config.trace {
        return run_trace(config);
    }

    // Standard query mode
    run_standard_query(config)
}

/// Run health check
fn run_health_check(config: &DigConfig, matches: &clap::ArgMatches) -> Result<(), DigError> {
    let diag_config = DiagnosticConfig::default();
    let diagnostic = DnsDiagnostic::new(diag_config);

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| DigError::ConfigError(format!("Failed to create runtime: {}", e)))?;

    let health = rt.block_on(diagnostic.health_check(&config.name))?;

    // Output based on format preference
    if matches.get_flag("json") {
        let json = serde_json::to_string_pretty(&health)
            .map_err(|e| DigError::QueryFailed(e.to_string()))?;
        println!("{}", json);
    } else {
        print_health_report(&health);
    }

    // Exit with error code if not healthy
    match health.status {
        dig_core::diagnostic::HealthStatus::Healthy => Ok(()),
        dig_core::diagnostic::HealthStatus::Warning => Ok(()),
        dig_core::diagnostic::HealthStatus::Critical => {
            Err(DigError::QueryFailed("Critical DNS issues detected".into()))
        }
        dig_core::diagnostic::HealthStatus::Failed => {
            Err(DigError::QueryFailed("DNS resolution failed".into()))
        }
    }
}

/// Print health check report
fn print_health_report(health: &dig_core::diagnostic::HealthCheck) {
    println!("{}", "DNS Health Check Report".bold().cyan());
    println!("Domain: {}", health.domain);
    println!(
        "Status: {}",
        match health.status {
            dig_core::diagnostic::HealthStatus::Healthy => "✓ Healthy".green(),
            dig_core::diagnostic::HealthStatus::Warning => "⚠ Warning".yellow(),
            dig_core::diagnostic::HealthStatus::Critical => "✗ Critical".red(),
            dig_core::diagnostic::HealthStatus::Failed => "✗ Failed".red(),
        }
    );
    println!();

    println!("{}", "Checks:".bold());
    for check in &health.checks {
        let status = match check.status {
            dig_core::diagnostic::CheckStatus::Pass => "✓".green(),
            dig_core::diagnostic::CheckStatus::Warning => "⚠".yellow(),
            dig_core::diagnostic::CheckStatus::Fail => "✗".red(),
            dig_core::diagnostic::CheckStatus::Skip => "○".dimmed(),
        };
        println!("  {} {} - {}", status, check.name, check.description);
        if let Some(value) = &check.value {
            println!("    Value: {}", value);
        }
    }

    if !health.issues.is_empty() {
        println!();
        println!("{}", "Issues Found:".bold().red());
        for issue in &health.issues {
            let severity = match issue.severity {
                dig_core::diagnostic::IssueSeverity::Info => "ℹ".blue(),
                dig_core::diagnostic::IssueSeverity::Warning => "⚠".yellow(),
                dig_core::diagnostic::IssueSeverity::Error => "✗".red(),
                dig_core::diagnostic::IssueSeverity::Critical => "✗".red().bold(),
            };
            println!(
                "  {} [{}] {}",
                severity,
                match issue.severity {
                    dig_core::diagnostic::IssueSeverity::Info => "INFO",
                    dig_core::diagnostic::IssueSeverity::Warning => "WARN",
                    dig_core::diagnostic::IssueSeverity::Error => "ERROR",
                    dig_core::diagnostic::IssueSeverity::Critical => "CRITICAL",
                },
                issue.description
            );
            if let Some(details) = &issue.details {
                println!("    {}", details);
            }
        }
    }

    if !health.recommendations.is_empty() {
        println!();
        println!("{}", "Recommendations:".bold().cyan());
        for rec in &health.recommendations {
            println!("  • {}", rec);
        }
    }
}

/// Run resolver comparison
fn run_compare<'a>(
    config: &DigConfig,
    resolvers: impl Iterator<Item = &'a String>,
) -> Result<(), DigError> {
    let resolver_list: Vec<String> = resolvers
        .map(|r| expand_resolver_alias(r.as_str()))
        .collect();

    if resolver_list.is_empty() {
        return Err(DigError::ConfigError(
            "At least one resolver required for comparison".into(),
        ));
    }

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| DigError::ConfigError(format!("Failed to create runtime: {}", e)))?;

    let result = rt.block_on(compare_resolvers(
        &config.name,
        &resolver_list,
        Some(&config.query_type),
    ))?;

    print_comparison_report(&result);

    // Exit with error if inconsistent
    if !result.consistent {
        Err(DigError::QueryFailed(
            "Resolver inconsistency detected".into(),
        ))
    } else {
        Ok(())
    }
}

/// Expand resolver aliases
fn expand_resolver_alias(resolver: &str) -> String {
    match resolver.to_lowercase().as_str() {
        "google" => "8.8.8.8".to_string(),
        "cloudflare" => "1.1.1.1".to_string(),
        "opendns" => "208.67.222.222".to_string(),
        "quad9" => "9.9.9.9".to_string(),
        "system" => {
            // Return system resolver
            // For now, use a placeholder
            "system".to_string()
        }
        _ => resolver.to_string(),
    }
}

/// Print comparison report
fn print_comparison_report(result: &dig_core::diagnostic::ComparisonResult) {
    println!("{}", "DNS Resolver Comparison".bold().cyan());
    println!("Domain: {} ({})", result.domain, result.query_type);
    println!();

    println!("{}", "Results:".bold());
    let max_resolver_len = result
        .resolver_results
        .iter()
        .map(|r| r.resolver.len())
        .max()
        .unwrap_or(0);

    for resolver_result in &result.resolver_results {
        let resolver = format!(
            "{:width$}",
            &resolver_result.resolver,
            width = max_resolver_len
        );

        if resolver_result.success {
            let latency = if resolver_result.latency_ms < 100 {
                format!("{}", resolver_result.latency_ms.to_string().green())
            } else if resolver_result.latency_ms < 300 {
                format!("{}", resolver_result.latency_ms.to_string().yellow())
            } else {
                format!("{}", resolver_result.latency_ms.to_string().red())
            };

            println!(
                "  {} → {} ({}ms)",
                resolver.cyan(),
                resolver_result.answers.join(" ").dimmed(),
                latency
            );
        } else {
            println!(
                "  {} → {}",
                resolver.red(),
                resolver_result
                    .error
                    .as_ref()
                    .unwrap_or(&"Failed".to_string())
                    .red()
            );
        }
    }

    if result.consistent {
        println!();
        println!("{} All resolvers returned consistent results", "✓".green());
    } else {
        println!();
        println!("{} Inconsistencies detected!", "⚠".yellow().bold());

        for inconsistency in &result.inconsistencies {
            println!("  • {}", inconsistency.description.yellow());
            println!("    Type: {:?}", inconsistency.inconsistency_type);
            println!("    Affected: {}", inconsistency.resolvers.join(", "));
        }
    }

    println!();
    println!(
        "Total query time: {}ms",
        result
            .resolver_results
            .iter()
            .map(|r| r.latency_ms)
            .max()
            .unwrap_or(0)
    );
}

/// Run batch mode
fn run_batch(file: &str, base_config: &DigConfig) -> Result<(), DigError> {
    use dig_core::batch::{BatchConfig, BatchProcessor};

    let batch_config = BatchConfig::default();
    let processor = BatchProcessor::new(base_config.clone(), batch_config)?;

    let results = processor.process_file(std::path::Path::new(file))?;

    for batch_result in &results {
        println!("Query: {}", batch_result.query.raw);

        match &batch_result.result {
            Ok(lookup_result) => {
                println!("Status: Success");
                println!("Time: {}ms", batch_result.exec_time_ms);

                // Format output
                let output = format_output(lookup_result, &base_config.output)?;
                println!("{}", output);
            }
            Err(e) => {
                println!("Status: Failed - {}", e);
            }
        }

        println!();
    }

    println!("Total queries: {}", results.len());
    Ok(())
}

/// Run standard query
fn run_standard_query(config: DigConfig) -> Result<(), DigError> {
    let lookup = DigLookup::new(config);

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| DigError::ConfigError(format!("Failed to create runtime: {}", e)))?;

    let result = rt.block_on(lookup.lookup())?;

    // Format and print output
    let config = lookup.config();
    let output = format_output(&result, &config.output)?;

    print!("{}", output);

    Ok(())
}

/// Build DigConfig from CLI arguments
fn build_config(matches: &clap::ArgMatches) -> Result<DigConfig, DigError> {
    let mut config = DigConfig::default();

    // Parse arguments manually to handle [@server] [name] [type] order
    if let Some(args) = matches.get_many::<String>("args") {
        let args: Vec<&String> = args.collect();

        for arg in &args {
            if arg.starts_with('@') {
                // Server argument
                if let Some(server_config) = ServerConfig::parse(arg) {
                    config.servers.push(server_config);
                    config.use_system_servers = false;
                }
            } else if config.name.is_empty() {
                // First non-@ argument is the domain name
                config.name = (**arg).clone();
            } else {
                // Second non-@ argument is the query type
                config.query_type = (**arg).clone();
            }
        }
    }

    // Set default query type if name is set but type is not
    if !config.name.is_empty() && config.query_type == "A" {
        // Keep the default A type
    }

    // Parse class
    if let Some(class) = matches.get_one::<String>("class") {
        config.query_class = class
            .parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid class: {}", class)))?;
    }

    // Parse transport options
    if matches.get_flag("ipv4") {
        config.ipv4 = true;
    }
    if matches.get_flag("ipv6") {
        config.ipv6 = true;
    }
    if matches.get_flag("tcp") {
        config.transport = Transport::Tcp;
    }
    if matches.get_flag("dot") {
        config.transport = Transport::Tls;
    }
    if matches.get_flag("doh") {
        config.transport = Transport::Https;
    }

    // Parse port
    if let Some(port) = matches.get_one::<String>("port") {
        let port: u16 = port
            .parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid port: {}", port)))?;
        for server in &mut config.servers {
            server.port = port;
        }
    }

    // Parse timeout
    if let Some(timeout) = matches.get_one::<String>("timeout") {
        let timeout: u64 = timeout
            .parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid timeout: {}", timeout)))?;
        config.timeout = Duration::from_secs(timeout);
    }

    // Parse retries
    if let Some(retries) = matches.get_one::<String>("retries") {
        config.retries = retries
            .parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid retries: {}", retries)))?;
    }

    // Parse output options
    if matches.get_flag("short") {
        config.output.format = OutputFormat::Short;
        config.output.comments = false;
        config.output.stats = false;
    } else if matches.get_flag("json") {
        config.output.format = OutputFormat::Json;
    } else if matches.get_flag("table") {
        config.output.format = OutputFormat::Table;
    }

    // Parse section visibility
    if matches.get_flag("no-comments") {
        config.output.comments = false;
    }
    if matches.get_flag("no-stats") {
        config.output.stats = false;
    }

    // Parse plus options
    if matches.get_flag("trace") {
        config.trace = true;
    }
    if matches.get_flag("dnssec") {
        config.dnssec.dnssec = true;
        config.dnssec.do_flag = true;
    }
    if matches.get_flag("norecurse") {
        config.recurse = false;
    }

    // Validate configuration
    if config.name.is_empty() {
        return Err(DigError::ConfigError(
            "No domain name specified. \
            Usage: dig-rs <domain> [--json] [--health] [--compare RESOLVERS...]"
                .into(),
        ));
    }

    Ok(config)
}

/// Format output based on configuration
fn format_output(
    result: &dig_core::lookup::LookupResult,
    output_config: &dig_core::config::OutputConfig,
) -> Result<String, DigError> {
    match output_config.format {
        OutputFormat::Standard => {
            let formatter = DigFormatter::new(dig_output::format::OutputConfig {
                comments: output_config.comments,
                question: true,
                answer: output_config.answer,
                authority: output_config.authority,
                additional: output_config.additional,
                stats: output_config.stats,
                ttl_units: output_config.ttl_units,
                color: output_config.color,
            });
            formatter
                .format(result)
                .map_err(|e| DigError::QueryFailed(e.to_string()))
        }
        OutputFormat::Json => {
            // Use structured JSON formatter
            let formatter = StructuredFormatter::new();
            formatter
                .format_lookup(result)
                .map_err(|e| DigError::QueryFailed(e.to_string()))
        }
        OutputFormat::Short => {
            let formatter = ShortFormatter::default();
            formatter
                .format(result)
                .map_err(|e| DigError::QueryFailed(e.to_string()))
        }
        OutputFormat::Table => {
            let formatter = TableFormatter::default();
            formatter
                .format(result)
                .map_err(|e| DigError::QueryFailed(e.to_string()))
        }
        OutputFormat::Yaml => {
            let formatter = JsonFormatter::default();
            formatter
                .format(result)
                .map_err(|e| DigError::QueryFailed(e.to_string()))
        }
        OutputFormat::Xml => Err(DigError::ConfigError("XML output not implemented".into())),
    }
}

/// Run trace mode
fn run_trace(config: DigConfig) -> Result<(), DigError> {
    let trace = DnsTrace::new(config.clone());

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| DigError::ConfigError(format!("Failed to create runtime: {}", e)))?;

    let result = rt.block_on(trace.trace())?;

    // Print trace results with enhanced formatting
    println!("{}", "DNS Trace Results".bold().cyan());
    println!("Query: {} ({})", result.query_name, result.query_type);
    println!("Total time: {}ms", result.total_time_ms);
    println!("Hops: {}", result.steps.len());
    println!();

    for (i, step) in result.steps.iter().enumerate() {
        let hop_num = format!("Hop {}", i + 1).bold();
        println!(
            "{}: {} ({})",
            hop_num,
            step.server.dimmed(),
            step.server_type.cyan()
        );

        // Show zone if available
        if let Some(zone) = &step.zone {
            println!("     Zone: {}", zone.dimmed());
        }

        // Show timing with color coding
        let time = step.query_time_ms;
        let time_str = if time < 50 {
            format!("{}ms", time).green()
        } else if time < 200 {
            format!("{}ms", time).yellow()
        } else {
            format!("{}ms", time).red()
        };
        println!("     Time: {}", time_str);

        // Show response status
        let status = if step.response.rcode == "NoError" {
            "✓".green()
        } else {
            "✗".red()
        };
        println!("     Status: {} {}", status, step.response.rcode);

        // Show answer if present
        if !step.response.answer.is_empty() {
            println!("     {}", "Answer:".bold());
            for a in &step.response.answer {
                println!("       • {}", a);
            }
        }

        // Show authority/referral
        if !step.response.authority.is_empty() {
            println!("     {}", "Referral:".bold());
            for a in &step.response.authority {
                println!("       → {}", a);
            }
        }

        // Show additional/glue records
        if !step.response.additional.is_empty() {
            println!("     {}", "Glue:".bold());
            for a in &step.response.additional {
                println!("       + {}", a);
            }
        }

        println!();
    }

    // Summary statistics
    println!("{}", "Summary".bold().cyan());
    let total_time = result.total_time_ms;
    let avg_time = if result.steps.is_empty() {
        0
    } else {
        result.steps.iter().map(|s| s.query_time_ms).sum::<u64>() / result.steps.len() as u64
    };
    let max_time = result
        .steps
        .iter()
        .map(|s| s.query_time_ms)
        .max()
        .unwrap_or(0);

    println!("  Total time: {}ms", total_time);
    println!("  Average per hop: {}ms", avg_time);
    println!("  Slowest hop: {}ms", max_time);
    println!("  Hops to answer: {}", result.steps.len());

    if let Some(final_answer) = &result.final_answer {
        println!();
        println!("{}", "Final Answer:".bold());
        println!("  Records: {}", final_answer.message.answer.len());
        println!("  Server: {}", final_answer.server);

        // Show actual answer records
        if !final_answer.message.answer.is_empty() {
            println!();
            for record in &final_answer.message.answer {
                println!(
                    "  {} {} IN {} {}",
                    record.name, record.ttl, record.rtype, record.rdata
                );
            }
        }
    } else {
        println!();
        println!("{}", "Warning: No final answer received".yellow());
    }

    println!(";; Total trace time: {}ms", result.total_time_ms);

    Ok(())
}
