//! dig-rs - A modern, cross-platform DNS inspection tool.
//!
//! This binary supports two invocation styles:
//! 1) New subcommand style: `dig-rs query|health|compare|trace|batch ...`
//! 2) Legacy dig-compatible style: `dig-rs [@SERVER] NAME [TYPE] [OPTIONS]`

use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Arg, ArgAction, ArgMatches, Command};
use colored::Colorize;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use dig_core::config::{DigConfig, OutputFormat, ServerConfig, Transport};
use dig_core::diagnostic::{compare_resolvers, DiagnosticConfig, DnsDiagnostic};
use dig_core::error::DigError;
use dig_core::lookup::DigLookup;
use dig_core::resolver::ResolverConfig;
use dig_core::trace::DnsTrace;
use dig_output::{
    DigFormatter, JsonFormatter, OutputFormatter, ShortFormatter, StructuredFormatter,
    TableFormatter,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const SCHEMA_VERSION: &str = "dig-rs/v1";

fn main() -> ExitCode {
    let matches = build_cli().get_matches();

    init_logging(&matches);

    match run(&matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} {}", "error:".red(), e);
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

fn init_logging(matches: &ArgMatches) {
    let level = if matches.get_flag("debug") {
        Some(Level::DEBUG)
    } else if matches.get_flag("verbose") {
        Some(Level::INFO)
    } else {
        None
    };

    if let Some(max_level) = level {
        let subscriber = FmtSubscriber::builder().with_max_level(max_level).finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set tracing subscriber");
    }
}

fn build_cli() -> Command {
    let legacy = add_common_query_options(
        Command::new("dig-rs")
            .about("A modern, cross-platform DNS inspection tool")
            .version(VERSION)
            .author("tianrking <tian.r.king@gmail.com>")
            .long_about(
                "dig-rs is a structured DNS inspection tool with built-in diagnostics.\n\
                 \n\
                 Invocation styles:\n\
                 - Subcommands: query, health, compare, trace, batch\n\
                 - Legacy compatible: dig-rs [@SERVER] NAME [TYPE] [OPTIONS]\n\
                 \n\
                 Examples:\n\
                   dig-rs query @8.8.8.8 example.com A --json\n\
                   dig-rs health example.com --json\n\
                   dig-rs compare example.com A --resolvers system google cloudflare\n\
                   dig-rs trace example.com\n\
                   dig-rs batch --file queries.txt\n\
                   dig-rs @1.1.1.1 example.com AAAA --short",
            )
            .arg(
                Arg::new("legacy_args")
                    .help("Legacy args: [@SERVER] [NAME] [TYPE]")
                    .value_name("ARGS")
                    .num_args(1..),
            )
            .arg(
                Arg::new("health")
                    .long("health")
                    .help("Run DNS health check (legacy mode)")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("compare")
                    .long("compare")
                    .help("Compare result across resolvers (legacy mode)")
                    .value_name("RESOLVERS")
                    .num_args(1..),
            )
            .arg(
                Arg::new("allow-inconsistent")
                    .long("allow-inconsistent")
                    .help("Do not return non-zero exit code for legacy --compare inconsistencies")
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("file")
                    .short('f')
                    .long("file")
                    .help("Read queries from file (legacy batch mode)")
                    .value_name("FILE"),
            ),
    )
    .arg(
        Arg::new("verbose")
            .short('v')
            .long("verbose")
            .global(true)
            .help("Verbose output")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("debug")
            .short('d')
            .long("debug")
            .global(true)
            .help("Debug output")
            .action(ArgAction::SetTrue),
    );

    legacy
        .subcommand(build_query_subcommand())
        .subcommand(build_health_subcommand())
        .subcommand(build_compare_subcommand())
        .subcommand(build_trace_subcommand())
        .subcommand(build_batch_subcommand())
}

fn build_query_subcommand() -> Command {
    add_common_query_options(
        Command::new("query").about("Run a standard DNS query").arg(
            Arg::new("args")
                .help("Arguments: [@SERVER] [NAME] [TYPE]")
                .value_name("ARGS")
                .num_args(1..),
        ),
    )
}

fn build_health_subcommand() -> Command {
    Command::new("health")
        .about("Run DNS health diagnostics for a domain")
        .arg(
            Arg::new("name")
                .help("Domain to diagnose")
                .value_name("NAME")
                .required(true),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .short('J')
                .help("Output health report as JSON")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("output-file")
                .long("output-file")
                .help("Write output to file as well")
                .value_name("FILE"),
        )
}

fn build_compare_subcommand() -> Command {
    Command::new("compare")
        .about("Compare query results across multiple resolvers")
        .arg(
            Arg::new("name")
                .help("Domain to query")
                .value_name("NAME")
                .required(true),
        )
        .arg(
            Arg::new("type")
                .help("Record type (A, AAAA, MX, TXT, ...)")
                .value_name("TYPE")
                .required(false),
        )
        .arg(
            Arg::new("resolvers")
                .long("resolvers")
                .help("Resolver list: IPs or aliases(system/google/cloudflare/opendns/quad9)")
                .value_name("RESOLVERS")
                .num_args(1..)
                .required(true),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .short('J')
                .help("Output comparison report as structured JSON")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("allow-inconsistent")
                .long("allow-inconsistent")
                .help("Do not return non-zero exit code when resolvers are inconsistent")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("output-file")
                .long("output-file")
                .help("Write output to file as well")
                .value_name("FILE"),
        )
}

fn build_trace_subcommand() -> Command {
    add_common_query_options(
        Command::new("trace")
            .about("Trace DNS delegation from root to authoritative answer")
            .arg(
                Arg::new("args")
                    .help("Arguments: [@SERVER] [NAME] [TYPE]")
                    .value_name("ARGS")
                    .num_args(1..),
            ),
    )
}

fn build_batch_subcommand() -> Command {
    add_common_query_options(
        Command::new("batch")
            .about("Run batch queries from a file")
            .arg(
                Arg::new("file")
                    .short('f')
                    .long("file")
                    .help("Path to batch query file")
                    .value_name("FILE")
                    .required(true),
            )
            .arg(
                Arg::new("args")
                    .help("Optional defaults: [@SERVER] [TYPE]")
                    .value_name("ARGS")
                    .num_args(0..),
            ),
    )
}

fn add_common_query_options(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("json")
            .long("json")
            .short('J')
            .help("Structured JSON output")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("class")
            .short('c')
            .long("class")
            .help("Query class (IN, CH, HS)")
            .value_name("CLASS")
            .default_value("IN"),
    )
    .arg(
        Arg::new("port")
            .short('p')
            .long("port")
            .help("Query port")
            .value_name("PORT")
            .default_value("53"),
    )
    .arg(
        Arg::new("reverse")
            .short('x')
            .long("reverse")
            .help("Reverse lookup (PTR)")
            .value_name("IP"),
    )
    .arg(
        Arg::new("ipv4")
            .short('4')
            .long("ipv4")
            .help("Use IPv4 only")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("ipv6")
            .short('6')
            .long("ipv6")
            .help("Use IPv6 only")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("tcp")
            .long("tcp")
            .help("Use TCP transport")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("dot")
            .long("dot")
            .help("Use DNS-over-TLS")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("doh")
            .long("doh")
            .help("Use DNS-over-HTTPS")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("short")
            .long("short")
            .help("Short output (answers only)")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("table")
            .long("table")
            .help("Table output")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("no-comments")
            .long("no-comments")
            .help("Hide comments in standard output")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("no-stats")
            .long("no-stats")
            .help("Hide stats in standard output")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("trace")
            .long("trace")
            .help("Enable trace mode (legacy style)")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("dnssec")
            .long("dnssec")
            .help("Request DNSSEC records")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("norecurse")
            .long("norecurse")
            .help("Disable recursion")
            .action(ArgAction::SetTrue),
    )
    .arg(
        Arg::new("timeout")
            .long("timeout")
            .help("Query timeout in seconds")
            .value_name("SECONDS")
            .default_value("5"),
    )
    .arg(
        Arg::new("retries")
            .long("retries")
            .help("Number of retries")
            .value_name("COUNT")
            .default_value("3"),
    )
    .arg(
        Arg::new("output-file")
            .long("output-file")
            .help("Write output to file as well")
            .value_name("FILE"),
    )
}

fn run(matches: &ArgMatches) -> Result<(), DigError> {
    match matches.subcommand() {
        Some(("query", sub)) => run_query_mode(sub, "args"),
        Some(("health", sub)) => run_health_subcommand(sub),
        Some(("compare", sub)) => run_compare_subcommand(sub),
        Some(("trace", sub)) => run_trace_subcommand(sub),
        Some(("batch", sub)) => run_batch_subcommand(sub),
        _ => run_legacy_mode(matches),
    }
}

fn run_query_mode(matches: &ArgMatches, args_key: &str) -> Result<(), DigError> {
    let config = build_config(matches, args_key, true)?;
    let output_file = matches.get_one::<String>("output-file");

    if config.trace {
        return run_trace(config, output_file);
    }

    run_standard_query(config, output_file)
}

fn run_health_subcommand(matches: &ArgMatches) -> Result<(), DigError> {
    let name = matches
        .get_one::<String>("name")
        .ok_or_else(|| DigError::ConfigError("Domain name is required".into()))?;
    let mut config = DigConfig::new(name.clone());
    config.output.format = if matches.get_flag("json") {
        OutputFormat::Json
    } else {
        OutputFormat::Standard
    };
    run_health_check(
        &config,
        matches.get_flag("json"),
        matches.get_one::<String>("output-file"),
    )
}

fn run_compare_subcommand(matches: &ArgMatches) -> Result<(), DigError> {
    let name = matches
        .get_one::<String>("name")
        .ok_or_else(|| DigError::ConfigError("Domain name is required".into()))?;
    let query_type = matches
        .get_one::<String>("type")
        .cloned()
        .unwrap_or_else(|| "A".to_string());
    let resolvers = matches
        .get_many::<String>("resolvers")
        .ok_or_else(|| DigError::ConfigError("At least one resolver is required".into()))?;

    let config = DigConfig::new(name.clone()).with_query_type(query_type);
    run_compare(
        &config,
        resolvers,
        matches.get_flag("json"),
        matches.get_flag("allow-inconsistent"),
        matches.get_one::<String>("output-file"),
    )
}

fn run_trace_subcommand(matches: &ArgMatches) -> Result<(), DigError> {
    let mut config = build_config(matches, "args", true)?;
    config.trace = true;
    run_trace(config, matches.get_one::<String>("output-file"))
}

fn run_batch_subcommand(matches: &ArgMatches) -> Result<(), DigError> {
    let file = matches
        .get_one::<String>("file")
        .ok_or_else(|| DigError::ConfigError("Batch file is required".into()))?;
    let base_config = build_config(matches, "args", false)?;
    run_batch(file, &base_config)
}

fn run_legacy_mode(matches: &ArgMatches) -> Result<(), DigError> {
    if let Some(file) = matches.get_one::<String>("file") {
        let config = build_config(matches, "legacy_args", false)?;
        return run_batch(file, &config);
    }

    if matches.get_flag("health") {
        let config = build_config(matches, "legacy_args", true)?;
        return run_health_check(
            &config,
            matches.get_flag("json"),
            matches.get_one::<String>("output-file"),
        );
    }

    if let Some(resolvers) = matches.get_many::<String>("compare") {
        let config = build_config(matches, "legacy_args", true)?;
        return run_compare(
            &config,
            resolvers,
            matches.get_flag("json"),
            matches.get_flag("allow-inconsistent"),
            matches.get_one::<String>("output-file"),
        );
    }

    run_query_mode(matches, "legacy_args")
}

fn run_health_check(
    config: &DigConfig,
    as_json: bool,
    output_file: Option<&String>,
) -> Result<(), DigError> {
    let diag_config = DiagnosticConfig::default();
    let diagnostic = DnsDiagnostic::new(diag_config);

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| DigError::ConfigError(format!("Failed to create runtime: {}", e)))?;

    let health = rt.block_on(diagnostic.health_check(&config.name))?;

    if as_json {
        let json = serde_json::to_string_pretty(&health)
            .map_err(|e| DigError::QueryFailed(e.to_string()))?;
        write_output(output_file, &json)?;
        println!("{}", json);
    } else {
        print_health_report(&health);
    }

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

fn print_health_report(health: &dig_core::diagnostic::HealthCheck) {
    println!("{}", "DNS Health Check Report".bold().cyan());
    println!("Domain: {}", health.domain);
    println!(
        "Status: {}",
        match health.status {
            dig_core::diagnostic::HealthStatus::Healthy => "[OK] Healthy".green(),
            dig_core::diagnostic::HealthStatus::Warning => "[WARN] Warning".yellow(),
            dig_core::diagnostic::HealthStatus::Critical => "[CRIT] Critical".red(),
            dig_core::diagnostic::HealthStatus::Failed => "[FAIL] Failed".red(),
        }
    );
    println!();

    println!("{}", "Checks:".bold());
    for check in &health.checks {
        let status = match check.status {
            dig_core::diagnostic::CheckStatus::Pass => "[OK]".green(),
            dig_core::diagnostic::CheckStatus::Warning => "[WARN]".yellow(),
            dig_core::diagnostic::CheckStatus::Fail => "[FAIL]".red(),
            dig_core::diagnostic::CheckStatus::Skip => "[SKIP]".dimmed(),
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
                dig_core::diagnostic::IssueSeverity::Info => "[INFO]".blue(),
                dig_core::diagnostic::IssueSeverity::Warning => "[WARN]".yellow(),
                dig_core::diagnostic::IssueSeverity::Error => "[ERROR]".red(),
                dig_core::diagnostic::IssueSeverity::Critical => "[CRIT]".red().bold(),
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
            println!("  - {}", rec);
        }
    }
}

fn run_compare<'a>(
    config: &DigConfig,
    resolvers: impl Iterator<Item = &'a String>,
    as_json: bool,
    allow_inconsistent: bool,
    output_file: Option<&String>,
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

    if as_json {
        let data =
            serde_json::to_value(&result).map_err(|e| DigError::QueryFailed(e.to_string()))?;
        emit_json_envelope("compare", data, output_file)?;
    } else {
        print_comparison_report(&result);
    }

    if !allow_inconsistent && !result.consistent {
        Err(DigError::QueryFailed(
            "Resolver inconsistency detected".into(),
        ))
    } else {
        Ok(())
    }
}

fn expand_resolver_alias(resolver: &str) -> String {
    match resolver.to_lowercase().as_str() {
        "google" => "8.8.8.8".to_string(),
        "cloudflare" => "1.1.1.1".to_string(),
        "opendns" => "208.67.222.222".to_string(),
        "quad9" => "9.9.9.9".to_string(),
        "system" => system_resolver_for_compare(),
        _ => resolver.to_string(),
    }
}

fn system_resolver_for_compare() -> String {
    ResolverConfig::from_system()
        .default_nameserver()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "8.8.8.8".to_string())
}

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
                "  {} -> {} ({}ms)",
                resolver.cyan(),
                resolver_result.answers.join(" ").dimmed(),
                latency
            );
        } else {
            println!(
                "  {} -> {}",
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
        println!(
            "{} All resolvers returned consistent results",
            "[OK]".green()
        );
    } else {
        println!();
        println!("{} Inconsistencies detected", "[WARN]".yellow().bold());

        for inconsistency in &result.inconsistencies {
            println!("  - {}", inconsistency.description.yellow());
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

fn run_standard_query(config: DigConfig, output_file: Option<&String>) -> Result<(), DigError> {
    let lookup = DigLookup::new(config);

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| DigError::ConfigError(format!("Failed to create runtime: {}", e)))?;

    let result = rt.block_on(lookup.lookup())?;
    let config = lookup.config();
    let output = format_output(&result, &config.output)?;
    write_output(output_file, &output)?;
    print!("{}", output);
    Ok(())
}

fn build_config(
    matches: &ArgMatches,
    args_key: &str,
    require_name: bool,
) -> Result<DigConfig, DigError> {
    let mut config = DigConfig::default();

    if let Some(args) = matches.get_many::<String>(args_key) {
        for arg in args {
            if arg.starts_with('@') {
                if let Some(server_config) = ServerConfig::parse(arg) {
                    config.servers.push(server_config);
                    config.use_system_servers = false;
                }
            } else if config.name.is_empty() {
                config.name = arg.clone();
            } else if config.query_type == "A" {
                config.query_type = arg.clone();
            }
        }
    }

    if let Some(reverse_ip) = matches.get_one::<String>("reverse") {
        config = config.with_reverse(reverse_ip.clone());
    }

    if let Some(class) = matches.get_one::<String>("class") {
        config.query_class = class
            .parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid class: {}", class)))?;
    }

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

    if let Some(port) = matches.get_one::<String>("port") {
        let port: u16 = port
            .parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid port: {}", port)))?;
        for server in &mut config.servers {
            server.port = port;
        }
    }

    if let Some(timeout) = matches.get_one::<String>("timeout") {
        let timeout: u64 = timeout
            .parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid timeout: {}", timeout)))?;
        config.timeout = Duration::from_secs(timeout);
    }

    if let Some(retries) = matches.get_one::<String>("retries") {
        config.retries = retries
            .parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid retries: {}", retries)))?;
    }

    if matches.get_flag("short") {
        config.output.format = OutputFormat::Short;
        config.output.comments = false;
        config.output.stats = false;
    } else if matches.get_flag("json") {
        config.output.format = OutputFormat::Json;
    } else if matches.get_flag("table") {
        config.output.format = OutputFormat::Table;
    }

    if matches.get_flag("no-comments") {
        config.output.comments = false;
    }
    if matches.get_flag("no-stats") {
        config.output.stats = false;
    }

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

    if require_name && config.name.is_empty() {
        return Err(DigError::ConfigError(
            "No domain name specified. Use `dig-rs query <domain>` or legacy `dig-rs <domain>`."
                .into(),
        ));
    }

    Ok(config)
}

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

fn run_trace(config: DigConfig, output_file: Option<&String>) -> Result<(), DigError> {
    let trace = DnsTrace::new(config.clone());

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| DigError::ConfigError(format!("Failed to create runtime: {}", e)))?;

    let result = rt.block_on(trace.trace())?;

    if config.output.format == OutputFormat::Json {
        let data =
            serde_json::to_value(&result).map_err(|e| DigError::QueryFailed(e.to_string()))?;
        emit_json_envelope("trace", data, output_file)?;
        return Ok(());
    }

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

        if let Some(zone) = &step.zone {
            println!("     Zone: {}", zone.dimmed());
        }

        let time = step.query_time_ms;
        let time_str = if time < 50 {
            format!("{}ms", time).green()
        } else if time < 200 {
            format!("{}ms", time).yellow()
        } else {
            format!("{}ms", time).red()
        };
        println!("     Time: {}", time_str);

        let status = if step.response.rcode == "NoError" {
            "[OK]".green()
        } else {
            "[FAIL]".red()
        };
        println!("     Status: {} {}", status, step.response.rcode);

        if !step.response.answer.is_empty() {
            println!("     {}", "Answer:".bold());
            for a in &step.response.answer {
                println!("       - {}", a);
            }
        }

        if !step.response.authority.is_empty() {
            println!("     {}", "Referral:".bold());
            for a in &step.response.authority {
                println!("       -> {}", a);
            }
        }

        if !step.response.additional.is_empty() {
            println!("     {}", "Glue:".bold());
            for a in &step.response.additional {
                println!("       + {}", a);
            }
        }

        println!();
    }

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

fn emit_json_envelope(
    mode: &str,
    data: serde_json::Value,
    output_file: Option<&String>,
) -> Result<(), DigError> {
    let payload = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "generated_at_unix_ms": unix_ms_now(),
        "data": data
    });
    let json =
        serde_json::to_string_pretty(&payload).map_err(|e| DigError::QueryFailed(e.to_string()))?;
    write_output(output_file, &json)?;
    println!("{}", json);
    Ok(())
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn write_output(output_file: Option<&String>, content: &str) -> Result<(), DigError> {
    if let Some(path) = output_file {
        std::fs::write(path, content).map_err(|e| {
            DigError::ConfigError(format!("Failed to write output file {}: {}", path, e))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_alias_known_presets() {
        assert_eq!(expand_resolver_alias("google"), "8.8.8.8");
        assert_eq!(expand_resolver_alias("cloudflare"), "1.1.1.1");
        assert_eq!(expand_resolver_alias("opendns"), "208.67.222.222");
        assert_eq!(expand_resolver_alias("quad9"), "9.9.9.9");
    }

    #[test]
    fn compare_alias_system_resolves_to_address_like_value() {
        let value = expand_resolver_alias("system");
        assert_ne!(value, "system");
        assert!(!value.trim().is_empty());
    }
}
