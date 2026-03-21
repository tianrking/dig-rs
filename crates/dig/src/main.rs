//! dig-rs - A modern, cross-platform DNS lookup utility
//!
//! A reimagining of the classic dig tool in Rust with:
//! - Cross-platform support (Windows, Linux, macOS)
//! - JSON output for programmatic consumption
//! - Modern CLI with helpful error messages
//! - Consistent behavior across all platforms

use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Arg, ArgAction, Command};
use tracing::{debug, Level};
use tracing_subscriber::FmtSubscriber;

use dig_core::config::{DigConfig, OutputFormat, QueryClass, ServerConfig, Transport};
use dig_core::error::DigError;
use dig_core::lookup::DigLookup;
use dig_core::trace::DnsTrace;
use dig_output::{DigFormatter, JsonFormatter, ShortFormatter, TableFormatter, OutputFormatter};

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
            eprintln!(";; error: {}", e);
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

/// Build the CLI command
fn build_cli() -> Command {
    Command::new("dig")
        .about("A modern, cross-platform DNS lookup utility")
        .version(VERSION)
        .author("dig-rs contributors")
        .arg(Arg::new("server")
            .help("DNS server to query (prefix with @)")
            .value_name("@SERVER")
            .index(1))
        .arg(Arg::new("name")
            .help("Domain name to query")
            .value_name("NAME")
            .index(2))
        .arg(Arg::new("type")
            .help("Query type (A, AAAA, MX, etc.)")
            .value_name("TYPE")
            .index(3))
        .arg(Arg::new("class")
            .help("Query class (IN, CH, HS)")
            .short('c')
            .long("class")
            .value_name("CLASS")
            .default_value("IN"))
        // Transport options
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
        .arg(Arg::new("udp")
            .long("udp")
            .help("Use UDP (default)")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("port")
            .short('p')
            .long("port")
            .help("Query port")
            .value_name("PORT")
            .default_value("53"))
        .arg(Arg::new("bind")
            .short('b')
            .long("bind")
            .help("Bind to source address")
            .value_name("ADDRESS"))
        // Query options
        .arg(Arg::new("reverse")
            .short('x')
            .long("reverse")
            .help("Reverse lookup (PTR)")
            .value_name("IP"))
        .arg(Arg::new("query_type")
            .short('t')
            .long("type")
            .help("Query type")
            .value_name("TYPE"))
        .arg(Arg::new("query_name")
            .short('q')
            .long("query")
            .help("Query name")
            .value_name("NAME"))
        // Output options
        .arg(Arg::new("short")
            .long("short")
            .help("Short output")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("json")
            .long("json")
            .help("JSON output")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("yaml")
            .long("yaml")
            .help("YAML output")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("table")
            .long("table")
            .help("Table output")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("no-comments")
            .long("no-comments")
            .help("Hide comments")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("no-question")
            .long("no-question")
            .help("Hide question section")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("no-answer")
            .long("no-answer")
            .help("Hide answer section")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("no-authority")
            .long("no-authority")
            .help("Hide authority section")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("no-additional")
            .long("no-additional")
            .help("Hide additional section")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("no-stats")
            .long("no-stats")
            .help("Hide statistics")
            .action(ArgAction::SetTrue))
        // Plus options
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
        .arg(Arg::new("aaonly")
            .long("aaonly")
            .help("Authoritative answer only")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("bufsize")
            .long("bufsize")
            .help("EDNS buffer size")
            .value_name("SIZE"))
        .arg(Arg::new("edns")
            .long("edns")
            .help("EDNS version")
            .value_name("VERSION"))
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
        // Debug options
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
    // Build configuration
    let config = build_config(matches)?;

    // If trace mode, run trace
    if config.trace {
        return run_trace(config);
    }

    // Create lookup
    let lookup = DigLookup::new(config);

    // Run the async lookup in a tokio runtime
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

    // Parse server (@server)
    if let Some(server_arg) = matches.get_one::<String>("server") {
        let server_str = server_arg.trim_start_matches('@');
        if let Some(server_config) = ServerConfig::parse(&format!("@{}", server_str)) {
            config.servers.push(server_config);
            config.use_system_servers = false;
        }
    }

    // Parse name
    if let Some(name) = matches.get_one::<String>("name") {
        config.name = name.clone();
    } else if let Some(name) = matches.get_one::<String>("query_name") {
        config.name = name.clone();
    }

    // Parse query type
    if let Some(qtype) = matches.get_one::<String>("type") {
        config.query_type = qtype.clone();
    } else if let Some(qtype) = matches.get_one::<String>("query_type") {
        config.query_type = qtype.clone();
    } else if !config.name.is_empty() {
        config.query_type = "A".to_string();
    }

    // Parse class
    if let Some(class) = matches.get_one::<String>("class") {
        config.query_class = class.parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid class: {}", class)))?;
    }

    // Parse reverse lookup
    if let Some(ip) = matches.get_one::<String>("reverse") {
        config.name = ip.clone();
        config.query_type = "PTR".to_string();
        config.reverse = true;
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

    // Parse port
    if let Some(port) = matches.get_one::<String>("port") {
        let port: u16 = port.parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid port: {}", port)))?;
        for server in &mut config.servers {
            server.port = port;
        }
    }

    // Parse bind address
    if let Some(bind) = matches.get_one::<String>("bind") {
        config.bind_address = Some(bind.parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid bind address: {}", bind)))?);
    }

    // Parse timeout
    if let Some(timeout) = matches.get_one::<String>("timeout") {
        let timeout: u64 = timeout.parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid timeout: {}", timeout)))?;
        config.timeout = Duration::from_secs(timeout);
    }

    // Parse retries
    if let Some(retries) = matches.get_one::<String>("retries") {
        config.retries = retries.parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid retries: {}", retries)))?;
    }

    // Parse output options
    if matches.get_flag("short") {
        config.output.format = OutputFormat::Short;
        config.output.comments = false;
        config.output.stats = false;
    } else if matches.get_flag("json") {
        config.output.format = OutputFormat::Json;
    } else if matches.get_flag("yaml") {
        config.output.format = OutputFormat::Yaml;
    } else if matches.get_flag("table") {
        config.output.format = OutputFormat::Table;
    }

    // Parse section visibility
    if matches.get_flag("no-comments") {
        config.output.comments = false;
    }
    if matches.get_flag("no-question") {
        config.output.question = false;
    }
    if matches.get_flag("no-answer") {
        config.output.answer = false;
    }
    if matches.get_flag("no-authority") {
        config.output.authority = false;
    }
    if matches.get_flag("no-additional") {
        config.output.additional = false;
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
    if matches.get_flag("aaonly") {
        config.aa_only = true;
    }

    // Parse EDNS options
    if let Some(bufsize) = matches.get_one::<String>("bufsize") {
        config.edns.udp_size = bufsize.parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid buffer size: {}", bufsize)))?;
    }
    if let Some(edns) = matches.get_one::<String>("edns") {
        config.edns.version = edns.parse()
            .map_err(|_| DigError::ConfigError(format!("Invalid EDNS version: {}", edns)))?;
    }

    // Validate configuration
    if config.name.is_empty() {
        return Err(DigError::ConfigError("No domain name specified".into()));
    }

    Ok(config)
}

/// Format output based on configuration
fn format_output(
    result: &dig_core::lookup::LookupResult,
    output_config: &dig_core::config::OutputConfig,
) -> Result<String, DigError> {
    use std::io;

    match output_config.format {
        OutputFormat::Standard => {
            let formatter = DigFormatter::new(dig_output::format::OutputConfig {
                comments: output_config.comments,
                question: output_config.question,
                answer: output_config.answer,
                authority: output_config.authority,
                additional: output_config.additional,
                stats: output_config.stats,
                ttl_units: output_config.ttl_units,
                color: output_config.color,
            });
            formatter.format(result)
                .map_err(|e| DigError::QueryFailed(e.to_string()))
        }
        OutputFormat::Json => {
            let formatter = JsonFormatter::default();
            formatter.format(result)
                .map_err(|e| DigError::QueryFailed(e.to_string()))
        }
        OutputFormat::Short => {
            let formatter = ShortFormatter::default();
            formatter.format(result)
                .map_err(|e| DigError::QueryFailed(e.to_string()))
        }
        OutputFormat::Table => {
            let formatter = TableFormatter::default();
            formatter.format(result)
                .map_err(|e| DigError::QueryFailed(e.to_string()))
        }
        OutputFormat::Yaml => {
            // YAML not implemented, fall back to JSON
            let formatter = JsonFormatter::default();
            formatter.format(result)
                .map_err(|e| DigError::QueryFailed(e.to_string()))
        }
        OutputFormat::Xml => {
            Err(DigError::ConfigError("XML output not implemented".into()))
        }
    }
}

/// Run trace mode
fn run_trace(mut config: DigConfig) -> Result<(), DigError> {
    let trace = DnsTrace::new(config.clone());

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| DigError::ConfigError(format!("Failed to create runtime: {}", e)))?;

    let result = rt.block_on(trace.trace())?;

    // Print trace results
    println!(";; Tracing query for {} {}", result.query_name, result.query_type);
    println!();

    for (i, step) in result.steps.iter().enumerate() {
        println!(";; Step {}: Querying {} ({}ms)",
            i + 1, step.server, step.query_time_ms);
        println!(";;   Query: {}", step.query);
        println!(";;   Response: {}", step.response.rcode);

        if !step.response.answer.is_empty() {
            println!(";;   Answer:");
            for a in &step.response.answer {
                println!(";;     {}", a);
            }
        }

        if !step.response.authority.is_empty() {
            println!(";;   Authority (referral):");
            for a in &step.response.authority {
                println!(";;     {}", a);
            }
        }

        println!();
    }

    if let Some(final_answer) = &result.final_answer {
        println!(";; Final Answer:");
        let output = format_output(final_answer, &config.output)?;
        println!("{}", output);
    } else {
        println!(";; No final answer received");
    }

    println!(";; Total trace time: {}ms", result.total_time_ms);

    Ok(())
}
