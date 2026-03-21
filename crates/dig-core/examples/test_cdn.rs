use dig_core::config::{DigConfig, ServerConfig};
use dig_core::diagnostic::DnsDiagnostic;
use dig_core::lookup::DigLookup;
use tokio::runtime::Runtime;

fn main() {
    let mut config = DigConfig::new("discord.com");
    // Add Google DNS as explicit server
    config.servers.push(ServerConfig::new("8.8.8.8"));

    let lookup = DigLookup::new(config.clone());

    let rt = Runtime::new().unwrap();
    let result = rt.block_on(lookup.lookup()).unwrap();

    println!("Answer records:");
    for ans in &result.message.answer {
        println!("  rdata: {}", ans.rdata);
        println!("  rdata lower: {}", ans.rdata.to_lowercase());
    }

    let diag = DnsDiagnostic::new(Default::default());
    let cdn = diag.detect_cdn_from_result(&result);
    println!("\nDetected CDN: {}", cdn);
}
