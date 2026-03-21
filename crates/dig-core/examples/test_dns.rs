use dig_core::config::DigConfig;
use dig_core::lookup::DigLookup;
use tokio::runtime::Runtime;

fn main() {
    let config = DigConfig {
        name: "example.com".to_string(),
        ..Default::default()
    };
    
    println!("Config servers: {:?}", config.servers);
    println!("Config use_system_servers: {}", config.use_system_servers);
    
    let lookup = DigLookup::new(config);
    let rt = Runtime::new().unwrap();
    
    match rt.block_on(lookup.lookup()) {
        Ok(result) => {
            println!("Query successful!");
            println!("Server: {}", result.server);
        }
        Err(e) => {
            println!("Query failed: {:?}", e);
        }
    }
}
