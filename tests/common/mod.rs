// Common test utilities for dig-rs

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Test DNS servers
pub const TEST_SERVERS: &[&str] = &[
    "8.8.8.8",      // Google DNS
    "1.1.1.1",      // Cloudflare DNS
    "208.67.222.222", // OpenDNS
];

/// Test domains
pub const TEST_DOMAINS: &[&str] = &[
    "example.com",
    "google.com",
    "cloudflare.com",
    "github.com",
];

/// Test IP addresses for reverse lookup
pub const TEST_IPS: &[&str] = &[
    "8.8.8.8",
    "1.1.1.1",
    "208.67.222.222",
];

/// Convert an IP address to its PTR reverse lookup name
pub fn ip_to_ptr(ip: &str) -> String {
    if let Ok(addr) = Ipv4Addr::from_str(ip) {
        let octets = addr.octets();
        format!("{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0])
    } else if let Ok(addr) = Ipv6Addr::from_str(ip) {
        // IPv6 PTR notation (nibble format)
        let segments = addr.segments();
        let mut result = String::new();

        for &s in segments.iter() {
            let high = (s >> 8) as u8;
            let low = (s & 0xFF) as u8;
            result.push_str(&format!(
                "{:x}.{:x}.{:x}.{:x}.",
                low & 0xF,
                low >> 4,
                high & 0xF,
                high >> 4
            ));
        }

        result.push_str("ip6.arpa");
        result
    } else {
        panic!("Invalid IP address: {}", ip);
    }
}

/// Check if a string looks like a valid DNS response
pub fn is_valid_dns_response(output: &str) -> bool {
    !output.is_empty() && (
        output.contains("ANSWER SECTION") ||
        output.contains("status:") ||
        output.chars().filter(|&c| c == '.').count() > 0
    )
}

/// Check if JSON output is valid
pub fn is_valid_json(output: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(output).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_to_ptr_ipv4() {
        assert_eq!(ip_to_ptr("8.8.8.8"), "8.8.8.8.in-addr.arpa");
        assert_eq!(ip_to_ptr("1.1.1.1"), "1.1.1.1.in-addr.arpa");
        assert_eq!(ip_to_ptr("192.0.2.1"), "1.2.0.192.in-addr.arpa");
    }

    #[test]
    fn test_ip_to_ptr_ipv6() {
        // Test IPv6 reverse lookup format
        let result = ip_to_ptr("2001:4860:4860::8888");
        assert!(result.ends_with("ip6.arpa"));
        assert!(result.contains("8.8.8.8"));
    }

    #[test]
    fn test_is_valid_dns_response() {
        assert!(is_valid_dns_response("ANSWER SECTION:\nexample.com. 3600 IN A 93.184.216.34"));
        assert!(is_valid_dns_response("93.184.216.34"));
        assert!(!is_valid_dns_response(""));
    }

    #[test]
    fn test_is_valid_json() {
        assert!(is_valid_json(r#"{"status": "NOERROR"}"#));
        assert!(!is_valid_json("not json"));
        assert!(!is_valid_json(""));
    }
}
