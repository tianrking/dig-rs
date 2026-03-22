//! DNS trace module for +trace functionality
//!
//! Implements iterative DNS resolution from root servers

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::dns_class::DNSClass;
use hickory_proto::rr::{Name, RecordType as HickoryRecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::config::DigConfig;
use crate::error::{DigError, Result};
use crate::lookup::{DnsRecord, LookupResult};
use crate::record::RecordType;

/// Root server addresses (IPv4)
const ROOT_SERVERS_IPV4: &[&str] = &[
    "198.41.0.4",     // a.root-servers.net
    "199.9.14.201",   // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
    "192.5.5.241",    // f.root-servers.net
    "192.112.36.4",   // g.root-servers.net
    "198.97.190.53",  // h.root-servers.net
    "192.36.148.17",  // i.root-servers.net
    "192.58.128.30",  // j.root-servers.net
    "193.0.14.129",   // k.root-servers.net
    "199.7.83.42",    // l.root-servers.net
    "202.12.27.33",   // m.root-servers.net
];

/// Root server addresses (IPv6)
const ROOT_SERVERS_IPV6: &[&str] = &[
    "2001:503:ba3e::2:30", // a.root-servers.net
    "2001:500:200::b",     // b.root-servers.net
    "2001:500:2::c",       // c.root-servers.net
    "2001:500:2d::d",      // d.root-servers.net
    "2001:500:a8::e",      // e.root-servers.net
    "2001:500:2f::f",      // f.root-servers.net
    "2001:500:12::d0d",    // g.root-servers.net
    "2001:500:1::53",      // h.root-servers.net
    "2001:7fe::53",        // i.root-servers.net
    "2001:503:c27::2:30",  // j.root-servers.net
    "2001:7fd::1",         // k.root-servers.net
    "2001:500:9f::42",     // l.root-servers.net
    "2001:dc3::35",        // m.root-servers.net
];

/// A single step in the DNS trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    /// Server that was queried
    pub server: String,
    /// Query sent
    pub query: String,
    /// Response received (simplified)
    pub response: TraceResponse,
    /// Time taken for this query
    pub query_time_ms: u64,
    /// Zone being queried at this step
    pub zone: Option<String>,
    /// Server type (root, tld, authoritative, etc.)
    pub server_type: String,
}

/// Simplified trace response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResponse {
    /// Response code
    pub rcode: String,
    /// Authority records (NS referrals)
    pub authority: Vec<String>,
    /// Additional records (glue addresses)
    pub additional: Vec<String>,
    /// Answer records (if any)
    pub answer: Vec<String>,
}

/// Complete trace result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    /// Original query name
    pub query_name: String,
    /// Query type
    pub query_type: String,
    /// All trace steps
    pub steps: Vec<TraceStep>,
    /// Final answer (if successful)
    pub final_answer: Option<LookupResult>,
    /// Total time
    pub total_time_ms: u64,
}

/// DNS trace executor
pub struct DnsTrace {
    config: DigConfig,
    max_iterations: u8,
    timeout: Duration,
}

impl DnsTrace {
    /// Create a new trace executor
    pub fn new(config: DigConfig) -> Self {
        Self {
            config,
            max_iterations: 20,
            timeout: Duration::from_secs(5),
        }
    }

    /// Set maximum iterations
    pub fn with_max_iterations(mut self, max: u8) -> Self {
        self.max_iterations = max;
        self
    }

    /// Set query timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Execute the trace
    pub async fn trace(&self) -> Result<TraceResult> {
        let start = Instant::now();
        let mut steps = Vec::new();

        // Parse the domain name
        let query_name = Name::from_utf8(&self.config.name)
            .map_err(|e| DigError::InvalidDomain(format!("Failed to parse domain: {}", e)))?;

        // Parse record type
        let record_type: RecordType = self
            .config
            .query_type
            .parse()
            .map_err(|e| DigError::UnsupportedRecordType(e))?;
        let hickory_type = self.to_hickory_record_type(record_type);

        // Start with root servers
        let mut current_servers = self.get_root_servers();
        let mut current_zone = Name::root();

        for iteration in 0..self.max_iterations {
            if current_servers.is_empty() {
                warn!("No more servers to query at iteration {}", iteration);
                break;
            }

            // Pick a server
            let server = current_servers[0];

            debug!(
                "Trace iteration {}: Querying {} for {} {} from {}",
                iteration, query_name, hickory_type, current_zone, server
            );

            // Send query
            let query_start = Instant::now();
            let response = match self.send_query(&server, &query_name, hickory_type).await {
                Ok(r) => r,
                Err(e) => {
                    warn!("Query to {} failed: {}", server, e);
                    // Try next server
                    current_servers.remove(0);
                    continue;
                }
            };
            let query_time = query_start.elapsed();

            // Check for answer
            if !response.answers().is_empty() {
                // We got an answer!
                let trace_response = self.parse_trace_response(&response);
                let server_type = self.classify_server(&current_zone);

                steps.push(TraceStep {
                    server: format!("{}", server),
                    query: format!("{} {}", query_name, hickory_type),
                    response: trace_response,
                    query_time_ms: query_time.as_millis() as u64,
                    zone: Some(current_zone.to_string()),
                    server_type,
                });

                // Build final result
                let final_answer = self.build_final_result(&response, server, query_time)?;

                return Ok(TraceResult {
                    query_name: self.config.name.clone(),
                    query_type: self.config.query_type.clone(),
                    steps,
                    final_answer: Some(final_answer),
                    total_time_ms: start.elapsed().as_millis() as u64,
                });
            }

            // Extract next servers from authority section
            let (next_servers, next_zone) = self.extract_referral(&response, &current_zone);

            let trace_response = self.parse_trace_response(&response);
            let server_type = self.classify_server(&current_zone);

            steps.push(TraceStep {
                server: format!("{}", server),
                query: format!("{} {}", query_name, hickory_type),
                response: trace_response,
                query_time_ms: query_time.as_millis() as u64,
                zone: Some(current_zone.to_string()),
                server_type,
            });

            if next_servers.is_empty() {
                // No referral - we're stuck
                debug!("No referral received from {}", server);
                break;
            }

            current_servers = next_servers;
            if let Some(zone) = next_zone {
                current_zone = zone;
            }
        }

        // No answer found
        Ok(TraceResult {
            query_name: self.config.name.clone(),
            query_type: self.config.query_type.clone(),
            steps,
            final_answer: None,
            total_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Get root server addresses
    fn get_root_servers(&self) -> Vec<SocketAddr> {
        let mut servers = Vec::new();

        // Prefer IPv4 or IPv6 based on config
        if self.config.ipv6 {
            for addr in ROOT_SERVERS_IPV6 {
                if let Ok(ip) = addr.parse::<IpAddr>() {
                    servers.push(SocketAddr::new(ip, 53));
                }
            }
        } else {
            for addr in ROOT_SERVERS_IPV4 {
                if let Ok(ip) = addr.parse::<IpAddr>() {
                    servers.push(SocketAddr::new(ip, 53));
                }
            }
        }

        servers
    }

    /// Send a DNS query
    async fn send_query(
        &self,
        server: &SocketAddr,
        name: &Name,
        record_type: HickoryRecordType,
    ) -> Result<Message> {
        // Build query
        let mut message = Message::new();
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(false); // No recursion for trace

        let mut query = Query::new();
        query.set_name(name.clone());
        query.set_query_type(record_type);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);

        // Encode
        let mut buf = Vec::with_capacity(4096);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            message
                .emit(&mut encoder)
                .map_err(|e| DigError::ProtocolError(format!("Failed to encode: {}", e)))?;
        }

        // Send via UDP
        let local_addr = match server {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| DigError::NetworkError(e.to_string()))?;

        let timeout = self.timeout;
        let response_data = tokio::time::timeout(timeout, async {
            socket.send_to(&buf, server).await?;
            let mut recv_buf = vec![0u8; 65535];
            let (len, _) = socket.recv_from(&mut recv_buf).await?;
            recv_buf.truncate(len);
            Ok::<Vec<u8>, std::io::Error>(recv_buf)
        })
        .await
        .map_err(|_| DigError::Timeout(timeout.as_millis() as u64))?
        .map_err(|e| DigError::NetworkError(e.to_string()))?;

        // Parse response
        let mut decoder = BinDecoder::new(&response_data);
        Message::read(&mut decoder)
            .map_err(|e| DigError::ProtocolError(format!("Failed to parse response: {}", e)))
    }

    /// Extract referral information from response
    fn extract_referral(
        &self,
        message: &Message,
        _current_zone: &Name,
    ) -> (Vec<SocketAddr>, Option<Name>) {
        let mut servers = Vec::new();
        let mut next_zone = None;
        let mut ns_names = Vec::new();

        // Look for NS records in authority section
        for record in message.name_servers() {
            if record.record_type() == HickoryRecordType::NS {
                if let Some(name) = Self::extract_ns_name(record.data()) {
                    ns_names.push(name);
                }
                if next_zone.is_none() {
                    next_zone = Some(record.name().clone());
                }
            }
        }

        // Look for glue records in additional section
        let glue_map = self.build_glue_map(message);

        // Resolve NS names to addresses
        for ns_name in &ns_names {
            if let Some(addrs) = glue_map.get(ns_name) {
                servers.extend(addrs.iter().cloned());
            } else {
                // No glue - would need to resolve (not implemented in basic trace)
                debug!("No glue for {}", ns_name);
            }
        }

        (servers, next_zone)
    }

    /// Extract NS name from RData
    fn extract_ns_name(rdata: &hickory_proto::rr::RData) -> Option<Name> {
        use hickory_proto::rr::RData;
        match rdata {
            RData::NS(ns) => Some(ns.0.clone()),
            _ => None,
        }
    }

    /// Build a map of NS names to their glue addresses
    fn build_glue_map(
        &self,
        message: &Message,
    ) -> std::collections::HashMap<Name, Vec<SocketAddr>> {
        use std::collections::HashMap;
        let mut map: HashMap<Name, Vec<SocketAddr>> = HashMap::new();

        for record in message.additionals() {
            let name = record.name().clone();
            let addr = match record.data() {
                hickory_proto::rr::RData::A(a) => Some(SocketAddr::new(IpAddr::V4(a.0), 53)),
                hickory_proto::rr::RData::AAAA(aaaa) => {
                    Some(SocketAddr::new(IpAddr::V6(aaaa.0), 53))
                }
                _ => None,
            };

            if let Some(addr) = addr {
                map.entry(name).or_default().push(addr);
            }
        }

        map
    }

    /// Parse trace response
    fn parse_trace_response(&self, message: &Message) -> TraceResponse {
        let authority: Vec<String> = message
            .name_servers()
            .iter()
            .map(|r| format!("{} {} {:?}", r.name(), r.ttl(), r.data()))
            .collect();

        let additional: Vec<String> = message
            .additionals()
            .iter()
            .map(|r| format!("{} {} {:?}", r.name(), r.ttl(), r.data()))
            .collect();

        let answer: Vec<String> = message
            .answers()
            .iter()
            .map(|r| format!("{} {} {:?}", r.name(), r.ttl(), r.data()))
            .collect();

        TraceResponse {
            rcode: format!("{:?}", message.response_code()),
            authority,
            additional,
            answer,
        }
    }

    /// Build final result from response
    fn build_final_result(
        &self,
        message: &Message,
        server: SocketAddr,
        query_time: Duration,
    ) -> Result<LookupResult> {
        let flags = crate::lookup::DnsFlags {
            qr: message.message_type() == MessageType::Response,
            aa: message.authoritative(),
            tc: message.truncated(),
            rd: message.recursion_desired(),
            ra: message.recursion_available(),
            ad: message.authentic_data(),
            cd: message.checking_disabled(),
        };

        let question: Vec<crate::lookup::DnsQuestion> = message
            .queries()
            .iter()
            .map(|q| crate::lookup::DnsQuestion {
                name: q.name().to_string(),
                qtype: format!("{:?}", q.query_type()),
                qclass: format!("{:?}", q.query_class()),
            })
            .collect();

        let answer = self.parse_records(message.answers());
        let authority = self.parse_records(message.name_servers());
        let additional = self.parse_records(message.additionals());

        let dns_message = crate::lookup::DnsMessage {
            id: message.id(),
            rcode: format!("{:?}", message.response_code()),
            opcode: format!("{:?}", message.op_code()),
            flags,
            question,
            answer,
            authority,
            additional,
        };

        let timestamp = chrono::Local::now()
            .format("%a %b %d %H:%M:%S %Z %Y")
            .to_string();

        Ok(LookupResult {
            query_name: self.config.name.clone(),
            query_type: self.config.query_type.clone(),
            query_class: self.config.query_class.to_string(),
            message: dns_message,
            server: format!("{}#{}", server.ip(), server.port()),
            query_time_ms: query_time.as_millis() as u64,
            message_size: 0, // Not tracked in trace
            timestamp,
        })
    }

    /// Parse records from hickory records
    fn parse_records(&self, records: &[hickory_proto::rr::Record]) -> Vec<DnsRecord> {
        records
            .iter()
            .map(|r| DnsRecord {
                name: r.name().to_string(),
                ttl: r.ttl(),
                class: format!("{:?}", r.dns_class()),
                rtype: format!("{:?}", r.record_type()),
                rdata: crate::lookup::DigLookup::format_rdata(r.data()),
            })
            .collect()
    }

    /// Classify the type of server being queried
    fn classify_server(&self, zone: &Name) -> String {
        let zone_str = zone.to_ascii();

        if zone_str == "." {
            "Root Server".to_string()
        } else if zone_str.ends_with(".arpa.") || zone_str.split('.').count() == 2 {
            // TLD servers (e.g., com., net., org.)
            "TLD Server".to_string()
        } else if zone_str.split('.').count() == 3 {
            "Authoritative Server".to_string()
        } else {
            format!("Zone Server ({})", zone_str)
        }
    }

    /// Convert our RecordType to hickory's RecordType
    fn to_hickory_record_type(&self, rt: RecordType) -> HickoryRecordType {
        match rt {
            RecordType::A => HickoryRecordType::A,
            RecordType::AAAA => HickoryRecordType::AAAA,
            RecordType::NS => HickoryRecordType::NS,
            RecordType::CNAME => HickoryRecordType::CNAME,
            RecordType::MX => HickoryRecordType::MX,
            RecordType::TXT => HickoryRecordType::TXT,
            RecordType::PTR => HickoryRecordType::PTR,
            RecordType::SOA => HickoryRecordType::SOA,
            RecordType::SRV => HickoryRecordType::SRV,
            RecordType::ANY => HickoryRecordType::ANY,
            _ => HickoryRecordType::from(rt.to_u16()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_servers() {
        let config = DigConfig::default();
        let trace = DnsTrace::new(config);
        let servers = trace.get_root_servers();
        assert!(!servers.is_empty());
    }
}
