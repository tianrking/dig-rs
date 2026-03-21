//! DNS lookup execution module
//!
//! Handles the actual DNS query execution and result collection

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType as HickoryRecordType};
use hickory_proto::rr::dns_class::DNSClass;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::config::{DigConfig, QueryClass, Transport};
use crate::error::{DigError, Result};
use crate::record::RecordType;

/// Result of a DNS lookup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupResult {
    /// Query name
    pub query_name: String,
    /// Query type
    pub query_type: String,
    /// Query class
    pub query_class: String,
    /// Response message
    pub message: DnsMessage,
    /// Server that was queried
    pub server: String,
    /// Query time in milliseconds
    pub query_time_ms: u64,
    /// Message size received
    pub message_size: usize,
    /// Timestamp of the query
    pub timestamp: String,
}

/// Serializable DNS message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMessage {
    /// Message ID
    pub id: u16,
    /// Response code
    pub rcode: String,
    /// Opcode
    pub opcode: String,
    /// Flags
    pub flags: DnsFlags,
    /// Question section
    pub question: Vec<DnsQuestion>,
    /// Answer section
    pub answer: Vec<DnsRecord>,
    /// Authority section
    pub authority: Vec<DnsRecord>,
    /// Additional section
    pub additional: Vec<DnsRecord>,
}

/// DNS message flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFlags {
    /// Query/Response flag
    pub qr: bool,
    /// Authoritative Answer
    pub aa: bool,
    /// Truncation
    pub tc: bool,
    /// Recursion Desired
    pub rd: bool,
    /// Recursion Available
    pub ra: bool,
    /// Authentic Data
    pub ad: bool,
    /// Checking Disabled
    pub cd: bool,
}

/// DNS question section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    /// Query name
    pub name: String,
    /// Query type
    pub qtype: String,
    /// Query class
    pub qclass: String,
}

/// DNS record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    /// Record name
    pub name: String,
    /// Record TTL
    pub ttl: u32,
    /// Record class
    pub class: String,
    /// Record type
    pub rtype: String,
    /// Record data
    pub rdata: String,
}

/// DNS lookup handler
pub struct DigLookup {
    config: DigConfig,
}

impl DigLookup {
    /// Create a new lookup handler
    pub fn new(config: DigConfig) -> Self {
        Self { config }
    }

    /// Perform the DNS lookup
    pub async fn lookup(&self) -> Result<LookupResult> {
        let name = if self.config.name.is_empty() {
            return Err(DigError::InvalidDomain("No domain name specified".into()));
        } else {
            &self.config.name
        };

        // Parse the domain name
        let query_name = Self::parse_name(name)?;

        // Parse the record type
        let record_type: RecordType = self.config.query_type.parse()
            .map_err(|e| DigError::UnsupportedRecordType(e))?;
        let hickory_type = Self::to_hickory_record_type(record_type);

        // Determine query class
        let query_class = match self.config.query_class {
            QueryClass::IN => DNSClass::IN,
            QueryClass::CH => DNSClass::CH,
            QueryClass::HS => DNSClass::HS,
            QueryClass::NONE => DNSClass::NONE,
            QueryClass::ANY => DNSClass::ANY,
        };

        // Get server addresses
        let servers = if self.config.servers.is_empty() {
            self.get_system_servers()
        } else {
            self.config.servers.iter()
                .filter_map(|s| {
                    let addr: Option<IpAddr> = s.address.parse().ok();
                    addr.map(|a| SocketAddr::new(a, s.port))
                })
                .collect()
        };

        if servers.is_empty() {
            return Err(DigError::NoServersConfigured);
        }

        let server = servers[0];

        // Build the query message
        let mut message = Message::new();
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(self.config.recurse);
        message.set_authentic_data(self.config.dnssec.ad_flag);
        message.set_checking_disabled(self.config.dnssec.cd_flag);

        let mut query = Query::new();
        query.set_name(query_name.clone());
        query.set_query_type(hickory_type);
        query.set_query_class(query_class);
        message.add_query(query);

        // Add EDNS if configured
        if self.config.edns.version > 0 || self.config.edns.udp_size > 512 {
            // EDNS configuration would be added here
            // hickory-proto supports this via edns
        }

        // Execute the query based on transport
        let start = Instant::now();
        let response = match self.config.transport {
            Transport::Udp => self.send_udp(&server, &message).await?,
            Transport::Tcp => self.send_tcp(&server, &message).await?,
            Transport::Tls => self.send_tls(&server, &message).await?,
            Transport::Https => self.send_https(&server, &message).await?,
            Transport::Quic => return Err(DigError::ConfigError("QUIC transport not yet implemented".into())),
        };

        let query_time = start.elapsed();

        // Parse the response
        let lookup_result = self.parse_response(&response, server, query_time)?;

        Ok(lookup_result)
    }

    /// Parse a domain name
    fn parse_name(name: &str) -> Result<Name> {
        // Handle reverse lookups
        let name = if name.parse::<IpAddr>().is_ok() {
            // Convert IP to PTR name
            Self::ip_to_ptr_name(name)?
        } else {
            name.to_string()
        };

        Name::from_utf8(&name)
            .map_err(|e| DigError::InvalidDomain(format!("Failed to parse domain '{}': {}", name, e)))
    }

    /// Convert IP address to PTR name
    fn ip_to_ptr_name(ip: &str) -> Result<String> {
        if let Ok(ipv4) = ip.parse::<Ipv4Addr>() {
            let octets = ipv4.octets();
            Ok(format!("{}.{}.{}.{}.in-addr.arpa.", octets[3], octets[2], octets[1], octets[0]))
        } else if let Ok(ipv6) = ip.parse::<Ipv6Addr>() {
            let segments = ipv6.segments();
            let mut ptr = String::new();
            for seg in segments.iter().rev() {
                let hex = format!("{:04x}", seg);
                for c in hex.chars().rev() {
                    ptr.push(c);
                    ptr.push('.');
                }
            }
            ptr.push_str("ip6.arpa.");
            Ok(ptr)
        } else {
            Err(DigError::InvalidIpAddress(ip.into()))
        }
    }

    /// Convert our RecordType to hickory's RecordType
    fn to_hickory_record_type(rt: RecordType) -> HickoryRecordType {
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
            RecordType::DNSKEY => HickoryRecordType::DNSKEY,
            RecordType::DS => HickoryRecordType::DS,
            RecordType::RRSIG => HickoryRecordType::RRSIG,
            RecordType::NSEC => HickoryRecordType::NSEC,
            RecordType::NSEC3 => HickoryRecordType::NSEC3,
            RecordType::NSEC3PARAM => HickoryRecordType::NSEC3PARAM,
            RecordType::TLSA => HickoryRecordType::TLSA,
            RecordType::CAA => HickoryRecordType::CAA,
            RecordType::ANY => HickoryRecordType::ANY,
            RecordType::AXFR => HickoryRecordType::AXFR,
            RecordType::IXFR => HickoryRecordType::IXFR,
            _ => HickoryRecordType::from(rt.to_u16()),
        }
    }

    /// Get system DNS servers
    fn get_system_servers(&self) -> Vec<SocketAddr> {
        use crate::resolver::ResolverConfig;

        let resolver_config = ResolverConfig::from_system();
        resolver_config.nameservers
    }

    /// Send query via UDP
    async fn send_udp(&self, server: &SocketAddr, message: &Message) -> Result<Vec<u8>> {
        // Encode the message
        let mut buf = Vec::with_capacity(4096);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            message.emit(&mut encoder)
                .map_err(|e| DigError::ProtocolError(format!("Failed to encode message: {}", e)))?;
        }

        // Determine local address based on server address family
        let local_addr = match server {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| DigError::NetworkError(e))?;

        // Set timeout
        let timeout = self.config.timeout;
        tokio::time::timeout(
            timeout,
            async {
                socket.send_to(&buf, server).await?;
                let mut recv_buf = vec![0u8; 65535];
                let (len, _) = socket.recv_from(&mut recv_buf).await?;
                recv_buf.truncate(len);
                Ok::<Vec<u8>, std::io::Error>(recv_buf)
            }
        )
        .await
        .map_err(|_| DigError::Timeout(timeout.as_millis() as u64))?
        .map_err(DigError::NetworkError)
    }

    /// Send query via TCP
    async fn send_tcp(&self, server: &SocketAddr, message: &Message) -> Result<Vec<u8>> {
        // Encode the message with 2-byte length prefix
        let mut buf = Vec::with_capacity(65535);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            message.emit(&mut encoder)
                .map_err(|e| DigError::ProtocolError(format!("Failed to encode message: {}", e)))?;
        }

        // Prepend length
        let len = buf.len() as u16;
        let mut packet = vec![(len >> 8) as u8, len as u8];
        packet.extend_from_slice(&buf);

        let timeout = self.config.timeout;
        tokio::time::timeout(
            timeout,
            async {
                let mut stream = TcpStream::connect(server).await?;

                // Send the query
                use tokio::io::{AsyncWriteExt, AsyncReadExt};
                stream.write_all(&packet).await?;

                // Read the response length
                let mut len_buf = [0u8; 2];
                stream.read_exact(&mut len_buf).await?;
                let response_len = ((len_buf[0] as u16) << 8) | (len_buf[1] as u16);

                // Read the response
                let mut response = vec![0u8; response_len as usize];
                stream.read_exact(&mut response).await?;

                Ok::<Vec<u8>, std::io::Error>(response)
            }
        )
        .await
        .map_err(|_| DigError::Timeout(timeout.as_millis() as u64))?
        .map_err(DigError::NetworkError)
    }

    /// Send query via DNS-over-TLS
    async fn send_tls(&self, server: &SocketAddr, message: &Message) -> Result<Vec<u8>> {
        // For now, fall back to TCP
        // TODO: Implement proper TLS with rustls
        debug!("TLS not fully implemented, falling back to TCP");
        self.send_tcp(server, message).await
    }

    /// Send query via DNS-over-HTTPS
    async fn send_https(&self, server: &SocketAddr, message: &Message) -> Result<Vec<u8>> {
        // For now, fall back to TCP
        // TODO: Implement DoH with reqwest
        debug!("HTTPS not fully implemented, falling back to TCP");
        self.send_tcp(server, message).await
    }

    /// Parse the DNS response
    fn parse_response(&self, data: &[u8], server: SocketAddr, query_time: Duration) -> Result<LookupResult> {
        let mut decoder = BinDecoder::new(data);
        let message = Message::read(&mut decoder)
            .map_err(|e| DigError::ProtocolError(format!("Failed to parse response: {}", e)))?;

        // Build the serializable message
        let dns_message = self.build_dns_message(&message)?;
        let message_size = data.len();

        let timestamp = chrono::Local::now().format("%a %b %d %H:%M:%S %Z %Y").to_string();

        Ok(LookupResult {
            query_name: self.config.name.clone(),
            query_type: self.config.query_type.clone(),
            query_class: self.config.query_class.to_string(),
            message: dns_message,
            server: format!("{}#{}", server.ip(), server.port()),
            query_time_ms: query_time.as_millis() as u64,
            message_size,
            timestamp,
        })
    }

    /// Build serializable DNS message from hickory message
    fn build_dns_message(&self, message: &Message) -> Result<DnsMessage> {
        let flags = DnsFlags {
            qr: message.message_type() == MessageType::Response,
            aa: message.authoritative(),
            tc: message.truncated(),
            rd: message.recursion_desired(),
            ra: message.recursion_available(),
            ad: message.authentic_data(),
            cd: message.checking_disabled(),
        };

        let question: Vec<DnsQuestion> = message.queries()
            .iter()
            .map(|q| DnsQuestion {
                name: q.name().to_string(),
                qtype: format!("{:?}", q.query_type()),
                qclass: format!("{:?}", q.query_class()),
            })
            .collect();

        let answer = self.parse_records(message.answers());
        let authority = self.parse_records(message.name_servers());
        let additional = self.parse_records(message.additionals());

        Ok(DnsMessage {
            id: message.id(),
            rcode: format!("{:?}", message.response_code()),
            opcode: format!("{:?}", message.op_code()),
            flags,
            question,
            answer,
            authority,
            additional,
        })
    }

    /// Parse records from hickory records
    fn parse_records(&self, records: &[Record]) -> Vec<DnsRecord> {
        records
            .iter()
            .map(|r| DnsRecord {
                name: r.name().to_string(),
                ttl: r.ttl(),
                class: format!("{:?}", r.dns_class()),
                rtype: format!("{:?}", r.record_type()),
                rdata: Self::format_rdata(r.data()),
            })
            .collect()
    }

    /// Format RData for display
    pub fn format_rdata(rdata: &RData) -> String {
        match rdata {
            RData::A(addr) => addr.to_string(),
            RData::AAAA(addr) => addr.to_string(),
            RData::MX(mx) => format!("{} {}", mx.preference(), mx.exchange()),
            RData::NS(ns) => ns.to_string(),
            RData::TXT(txt) => {
                txt.txt_data()
                    .iter()
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            }
            RData::CNAME(name) => name.to_string(),
            RData::PTR(name) => name.to_string(),
            RData::SOA(soa) => format!(
                "{} {} {} {} {} {} {}",
                soa.mname(),
                soa.rname(),
                soa.serial(),
                soa.refresh(),
                soa.retry(),
                soa.expire(),
                soa.minimum()
            ),
            RData::SRV(srv) => format!(
                "{} {} {} {}",
                srv.priority(),
                srv.weight(),
                srv.port(),
                srv.target()
            ),
            RData::CAA(caa) => format!(
                "{} {} {:?}",
                caa.issuer_critical() as u8,
                caa.tag(),
                caa.raw_value()
            ),
            other => format!("{:?}", other),
        }
    }
}

impl DigLookup {
    /// Create a lookup for reverse DNS query
    pub fn reverse_lookup(ip: &str) -> Result<Self> {
        let mut config = DigConfig::default();
        config.name = ip.to_string();
        config.query_type = "PTR".to_string();
        config.reverse = true;
        Ok(Self::new(config))
    }

    /// Get the configuration
    pub fn config(&self) -> &DigConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_to_ptr_name() {
        let ptr = DigLookup::ip_to_ptr_name("8.8.8.8").unwrap();
        assert_eq!(ptr, "8.8.8.8.in-addr.arpa.");

        let ptr = DigLookup::ip_to_ptr_name("2001:4860:4860::8888").unwrap();
        assert!(ptr.ends_with("ip6.arpa."));
    }
}
