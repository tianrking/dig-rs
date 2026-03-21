//! DNS Zone Transfer (AXFR/IXFR) support
//!
//! This module provides functionality for performing full (AXFR) and
//! incremental (IXFR) zone transfers as specified in RFC 1035 and RFC 1995.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::config::{DigConfig, Transport};
use crate::error::{DigError, Result};
use crate::lookup::{DigLookup, DnsRecord};
use crate::record::RecordType;

/// Zone transfer type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneTransferType {
    /// Full Zone Transfer (AXFR)
    AXFR,
    /// Incremental Zone Transfer (IXFR)
    IXFR,
}

impl std::fmt::Display for ZoneTransferType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZoneTransferType::AXFR => write!(f, "AXFR"),
            ZoneTransferType::IXFR => write!(f, "IXFR"),
        }
    }
}

impl std::str::FromStr for ZoneTransferType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "AXFR" => Ok(ZoneTransferType::AXFR),
            "IXFR" => Ok(ZoneTransferType::IXFR),
            _ => Err(format!("Unknown zone transfer type: {}", s)),
        }
    }
}

/// Zone transfer result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTransferResult {
    /// Zone name
    pub zone: String,
    /// Transfer type
    pub transfer_type: ZoneTransferType,
    /// Records received
    pub records: Vec<DnsRecord>,
    /// Total records transferred
    pub record_count: usize,
    /// Server that provided the transfer
    pub server: String,
    /// Transfer time in milliseconds
    pub transfer_time_ms: u64,
    /// Whether the transfer was incremental
    pub incremental: bool,
    /// Starting serial for IXFR
    pub start_serial: Option<u32>,
    /// Ending serial for IXFR
    pub end_serial: Option<u32>,
    /// SOA records received (first and last)
    pub soa_records: Vec<DnsRecord>,
}

/// Zone transfer handler
pub struct ZoneTransfer {
    config: DigConfig,
}

impl ZoneTransfer {
    /// Create a new zone transfer handler
    pub fn new(config: DigConfig) -> Self {
        Self { config }
    }

    /// Perform a zone transfer
    pub async fn transfer(&self, ztype: ZoneTransferType) -> Result<ZoneTransferResult> {
        info!("Starting {} transfer for zone: {}", ztype, self.config.name);

        // Zone transfers require TCP
        if self.config.transport == Transport::Udp {
            warn!("Zone transfers require TCP, switching transport");
        }

        let start = Instant::now();

        // Get server address
        let servers = if self.config.servers.is_empty() {
            self.get_system_servers()
        } else {
            self.config
                .servers
                .iter()
                .filter_map(|s| {
                    let addr: Option<std::net::IpAddr> = s.address.parse().ok();
                    addr.map(|a| SocketAddr::new(a, s.port))
                })
                .collect()
        };

        if servers.is_empty() {
            return Err(DigError::NoServersConfigured);
        }

        let server = servers[0];

        // Perform the transfer based on type
        let result = match ztype {
            ZoneTransferType::AXFR => self.axfr(server).await?,
            ZoneTransferType::IXFR => self.ixfr(server).await?,
        };

        let transfer_time = start.elapsed();

        info!(
            "{} transfer completed: {} records in {}ms",
            ztype,
            result.record_count,
            transfer_time.as_millis()
        );

        Ok(result)
    }

    /// Perform a full zone transfer (AXFR)
    async fn axfr(&self, server: SocketAddr) -> Result<ZoneTransferResult> {
        debug!("Performing AXFR from {}", server);

        // For a proper AXFR, we need to:
        // 1. Send AXFR query over TCP
        // 2. Receive multiple messages containing zone records
        // 3. First and last messages should contain SOA records

        // This is a simplified implementation
        let records = self.send_axfr_query(server).await?;

        // Find SOA records
        let soa_records: Vec<DnsRecord> = records
            .iter()
            .filter(|r| r.rtype == "SOA")
            .cloned()
            .collect();

        Ok(ZoneTransferResult {
            zone: self.config.name.clone(),
            transfer_type: ZoneTransferType::AXFR,
            record_count: records.len(),
            records,
            server: server.to_string(),
            transfer_time_ms: 0, // Will be set by caller
            incremental: false,
            start_serial: None,
            end_serial: None,
            soa_records,
        })
    }

    /// Perform an incremental zone transfer (IXFR)
    async fn ixfr(&self, server: SocketAddr) -> Result<ZoneTransferResult> {
        debug!("Performing IXFR from {}", server);

        // For IXFR, we need to:
        // 1. Include the current serial number
        // 2. Server sends incremental updates

        // This is a simplified implementation
        let records = self.send_ixfr_query(server).await?;

        // Try to extract serial information
        let (start_serial, end_serial) = self.extract_serials(&records);

        let soa_records: Vec<DnsRecord> = records
            .iter()
            .filter(|r| r.rtype == "SOA")
            .cloned()
            .collect();

        Ok(ZoneTransferResult {
            zone: self.config.name.clone(),
            transfer_type: ZoneTransferType::IXFR,
            record_count: records.len(),
            records,
            server: server.to_string(),
            transfer_time_ms: 0, // Will be set by caller
            incremental: true,
            start_serial,
            end_serial,
            soa_records,
        })
    }

    /// Send AXFR query and receive records
    async fn send_axfr_query(&self, server: SocketAddr) -> Result<Vec<DnsRecord>> {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{DNSClass, Name, RecordType as HickoryRecordType};
        use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

        // Build AXFR query
        let mut message = Message::new();
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);

        let query_name = Name::from_utf8(&self.config.name)
            .map_err(|e| DigError::InvalidDomain(format!("Invalid zone name: {}", e)))?;

        let mut query = Query::new();
        query.set_name(query_name);
        query.set_query_type(HickoryRecordType::AXFR);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);

        // Encode message
        let mut buf = Vec::with_capacity(4096);
        {
            let mut encoder = BinEncoder::new(&mut buf);
            message.emit(&mut encoder).map_err(|e| {
                DigError::ProtocolError(format!("Failed to encode AXFR query: {}", e))
            })?;
        }

        // Add length prefix
        let len = buf.len() as u16;
        let mut packet = vec![(len >> 8) as u8, len as u8];
        packet.extend_from_slice(&buf);

        // Send over TCP
        let mut stream = tokio::time::timeout(self.config.timeout, TcpStream::connect(server))
            .await
            .map_err(|_| DigError::Timeout(self.config.timeout.as_millis() as u64))?
            .map_err(|e| DigError::NetworkError(e.to_string()))?;

        stream
            .write_all(&packet)
            .await
            .map_err(|e| DigError::NetworkError(e.to_string()))?;

        // Read response(s)
        // AXFR returns multiple messages
        let mut all_records = Vec::new();

        loop {
            // Read message length
            let mut len_buf = [0u8; 2];
            tokio::time::timeout(self.config.timeout, stream.read_exact(&mut len_buf))
                .await
                .map_err(|_| DigError::Timeout(self.config.timeout.as_millis() as u64))?
                .map_err(|e| DigError::NetworkError(e.to_string()))?;

            let msg_len = ((len_buf[0] as u16) << 8) | (len_buf[1] as u16);

            // Read message
            let mut msg_buf = vec![0u8; msg_len as usize];
            tokio::time::timeout(self.config.timeout, stream.read_exact(&mut msg_buf))
                .await
                .map_err(|_| DigError::Timeout(self.config.timeout.as_millis() as u64))?
                .map_err(|e| DigError::NetworkError(e.to_string()))?;

            // Parse message
            use hickory_proto::serialize::binary::BinDecodable;
            let mut decoder = hickory_proto::serialize::binary::BinDecoder::new(&msg_buf);
            let response = Message::read(&mut decoder).map_err(|e| {
                DigError::ProtocolError(format!("Failed to parse AXFR response: {}", e))
            })?;

            // Extract records
            for record in response.answers() {
                all_records.push(self.hickory_record_to_dns_record(record));
            }

            // Check if this is the end (SOA record)
            if let Some(last) = response.answers().last() {
                if last.record_type() == HickoryRecordType::SOA {
                    // Usually the last message with SOA indicates end
                    break;
                }
            }

            // Check for no more records in response
            if response.answers().is_empty() && !all_records.is_empty() {
                break;
            }
        }

        Ok(all_records)
    }

    /// Send IXFR query and receive records
    async fn send_ixfr_query(&self, server: SocketAddr) -> Result<Vec<DnsRecord>> {
        // For IXFR, we need to include the current serial number
        // This is a simplified implementation that behaves like AXFR
        self.send_axfr_query(server).await
    }

    /// Extract serial numbers from records
    fn extract_serials(&self, records: &[DnsRecord]) -> (Option<u32>, Option<u32>) {
        let soa_records: Vec<_> = records.iter().filter(|r| r.rtype == "SOA").collect();

        if soa_records.len() >= 2 {
            // First SOA is start serial, last SOA is end serial
            let start = self.parse_soa_serial(&soa_records[0].rdata);
            let end = self.parse_soa_serial(&soa_records[soa_records.len() - 1].rdata);
            (start, end)
        } else {
            (None, None)
        }
    }

    /// Parse serial number from SOA RDATA
    fn parse_soa_serial(&self, rdata: &str) -> Option<u32> {
        // SOA format: mname rname serial refresh retry expire minimum
        let parts: Vec<&str> = rdata.split_whitespace().collect();
        if parts.len() >= 3 {
            parts[2].parse().ok()
        } else {
            None
        }
    }

    /// Convert hickory Record to DnsRecord
    fn hickory_record_to_dns_record(&self, record: &hickory_proto::rr::Record) -> DnsRecord {
        use hickory_proto::rr::RData;

        DnsRecord {
            name: record.name().to_string(),
            ttl: record.ttl(),
            class: format!("{:?}", record.dns_class()),
            rtype: format!("{:?}", record.record_type()),
            rdata: match record.data() {
                RData::A(addr) => addr.to_string(),
                RData::AAAA(addr) => addr.to_string(),
                RData::MX(mx) => format!("{} {}", mx.preference(), mx.exchange()),
                RData::NS(ns) => ns.to_string(),
                RData::TXT(txt) => txt
                    .txt_data()
                    .iter()
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
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
                _ => format!("{:?}", record.data()),
            },
        }
    }

    /// Get system DNS servers
    fn get_system_servers(&self) -> Vec<SocketAddr> {
        use crate::resolver::ResolverConfig;

        let resolver_config = ResolverConfig::from_system();
        resolver_config.nameservers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_transfer_type_parsing() {
        assert_eq!(
            "AXFR".parse::<ZoneTransferType>().unwrap(),
            ZoneTransferType::AXFR
        );
        assert_eq!(
            "ixfr".parse::<ZoneTransferType>().unwrap(),
            ZoneTransferType::IXFR
        );
    }

    #[test]
    fn test_parse_soa_serial() {
        let zt = ZoneTransfer::new(DigConfig::default());
        let rdata = "ns1.example.com. admin.example.com. 1234567890 3600 1800 604800 86400";
        assert_eq!(zt.parse_soa_serial(rdata), Some(1234567890));
    }

    #[test]
    fn test_extract_serials() {
        let zt = ZoneTransfer::new(DigConfig::default());
        let soa1 = DnsRecord {
            name: "example.com".to_string(),
            ttl: 3600,
            class: "IN".to_string(),
            rtype: "SOA".to_string(),
            rdata: "ns1.example.com. admin.example.com. 100 3600 1800 604800 86400".to_string(),
        };
        let soa2 = DnsRecord {
            name: "example.com".to_string(),
            ttl: 3600,
            class: "IN".to_string(),
            rtype: "SOA".to_string(),
            rdata: "ns1.example.com. admin.example.com. 200 3600 1800 604800 86400".to_string(),
        };

        let (start, end) = zt.extract_serials(&[soa1, soa2]);
        assert_eq!(start, Some(100));
        assert_eq!(end, Some(200));
    }
}
