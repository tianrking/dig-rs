//! EDNS(0) options and extensions
//!
//! This module provides support for various EDNS(0) options as specified
//! in RFC 6891 and related RFCs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// EDNS option errors
#[derive(Debug, Error)]
pub enum EdnsError {
    #[error("Invalid EDNS option code: {0}")]
    InvalidCode(u16),
    #[error("Invalid option data length")]
    InvalidLength,
    #[error("Invalid subnet prefix: {0}")]
    InvalidSubnetPrefix(String),
}

/// EDNS option codes as defined in various RFCs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum EdnsOptionCode {
    /// LLQ (Long-Lived Queries) - RFC 5001
    LLQ = 1,
    /// Update Lease - UNASSIGNED
    UpdateLease = 2,
    /// NSID (Name Server Identifier) - RFC 5001
    NSID = 3,
    /// Client Subnet - RFC 7871
    ClientSubnet = 8,
    /// Expire - RFC 7314
    Expire = 9,
    /// Cookie - RFC 7873
    Cookie = 10,
    /// TCP Keepalive - RFC 7828
    TcpKeepalive = 11,
    /// Padding - RFC 7830
    Padding = 12,
    /// Chain - RFC 7901
    Chain = 13,
    /// Key Tag - RFC 8145
    KeyTag = 14,
    /// Extended Error - RFC 8914
    ExtendedError = 15,
    /// Client Tag - UNASSIGNED (removed to avoid conflict)
    // ClientTag was 15 but conflicts with ExtendedError
    /// Server Tag - UNASSIGNED
    ServerTag = 16,
    /// DNSSEC Scheme - UNASSIGNED
    DnssecScheme = 17,
}

impl EdnsOptionCode {
    /// Parse from u16
    pub fn from_u16(code: u16) -> Result<Self, EdnsError> {
        match code {
            1 => Ok(EdnsOptionCode::LLQ),
            2 => Ok(EdnsOptionCode::UpdateLease),
            3 => Ok(EdnsOptionCode::NSID),
            8 => Ok(EdnsOptionCode::ClientSubnet),
            9 => Ok(EdnsOptionCode::Expire),
            10 => Ok(EdnsOptionCode::Cookie),
            11 => Ok(EdnsOptionCode::TcpKeepalive),
            12 => Ok(EdnsOptionCode::Padding),
            13 => Ok(EdnsOptionCode::Chain),
            14 => Ok(EdnsOptionCode::KeyTag),
            15 => Ok(EdnsOptionCode::ExtendedError),
            _ => Err(EdnsError::InvalidCode(code)),
        }
    }

    /// Get the code as u16
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
}

/// Generic EDNS option
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdnsOption {
    /// Option code
    pub code: EdnsOptionCode,
    /// Option data
    pub data: Vec<u8>,
}

impl EdnsOption {
    /// Create a new EDNS option
    pub fn new(code: EdnsOptionCode, data: Vec<u8>) -> Self {
        Self { code, data }
    }

    /// Create an empty option
    pub fn empty(code: EdnsOptionCode) -> Self {
        Self { code, data: Vec::new() }
    }

    /// Get the length of the option data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the option is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// NSID (Name Server Identifier) option - RFC 5001
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NsidOption {
    /// NSID data
    pub nsid: Vec<u8>,
}

impl NsidOption {
    /// Create a new NSID option (request NSID from server)
    pub fn request() -> Self {
        Self { nsid: Vec::new() }
    }

    /// Create NSID with specific data
    pub fn with_data(nsid: Vec<u8>) -> Self {
        Self { nsid }
    }

    /// Create NSID from string
    pub fn from_string(s: &str) -> Self {
        Self { nsid: s.as_bytes().to_vec() }
    }

    /// Convert to EDNS option
    pub fn to_edns_option(&self) -> EdnsOption {
        EdnsOption::new(EdnsOptionCode::NSID, self.nsid.clone())
    }

    /// Get NSID as string if valid UTF-8
    pub fn as_string(&self) -> Option<String> {
        String::from_utf8(self.nsid.clone()).ok()
    }
}

/// COOKIE option - RFC 7873
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieOption {
    /// Client cookie (8 bytes)
    pub client_cookie: [u8; 8],
    /// Server cookie (8 bytes, optional)
    pub server_cookie: Option<[u8; 8]>,
}

impl CookieOption {
    /// Create a new cookie option with only client cookie
    pub fn new(client_cookie: [u8; 8]) -> Self {
        Self {
            client_cookie,
            server_cookie: None,
        }
    }

    /// Create a cookie option with both client and server cookies
    pub fn with_server(client_cookie: [u8; 8], server_cookie: [u8; 8]) -> Self {
        Self {
            client_cookie,
            server_cookie: Some(server_cookie),
        }
    }

    /// Generate a random client cookie
    pub fn generate_client() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut cookie = [0u8; 8];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        cookie[0..8].copy_from_slice(&timestamp.to_le_bytes()[0..8]);
        Self { client_cookie: cookie, server_cookie: None }
    }

    /// Convert to EDNS option
    pub fn to_edns_option(&self) -> EdnsOption {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&self.client_cookie);

        if let Some(ref server_cookie) = self.server_cookie {
            data.extend_from_slice(server_cookie);
        }

        EdnsOption::new(EdnsOptionCode::Cookie, data)
    }

    /// Parse from EDNS option data
    pub fn from_edns_option(data: &[u8]) -> Result<Self, EdnsError> {
        if data.len() < 8 {
            return Err(EdnsError::InvalidLength);
        }

        let mut client_cookie = [0u8; 8];
        client_cookie.copy_from_slice(&data[0..8]);

        let server_cookie = if data.len() >= 16 {
            let mut sc = [0u8; 8];
            sc.copy_from_slice(&data[8..16]);
            Some(sc)
        } else {
            None
        };

        Ok(Self {
            client_cookie,
            server_cookie,
        })
    }

    /// Get the total cookie size
    pub fn size(&self) -> usize {
        8 + self.server_cookie.map(|_| 8).unwrap_or(0)
    }
}

/// Client Subnet option - RFC 7871
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetOption {
    /// Source IP address
    pub address: IpAddr,
    /// Source prefix length
    pub source_prefix: u8,
    /// Scope prefix length
    pub scope_prefix: u8,
}

impl SubnetOption {
    /// Create a new subnet option
    pub fn new(address: IpAddr, source_prefix: u8) -> Result<Self, EdnsError> {
        let max_prefix = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if source_prefix > max_prefix {
            return Err(EdnsError::InvalidSubnetPrefix(format!(
                "Prefix {} exceeds maximum {}",
                source_prefix, max_prefix
            )));
        }

        Ok(Self {
            address,
            source_prefix,
            scope_prefix: 0,
        })
    }

    /// Create subnet option for IPv4
    pub fn ipv4(addr: Ipv4Addr, prefix: u8) -> Result<Self, EdnsError> {
        Self::new(IpAddr::V4(addr), prefix)
    }

    /// Create subnet option for IPv6
    pub fn ipv6(addr: Ipv6Addr, prefix: u8) -> Result<Self, EdnsError> {
        Self::new(IpAddr::V6(addr), prefix)
    }

    /// Set the scope prefix
    pub fn with_scope(mut self, scope: u8) -> Self {
        self.scope_prefix = scope;
        self
    }

    /// Convert to EDNS option
    pub fn to_edns_option(&self) -> Result<EdnsOption, EdnsError> {
        let mut data = Vec::new();

        // Family
        data.push(match self.address {
            IpAddr::V4(_) => 1,
            IpAddr::V6(_) => 2,
        });

        // Source prefix length
        data.push(self.source_prefix);

        // Scope prefix length
        data.push(self.scope_prefix);

        // Address
        match self.address {
            IpAddr::V4(addr) => {
                let bytes = addr.octets();
                let prefix_bytes = ((self.source_prefix as usize) + 7) / 8;
                data.extend_from_slice(&bytes[0..prefix_bytes.min(4)]);
            }
            IpAddr::V6(addr) => {
                let bytes = addr.octets();
                let prefix_bytes = ((self.source_prefix as usize) + 7) / 8;
                data.extend_from_slice(&bytes[0..prefix_bytes.min(16)]);
            }
        }

        Ok(EdnsOption::new(EdnsOptionCode::ClientSubnet, data))
    }

    /// Parse from EDNS option data
    pub fn from_edns_option(data: &[u8]) -> Result<Self, EdnsError> {
        if data.len() < 4 {
            return Err(EdnsError::InvalidLength);
        }

        let family = data[0];
        let source_prefix = data[1];
        let scope_prefix = data[2];
        let addr_data = &data[4..];

        let address = match family {
            1 => {
                // IPv4
                let mut octets = [0u8; 4];
                let copy_len = addr_data.len().min(4);
                octets[0..copy_len].copy_from_slice(&addr_data[0..copy_len]);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            2 => {
                // IPv6
                let mut octets = [0u8; 16];
                let copy_len = addr_data.len().min(16);
                octets[0..copy_len].copy_from_slice(&addr_data[0..copy_len]);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => {
                return Err(EdnsError::InvalidSubnetPrefix(format!(
                    "Unknown address family: {}",
                    family
                )));
            }
        };

        Ok(Self {
            address,
            source_prefix,
            scope_prefix,
        })
    }
}

/// Padding option - RFC 7830
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaddingOption {
    /// Padding size
    pub size: u16,
}

impl PaddingOption {
    /// Create a new padding option
    pub fn new(size: u16) -> Self {
        Self { size }
    }

    /// Convert to EDNS option
    pub fn to_edns_option(&self) -> EdnsOption {
        EdnsOption::new(EdnsOptionCode::Padding, vec![0u8; self.size as usize])
    }
}

/// Extended DNS Error option - RFC 8914
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedErrorOption {
    /// Error code
    pub info_code: u16,
    /// Error message
    pub extra_text: String,
}

impl ExtendedErrorOption {
    /// Create a new extended error option
    pub fn new(info_code: u16, extra_text: String) -> Self {
        Self { info_code, extra_text }
    }

    /// Convert to EDNS option
    pub fn to_edns_option(&self) -> EdnsOption {
        let mut data = vec![(self.info_code >> 8) as u8, (self.info_code & 0xFF) as u8];
        data.extend_from_slice(self.extra_text.as_bytes());
        EdnsOption::new(EdnsOptionCode::ExtendedError, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edns_option_code_from_u16() {
        assert_eq!(EdnsOptionCode::from_u16(3).unwrap(), EdnsOptionCode::NSID);
        assert_eq!(EdnsOptionCode::from_u16(10).unwrap(), EdnsOptionCode::Cookie);
        assert!(EdnsOptionCode::from_u16(999).is_err());
    }

    #[test]
    fn test_nsid_option() {
        let nsid = NsidOption::from_string("test-server");
        assert_eq!(nsid.as_string().unwrap(), "test-server");

        let option = nsid.to_edns_option();
        assert_eq!(option.code, EdnsOptionCode::NSID);
    }

    #[test]
    fn test_cookie_option() {
        let cookie = CookieOption::generate_client();
        assert_eq!(cookie.size(), 8);

        let option = cookie.to_edns_option();
        assert_eq!(option.code, EdnsOptionCode::Cookie);
        assert_eq!(option.len(), 8);

        let parsed = CookieOption::from_edns_option(&option.data).unwrap();
        assert_eq!(parsed.client_cookie, cookie.client_cookie);
    }

    #[test]
    fn test_subnet_option() {
        let subnet = SubnetOption::ipv4(Ipv4Addr::new(192, 0, 2, 1), 24).unwrap();
        assert_eq!(subnet.source_prefix, 24);

        let option = subnet.to_edns_option().unwrap();
        assert_eq!(option.code, EdnsOptionCode::ClientSubnet);
    }

    #[test]
    fn test_padding_option() {
        let padding = PaddingOption::new(128);
        let option = padding.to_edns_option();
        assert_eq!(option.code, EdnsOptionCode::Padding);
        assert_eq!(option.len(), 128);
    }

    #[test]
    fn test_extended_error_option() {
        let error = ExtendedErrorOption::new(1, "Network error".to_string());
        let option = error.to_edns_option();
        assert_eq!(option.code, EdnsOptionCode::ExtendedError);
    }
}
