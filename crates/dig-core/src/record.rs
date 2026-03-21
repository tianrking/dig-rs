//! DNS record type definitions
//!
//! Based on BIND9's dns_rdatatype_t and IANA DNS parameters

use serde::{Deserialize, Serialize};

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum RecordType {
    // Standard record types (RFC 1035)
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,

    // RFC 1183
    RP,
    AFSDB,
    X25,
    ISDN,
    RT,

    // RFC 1348
    NSAP,
    #[allow(non_camel_case_types)]
    NSAP_PTR,

    // RFC 1982
    SIG,

    // RFC 2065
    KEY,

    // RFC 2163
    PX,

    // RFC 2230
    KX,

    // RFC 2535
    NXT,

    // RFC 2538
    CERT,

    // RFC 2671
    OPT,

    // RFC 2672
    DNAME,

    // RFC 2782
    SRV,

    // RFC 2845
    TSIG,

    // RFC 2930
    TKEY,

    // RFC 2915
    NAPTR,

    // RFC 3123
    APL,

    // RFC 3152
    DS,

    // RFC 3225
    SSHFP,

    // RFC 3596
    AAAA,

    // RFC 3658
    RRSIG,

    // RFC 3755
    NSEC,

    // RFC 4025
    IPSECKEY,

    // RFC 4034
    DNSKEY,
    NSEC3,
    NSEC3PARAM,

    // RFC 4255
    OPENPGPKEY,

    // RFC 4310
    DHCID,

    // RFC 4431
    DLV,

    // RFC 5205 / RFC 6563
    HIP,

    // RFC 6742
    L32,
    L64,
    LP,
    EUI48,
    EUI64,

    // RFC 6895
    NONE,

    // RFC 7208
    SPF,

    // RFC 7477
    CSYNC,

    // RFC 8078
    CDS,
    CDNSKEY,

    // RFC 8499
    ANY,

    // RFC 8630
    TLSA,

    // RFC 8659
    CAA,

    // RFC 9460
    SVCB,
    HTTPS,

    // RFC 9461
    ZONEMD,

    // Other
    LOC,
    URI,

    // RFC 1995
    IXFR,

    // RFC 1996
    AXFR,
    MAILB,
    MAILA,

    // Private use range
    PRIVATE(u16),

    // Unknown type
    UNKNOWN(u16),
}

impl RecordType {
    /// Get the numeric value of the record type
    pub fn to_u16(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::MD => 3,
            RecordType::MF => 4,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::MB => 7,
            RecordType::MG => 8,
            RecordType::MR => 9,
            RecordType::NULL => 10,
            RecordType::WKS => 11,
            RecordType::PTR => 12,
            RecordType::HINFO => 13,
            RecordType::MINFO => 14,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::RP => 17,
            RecordType::AFSDB => 18,
            RecordType::X25 => 19,
            RecordType::ISDN => 20,
            RecordType::RT => 21,
            RecordType::NSAP => 22,
            RecordType::NSAP_PTR => 23,
            RecordType::SIG => 24,
            RecordType::KEY => 25,
            RecordType::PX => 26,
            RecordType::KX => 36,
            RecordType::NXT => 30,
            RecordType::CERT => 37,
            RecordType::DNAME => 39,
            RecordType::OPT => 41,
            RecordType::APL => 42,
            RecordType::DS => 43,
            RecordType::SSHFP => 44,
            RecordType::IPSECKEY => 45,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::DHCID => 49,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::TLSA => 52,
            RecordType::HIP => 55,
            RecordType::CDS => 59,
            RecordType::CDNSKEY => 60,
            RecordType::OPENPGPKEY => 61,
            RecordType::CSYNC => 62,
            RecordType::ZONEMD => 63,
            RecordType::SVCB => 64,
            RecordType::HTTPS => 65,
            RecordType::LOC => 29,
            RecordType::SRV => 33,
            RecordType::NAPTR => 35,
            RecordType::AAAA => 28,
            RecordType::SPF => 99,
            RecordType::EUI48 => 108,
            RecordType::EUI64 => 109,
            RecordType::L32 => 105,
            RecordType::L64 => 106,
            RecordType::LP => 107,
            RecordType::URI => 256,
            RecordType::CAA => 257,
            RecordType::TKEY => 249,
            RecordType::TSIG => 250,
            RecordType::IXFR => 251,
            RecordType::AXFR => 252,
            RecordType::MAILB => 253,
            RecordType::MAILA => 254,
            RecordType::ANY => 255,
            RecordType::NONE => 0,
            RecordType::DLV => 32769,
            RecordType::PRIVATE(v) | RecordType::UNKNOWN(v) => *v,
        }
    }

    /// Create a record type from a u16 value
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            3 => RecordType::MD,
            4 => RecordType::MF,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            7 => RecordType::MB,
            8 => RecordType::MG,
            9 => RecordType::MR,
            10 => RecordType::NULL,
            11 => RecordType::WKS,
            12 => RecordType::PTR,
            13 => RecordType::HINFO,
            14 => RecordType::MINFO,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            17 => RecordType::RP,
            18 => RecordType::AFSDB,
            19 => RecordType::X25,
            20 => RecordType::ISDN,
            21 => RecordType::RT,
            22 => RecordType::NSAP,
            23 => RecordType::NSAP_PTR,
            24 => RecordType::SIG,
            25 => RecordType::KEY,
            26 => RecordType::PX,
            28 => RecordType::AAAA,
            29 => RecordType::LOC,
            30 => RecordType::NXT,
            33 => RecordType::SRV,
            35 => RecordType::NAPTR,
            36 => RecordType::KX,
            37 => RecordType::CERT,
            39 => RecordType::DNAME,
            41 => RecordType::OPT,
            42 => RecordType::APL,
            43 => RecordType::DS,
            44 => RecordType::SSHFP,
            45 => RecordType::IPSECKEY,
            46 => RecordType::RRSIG,
            47 => RecordType::NSEC,
            48 => RecordType::DNSKEY,
            49 => RecordType::DHCID,
            50 => RecordType::NSEC3,
            51 => RecordType::NSEC3PARAM,
            52 => RecordType::TLSA,
            55 => RecordType::HIP,
            59 => RecordType::CDS,
            60 => RecordType::CDNSKEY,
            61 => RecordType::OPENPGPKEY,
            62 => RecordType::CSYNC,
            63 => RecordType::ZONEMD,
            64 => RecordType::SVCB,
            65 => RecordType::HTTPS,
            99 => RecordType::SPF,
            105 => RecordType::L32,
            106 => RecordType::L64,
            107 => RecordType::LP,
            108 => RecordType::EUI48,
            109 => RecordType::EUI64,
            249 => RecordType::TKEY,
            250 => RecordType::TSIG,
            251 => RecordType::IXFR,
            252 => RecordType::AXFR,
            253 => RecordType::MAILB,
            254 => RecordType::MAILA,
            255 => RecordType::ANY,
            256 => RecordType::URI,
            257 => RecordType::CAA,
            32769 => RecordType::DLV,
            0 => RecordType::NONE,
            v if (65280..=65535).contains(&v) => RecordType::PRIVATE(v),
            v => RecordType::UNKNOWN(v),
        }
    }

    /// Check if this is a meta type (for queries)
    pub fn is_meta_type(&self) -> bool {
        matches!(
            self,
            RecordType::AXFR
                | RecordType::IXFR
                | RecordType::ANY
                | RecordType::MAILB
                | RecordType::MAILA
        )
    }

    /// Check if this is a DNSSEC type
    pub fn is_dnssec_type(&self) -> bool {
        matches!(
            self,
            RecordType::DS
                | RecordType::RRSIG
                | RecordType::NSEC
                | RecordType::DNSKEY
                | RecordType::NSEC3
                | RecordType::NSEC3PARAM
                | RecordType::CDS
                | RecordType::CDNSKEY
                | RecordType::DLV
        )
    }
}

impl Default for RecordType {
    fn default() -> Self {
        RecordType::A
    }
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::NS => write!(f, "NS"),
            RecordType::MD => write!(f, "MD"),
            RecordType::MF => write!(f, "MF"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::MB => write!(f, "MB"),
            RecordType::MG => write!(f, "MG"),
            RecordType::MR => write!(f, "MR"),
            RecordType::NULL => write!(f, "NULL"),
            RecordType::WKS => write!(f, "WKS"),
            RecordType::PTR => write!(f, "PTR"),
            RecordType::HINFO => write!(f, "HINFO"),
            RecordType::MINFO => write!(f, "MINFO"),
            RecordType::MX => write!(f, "MX"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::RP => write!(f, "RP"),
            RecordType::AFSDB => write!(f, "AFSDB"),
            RecordType::X25 => write!(f, "X25"),
            RecordType::ISDN => write!(f, "ISDN"),
            RecordType::RT => write!(f, "RT"),
            RecordType::NSAP => write!(f, "NSAP"),
            RecordType::NSAP_PTR => write!(f, "NSAP-PTR"),
            RecordType::SIG => write!(f, "SIG"),
            RecordType::KEY => write!(f, "KEY"),
            RecordType::PX => write!(f, "PX"),
            RecordType::KX => write!(f, "KX"),
            RecordType::NXT => write!(f, "NXT"),
            RecordType::CERT => write!(f, "CERT"),
            RecordType::DNAME => write!(f, "DNAME"),
            RecordType::OPT => write!(f, "OPT"),
            RecordType::APL => write!(f, "APL"),
            RecordType::DS => write!(f, "DS"),
            RecordType::SSHFP => write!(f, "SSHFP"),
            RecordType::IPSECKEY => write!(f, "IPSECKEY"),
            RecordType::RRSIG => write!(f, "RRSIG"),
            RecordType::NSEC => write!(f, "NSEC"),
            RecordType::DNSKEY => write!(f, "DNSKEY"),
            RecordType::DHCID => write!(f, "DHCID"),
            RecordType::NSEC3 => write!(f, "NSEC3"),
            RecordType::NSEC3PARAM => write!(f, "NSEC3PARAM"),
            RecordType::TLSA => write!(f, "TLSA"),
            RecordType::HIP => write!(f, "HIP"),
            RecordType::CDS => write!(f, "CDS"),
            RecordType::CDNSKEY => write!(f, "CDNSKEY"),
            RecordType::OPENPGPKEY => write!(f, "OPENPGPKEY"),
            RecordType::CSYNC => write!(f, "CSYNC"),
            RecordType::ZONEMD => write!(f, "ZONEMD"),
            RecordType::SVCB => write!(f, "SVCB"),
            RecordType::HTTPS => write!(f, "HTTPS"),
            RecordType::LOC => write!(f, "LOC"),
            RecordType::SRV => write!(f, "SRV"),
            RecordType::NAPTR => write!(f, "NAPTR"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::SPF => write!(f, "SPF"),
            RecordType::EUI48 => write!(f, "EUI48"),
            RecordType::EUI64 => write!(f, "EUI64"),
            RecordType::L32 => write!(f, "L32"),
            RecordType::L64 => write!(f, "L64"),
            RecordType::LP => write!(f, "LP"),
            RecordType::URI => write!(f, "URI"),
            RecordType::CAA => write!(f, "CAA"),
            RecordType::TKEY => write!(f, "TKEY"),
            RecordType::TSIG => write!(f, "TSIG"),
            RecordType::IXFR => write!(f, "IXFR"),
            RecordType::AXFR => write!(f, "AXFR"),
            RecordType::MAILB => write!(f, "MAILB"),
            RecordType::MAILA => write!(f, "MAILA"),
            RecordType::ANY => write!(f, "ANY"),
            RecordType::NONE => write!(f, "NONE"),
            RecordType::DLV => write!(f, "DLV"),
            RecordType::PRIVATE(v) => write!(f, "TYPE{}", v),
            RecordType::UNKNOWN(v) => write!(f, "TYPE{}", v),
        }
    }
}

impl std::str::FromStr for RecordType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let upper = s.to_uppercase();
        match upper.as_str() {
            "A" => Ok(RecordType::A),
            "NS" => Ok(RecordType::NS),
            "MD" => Ok(RecordType::MD),
            "MF" => Ok(RecordType::MF),
            "CNAME" => Ok(RecordType::CNAME),
            "SOA" => Ok(RecordType::SOA),
            "MB" => Ok(RecordType::MB),
            "MG" => Ok(RecordType::MG),
            "MR" => Ok(RecordType::MR),
            "NULL" => Ok(RecordType::NULL),
            "WKS" => Ok(RecordType::WKS),
            "PTR" => Ok(RecordType::PTR),
            "HINFO" => Ok(RecordType::HINFO),
            "MINFO" => Ok(RecordType::MINFO),
            "MX" => Ok(RecordType::MX),
            "TXT" => Ok(RecordType::TXT),
            "RP" => Ok(RecordType::RP),
            "AFSDB" => Ok(RecordType::AFSDB),
            "X25" => Ok(RecordType::X25),
            "ISDN" => Ok(RecordType::ISDN),
            "RT" => Ok(RecordType::RT),
            "NSAP" => Ok(RecordType::NSAP),
            "NSAP-PTR" => Ok(RecordType::NSAP_PTR),
            "SIG" => Ok(RecordType::SIG),
            "KEY" => Ok(RecordType::KEY),
            "PX" => Ok(RecordType::PX),
            "KX" => Ok(RecordType::KX),
            "NXT" => Ok(RecordType::NXT),
            "CERT" => Ok(RecordType::CERT),
            "DNAME" => Ok(RecordType::DNAME),
            "OPT" => Ok(RecordType::OPT),
            "APL" => Ok(RecordType::APL),
            "DS" => Ok(RecordType::DS),
            "SSHFP" => Ok(RecordType::SSHFP),
            "IPSECKEY" => Ok(RecordType::IPSECKEY),
            "RRSIG" => Ok(RecordType::RRSIG),
            "NSEC" => Ok(RecordType::NSEC),
            "DNSKEY" => Ok(RecordType::DNSKEY),
            "DHCID" => Ok(RecordType::DHCID),
            "NSEC3" => Ok(RecordType::NSEC3),
            "NSEC3PARAM" => Ok(RecordType::NSEC3PARAM),
            "TLSA" => Ok(RecordType::TLSA),
            "HIP" => Ok(RecordType::HIP),
            "CDS" => Ok(RecordType::CDS),
            "CDNSKEY" => Ok(RecordType::CDNSKEY),
            "OPENPGPKEY" => Ok(RecordType::OPENPGPKEY),
            "CSYNC" => Ok(RecordType::CSYNC),
            "ZONEMD" => Ok(RecordType::ZONEMD),
            "SVCB" => Ok(RecordType::SVCB),
            "HTTPS" => Ok(RecordType::HTTPS),
            "LOC" => Ok(RecordType::LOC),
            "SRV" => Ok(RecordType::SRV),
            "NAPTR" => Ok(RecordType::NAPTR),
            "AAAA" => Ok(RecordType::AAAA),
            "SPF" => Ok(RecordType::SPF),
            "EUI48" => Ok(RecordType::EUI48),
            "EUI64" => Ok(RecordType::EUI64),
            "L32" => Ok(RecordType::L32),
            "L64" => Ok(RecordType::L64),
            "LP" => Ok(RecordType::LP),
            "URI" => Ok(RecordType::URI),
            "CAA" => Ok(RecordType::CAA),
            "TKEY" => Ok(RecordType::TKEY),
            "TSIG" => Ok(RecordType::TSIG),
            "IXFR" => Ok(RecordType::IXFR),
            "AXFR" => Ok(RecordType::AXFR),
            "MAILB" => Ok(RecordType::MAILB),
            "MAILA" => Ok(RecordType::MAILA),
            "ANY" | "*" => Ok(RecordType::ANY),
            "NONE" => Ok(RecordType::NONE),
            "DLV" => Ok(RecordType::DLV),
            s if s.starts_with("TYPE") => {
                let num: u16 = s[4..]
                    .parse()
                    .map_err(|_| format!("Invalid TYPE number: {}", s))?;
                Ok(RecordType::from_u16(num))
            }
            _ => Err(format!("Unknown record type: {}", s)),
        }
    }
}

impl From<RecordType> for String {
    fn from(rt: RecordType) -> Self {
        rt.to_string()
    }
}

impl TryFrom<String> for RecordType {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        Self::from_u16(value)
    }
}

impl From<RecordType> for u16 {
    fn from(rt: RecordType) -> Self {
        rt.to_u16()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::from_u16(1), RecordType::A);
        assert_eq!(RecordType::AAAA.to_u16(), 28);
        assert_eq!(RecordType::from_u16(28), RecordType::AAAA);
    }

    #[test]
    fn test_record_type_parsing() {
        assert_eq!("A".parse::<RecordType>().unwrap(), RecordType::A);
        assert_eq!("AAAA".parse::<RecordType>().unwrap(), RecordType::AAAA);
        assert_eq!("MX".parse::<RecordType>().unwrap(), RecordType::MX);
    }
}
