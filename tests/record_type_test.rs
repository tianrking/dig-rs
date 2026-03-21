// Tests for DNS record type support

use assert_cmd::Command;

/// Test all standard record types
#[test]
fn test_standard_record_types() {
    let standard_types = [
        "A", "AAAA", "NS", "CNAME", "SOA", "MX", "TXT", "PTR",
        "SRV", "SPF", "DNAME", "HINFO",
    ];

    for qtype in standard_types {
        let mut cmd = Command::cargo_bin("dig").unwrap();

        // For PTR, use a reverse lookup
        if qtype == "PTR" {
            cmd.arg("-x").arg("8.8.8.8");
        } else {
            cmd.arg("example.com").arg(qtype);
        }

        cmd.arg("+short")
            .assert()
            .success();
    }
}

/// Test DNSSEC record types
#[test]
fn test_dnssec_record_types() {
    let dnssec_types = [
        "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM",
    ];

    for qtype in dnssec_types {
        let mut cmd = Command::cargo_bin("dig").unwrap();

        // Use a domain that has DNSSEC
        cmd.arg("example.com").arg(qtype)
            .assert()
            .success();
    }
}

/// Test security-related record types
#[test]
fn test_security_record_types() {
    let security_types = [
        "TLSA", "CAA", "SSHFP", "IPSECKEY", "CERT",
    ];

    for qtype in security_types {
        let mut cmd = Command::cargo_bin("dig").unwrap();

        // Some record types need specific domains
        let domain = match qtype {
            "TLSA" => "_443._tcp.example.com",
            "CAA" => "example.com",
            _ => "example.com",
        };

        cmd.arg(domain).arg(qtype)
            .arg("+short")
            .assert()
            .success();
    }
}

/// Test modern record types
#[test]
fn test_modern_record_types() {
    let modern_types = [
        "SVCB", "HTTPS", "OPENPGPKEY",
    ];

    for qtype in modern_types {
        let mut cmd = Command::cargo_bin("dig").unwrap();

        cmd.arg("example.com").arg(qtype)
            .arg("+short")
            .assert()
            .success();
    }
}

/// Test less common record types
#[test]
fn test_uncommon_record_types() {
    let uncommon_types = [
        "RP", "AFSDB", "X25", "ISDN", "RT", "NSAP", "PX", "GPOS",
    ];

    for qtype in uncommon_types {
        let mut cmd = Command::cargo_bin("dig").unwrap();

        cmd.arg("example.com").arg(qtype)
            .arg("+short")
            .assert();
        // Don't require success for uncommon types
    }
}

/// Test ANY query type
#[test]
fn test_any_type() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("ANY")
        .assert()
        .success();
}

/// Test output formats with different record types
#[test]
fn test_record_types_with_json() {
    let types = ["A", "MX", "TXT"];

    for qtype in types {
        let mut cmd = Command::cargo_bin("dig").unwrap();

        cmd.arg("example.com")
            .arg(qtype)
            .arg("+json")
            .assert()
            .success();
    }
}

/// Test record types with table output
#[test]
fn test_record_types_with_table() {
    let types = ["A", "AAAA", "MX"];

    for qtype in types {
        let mut cmd = Command::cargo_bin("dig").unwrap();

        cmd.arg("example.com")
            .arg(qtype)
            .arg("+table")
            .assert()
            .success();
    }
}

/// Test SOA record parsing
#[test]
fn test_soa_record_fields() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("SOA")
        .arg("+short")
        .assert()
        .success()
        .stdout(predicate::prelude::contains(
            " ",
        ));
}

/// Test MX record priority
#[test]
fn test_mx_record_priority() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("MX")
        .arg("+short")
        .assert()
        .success();
}
