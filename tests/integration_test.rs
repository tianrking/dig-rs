// Integration tests for dig-rs
//
// These tests verify the complete functionality of the dig tool
// end-to-end.

use assert_cmd::Command;
use predicates::prelude::*;

/// Test basic A record lookup
#[test]
fn test_basic_a_lookup() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+short")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "93.184.216.34",
        ));
}

/// Test MX record lookup
#[test]
fn test_mx_lookup() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("MX")
        .arg("+short")
        .assert()
        .success();
}

/// Test reverse DNS lookup
#[test]
fn test_reverse_lookup() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("-x")
        .arg("8.8.8.8")
        .arg("+short")
        .assert()
        .success();
}

/// Test query with specific server
#[test]
fn test_query_with_server() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("@8.8.8.8")
        .arg("example.com")
        .arg("+short")
        .assert()
        .success();
}

/// Test JSON output format
#[test]
fn test_json_output() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+json")
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""status""#));
}

/// Test table output format
#[test]
fn test_table_output() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+table")
        .assert()
        .success();
}

/// Test TCP mode
#[test]
fn test_tcp_mode() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+tcp")
        .assert()
        .success();
}

/// Test EDNS support
#[test]
fn test_edns_support() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+edns=0")
        .arg("+bufsize=1232")
        .assert()
        .success();
}

/// Test DNSSEC flag
#[test]
fn test_dnssec_flag() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+dnssec")
        .assert()
        .success();
}

/// Test with timeout
#[test]
fn test_timeout() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+timeout=2")
        .assert()
        .success();
}

/// Test with retry
#[test]
fn test_retry() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+retry=1")
        .assert()
        .success();
}

/// Test TXT record lookup
#[test]
fn test_txt_lookup() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("TXT")
        .arg("+short")
        .assert()
        .success();
}

/// Test NS record lookup
#[test]
fn test_ns_lookup() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("NS")
        .arg("+short")
        .assert()
        .success();
}

/// Test SOA record lookup
#[test]
fn test_soa_lookup() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("SOA")
        .arg("+short")
        .assert()
        .success();
}

/// Test CNAME record lookup
#[test]
fn test_cname_lookup() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("www.example.com")
        .arg("CNAME")
        .arg("+short")
        .assert()
        .success();
}

/// Test AAAA record lookup
#[test]
fn test_aaaa_lookup() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("AAAA")
        .arg("+short")
        .assert()
        .success();
}

/// Test multiple query types
#[test]
fn test_multiple_query_types() {
    let types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"];

    for qtype in types {
        let mut cmd = Command::cargo_bin("dig").unwrap();

        cmd.arg("example.com")
            .arg(qtype)
            .assert()
            .success();
    }
}

/// Test help output
#[test]
fn test_help() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("dig-rs"))
        .stdout(predicate::str::contains("USAGE"))
        .stdout(predicate::str::contains("OPTIONS"));
}

/// Test version output
#[test]
fn test_version() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("dig"));
}

/// Test invalid domain name handling
#[test]
fn test_invalid_domain() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("")
        .assert()
        .failure();
}

/// Test with class specification
#[test]
fn test_class_specification() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("-c")
        .arg("IN")
        .assert()
        .success();
}

/// Test port specification
#[test]
fn test_port_specification() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("-p")
        .arg("53")
        .assert()
        .success();
}

/// Test query with multiple flags
#[test]
fn test_multiple_flags() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("@1.1.1.1")
        .arg("example.com")
        .arg("+tcp")
        .arg("+dnssec")
        .arg("+short")
        .assert()
        .success();
}

/// Test statistics output
#[test]
fn test_stats_output() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+stats")
        .assert()
        .success();
}

/// Test no comments flag
#[test]
fn test_no_comments() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+nocomments")
        .assert()
        .success();
}

/// Test question section display
#[test]
fn test_question_section() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+question")
        .assert()
        .success();
}

/// Test authority section display
#[test]
fn test_authority_section() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+authority")
        .assert()
        .success();
}

/// Test additional section display
#[test]
fn test_additional_section() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+additional")
        .assert()
        .success();
}

/// Test TTL display
#[test]
fn test_ttl_display() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+ttlid")
        .assert()
        .success();
}

/// Test class display
#[test]
fn test_class_display() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+class")
        .assert()
        .success();
}

/// Test all display flags
#[test]
fn test_all_display_flags() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+all")
        .assert()
        .success();
}

/// Test IPv4 force
#[test]
fn test_ipv4_force() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("-4")
        .assert()
        .success();
}

/// Test IPv6 force
#[test]
fn test_ipv6_force() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("-6")
        .assert()
        .success();
}

/// Test with query name flag
#[test]
fn test_query_name_flag() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("-q")
        .arg("example.com")
        .arg("+short")
        .assert()
        .success();
}

/// Test with type flag
#[test]
fn test_type_flag() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("-t")
        .arg("A")
        .arg("+short")
        .assert()
        .success();
}

/// Test batch mode with invalid file
#[test]
fn test_batch_mode_invalid_file() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("-f")
        .arg("/nonexistent/file.txt")
        .assert()
        .failure();
}

/// Test DNSSEC with DO flag
#[test]
fn test_dnssec_do_flag() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+do")
        .assert()
        .success();
}

/// Test AD flag
#[test]
fn test_ad_flag() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+adflag")
        .assert()
        .success();
}

/// Test CD flag
#[test]
fn test_cd_flag() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+cdflag")
        .assert()
        .success();
}

/// Test recursion flag
#[test]
fn test_recursion_flag() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+recurse")
        .assert()
        .success();
}

/// Test no recursion flag
#[test]
fn test_no_recursion_flag() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+norecurse")
        .assert()
        .success();
}

/// Test trace mode (this may take longer)
#[test]
#[ignore]
fn test_trace_mode() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+trace")
        .assert()
        .success();
}

/// Test with custom timeout and retry
#[test]
fn test_custom_timeout_and_retry() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+timeout=1")
        .arg("+retry=0")
        .assert()
        .success();
}
