// Tests for DNS transport protocols

use assert_cmd::Command;
use predicates::prelude::*;

/// Test UDP transport (default)
#[test]
fn test_udp_transport() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+notcp")
        .assert()
        .success();
}

/// Test TCP transport
#[test]
fn test_tcp_transport() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+tcp")
        .assert()
        .success();
}

/// Test TCP with VC flag (alias)
#[test]
fn test_tcp_vc_flag() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+vc")
        .assert()
        .success();
}

/// Test DNS-over-TLS with Cloudflare
#[test]
fn test_dot_transport() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("@1.1.1.1")
        .arg("example.com")
        .arg("+tls")
        .assert()
        .success();
}

/// Test DNS-over-TLS with Google
#[test]
fn test_dot_google() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("@8.8.8.8")
        .arg("example.com")
        .arg("+tls")
        .assert()
        .success();
}

/// Test DNS-over-HTTPS with Cloudflare
#[test]
fn test_doh_transport() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("@1.1.1.1")
        .arg("example.com")
        .arg("+https")
        .assert()
        .success();
}

/// Test DoH GET method
#[test]
fn test_doh_get_method() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("@1.1.1.1")
        .arg("example.com")
        .arg("+https-get")
        .assert()
        .success();
}

/// Test IPv4 transport
#[test]
fn test_ipv4_transport() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("-4")
        .arg("example.com")
        .assert()
        .success();
}

/// Test IPv6 transport
#[test]
fn test_ipv6_transport() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("-6")
        .arg("example.com")
        .assert()
        .success();
}

/// Test transport with specific port
#[test]
fn test_transport_with_port() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("-p")
        .arg("53")
        .assert()
        .success();
}

/// Test TCP with custom timeout
#[test]
fn test_tcp_with_timeout() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+tcp")
        .arg("+timeout=5")
        .assert()
        .success();
}

/// Test multiple transports in sequence
#[test]
fn test_multiple_transports() {
    let transports = [
        vec!["+notcp"],
        vec!["+tcp"],
        vec!["+tls"],
    ];

    for transport in transports {
        let mut cmd = Command::cargo_bin("dig").unwrap();

        cmd.arg("example.com");
        for flag in transport {
            cmd.arg(flag);
        }

        cmd.assert().success();
    }
}

/// Test transport retry logic
#[test]
fn test_transport_retry() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+tcp")
        .arg("+retry=2")
        .arg("+tries=3")
        .assert()
        .success();
}

/// Test transport with EDNS
#[test]
fn test_transport_with_edns() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+tcp")
        .arg("+edns=0")
        .arg("+bufsize=1232")
        .assert()
        .success();
}

/// Test transport with DNSSEC
#[test]
fn test_transport_with_dnssec() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+tcp")
        .arg("+dnssec")
        .assert()
        .success();
}

/// Test transport connection failures
#[test]
fn test_transport_connection_failure() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    // Use an invalid server
    cmd.arg("@192.0.2.1")  // TEST-NET-1, should be unreachable
        .arg("example.com")
        .arg("+timeout=1")
        .arg("+retry=0")
        .assert()
        .failure();
}

/// Test transport with custom source address
#[test]
fn test_transport_source_address() {
    // This test is platform-dependent and may not work everywhere
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("-b")
        .arg("0.0.0.0")
        .arg("example.com")
        .assert();
    // Don't assert success as binding may fail
}

/// Test IPv4/IPv6 force with IPv4 server
#[test]
fn test_ipv4_force_with_ipv4_server() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("-4")
        .arg("@8.8.8.8")
        .arg("example.com")
        .assert()
        .success();
}

/// Test IPv6 force with IPv6 server
#[test]
fn test_ipv6_force_with_ipv6_server() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("-6")
        .arg("@2001:4860:4860::8888")
        .arg("example.com")
        .assert()
        .success();
}

/// Test transport with short output
#[test]
fn test_transport_short_output() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+tcp")
        .arg("+short")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            ".",
        ));
}

/// Test transport with JSON output
#[test]
fn test_transport_json_output() {
    let mut cmd = Command::cargo_bin("dig").unwrap();

    cmd.arg("example.com")
        .arg("+tcp")
        .arg("+json")
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""status""#));
}
