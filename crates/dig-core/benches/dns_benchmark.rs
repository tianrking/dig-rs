// Benchmark tests for dig-rs using Criterion

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use dig_core::config::DigConfig;
use dig_core::lookup::DigLookup;
use dig_core::record::RecordType;

/// Benchmark basic A record lookup
fn bench_basic_lookup(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("basic A lookup", |b| {
        b.to_async(&rt).iter(|| async {
            let config = DigConfig::new("example.com");

            let lookup = DigLookup::new(config);
            let _ = lookup.lookup().await;
        })
    });
}

/// Benchmark different record types
fn bench_record_types(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let types = vec![
        ("A", RecordType::A),
        ("AAAA", RecordType::AAAA),
        ("MX", RecordType::MX),
        ("TXT", RecordType::TXT),
        ("NS", RecordType::NS),
    ];

    let mut group = c.benchmark_group("record_types");

    for (name, rtype) in types {
        group.bench_with_input(BenchmarkId::from_parameter(name), &rtype, |b, &rtype| {
            b.to_async(&rt).iter(|| async {
                let mut config = DigConfig::new("example.com");
                config.query_type = rtype.to_string();

                let lookup = DigLookup::new(config);
                let _ = lookup.lookup().await;
            })
        });
    }
    group.finish();
}

/// Benchmark with different servers
fn bench_different_servers(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let servers = vec![
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("208.67.222.222", "OpenDNS"),
    ];

    let mut group = c.benchmark_group("servers");

    for (addr, name) in servers {
        group.bench_with_input(BenchmarkId::from_parameter(name), &addr, |b, &addr| {
            b.to_async(&rt).iter(|| async {
                let mut config = DigConfig::new("example.com");
                config
                    .servers
                    .push(dig_core::config::ServerConfig::new(addr));

                let lookup = DigLookup::new(config);
                let _ = lookup.lookup().await;
            })
        });
    }
    group.finish();
}

/// Benchmark query parsing
fn bench_query_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing");

    group.bench_function("parse domain", |b| {
        b.iter(|| {
            let _ = DigConfig::new("example.com");
        })
    });

    group.bench_function("parse record type", |b| {
        b.iter(|| {
            let _: Result<RecordType, _> = "AAAA".parse();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_basic_lookup,
    bench_record_types,
    bench_different_servers,
    bench_query_parsing
);
criterion_main!(benches);
