// Benchmark tests for dig-rs using Criterion

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dig_core::config::{Config, DnsServer, QueryType, RecordType, TransportProtocol};
use dig_core::lookup::Lookup;
use dig_core::resolver::Resolver;
use std::time::Duration;

/// Benchmark basic A record lookup
fn bench_basic_lookup(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("basic A lookup", |b| {
        b.to_async(&rt).iter(|| async {
            let config = Config::builder()
                .query_name("example.com".to_string())
                .record_type(RecordType::A)
                .build()
                .unwrap();

            let _ = Lookup::query(&config).await;
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
                let config = Config::builder()
                    .query_name("example.com".to_string())
                    .record_type(rtype)
                    .build()
                    .unwrap();

                let _ = Lookup::query(&config).await;
            })
        });
    }

    group.finish();
}

/// Benchmark transport protocols
fn bench_transports(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("transports");
    group.sample_size(20); // Reduce samples for slower tests

    group.bench_function("UDP", |b| {
        b.to_async(&rt).iter(|| async {
            let config = Config::builder()
                .query_name("example.com".to_string())
                .record_type(RecordType::A)
                .transport(TransportProtocol::Udp)
                .build()
                .unwrap();

            let _ = Lookup::query(&config).await;
        })
    });

    group.bench_function("TCP", |b| {
        b.to_async(&rt).iter(|| async {
            let config = Config::builder()
                .query_name("example.com".to_string())
                .record_type(RecordType::A)
                .transport(TransportProtocol::Tcp)
                .build()
                .unwrap();

            let _ = Lookup::query(&config).await;
        })
    });

    group.finish();
}

/// Benchmark DNSSEC queries
fn bench_dnssec(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("DNSSEC query", |b| {
        b.to_async(&rt).iter(|| async {
            let config = Config::builder()
                .query_name("example.com".to_string())
                .record_type(RecordType::A)
                .dnssec(true)
                .build()
                .unwrap();

            let _ = Lookup::query(&config).await;
        })
    });
}

/// Benchmark EDNS with different buffer sizes
fn bench_edns_buffer_sizes(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let buffer_sizes = vec![512, 1232, 4096, 8192];

    let mut group = c.benchmark_group("edns_buffer_sizes");

    for size in buffer_sizes {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.to_async(&rt).iter(|| async {
                let config = Config::builder()
                    .query_name("example.com".to_string())
                    .record_type(RecordType::A)
                    .edns_buffer_size(size)
                    .build()
                    .unwrap();

                let _ = Lookup::query(&config).await;
            })
        });
    }

    group.finish();
}

/// Benchmark timeout settings
fn bench_timeouts(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let timeouts = vec![1, 2, 5, 10];

    let mut group = c.benchmark_group("timeouts");

    for timeout in timeouts {
        group.bench_with_input(
            BenchmarkId::from_parameter(timeout),
            &timeout,
            |b, &timeout| {
                b.to_async(&rt).iter(|| async {
                    let config = Config::builder()
                        .query_name("example.com".to_string())
                        .record_type(RecordType::A)
                        .timeout(Duration::from_secs(timeout))
                        .build()
                        .unwrap();

                    let _ = Lookup::query(&config).await;
                })
            },
        );
    }

    group.finish();
}

/// Benchmark parallel queries
fn bench_parallel_queries(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("parallel_queries");
    group.sample_size(20);

    for count in [1, 5, 10].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            b.to_async(&rt).iter(|| async {
                let domains = vec!["example.com"; count];
                let handles: Vec<_> = domains
                    .iter()
                    .map(|domain| {
                        tokio::spawn(async move {
                            let config = Config::builder()
                                .query_name(domain.to_string())
                                .record_type(RecordType::A)
                                .build()
                                .unwrap();

                            Lookup::query(&config).await
                        })
                    })
                    .collect();

                for handle in handles {
                    let _ = handle.await;
                }
            })
        });
    }

    group.finish();
}

/// Benchmark reverse DNS lookups
fn bench_reverse_lookup(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("reverse DNS lookup", |b| {
        b.to_async(&rt).iter(|| async {
            let config = Config::builder()
                .reverse_lookup("8.8.8.8".parse().unwrap())
                .build()
                .unwrap();

            let _ = Lookup::query(&config).await;
        })
    });
}

/// Benchmark with different DNS servers
fn bench_dns_servers(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let servers = vec![
        ("Google", "8.8.8.8:53"),
        ("Cloudflare", "1.1.1.1:53"),
        ("Quad9", "9.9.9.9:53"),
    ];

    let mut group = c.benchmark_group("dns_servers");

    for (name, server) in servers {
        group.bench_with_input(BenchmarkId::new(name, server), &server, |b, server| {
            b.to_async(&rt).iter(|| async {
                let config = Config::builder()
                    .query_name("example.com".to_string())
                    .record_type(RecordType::A)
                    .server(DnsServer::from_str(server).unwrap())
                    .build()
                    .unwrap();

                let _ = Lookup::query(&config).await;
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_basic_lookup,
    bench_record_types,
    bench_transports,
    bench_dnssec,
    bench_edns_buffer_sizes,
    bench_timeouts,
    bench_parallel_queries,
    bench_reverse_lookup,
    bench_dns_servers
);

criterion_main!(benches);
