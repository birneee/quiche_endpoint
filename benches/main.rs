use criterion::{black_box, criterion_main};
use criterion::{criterion_group, Criterion, Throughput};
use pprof::criterion::Output;
use pprof::criterion::PProfProfiler;
use quiche_endpoint::test_utils::Pipe;
use quiche_endpoint::Error;
use std::time::{Duration, Instant};

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench_handshake, bench_throughput
);
criterion_main!(benches);

fn bench_handshake(c: &mut Criterion) {
    let mut pipe = Pipe::new();
    c.bench_function("handshake", |b| {
        b.iter(|| {
            pipe.reset();
            pipe.connect();
            pipe.handshake_all().unwrap();
        });
    });
}

fn _bench_throughput(pipe: &mut Pipe, buf: &mut [u8; 1_000_000], target: usize) {
    let mut received = 0;
    loop {
        pipe.server.on_timeout();
        pipe.client.on_timeout();
        'send: loop {
            match pipe.server.stream_send(0, 1, buf.as_mut(), false) {
                Ok(_) => {}
                Err(Error::Quiche(quiche::Error::Done)) => break 'send,
                Err(e) => unimplemented!("{:?}", e),
            }
        }
        'recv: loop {
            match pipe.client.stream_recv(0, 1, buf.as_mut()) {
                Ok((n, _)) => {
                    received += n;
                    if received >= target {
                        break 'recv;
                    }
                }
                Err(Error::Quiche(quiche::Error::Done)) => break 'recv,
                Err(Error::Quiche(quiche::Error::InvalidStreamState(1))) => break 'recv,
                Err(e) => unimplemented!("{:?}", e),
            }
        }
        if received >= target {
            break;
        }
        pipe.advance();
    }
}

fn bench_throughput(c: &mut Criterion) {
    let mut g = c.benchmark_group("throughput");
    const TARGET: usize = 1E9 as usize;
    g.throughput(Throughput::Bytes(TARGET as u64));
    g.sample_size(10);
    let mut buf = [0u8; 1_000_000];
    let mut pipe = Pipe::new();
    g.bench_function("1GB", |b| {
        b.iter_custom(|iters| {
            let mut total_duration = Duration::ZERO;
            for _ in 0..iters {
                pipe.reset();
                pipe.connect();
                pipe.handshake_all().unwrap();
                let start = Instant::now();
                black_box(_bench_throughput(&mut pipe, &mut buf, TARGET));
                total_duration += start.elapsed();
            }
            total_duration
        });
    });
}
