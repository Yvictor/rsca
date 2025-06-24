use criterion::{criterion_group, criterion_main, Criterion};
use rsca::{get_timestamp_coarse, get_timestamp_system};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Timestamp Performance (Isolated Rust)");

    group.bench_function("SystemTime (syscall)", |b| {
        b.iter(|| get_timestamp_system())
    });

    group.bench_function("CoarseTime (memory read)", |b| {
        b.iter(|| get_timestamp_coarse())
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches); 