use criterion::{criterion_group, criterion_main, Criterion};
use rsca::TWCA;
use std::env;
use std::time::Duration;

fn benchmark_signing(c: &mut Criterion) {
    // Gracefully skip the benchmark if environment variables are not set.
    let pfx_path = match env::var("PFX_PATH") {
        Ok(val) => val,
        Err(_) => {
            println!("Skipping signing benchmark: PFX_PATH environment variable not set.");
            return;
        }
    };
    let password = match env::var("PFX_PASSWORD") {
        Ok(val) => val,
        Err(_) => {
            println!("Skipping signing benchmark: PFX_PASSWORD environment variable not set.");
            return;
        }
    };

    let data_to_sign = "This is the data to be signed for benchmarking purposes. It's a bit longer to ensure the signing cost is dominant.";

    let mut group = c.benchmark_group("Signing Performance (PKCS7 vs PKCS1)");
    // Cryptographic operations are slow, so we increase the measurement time.
    group.measurement_time(Duration::from_secs(10));

    // We use a separate TWCA instance for each benchmark function to ensure
    // that the warmup and caching behavior of one does not affect the other.
    let ca_for_pkcs7 = TWCA::new(&pfx_path, &password, "0.0.0.0")
        .expect("Failed to create TWCA instance for PKCS7 benchmark");

    group.bench_function("sign (PKCS7)", |b| {
        b.iter(|| ca_for_pkcs7.sign(data_to_sign))
    });

    let ca_for_pkcs1 = TWCA::new(&pfx_path, &password, "0.0.0.0")
        .expect("Failed to create TWCA instance for PKCS1 benchmark");

    group.bench_function("sign_pkcs1", |b| {
        b.iter(|| ca_for_pkcs1.sign_pkcs1(data_to_sign))
    });

    group.finish();
}

criterion_group!(benches, benchmark_signing);
criterion_main!(benches); 