use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rand::RngCore;
use signature::Signer;
use slh_dsa::*;

fn make_msg(n: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let mut msg = vec![0u8; n];
    rng.fill_bytes(&mut msg);
    msg
}

pub fn sign_large_benchmark<P: ParameterSet>(c: &mut Criterion) {
    let mut rng = rand::rng();
    let sk = SigningKey::<P>::new(&mut rng);
    let sizes = [64usize, 1024 * 1024, 100 * 1024 * 1024]; // 64B, 1MB, 100MB
    let mut group = c.benchmark_group(format!("sign_large: {}", P::NAME));
    group
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(10));

    for &sz in &sizes {
        let msg = make_msg(sz); // reused across iterations
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::from_parameter(sz), &msg, |b, m| {
            b.iter(|| {
                let sig = sk.try_sign(black_box(&m[..])).unwrap();
                black_box(sig)
            })
        });
    }
    group.finish();
}

criterion_group!(name = large_benches;
    config = Criterion::default();
    targets =
        sign_large_benchmark<Shake128s>,
        sign_large_benchmark<Blake3_128s>,
        sign_large_benchmark<Sha2_128s>,
        sign_large_benchmark<Shake128f>,
        sign_large_benchmark<Blake3_128f>,
        sign_large_benchmark<Sha2_128f>,
);
criterion_main!(large_benches);
