use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::{hint::black_box, time::Duration};

use hybrid_array::Array;
use ml_dsa::{B32, KeyGen, MlDsa65, Signature, SigningKey, VerifyingKey};

fn fixed_xi() -> B32 {
    let mut xi: B32 = Array::default();
    xi.as_mut_slice().fill(0x11);
    xi
}
fn fixed_ctx() -> B32 {
    let mut ctx: B32 = Array::default();
    ctx.as_mut_slice().fill(0x33);
    ctx
}
// 32B
fn fixed_msg_32() -> Vec<u8> {
    let m = vec![0x22u8; 32];
    m
}
// 256B
fn fixed_msg_256() -> Vec<u8> {
    let m = vec![0x22u8; 256];
    m
}
// 1024B
fn fixed_msg_1024() -> Vec<u8> {
    let m = vec![0x22u8; 1024];
    m
}
// 4096B
fn fixed_msg_4096() -> Vec<u8> {
    let m = vec![0x22u8; 4096];
    m
}
// 256 KiB
fn fixed_msg_256_1024() -> Vec<u8> {
    let m = vec![0x22u8; 262_144];
    m
}
// 1 MiB
fn fixed_msg_1_1024() -> Vec<u8> {
    let m = vec![0x22u8; 1_048_576];
    m
}
// 10 MiB
fn fixed_msg_10_1024() -> Vec<u8> {
    let m = vec![0x22u8; 10_485_760];
    m
}
// 100 MiB
fn fixed_msg_100_1024() -> Vec<u8> {
    let m = vec![0x22u8; 100_485_760];
    m
}

/// Bench keygen (independent of message size)
fn bench_keygen(c: &mut Criterion) {
    let xi = fixed_xi();
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let kp = MlDsa65::key_gen_internal(black_box(&xi));
            // consume to avoid elision
            black_box(kp.signing_key().encode());
            black_box(kp.verifying_key().encode());
        })
    });
}

/// Bench verify (uses fixed-size B32 message by convention; change if you want size parity)
fn bench_verify(c: &mut Criterion) {
    let xi = fixed_xi();
    let ctx = fixed_ctx();
    let m = fixed_msg_256(); // verify cost barely changes with m, 256 is fine

    let kp = MlDsa65::key_gen_internal(&xi);
    let sk = kp.signing_key();
    let vk = kp.verifying_key();
    // produce a reference signature (not timed)
    let sig = sk.sign_deterministic(&m, &ctx).unwrap();

    let vk_bytes = vk.encode();
    let sig_bytes = sig.encode();
    let vk_dec = VerifyingKey::<MlDsa65>::decode(&vk_bytes);
    let sig_dec = Signature::<MlDsa65>::decode(&sig_bytes).unwrap();

    c.bench_function("verify", |b| {
        b.iter(|| {
            let ok =
                vk_dec.verify_with_context(black_box(&m), black_box(&ctx), black_box(&sig_dec));
            black_box(ok);
        })
    });
}

/// Cold-sign benches (decode -> one sign per iteration), parameterized by message size.
fn bench_sign_cold(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_cold");

    let xi = fixed_xi();
    let ctx = fixed_ctx();
    let kp = MlDsa65::key_gen_internal(&xi);
    let sk_bytes = kp.signing_key().encode();

    // 32B
    {
        let m = fixed_msg_32();
        group.bench_with_input(BenchmarkId::new("32B", 32), &m, |b, m| {
            b.iter(|| {
                let sk = SigningKey::<MlDsa65>::decode(&sk_bytes);
                let sig = sk
                    .sign_deterministic(black_box(m), black_box(&ctx))
                    .unwrap();
                black_box(sig);
            })
        });
    }
    // 256B
    {
        let m = fixed_msg_256();
        group.bench_with_input(BenchmarkId::new("256B", 256), &m, |b, m| {
            b.iter(|| {
                let sk = SigningKey::<MlDsa65>::decode(&sk_bytes);
                let sig = sk
                    .sign_deterministic(black_box(m), black_box(&ctx))
                    .unwrap();
                black_box(sig);
            })
        });
    }
    // 1024B
    {
        let m = fixed_msg_1024();
        group.bench_with_input(BenchmarkId::new("1024B", 1024), &m, |b, m| {
            b.iter(|| {
                let sk = SigningKey::<MlDsa65>::decode(&sk_bytes);
                let sig = sk
                    .sign_deterministic(black_box(m), black_box(&ctx))
                    .unwrap();
                black_box(sig);
            })
        });
    }
    // 4096B
    {
        let m = fixed_msg_4096();
        group.bench_with_input(BenchmarkId::new("4096B", 4096), &m, |b, m| {
            b.iter(|| {
                let sk = SigningKey::<MlDsa65>::decode(&sk_bytes);
                let sig = sk
                    .sign_deterministic(black_box(m), black_box(&ctx))
                    .unwrap();
                black_box(sig);
            })
        });
    }
    // 256 KiB
    {
        let m = fixed_msg_256_1024();
        group.bench_with_input(BenchmarkId::new("256 KiB", 256_1024), &m, |b, m| {
            b.iter(|| {
                let sk = SigningKey::<MlDsa65>::decode(&sk_bytes);
                let sig = sk
                    .sign_deterministic(black_box(m), black_box(&ctx))
                    .unwrap();
                black_box(sig);
            })
        });
    }
    // 1 MiB
    {
        let m = fixed_msg_1_1024();
        group.bench_with_input(BenchmarkId::new("1 MiB", 1_048_576), &m, |b, m| {
            b.iter(|| {
                let sk = SigningKey::<MlDsa65>::decode(&sk_bytes);
                let sig = sk
                    .sign_deterministic(black_box(m), black_box(&ctx))
                    .unwrap();
                black_box(sig);
            })
        });
    }
    // 10 MiB
    {
        let m = fixed_msg_10_1024();
        group.bench_with_input(BenchmarkId::new("10 MiB", 10_485_760), &m, |b, m| {
            b.iter(|| {
                let sk = SigningKey::<MlDsa65>::decode(&sk_bytes);
                let sig = sk
                    .sign_deterministic(black_box(m), black_box(&ctx))
                    .unwrap();
                black_box(sig);
            })
        });
    }
    group.finish();
}

/// Warm-sign benches (decode once, warm once, sign repeatedly), parameterized by message size.
fn bench_sign_warm(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_warm");

    let xi = fixed_xi();
    let ctx = fixed_ctx();
    let kp = MlDsa65::key_gen_internal(&xi);
    let sk_bytes = kp.signing_key().encode();

    // Helper to warm a decoded key on a message, then measure pure sign()
    let mut add = |label: &str, m_len: usize, m_any: &[u8]| {
        // decode once
        let sk = SigningKey::<MlDsa65>::decode(&sk_bytes);
        // warm once (outside timer)
        let _ = sk.sign_deterministic(m_any, &ctx).unwrap();

        group.bench_with_input(BenchmarkId::new(label, m_len), &m_len, |b, _| {
            b.iter(|| {
                let sig = sk
                    .sign_deterministic(black_box(m_any), black_box(&ctx))
                    .unwrap();
                black_box(sig);
            })
        });
    };

    let m32 = fixed_msg_32();
    add("32B", 32, m32.as_slice());
    let m256 = fixed_msg_256();
    add("256B", 256, m256.as_slice());
    let m1k = fixed_msg_1024();
    add("1024B", 1024, m1k.as_slice());
    let m4k = fixed_msg_4096();
    add("4096B", 4096, m4k.as_slice());
    let m256k = fixed_msg_256_1024();
    add("256 KiB", 256_1024, m256k.as_slice());
    let m1m = fixed_msg_1_1024();
    add("1 MiB", 1_048_576, m1m.as_slice());
    let m10m = fixed_msg_10_1024();
    add("10 MiB", 10_485_760, m10m.as_slice());
    let m100m = fixed_msg_100_1024();
    add("100 MiB", 100_485_760, m100m.as_slice());
    group.finish();
}

/// Round-trip: keygen + sign + verify (uses 256B msg by default; duplicate if you want size sweep)
fn bench_round_trip(c: &mut Criterion) {
    let xi = fixed_xi();
    let ctx = fixed_ctx();
    let m = fixed_msg_256();

    c.bench_function("round_trip", |b| {
        b.iter(|| {
            let kp = MlDsa65::key_gen_internal(black_box(&xi));
            let sig = kp
                .signing_key()
                .sign_deterministic(black_box(&m), black_box(&ctx))
                .unwrap();
            let ok = kp.verifying_key().verify_with_context(
                black_box(&m),
                black_box(&ctx),
                black_box(&sig),
            );
            black_box(ok);
        })
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench_keygen(c);
    bench_verify(c);
    bench_sign_cold(c);
    bench_sign_warm(c);
    bench_round_trip(c);
}

criterion_group!(
  name = benches;
  config = Criterion::default()
    .warm_up_time(Duration::from_secs(3))
    .measurement_time(Duration::from_secs(10))
    .sample_size(50);
  targets = criterion_benchmark
);
criterion_main!(benches);
