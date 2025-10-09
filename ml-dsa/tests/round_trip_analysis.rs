use hybrid_array::Array;
use ml_dsa::*;
use std::time::Instant;

#[test]
fn analyze_key_gen_internal() {
    println!("\nAnalyzing ML-DSA-44 Round Trip:");
    println!("----------------------------------");

    let round_trip_start = Instant::now();

    // Create a fixed seed for reproducibilitys
    let seed = Array([42u8; 32]); // Fixed seed for reproducible results

    // key generation
    let keygen_start = Instant::now();
    let kp = MlDsa44::key_gen_internal(&seed);
    let sk = kp.signing_key();
    let vk = kp.verifying_key();
    let keygen_duration = keygen_start.elapsed();

    // signing
    let sign_start = Instant::now();
    // make message of lenght N where N can be bigger than Array:default() allows
    // let msg: Array<u8, U4096> = Array::default();
    let msg = vec![0x22u8; 4096 * 1024 + 1024]; // 4097 KiB to ensure Rayon parallel processing
    let mut ctx: B32 = Array::default();
    ctx.as_mut_slice().fill(0x33);
    let sig = sk.sign_deterministic(&msg, &ctx).unwrap();
    let sign_duration = sign_start.elapsed();

    // verifying
    let verify_start = Instant::now();
    let is_valid = vk.verify_with_context(&msg, &ctx, &sig);
    assert!(is_valid);
    let verify_duration = verify_start.elapsed();

    // total duration
    let round_trip_duration = round_trip_start.elapsed();
    println!("Round trip took: {round_trip_duration:?}");
    println!("KeyGen took: {keygen_duration:?}");
    println!("Sign took: {sign_duration:?}");
    println!("Verify took: {verify_duration:?}");
}
