#![allow(non_snake_case)]
#![cfg(feature = "alloc")]

use serde::{Deserialize, Serialize};
use signature::Keypair;
use slh_dsa::*;
use std::{env, fs::{read_to_string, File}, io::Write, path::PathBuf};

#[test]
fn blake3_ver() {
    if env::var("CREATE_VECTOR_SET").is_ok() {
        create_vector_set();
    } else {
        test_sigver_blake3();
    }
}

macro_rules! parameter_case {
    ($param:ident, $test_case:expr) => {{
        let pk = VerifyingKey::<$param>::try_from($test_case.pk.as_slice()).unwrap();
        assert_eq!($test_case.pk, pk.to_vec());
        if let Ok(sig) = $test_case.signature.as_slice().try_into() {
            let success = pk.slh_verify_internal(&[$test_case.message.as_slice()], &sig);
            println!("{:?}", $test_case.testPassed);
            println!("{:?}", success.is_ok());
            assert_eq!($test_case.testPassed, success.is_ok());
        } else {
            println!("{:?}", $test_case.testPassed);
            assert!(!$test_case.testPassed);
        }
    }};
}

macro_rules! push_tc {
    ($tg:expr, $f:expr, $($args:expr),* $(,)?) => {
        $tg.tests.push($f($($args),*));
    };
}

fn test_sigver_blake3() {
    let mut i = 0;
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/blake3_ver.json");
    let test_file = read_to_string(p.as_path()).unwrap();
    let vs: TestFile = serde_json::from_str(&test_file).unwrap();
    for test_group in vs.testGroups {
        let p = test_group.parameterSet;
        for test_case in test_group.tests {
            match p {
                ParamSet::Blake3_128f => parameter_case!(Blake3_128f, test_case),
                ParamSet::Blake3_128s => parameter_case!(Blake3_128s, test_case),
                ParamSet::Blake3_192f => parameter_case!(Blake3_192f, test_case),
                ParamSet::Blake3_192s => parameter_case!(Blake3_192s, test_case),
                ParamSet::Blake3_256f => parameter_case!(Blake3_256f, test_case),
                ParamSet::Blake3_256s => parameter_case!(Blake3_256s, test_case),
            }
            i += 1;
        }
    }
    print!("Number of test cases: {}", i);
}

fn create_vector_set() {
    let params = [ParamSet::Blake3_128f, ParamSet::Blake3_128s,
                  ParamSet::Blake3_192f, ParamSet::Blake3_192s,
                  ParamSet::Blake3_256f, ParamSet::Blake3_256s];

    let mut vs = TestFile {
        id: 0,
        algorithm: String::from("SLH-DSA-B"),
        mode: String::from("sigGen"),
        revision: String::from("1.0"),
        isSample: false,
        testGroups: vec![]
    };

    for (i, param) in params.iter().enumerate() {
        let mut tg_det = TestGroup {
            id: i,
            parameterSet: *param,
            tests: vec![]
        };
        match_p(&mut tg_det, *param);
        vs.testGroups.push(tg_det);
    }

    let json = serde_json::to_string_pretty(&vs).expect("failed to serialize json");
    let mut file = File::create("tests/blake3_ver.json").expect("could not create file");
    file.write_all(json.as_bytes()).expect("failed to write into file");
}

fn match_p(tg: &mut TestGroup, param: ParamSet) {
    match param {
            ParamSet::Blake3_128f => create_test_case::<Blake3_128f, 16>(tg, 33, 6),
            ParamSet::Blake3_128s => create_test_case::<Blake3_128s, 16>(tg, 14, 12),
            ParamSet::Blake3_192f => create_test_case::<Blake3_192f, 24>(tg, 33, 8),
            ParamSet::Blake3_192s => create_test_case::<Blake3_192s, 24>(tg, 17, 14),
            ParamSet::Blake3_256f => create_test_case::<Blake3_256f, 32>(tg, 35, 9),
            ParamSet::Blake3_256s => create_test_case::<Blake3_256s, 32>(tg, 22, 14),
    }
}

fn create_test_case<P: ParameterSet, const SEED_LEN: usize>(tg: &mut TestGroup, k: usize, a: usize) {
    let mut msg_len = 32768;
    let common_ratio = 2;
    
    let mut i = 0;
    for _ in 1..=2 {
        
        let (rng, msg) = rand_rng_msg::<SEED_LEN>(msg_len);
        let sk = SigningKey::<P>::new(&mut rand::rng());
        let pk = sk.verifying_key();
        let sig = sk.slh_sign_internal(&[msg.as_slice()], Some(&rng));
        push_tc!(tg, no_modification, i, sk.to_vec(), pk.to_vec(), rng.to_vec(), msg_len, msg, sig.to_vec());
        i += 1;

        let (rng, msg) = rand_rng_msg::<SEED_LEN>(msg_len);
        let sk = SigningKey::<P>::new(&mut rand::rng());
        let pk = sk.verifying_key();
        let sig = sk.slh_sign_internal(&[msg.as_slice()], Some(&rng));
        push_tc!(tg, message_altered, i, sk.to_vec(), pk.to_vec(), rng.to_vec(), msg_len, msg, sig.to_vec());
        i += 1;

        let (rng, msg) = rand_rng_msg::<SEED_LEN>(msg_len);
        let sk = SigningKey::<P>::new(&mut rand::rng());
        let pk = sk.verifying_key();
        let sig = sk.slh_sign_internal(&[msg.as_slice()], Some(&rng));
        push_tc!(tg, sig_too_large, i, sk.to_vec(), pk.to_vec(), rng.to_vec(), msg_len, msg, sig.to_vec());
        i += 1;

        let (rng, msg) = rand_rng_msg::<SEED_LEN>(msg_len);
        let sk = SigningKey::<P>::new(&mut rand::rng());
        let pk = sk.verifying_key();
        let sig = sk.slh_sign_internal(&[msg.as_slice()], Some(&rng));
        push_tc!(tg, sig_too_small, i, sk.to_vec(), pk.to_vec(), rng.to_vec(), msg_len, msg, sig.to_vec());
        i += 1;

        let (rng, msg) = rand_rng_msg::<SEED_LEN>(msg_len);
        let sk = SigningKey::<P>::new(&mut rand::rng());
        let pk = sk.verifying_key();
        let sig = sk.slh_sign_internal(&[msg.as_slice()], Some(&rng));
        push_tc!(tg, sig_ht_modified, i, sk.to_vec(), pk.to_vec(), rng.to_vec(), msg_len, msg, sig.to_vec(), k, a, SEED_LEN);
        i += 1;

        let (rng, msg) = rand_rng_msg::<SEED_LEN>(msg_len);
        let sk = SigningKey::<P>::new(&mut rand::rng());
        let pk = sk.verifying_key();
        let sig = sk.slh_sign_internal(&[msg.as_slice()], Some(&rng));
        push_tc!(tg, fors_modified, i, sk.to_vec(), pk.to_vec(), rng.to_vec(), msg_len, msg, sig.to_vec(), k, a, SEED_LEN);
        i += 1;

        let (rng, msg) = rand_rng_msg::<SEED_LEN>(msg_len);
        let sk = SigningKey::<P>::new(&mut rand::rng());
        let pk = sk.verifying_key();
        let sig = sk.slh_sign_internal(&[msg.as_slice()], Some(&rng));
        push_tc!(tg, r_modified, i, sk.to_vec(), pk.to_vec(), rng.to_vec(), msg_len, msg, sig.to_vec(), k, a, SEED_LEN);
        i += 1;

        msg_len *= common_ratio;
    }
}

fn rand_rng_msg<const SEED_LEN: usize>(msg_len: usize) -> ([u8; SEED_LEN], Vec<u8>) {
    let mut rng = [0u8; SEED_LEN];
    let mut msg = vec![0u8; msg_len];
    rand::fill(&mut rng);
    rand::fill(&mut msg[..]);
    (rng, msg)
}

fn no_modification(idx: usize, sk: Vec<u8>, pk: Vec<u8>, rng: Vec<u8>,
                   msg_len: usize, msg: Vec<u8>, sig: Vec<u8>) 
-> TestCase {
    TestCase { 
        id: idx,
        testPassed: true,
        deferred: false,
        sk: sk,
        pk: pk,
        additionalRandomness: rng,
        messageLength: msg_len,
        message: msg,
        signature: sig,
        reason: String::from("valid signature and message - signature should verify successfully")
    }
}

#[allow(clippy::too_many_arguments)]
fn fors_modified(idx: usize, sk: Vec<u8>, pk: Vec<u8>, rng: Vec<u8>, 
                 msg_len: usize, msg: Vec<u8>, sig: Vec<u8>,
                 k: usize, a: usize, n: usize) 
-> TestCase {
    let (r_fors, sig_ht) = sig.split_at((1 + k * (1 + a)) * n);
    let (r, fors) = r_fors.split_at(n);
    let mut fors_vec = fors.to_vec();
    fors_vec[idx] = 0x0;
    fors_vec[idx*3] = 0x0;
    let mut ret_sig = r.to_vec();
    ret_sig.append(&mut fors_vec);
    ret_sig.append(&mut sig_ht.to_vec());

    TestCase { 
        id: idx,
        testPassed: false,
        deferred: false,
        sk: sk,
        pk: pk,
        additionalRandomness: rng,
        messageLength: msg_len,
        message: msg,
        signature: ret_sig,
        reason: String::from("modified signature - SIGFORS modified")
    }
}

#[allow(clippy::too_many_arguments)]
fn r_modified(idx: usize, sk: Vec<u8>, pk: Vec<u8>, rng: Vec<u8>, 
              msg_len: usize, msg: Vec<u8>, sig: Vec<u8>,
              _k: usize, _a: usize, n: usize) 
-> TestCase {
    let (r, fors_ht) = sig.split_at(n);
    let mut r_vec = r.to_vec();
    r_vec[idx] = 0x0;
    r_vec[idx+2] = 0x0;
    r_vec.append(&mut fors_ht.to_vec());

    TestCase { 
        id: idx,
        testPassed: false,
        deferred: false,
        sk: sk,
        pk: pk,
        additionalRandomness: rng,
        messageLength: msg_len,
        message: msg,
        signature: r_vec,
        reason: String::from("modified signature - R modified")
    }
}

#[allow(clippy::too_many_arguments)]
fn sig_ht_modified(idx: usize, sk: Vec<u8>, pk: Vec<u8>, rng: Vec<u8>, 
                   msg_len: usize, msg: Vec<u8>, sig: Vec<u8>,
                   k: usize, a: usize, n: usize) 
-> TestCase {
    let (new_sig, sig_ht) = sig.split_at((1 + k * (1 + a)) * n);
    let mut sig_ht_vec = sig_ht.to_vec();
    sig_ht_vec[idx] = 0x0;
    sig_ht_vec[idx*3] = 0x0;
    let mut res = new_sig.to_vec();
    res.append(&mut sig_ht_vec);

    TestCase { 
        id: idx,
        testPassed: false,
        deferred: false,
        sk: sk,
        pk: pk,
        additionalRandomness: rng,
        messageLength: msg_len,
        message: msg,
        signature: res,
        reason: String::from("modified signature - SIGHT modified")
    }
}

fn message_altered(idx: usize, sk: Vec<u8>, pk: Vec<u8>, rng: Vec<u8>, 
                   msg_len: usize, mut msg: Vec<u8>, sig: Vec<u8>) 
-> TestCase {
    msg[idx] = 0x0;
    msg[idx*3] = 0x0;
    TestCase { 
        id: idx,
        testPassed: false,
        deferred: false,
        sk: sk,
        pk: pk,
        additionalRandomness: rng,
        messageLength: msg_len,
        message: msg,
        signature: sig,
        reason: String::from("message altered")
    }
}

fn sig_too_small(idx: usize, sk: Vec<u8>, pk: Vec<u8>, rng: Vec<u8>, 
                 msg_len: usize, msg: Vec<u8>, mut sig: Vec<u8>) 
-> TestCase {
    let small_sig = sig.split_off(2);
    TestCase { 
        id: idx,
        testPassed: false,
        deferred: false,
        sk: sk,
        pk: pk,
        additionalRandomness: rng,
        messageLength: msg_len,
        message: msg,
        signature: small_sig,
        reason: String::from("invalid signature - signature is too small")
    }
}

fn sig_too_large(idx: usize, sk: Vec<u8>, pk: Vec<u8>, rng: Vec<u8>, 
                 msg_len: usize, msg: Vec<u8>, mut sig: Vec<u8>) 
-> TestCase {
    sig.push(sig.last().unwrap().clone());
    TestCase { 
        id: idx,
        testPassed: false,
        deferred: false,
        sk: sk,
        pk: pk,
        additionalRandomness: rng,
        messageLength: msg_len,
        message: msg,
        signature: sig,
        reason: String::from("invalid signature - signature is too large")
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct TestCase {
    #[serde(rename = "tcId")]
    id: usize,
    testPassed: bool,
    deferred: bool,
    #[serde(with = "hex::serde")]
    sk: Vec<u8>,
    #[serde(with = "hex::serde")]
    pk: Vec<u8>,
    #[serde(with = "hex::serde")]
    additionalRandomness: Vec<u8>,
    messageLength: usize,
    #[serde(with = "hex::serde")]
    message: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature: Vec<u8>,
    reason: String
}

#[derive(Deserialize, Serialize, Debug)]
struct TestGroup {
    #[serde(rename = "tgId")]
    id: usize,
    parameterSet: ParamSet,
    tests: Vec<TestCase>,
}

#[derive(Deserialize, Serialize, Debug, Copy, Clone)]
enum ParamSet {
    #[serde(rename = "SLH-DSA-BLAKE3-128f")]
    Blake3_128f,
    #[serde(rename = "SLH-DSA-BLAKE3-128s")]
    Blake3_128s,
    #[serde(rename = "SLH-DSA-BLAKE3-192f")]
    Blake3_192f,
    #[serde(rename = "SLH-DSA-BLAKE3-192s")]
    Blake3_192s,
    #[serde(rename = "SLH-DSA-BLAKE3-256f")]
    Blake3_256f,
    #[serde(rename = "SLH-DSA-BLAKE3-256s")]
    Blake3_256s,
}

#[derive(Deserialize, Serialize, Debug)]
struct TestFile {
    #[serde(rename = "vsId")]
    id: usize,
    algorithm: String,
    mode: String,
    revision: String,
    isSample: bool,
    testGroups: Vec<TestGroup>,
}
