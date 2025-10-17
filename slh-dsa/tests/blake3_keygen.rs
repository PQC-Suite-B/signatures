#![allow(non_snake_case)]
#![cfg(feature = "alloc")]

use serde::{Deserialize, Serialize};
use signature::Keypair;
use slh_dsa::*;
use std::{env, fs::{read_to_string, File}, io::Write, path::PathBuf};

#[test]
fn blake3_keygen() {
    if env::var("CREATE_VECTOR_SET").is_ok() {
        create_vector_set();
    } else {
        test_keygen_blake3();
    }
}

macro_rules! parameter_case {
    ($param:ident, $test_case:expr) => {{
        let sk = SigningKey::<$param>::slh_keygen_internal(
            &$test_case.skSeed,
            &$test_case.skPrf,
            &$test_case.pkSeed,
        );
        let vk = sk.verifying_key();
        assert_eq!(sk.to_vec(), $test_case.sk);
        assert_eq!(vk.to_vec(), $test_case.pk);
    }};
}

fn test_keygen_blake3() {
    let mut i = 0;
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/blake3_keygen.json");
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
        mode: String::from("keyGen"),
        revision: String::from("1.0"),
        isSample: false,
        testGroups: vec![]
    };

    for (i, param) in params.iter().enumerate() {
        let mut tg = TestGroup {
            id: i + 1,
            parameterSet: *param,
            tests: vec![]
        };
        match param {
                ParamSet::Blake3_128f => create_test_case::<Blake3_128f, 16>(&mut tg),
                ParamSet::Blake3_128s => create_test_case::<Blake3_128s, 16>(&mut tg),
                ParamSet::Blake3_192f => create_test_case::<Blake3_192f, 24>(&mut tg),
                ParamSet::Blake3_192s => create_test_case::<Blake3_192s, 24>(&mut tg),
                ParamSet::Blake3_256f => create_test_case::<Blake3_256f, 32>(&mut tg),
                ParamSet::Blake3_256s => create_test_case::<Blake3_256s, 32>(&mut tg),
        }
        vs.testGroups.push(tg);
    }

    let json = serde_json::to_string_pretty(&vs).expect("failed to serialize json");
    let mut file = File::create("tests/blake3_keygen.json").expect("could not create file");
    file.write_all(json.as_bytes()).expect("failed to write into file");
}

fn create_test_case<P: ParameterSet, const SEED_LEN: usize>(tg: &mut TestGroup) {

    let mut sk_seed = [0u8; SEED_LEN];
    let mut sk_prf = [0u8; SEED_LEN];
    let mut pk_seed = [0u8; SEED_LEN];

    for i in 1..=10 {
        rand::fill(&mut sk_seed);
        rand::fill(&mut sk_prf);
        rand::fill(&mut pk_seed);
        let sk = SigningKey::<P>::slh_keygen_internal(&sk_seed,
                                                      &sk_prf,
                                                      &pk_seed);
        println!("key!!");
        let pk = sk.verifying_key();

        let tc = TestCase {
            id: i,
            deferred: false,
            skSeed: sk_seed.to_vec(),
            skPrf: sk_prf.to_vec(),
            pkSeed: pk_seed.to_vec(),
            sk: sk.to_vec(),
            pk: pk.to_vec()
        };
        tg.tests.push(tc);
    }
}


#[derive(Deserialize, Serialize, Debug)]
struct TestCase {
    #[serde(rename = "tcId")]
    id: usize,
    deferred: bool,
    #[serde(with = "hex::serde")]
    skSeed: Vec<u8>,
    #[serde(with = "hex::serde")]
    skPrf: Vec<u8>,
    #[serde(with = "hex::serde")]
    pkSeed: Vec<u8>,
    #[serde(with = "hex::serde")]
    sk: Vec<u8>,
    #[serde(with = "hex::serde")]
    pk: Vec<u8>,
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
