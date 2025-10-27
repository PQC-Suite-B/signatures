#![allow(non_snake_case)]
#![cfg(feature = "alloc")]

use serde::{Deserialize, Serialize};
use slh_dsa::*;
use std::{env, fs::{read_to_string, File}, io::Write, path::PathBuf};

#[test]
fn blake3_sig() {
    if env::var("CREATE_VECTOR_SET").is_ok() {
        create_vector_set();
    } else {
        test_siggen_blake3();
    }
}

macro_rules! parameter_case {
    ($param:ident, $test_case:expr) => {{
        let sk = SigningKey::<$param>::try_from($test_case.sk.as_slice()).unwrap();
        let rand: Option<&[u8]> =
            if $test_case.additionalRandomness.is_empty() {
                None
            } else {
                Some($test_case
                .additionalRandomness
                .as_slice())
            };
        println!("{:?}", rand);
        let sig = sk.slh_sign_internal(&[$test_case.message.as_slice()], rand);
        assert_eq!(sig.to_vec(), $test_case.signature);
    }};
}

fn test_siggen_blake3() {
    let mut i = 0;
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/blake3_sig.json");
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

    let mut i = 1;
    for param in &params {
        let mut tg_det = TestGroup {
            id: i,
            parameterSet: *param,
            deterministic: true,
            tests: vec![]
        };
        match_p(&mut tg_det, param.clone());
        vs.testGroups.push(tg_det);
        i += 1;

        let mut tg_not_det = TestGroup {
            id: i,
            parameterSet: *param,
            deterministic: false,
            tests: vec![]
        };
        match_p(&mut tg_not_det, param.clone());
        vs.testGroups.push(tg_not_det);
        i += 1;
    }

    let json = serde_json::to_string_pretty(&vs).expect("failed to serialize json");
    let mut file = File::create("tests/blake3_sig.json").expect("could not create file");
    file.write_all(json.as_bytes()).expect("failed to write into file");
}

fn match_p(tg: &mut TestGroup, param: ParamSet) {
    match param {
            ParamSet::Blake3_128f => create_test_case::<Blake3_128f, 16>(tg),
            ParamSet::Blake3_128s => create_test_case::<Blake3_128s, 16>(tg),
            ParamSet::Blake3_192f => create_test_case::<Blake3_192f, 24>(tg),
            ParamSet::Blake3_192s => create_test_case::<Blake3_192s, 24>(tg),
            ParamSet::Blake3_256f => create_test_case::<Blake3_256f, 32>(tg),
            ParamSet::Blake3_256s => create_test_case::<Blake3_256s, 32>(tg),
    }
}

fn create_test_case<P: ParameterSet, const SEED_LEN: usize>(tg: &mut TestGroup) {
    let mut msg_len = 2;
    let common_ratio = 16;

    for i in 1..=4 {
        let mut rng = [0u8; SEED_LEN];
        let mut msg = vec![0u8; msg_len];
        let opt_rng;
        if !tg.deterministic {
            rand::fill(&mut rng);
            opt_rng = Some(rng.as_slice());
        } else {
            opt_rng = None
        }
        rand::fill(&mut msg[..]);
        let sk = SigningKey::<P>::new(&mut rand::rng());

        let sig = sk.slh_sign_internal(&[msg.as_slice()], opt_rng);

        let tc = TestCase {
            id: i,
            deferred: false,
            sk: sk.to_vec(),
            additionalRandomness: if tg.deterministic {Vec::new()} else {rng.to_vec()},
            messageLength: msg_len * 8,
            message: msg,
            signature: sig.to_vec()
        };
        tg.tests.push(tc);
        msg_len = msg_len * common_ratio;
    }
}


#[derive(Deserialize, Serialize, Debug)]
struct TestCase {
    #[serde(rename = "tcId")]
    id: usize,
    deferred: bool,
    #[serde(with = "hex::serde")]
    sk: Vec<u8>,
    #[serde(with = "hex::serde")]
    additionalRandomness: Vec<u8>,
    messageLength: usize,
    #[serde(with = "hex::serde")]
    message: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature: Vec<u8>
}

#[derive(Deserialize, Serialize, Debug)]
struct TestGroup {
    #[serde(rename = "tgId")]
    id: usize,
    parameterSet: ParamSet,
    deterministic: bool,
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
