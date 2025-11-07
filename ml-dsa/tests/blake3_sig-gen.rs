use ml_dsa::*;
use crate::SigningKey;

use data::ParameterSet;
use rand::Rng;
use std::collections::VecDeque;
use std::env;
use std::{fs::{read_to_string, File}, io::Write, path::PathBuf};
use serde_json;

#[test]
pub fn siggen_blake3() {
    if env::var("CREATE_VECTOR_SET").is_ok() {
        siggen_create_vector_set();
    } else {
        verify_vector_set();
    }
}

fn verify_vector_set() {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/blake3_sig-gen.json");
    let vs_json = read_to_string(p.as_path()).unwrap();

    let vs: data::VectorSet = serde_json::from_str(&vs_json).unwrap();

    for tg in vs.test_groups {
        for tc in tg.tests {
            match tg.parameter_set {
                ParameterSet::MlDsa44 => verify::<MlDsa44>(&tc, tg.deterministic),
                ParameterSet::MlDsa65 => verify::<MlDsa65>(&tc, tg.deterministic),
                ParameterSet::MlDsa87 => verify::<MlDsa87>(&tc, tg.deterministic),
            }
        }
    }
}

fn verify<P: MlDsaParams>(tc: &data::TestCase, deterministic: bool) {
    // Import the signing key
    let sk_bytes = EncodedSigningKey::<P>::try_from(tc.sk.as_slice()).unwrap();
    let sk = SigningKey::<P>::decode(&sk_bytes);

    // Verify correctness
    let rnd = if deterministic {
        B32::default()
    } else {
        B32::try_from(tc.rnd.as_slice()).unwrap()
    };
    let sig = sk.sign_internal(&[&tc.message], &rnd);
    let sig_bytes = sig.encode();

    assert_eq!(tc.signature.as_slice(), sig_bytes.as_slice());
}

fn siggen_create_vector_set() {
    let params = vec![ParameterSet::MlDsa44, ParameterSet::MlDsa65, ParameterSet::MlDsa87];

    let mut vs = data::VectorSet {
        id: 0,
        algorithm: String::from("ML-DSA-B"),
        mode: String::from("sigGen"),
        revision: String::from("1.0"),
        is_sample: false,
        test_groups: vec![]
    };

    let mut messages = get_messages();

    let mut tg_id = 1;
    for param in &params {
        let mut tg = data::TestGroup {
            id: tg_id,
            parameter_set: *param,
            deterministic: true,
            tests: vec![]
        };
        match_parameters(param, &mut tg, &mut messages);
        vs.test_groups.push(tg);
        tg_id += 1;
        
        let mut tg = data::TestGroup {
            id: tg_id,
            parameter_set: *param,
            deterministic: false,
            tests: vec![]
        };
        match_parameters(param, &mut tg, &mut messages);
        vs.test_groups.push(tg);
        tg_id += 1;
    }
    let json = serde_json::to_string_pretty(&vs).expect("failed to serialize json");
    let mut file = File::create("tests/blake3_sig-gen.json").expect("could not create file");
    file.write_all(json.as_bytes()).expect("failed to write into file");
}

fn get_messages() -> VecDeque<Vec<u8>> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/sig-gen.json");
    let vs_json = read_to_string(p.as_path()).unwrap();
    let vs: data::VectorSet = serde_json::from_str(&vs_json).unwrap();

    let mut messages: VecDeque<Vec<u8>> = VecDeque::new();

    for tg in vs.test_groups {
        for tc in tg.tests {
            messages.push_back(tc.message);
        }
    }
    messages
}

fn match_parameters(param: &ParameterSet, tg: &mut data::TestGroup, messages: &mut VecDeque<Vec<u8>>) {
    match param {
        ParameterSet::MlDsa44 => create_test_cases::<MlDsa44>(tg, messages),
        ParameterSet::MlDsa65 => create_test_cases::<MlDsa65>(tg, messages),
        ParameterSet::MlDsa87 => create_test_cases::<MlDsa87>(tg, messages),
    }
}

fn create_test_cases<P>(tg: &mut data::TestGroup, messages: &mut VecDeque<Vec<u8>>) 
where 
    P: MlDsaParams,
    {
    let mut rng = rand::rng();

    for i in 1..=10 {
        let mut rnd = B32::default();
        if !tg.deterministic {
            let rnd_data: &mut [u8] = rnd.as_mut();
            rng.fill(rnd_data);
        }

        let kp = P::key_gen(&mut rng);
        let sk = kp.signing_key();

        let msg = messages.pop_front().unwrap();

        let sig = sk.sign_internal(&[msg.as_slice()], &rnd);

        let tc = data::TestCase {
            id: i,
            deferred: false,
            sk: sk.encode().to_vec(),
            message: msg.to_vec(),
            rnd: if tg.deterministic {Vec::new()} else {rnd.to_vec()},
            signature: sig.encode().to_vec()
        };
        tg.tests.push(tc);
    } 
}

mod data {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    pub struct VectorSet {
        #[serde(rename = "vsId")]
        pub id: u32,

        pub algorithm: String,

        pub mode: String,
        
        pub revision: String,

        #[serde(rename = "isSample")]
        pub is_sample: bool,

        #[serde(rename = "testGroups")]
        pub test_groups: Vec<TestGroup>
    }

    #[derive(Deserialize, Serialize)]
    pub struct TestGroup {
        #[serde(rename = "tgId")]
        pub id: usize,

        #[serde(rename = "parameterSet")]
        pub parameter_set: ParameterSet,

        pub deterministic: bool,

        pub tests: Vec<TestCase>,
    }

    #[derive(Deserialize, Serialize, Copy, Clone)]
    pub enum ParameterSet {
        #[serde(rename = "ML-DSA-B-44", alias = "ML-DSA-44")]
        MlDsa44,

        #[serde(rename = "ML-DSA-B-65", alias = "ML-DSA-65")]
        MlDsa65,

        #[serde(rename = "ML-DSA-B-87", alias = "ML-DSA-87")]
        MlDsa87,
    }

    #[derive(Deserialize, Serialize)]
    pub struct TestCase {
        #[serde(rename = "tcId")]
        pub id: usize,

        pub deferred: bool,

        #[serde(with = "hex::serde")]
        pub sk: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub message: Vec<u8>,

        #[serde(default, with = "hex::serde")]
        pub rnd: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub signature: Vec<u8>,
    }
}
