use ml_dsa::*;
use crate::{SigningKey, VerifyingKey};

use data::ParameterSet;
use rand::Rng;
use std::env;
use std::{fs::{read_to_string, File}, io::Write, path::PathBuf};
use serde_json;
use hybrid_array::Array;

// Verify vector set:
//  cargo test --test blake3_key-gen --no-default-features --features blake3
// Create vector set
//  CREATE_VECTOR_SET=1 cargo test --test blake3_key-gen --no-default-features --features blake3
#[test]
pub fn keygen_blake3() {
    if env::var("CREATE_VECTOR_SET").is_ok() {
        keygen_create_vector_set();
    } else {
        verify_vector_set();
    }
}

fn verify_vector_set() {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/blake3_key-gen.json");
    let vs_json = read_to_string(p.as_path()).unwrap();

    let vs: data::VectorSet = serde_json::from_str(&vs_json).unwrap();

    for tg in vs.test_groups {
        for tc in tg.tests {
            match tg.parameter_set {
                ParameterSet::MlDsa44 => verify::<MlDsa44>(&tc),
                ParameterSet::MlDsa65 => verify::<MlDsa65>(&tc),
                ParameterSet::MlDsa87 => verify::<MlDsa87>(&tc),
            }
        }
    }
}

fn verify<P: MlDsaParams>(tc: &data::TestCase) {
    // Import test data into the relevant array structures
    let seed = Array::try_from(tc.seed.as_slice()).unwrap();
    let vk_bytes = EncodedVerifyingKey::<P>::try_from(tc.pk.as_slice()).unwrap();
    let sk_bytes = EncodedSigningKey::<P>::try_from(tc.sk.as_slice()).unwrap();

    let kp = P::key_gen_internal(&seed);
    let sk = kp.signing_key().clone();
    let vk = kp.verifying_key().clone();

    // Verify correctness via serialization
    assert_eq!(sk.encode(), sk_bytes);
    assert_eq!(vk.encode(), vk_bytes);

    // Verify correctness via deserialization
    assert!(sk == SigningKey::<P>::decode(&sk_bytes));
    assert!(vk == VerifyingKey::<P>::decode(&vk_bytes));
}

fn keygen_create_vector_set() {
    let params = vec![ParameterSet::MlDsa44, ParameterSet::MlDsa65, ParameterSet::MlDsa87];

    let mut vs = data::VectorSet {
        id: 0,
        algorithm: String::from("ML-DSA-B"),
        mode: String::from("keyGen"),
        revision: String::from("1.0"),
        is_sample: false,
        test_groups: vec![]
    };

    let mut tg_id = 1;
    for param in &params {
        let mut tg = data::TestGroup {
            id: tg_id,
            parameter_set: *param,
            tests: vec![]
        };
        match param {
            ParameterSet::MlDsa44 => create_test_cases::<MlDsa44>(&mut tg),
            ParameterSet::MlDsa65 => create_test_cases::<MlDsa65>(&mut tg),
            ParameterSet::MlDsa87 => create_test_cases::<MlDsa87>(&mut tg),
        }
        vs.test_groups.push(tg);
        tg_id += 1;
    }
    let json = serde_json::to_string_pretty(&vs).expect("failed to serialize json");
    let mut file = File::create("tests/blake3_key-gen.json").expect("could not create file");
    file.write_all(json.as_bytes()).expect("failed to write into file");
}

fn create_test_cases<P>(tg: &mut data::TestGroup) 
where 
    P: MlDsaParams,
    {
    let mut rng = rand::rng();
    let mut seed = B32::default();

    for i in 1..=25 {
        let seed_data: &mut [u8] = seed.as_mut();
        rng.fill(seed_data);

        let kp = P::key_gen_internal(&seed);
        data::push_tc(tg, i, &seed, &kp);
    }
}

mod data {
    use ml_dsa::*;
    use serde::{Deserialize, Serialize};

    use hybrid_array::{
        Array,
        typenum::U32,
    };

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
        pub id: u32,

        pub deferred: bool,

        #[serde(with = "hex::serde")]
        pub seed: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub pk: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub sk: Vec<u8>
    }

    pub fn push_tc<P: MlDsaParams>(tg: &mut TestGroup, idx: u32, seed: &Array<u8, U32>, kp: &KeyPair<P>) {
        let signing_key = kp.signing_key().encode().to_vec();
        let verifying_key = kp.verifying_key().encode().to_vec();
        let tc = TestCase {
            id: idx,
            deferred: false,
            seed: seed.to_vec(),
            pk: verifying_key,
            sk: signing_key
        };
        tg.tests.push(tc);
    }
}

