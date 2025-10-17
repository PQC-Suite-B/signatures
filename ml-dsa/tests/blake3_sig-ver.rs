use ml_dsa::*;

use data::ParameterSet;
use std::collections::VecDeque;
use std::env;
use std::{fs::{read_to_string, File}, io::Write, path::PathBuf};
use serde_json;

// Verify vector set:
//  cargo test --test blake3_sig-ver --no-default-features --features blake3
// Create vector set
//  CREATE_VECTOR_SET=1 cargo test --test blake3_sig-ver --no-default-features --features blake3
#[test]
pub fn sigver_blake3() {
    if env::var("CREATE_VECTOR_SET").is_ok() {
        sigver_create_vector_set();
    } else {
        verify_vector_set();
    }
}

fn verify_vector_set() {
    // Load the JSON test file
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/blake3_sig-ver.json");
    let tv_json = read_to_string(p.as_path()).unwrap();

    // Parse the test vectors
    let tv: data::VectorSet = serde_json::from_str(&tv_json).unwrap();

    // Verify the test vectors
    for tg in tv.test_groups {
        for tc in tg.tests.iter() {
            match tg.parameter_set {
                data::ParameterSet::MlDsa44 => verify::<MlDsa44>(&tg, tc),
                data::ParameterSet::MlDsa65 => verify::<MlDsa65>(&tg, tc),
                data::ParameterSet::MlDsa87 => verify::<MlDsa87>(&tg, tc),
            }
        }
    }
}

fn verify<P: MlDsaParams>(tg: &data::TestGroup, tc: &data::TestCase) {
    // Import the verification key
    let vk_bytes = EncodedVerifyingKey::<P>::try_from(tg.pk.as_slice()).unwrap();
    let vk = VerifyingKey::<P>::decode(&vk_bytes);

    // Import the signature
    let sig_bytes = EncodedSignature::<P>::try_from(tc.signature.as_slice()).unwrap();
    let sig = Signature::<P>::decode(&sig_bytes);

    // Verify the signature if it successfully decoded
    let test_passed = sig
        .map(|sig| vk.verify_internal(&[&tc.message], &sig))
        .unwrap_or_default();
    assert_eq!(test_passed, tc.test_passed);
}

fn sigver_create_vector_set() {
    let params = vec![ParameterSet::MlDsa44, ParameterSet::MlDsa65, ParameterSet::MlDsa87];

    let mut vs = data::VectorSet {
        id: 0,
        algorithm: String::from("ML-DSA-B"),
        mode: String::from("sigVer"),
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
            pk: vec![],
            sk: vec![],
            tests: vec![]
        };
        match param {
            ParameterSet::MlDsa44 => create_test_cases::<MlDsa44>(&mut tg, &mut messages, 80),
            ParameterSet::MlDsa65 => create_test_cases::<MlDsa65>(&mut tg, &mut messages, 55),
            ParameterSet::MlDsa87 => create_test_cases::<MlDsa87>(&mut tg, &mut messages, 75),
        }
        vs.test_groups.push(tg);

        tg_id += 1;
    }

    let json = serde_json::to_string_pretty(&vs).expect("failed to serialize json");
    let mut file = File::create("tests/blake3_sig-ver.json").expect("could not create file");
    file.write_all(json.as_bytes()).expect("failed to write into file");
}

fn get_messages() -> VecDeque<Vec<u8>> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/sig-ver.json");
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

fn create_test_cases<P>(tg: &mut data::TestGroup, messages: &mut VecDeque<Vec<u8>>, omega: usize) 
where 
    P: MlDsaParams,
    {
    let mut rng = rand::rng();
    let kp = P::key_gen(&mut rng);
    let sk = kp.signing_key();
    let pk = kp.verifying_key();

    tg.sk = sk.encode().to_vec();
    tg.pk = pk.encode().to_vec();

    for i in 1..=3 {
        let offset = 4 * (i - 1);
        let msg = messages.pop_front().unwrap();
        let sig = sk.sign_internal(&[msg.as_slice()], &B32::default());
        let tc = data::no_modification(i + offset, msg, sig);
        tg.tests.push(tc);

        let msg = messages.pop_front().unwrap();
        let sig = sk.sign_internal(&[msg.as_slice()], &B32::default());
        let tc = data::too_many_hints(i + 1 + offset, msg, sig, omega);
        tg.tests.push(tc);

        let msg = messages.pop_front().unwrap();
        let sig = sk.sign_internal(&[msg.as_slice()], &B32::default());
        let tc = data::z_too_large(i + 2 + offset, msg, sig);
        tg.tests.push(tc);

        let msg = messages.pop_front().unwrap();
        let sig = sk.sign_internal(&[msg.as_slice()], &B32::default());
        let tc = data::modify_message(i + 3 + offset, msg, sig);
        tg.tests.push(tc);

        let msg = messages.pop_front().unwrap();
        let sig = sk.sign_internal(&[msg.as_slice()], &B32::default());
        let tc = data::modify_signature(i + 4 + offset, msg, sig);
        tg.tests.push(tc);
    } 
}

mod data {
    use ml_dsa::{MlDsaParams, Signature};
    use serde::{Deserialize, Serialize};
    use std::cmp::min;

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

        #[serde(with = "hex::serde")]
        pub pk: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub sk: Vec<u8>,

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

        #[serde(rename = "testPassed")]
        pub test_passed: bool,

        pub deferred: bool,

        #[serde(with = "hex::serde")]
        pub message: Vec<u8>,

        #[serde(with = "hex::serde")]
        pub signature: Vec<u8>,

        pub reason: String
    }

    pub fn no_modification<P: MlDsaParams>(idx: usize,
                                           msg: Vec<u8>,
                                           sig: Signature<P>)
    -> TestCase {
        TestCase {
            id: idx,
            test_passed: true,
            deferred: false,
            message: msg,
            signature: sig.encode().to_vec(),
            reason: String::from("no modification")
        }
    }

    pub fn too_many_hints<P: MlDsaParams>(idx: usize,
                                          msg: Vec<u8>,
                                          sig: Signature<P>,
                                          omega: usize)
    -> TestCase {
        let encoded_sig = sig.encode();
        let (c_tilde, z, h) = P::split_sig(&encoded_sig);
        let (indices, cuts) = P::split_hint(&h);

        let mut h_mut = h.clone();
        let h_slice = h_mut.as_mut_slice();

        let indices_len = indices.len();
        let cuts_len = cuts.len();

        h_slice[..indices_len].copy_from_slice(indices);
        h_slice[indices_len..indices_len + cuts_len].copy_from_slice(cuts);

        let start = min(indices_len.saturating_sub(1), omega.saturating_sub(4));
        let end = min(indices_len, omega + 4);
        for i in start..end {
            h_slice[i] |= 0xFF;
        }

        for b in &mut h_slice[indices_len + cuts_len..] {
            *b = 0;
        }

        let bad_sig = P::concat_sig(c_tilde.clone(), z.clone(), h_mut);

        TestCase {
            id: idx,
            test_passed: false,
            deferred: false,
            message: msg,
            signature: bad_sig.to_vec(),
            reason: String::from("too many hints"),
        }
    }

    pub fn z_too_large<P: MlDsaParams>(idx: usize,
                                       msg: Vec<u8>,
                                       sig: Signature<P>)
    -> TestCase {
        let encoded_sig = sig.encode();
        let (c_tilde, z, h) = P::split_sig(&encoded_sig);

        let mut z_mut = z.clone();
        let z_slice = z_mut.as_mut_slice();

        let z_len = z_slice.len();
        let start = (z_len / 2).saturating_sub(idx);
        for i in start..min(z_len, start + 6) {
            z_slice[i] ^= 0xFF;
        }

        let bad_sig = P::concat_sig(c_tilde.clone(), z_mut.clone(), h.clone());

        TestCase {
            id: idx,
            test_passed: false,
            deferred: false,
            message: msg,
            signature: bad_sig.to_vec(),
            reason: String::from("z too large"),
        }
    }

    pub fn modify_message<P: MlDsaParams>(idx: usize,
                                          mut msg: Vec<u8>,
                                          sig: Signature<P>)
    -> TestCase {
        msg[idx] = 0x0;
        msg[3*idx] = 0x0;

        TestCase {
            id: idx,
            test_passed: false,
            deferred: false,
            message: msg,
            signature: sig.encode().to_vec(),
            reason: String::from("modify message")
        }
    }

    pub fn modify_signature<P: MlDsaParams>(idx: usize,
                                            msg: Vec<u8>,
                                            sig: Signature<P>)
    -> TestCase {
        let mut sig_vec = sig.encode().to_vec();
        sig_vec[idx] = 0x0;
        sig_vec[5*idx] = 0x0;

        TestCase {
            id: idx,
            test_passed: false,
            deferred: false,
            message: msg,
            signature: sig_vec,
            reason: String::from("modify signature")
        }
    }
}
