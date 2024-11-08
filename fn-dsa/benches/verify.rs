#![allow(non_snake_case)]

mod util;
use util::{banner_arch, core_cycles, FakeRNG};

use fn_dsa::{KeyPairGenerator, KeyPairGeneratorStandard, SigningKey, SigningKeyStandard, VerifyingKey, VerifyingKeyStandard, sign_key_size, vrfy_key_size, signature_size, DOMAIN_NONE, HASH_ID_RAW};

fn bench_verify(logn: u32) -> (f64, u8) {
    // Make a key pair.
    let z = core_cycles();
    let seed = z.to_le_bytes();
    let mut rng = FakeRNG::new(&seed);
    let mut kg = KeyPairGeneratorStandard::default();
    let mut sk_buf = [0u8; sign_key_size(10)];
    let mut vk_buf = [0u8; vrfy_key_size(10)];
    let sk_e = &mut sk_buf[..sign_key_size(logn)];
    let vk_e = &mut vk_buf[..vrfy_key_size(logn)];
    kg.keygen(logn, &mut rng, sk_e, vk_e);

    // Make some signatures.
    let mut sigs_buf = [[0u8; signature_size(10)]; 16];
    let sig_len = signature_size(logn);
    let mut sk = SigningKeyStandard::decode(sk_e).unwrap();
    let mut msg = [0u8];
    for i in 0..sigs_buf.len() {
        sk.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, &msg,
            &mut sigs_buf[i][..sig_len]);
    }

    let vk = VerifyingKeyStandard::decode(vk_e).unwrap();
    let mut tt = [0; 10];
    for i in 0..tt.len() {
        let begin = core_cycles();
        for _ in 0..1000 {
            let x = vk.verify(&sigs_buf[i][..sig_len],
                &DOMAIN_NONE, &HASH_ID_RAW, &msg);
            msg[0] = msg[0].wrapping_mul(((x as u8) << 1) + 3);
        }
        let end = core_cycles();
        tt[i] = end.wrapping_sub(begin);
    }
    tt.sort();
    ((tt[tt.len() >> 1] as f64) / 1000.0, msg[0])
}

fn bench_verify_full(logn: u32) -> (f64, u8) {
    // Make a key pair.
    let z = core_cycles();
    let seed = z.to_le_bytes();
    let mut rng = FakeRNG::new(&seed);
    let mut kg = KeyPairGeneratorStandard::default();
    let mut sk_buf = [0u8; sign_key_size(10)];
    let mut vk_buf = [0u8; vrfy_key_size(10)];
    let sk_e = &mut sk_buf[..sign_key_size(logn)];
    let vk_e = &mut vk_buf[..vrfy_key_size(logn)];
    kg.keygen(logn, &mut rng, sk_e, vk_e);

    // Make some signatures.
    let mut sigs_buf = [[0u8; signature_size(10)]; 16];
    let sig_len = signature_size(logn);
    let mut sk = SigningKeyStandard::decode(sk_e).unwrap();
    let mut msg = [0u8];
    for i in 0..sigs_buf.len() {
        sk.sign(&mut rng,
            &DOMAIN_NONE, &HASH_ID_RAW, &msg, &mut sigs_buf[i][..sig_len]);
    }

    let mut tt = [0; 10];
    for i in 0..tt.len() {
        let begin = core_cycles();
        for _ in 0..1000 {
            let vk = VerifyingKeyStandard::decode(vk_e).unwrap();
            let x = vk.verify(&sigs_buf[i][..sig_len],
                &DOMAIN_NONE, &HASH_ID_RAW, &msg);
            msg[0] = msg[0].wrapping_mul(((x as u8) << 1) + 3);
        }
        let end = core_cycles();
        tt[i] = end.wrapping_sub(begin);
    }
    tt.sort();
    ((tt[tt.len() >> 1] as f64) / 1000.0, msg[0])
}

fn main() {
    banner_arch();

    let mut bx = 0u8;

    let (v, x) = bench_verify_full(9);
    bx ^= x;
    let (w, x) = bench_verify(9);
    bx ^= x;
    println!("FN-DSA verify (n = 512)        {:13.2}     add.: {:13.2}", v, w);
    let (v, x) = bench_verify_full(10);
    bx ^= x;
    let (w, x) = bench_verify(10);
    bx ^= x;
    println!("FN-DSA verify (n = 1024)       {:13.2}     add.: {:13.2}", v, w);

    println!("{}", bx);
}
