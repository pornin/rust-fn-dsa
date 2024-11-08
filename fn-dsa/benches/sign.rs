#![allow(non_snake_case)]

mod util;
use util::{banner_arch, core_cycles, FakeRNG};

use fn_dsa::{KeyPairGenerator, KeyPairGeneratorStandard, SigningKey, SigningKeyStandard, sign_key_size, vrfy_key_size, signature_size, DOMAIN_NONE, HASH_ID_RAW};

fn bench_sign(logn: u32) -> (f64, u8) {
    let z = core_cycles();
    let seed = z.to_le_bytes();
    let mut rng = FakeRNG::new(&seed);
    let mut kg = KeyPairGeneratorStandard::default();
    let mut sk_buf = [0u8; sign_key_size(10)];
    let mut vk_buf = [0u8; vrfy_key_size(10)];
    let mut sig_buf = [0u8; signature_size(10)];
    let sk_e = &mut sk_buf[..sign_key_size(logn)];
    let vk_e = &mut vk_buf[..vrfy_key_size(logn)];
    kg.keygen(logn, &mut rng, sk_e, vk_e);
    let mut sk = SigningKeyStandard::decode(sk_e).unwrap();
    let sig = &mut sig_buf[..signature_size(logn)];
    let mut msg = [0u8];
    let mut tt = [0; 10];
    for i in 0..tt.len() {
        let begin = core_cycles();
        for _ in 0..100 {
            sk.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, &msg, sig);
            msg[0] = sig[sig.len() >> 1];
        }
        let end = core_cycles();
        tt[i] = end.wrapping_sub(begin);
    }
    tt.sort();
    ((tt[tt.len() >> 1] as f64) / 100.0, msg[0])
}

fn bench_sign_full(logn: u32) -> (f64, u8) {
    let z = core_cycles();
    let seed = z.to_le_bytes();
    let mut rng = FakeRNG::new(&seed);
    let mut kg = KeyPairGeneratorStandard::default();
    let mut sk_buf = [0u8; sign_key_size(10)];
    let mut vk_buf = [0u8; vrfy_key_size(10)];
    let mut sig_buf = [0u8; signature_size(10)];
    let sk_e = &mut sk_buf[..sign_key_size(logn)];
    let vk_e = &mut vk_buf[..vrfy_key_size(logn)];
    kg.keygen(logn, &mut rng, sk_e, vk_e);
    let sig = &mut sig_buf[..signature_size(logn)];
    let mut msg = [0u8];
    let mut tt = [0; 10];
    for i in 0..tt.len() {
        let begin = core_cycles();
        for _ in 0..100 {
            let mut sk = SigningKeyStandard::decode(sk_e).unwrap();
            sk.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, &msg, sig);
            msg[0] = sig[sig.len() >> 1];
        }
        let end = core_cycles();
        tt[i] = end.wrapping_sub(begin);
    }
    tt.sort();
    ((tt[tt.len() >> 1] as f64) / 100.0, msg[0])
}

fn main() {
    banner_arch();

    let mut bx = 0u8;

    let (v, x) = bench_sign_full(9);
    bx ^= x;
    let (w, x) = bench_sign(9);
    bx ^= x;
    println!("fn-dsa sign (n = 512)          {:13.2}     add.: {:13.2}", v, w);

    let (v, x) = bench_sign_full(10);
    bx ^= x;
    let (w, x) = bench_sign(10);
    bx ^= x;
    println!("fn-dsa sign (n = 1024)         {:13.2}     add.: {:13.2}", v, w);

    println!("{}", bx);
}
