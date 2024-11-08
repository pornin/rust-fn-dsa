#![allow(non_snake_case)]

mod util;
use util::{banner_arch, core_cycles, FakeRNG};

use fn_dsa::{KeyPairGenerator, KeyPairGeneratorStandard, sign_key_size, vrfy_key_size};

fn bench_keygen(logn: u32) -> (f64, u8) {
    let z = core_cycles();
    let mut seed = z.to_le_bytes();
    let mut kg = KeyPairGeneratorStandard::default();
    let mut sk_buf = [0u8; sign_key_size(10)];
    let mut vk_buf = [0u8; vrfy_key_size(10)];
    let sk_e = &mut sk_buf[..sign_key_size(logn)];
    let vk_e = &mut vk_buf[..vrfy_key_size(logn)];
    let mut tt = [0; 100];
    for i in 0..(20 + tt.len()) {
        let begin = core_cycles();
        let mut rng = FakeRNG::new(&seed);
        kg.keygen(logn, &mut rng, sk_e, vk_e);
        seed[0] ^= sk_e[sk_e.len() - 1];
        seed[1] ^= vk_e[vk_e.len() - 1];
        let end = core_cycles();
        if i >= 20 {
            tt[i - 20] = end.wrapping_sub(begin);
        }
    }
    tt.sort();
    (tt[tt.len() >> 1] as f64, seed[0] ^ seed[1])
}

fn main() {
    banner_arch();

    let mut bx = 0u8;

    let (v, x) = bench_keygen(9);
    bx ^= x;
    println!("FN-DSA keygen (n = 512)        {:13.2}", v);
    let (v, x) = bench_keygen(10);
    bx ^= x;
    println!("FN-DSA keygen (n = 1024)       {:13.2}", v);

    println!("{}", bx);
}
