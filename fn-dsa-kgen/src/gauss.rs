#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use fn_dsa_comm::PRNG;

// ========================================================================
// Gaussian sampling for (f,g)
// ========================================================================

// This code samples the secret polynomials f and g deterministically
// from a given seed. The polynomial coefficients follow a given
// Gaussian distribution centred on zero. A PRNG (type parameter) is used
// to produce random 16-bit samples which are then used in a CDT table.
// The table only covers half of the range; a sampled sign bit is then
// applied.

const KGDIST_512: [u16; 17] = [
    29543, 23286, 17574, 12669,  8706,  5692,  3535,  2083,  1164,
      615,   308,   146,    65,    28,    11,     4,     1
];

const KGDIST_1024: [u16; 12] = [
    28207, 19623, 12472,  7198,  3753,  1761,
      742,   280,    94,    28,     8,     2
];

// Sample the f (or g) polynomial, using the provided PRNG,
// for a given degree n = 2^logn (with 1 <= logn <= 10). This function
// ensures that the returned polynomial has odd parity.
pub(crate) fn sample_f<T: PRNG>(logn: u32, rng: &mut T, f: &mut [i8]) {
    assert!(1 <= logn && logn <= 10);
    let n = 1 << logn;
    assert!(f.len() == n);

    // For degrees 512 and 1024, we can use the tables as is. For lower
    // degrees, we use the degree-512 table and sum 512/n successive samples
    // to get one sample at degree n.
    let (tab, zz) = match logn {
        10 => (&KGDIST_1024[..], 1),
        _ => (&KGDIST_512[..], 1 << (9 - logn)),
    };

    let mut parity = 0;
    let mut i = 0;
    while i < n {
        // aa accumulates the individual samples when zz > 1 (low degree).
        let mut aa = 0u32;
        for _ in 0..zz {
            // lsb(u) is the sign bit; v is the random 15-bit value.
            let u = rng.next_u16() as u32;
            let v = u >> 1;
            // hi16(a) = #{j | v < tab[j]}
            let mut a = 0u32;
            for j in 0..tab.len() {
                a = a.wrapping_sub(v.wrapping_sub(tab[j] as u32) & 0xFFFF0000);
            }
            // Apply sign bit (replace a with -a if sign bit is 1).
            a = a.wrapping_sub((a << 1) & (u & 1).wrapping_neg());
            aa = aa.wrapping_add(a);
        }
        // Aggregate sampled value is in the high 16 bits of aa.
        let ai = (aa as i32) >> 16;

        // For reduced/test degrees 2^6 or less, the value may be outside
        // of [-127, +127], which we do not want. This cannot happen for
        // degrees 2^7 and more, in particular for the "normal" degrees
        // 512 and 1024.
        if ai < -127 || ai > 127 {
            continue;
        }
        if i == n - 1 {
            if ((parity ^ (ai as u32)) & 1) != 1 {
                continue;
            }
        } else {
            parity ^= ai as u32;
        }
        f[i] = ai as i8;
        i += 1;
    }
}

/* TODO: add more tests with KATs from NIST (when they exist) */
