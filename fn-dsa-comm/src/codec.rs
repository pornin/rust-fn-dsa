/// Encode small integers into bytes, with a fixed size per value.
///
/// Encode the provided sequence of signed integers `f`, with `nbits` bits per
/// value, into the destination buffer `d`. The actual number of written bytes
/// is returned. This function assumes that the total encoded output uses
/// an integral number of bytes (no unused bits in the last byte).
pub fn trim_i8_encode(f: &[i8], nbits: u32, d: &mut [u8]) -> usize {
    assert!((((f.len() as u32) * nbits) & 0x07) == 0);
    let mut k = 0;
    let mut acc = 0;
    let mut acc_len = 0;
    let mask = (1u32 << nbits) - 1;
    for i in 0..f.len() {
        acc |= (((f[i] as u8) as u32) & mask) << acc_len;
        acc_len += nbits;
        while acc_len >= 8 {
            d[k] = acc as u8;
            k += 1;
            acc >>= 8;
            acc_len -= 8;
        }
    }
    k
}

/// Decode small integers from bytes, with a fixed size per value.
///
/// Decode the provided bytes `d` into the signed integers `f`, using
/// `nbits` bits per value. Exactly as many bytes as necessary are read
/// from `d` in order to fill the slice `f` entirely. The actual number
/// of bytes read from `d` is returned. `None` is returned if any of the
/// following happens:
/// 
///  - Source buffer is not large enough.
///  - An invalid encoding (`-2^(nbits-1)`) is encountered.
/// 
/// The number of bits per coefficient (nbits) MUST lie between 2 and 8
/// (inclusive).
pub fn trim_i8_decode(d: &[u8], f: &mut [i8], nbits: u32) -> Option<usize> {
    let n = f.len();
    let needed = n * (nbits as usize);
    assert!((needed & 0x07) == 0);
    let needed = needed >> 3;
    if d.len() < needed {
        return None;
    }
    let mut j = 0;
    let mut acc = 0;
    let mut acc_len = 0;
    let mask1 = (1 << nbits) - 1;
    let mask2 = 1 << (nbits - 1);
    for i in 0..needed {
        acc |= (d[i] as u32) << acc_len;
        acc_len += 8;
        while acc_len >= nbits {
            let w = acc & mask1;
            acc >>= nbits;
            acc_len -= nbits;
            let w = w | (w & mask2).wrapping_neg();
            if w == mask2.wrapping_neg() {
                return None;
            }
            if j >= n {
                return None;
            }
            f[j] = w as i8;
            j += 1;
        }
    }
    Some(needed)
}

/// Encode integers modulo 12289 into bytes, with 14 bits per value.
///
/// Encode the provided sequence of integers modulo q = 12289 into the
/// destination buffer `d`. Exactly 14 bits are used for each value.
/// The values MUST be in the `[0,q-1]` range. The number of source values
/// MUST be a multiple of 4.
pub fn modq_encode(h: &[u16], d: &mut [u8]) -> usize {
    assert!((h.len() & 3) == 0);
    let mut j = 0;
    for i in 0..(h.len() >> 2) {
        let x0 = h[4 * i + 0] as u64;
        let x1 = h[4 * i + 1] as u64;
        let x2 = h[4 * i + 2] as u64;
        let x3 = h[4 * i + 3] as u64;
        let x = (x3 << 42) | (x2 << 28) | (x1 << 14) | x0;
        d[j..(j + 7)].copy_from_slice(&x.to_le_bytes()[0..7]);
        j += 7;
    }
    j
}

/// Decode integers modulo 12289 from bytes, with 14 bits per value.
///
/// Decode some bytes into integers modulo q = 12289. Exactly as many
/// bytes as necessary are read from the source `d` to fill all values in
/// the destination slice `h`. The number of elements in `h` MUST be a
/// multiple of 4. The total number of read bytes is returned. If the
/// source is too short, of if any of the decoded values is invalid (i.e.
/// not in the `[0,q-1]` range), then this function returns `None`.
pub fn modq_decode(d: &[u8], h: &mut [u16]) -> Option<usize> {
    let n = h.len();
    if n == 0 {
        return Some(0);
    }
    assert!((n & 3) == 0);
    let needed = 7 * (n >> 2);
    if d.len() != needed {
        return None;
    }
    let mut ov = 0xFFFF;
    if n >= 8 {
        for i in 0..((n >> 2) - 1) {
            let x = u64::from_le_bytes(
                *<&[u8; 8]>::try_from(&d[(7 * i)..(7 * i + 8)]).unwrap());
            let h0 = (x as u32) & 0x3FFF;
            let h1 = ((x >> 14) as u32) & 0x3FFF;
            let h2 = ((x >> 28) as u32) & 0x3FFF;
            let h3 = ((x >> 42) as u32) & 0x3FFF;
            ov &= h0.wrapping_sub(12289);
            ov &= h1.wrapping_sub(12289);
            ov &= h2.wrapping_sub(12289);
            ov &= h3.wrapping_sub(12289);
            h[4 * i + 0] = h0 as u16;
            h[4 * i + 1] = h1 as u16;
            h[4 * i + 2] = h2 as u16;
            h[4 * i + 3] = h3 as u16;
        }
    }
    let j = d.len() - 7;
    let x = (d[j + 0] as u64)
        | ((d[j + 1] as u64) << 8)
        | ((d[j + 2] as u64) << 16)
        | ((d[j + 3] as u64) << 24)
        | ((d[j + 4] as u64) << 32)
        | ((d[j + 5] as u64) << 40)
        | ((d[j + 6] as u64) << 48);
    let h0 = (x as u32) & 0x3FFF;
    let h1 = ((x >> 14) as u32) & 0x3FFF;
    let h2 = ((x >> 28) as u32) & 0x3FFF;
    let h3 = ((x >> 42) as u32) & 0x3FFF;
    ov &= h0.wrapping_sub(12289);
    ov &= h1.wrapping_sub(12289);
    ov &= h2.wrapping_sub(12289);
    ov &= h3.wrapping_sub(12289);
    h[n - 4] = h0 as u16;
    h[n - 3] = h1 as u16;
    h[n - 2] = h2 as u16;
    h[n - 1] = h3 as u16;
    if (ov & 0x8000) == 0 {
        return None;
    }
    Some(needed)
}

/// Maximum allowed L-infinity norm for signature elements.
pub const B_INF: i32 = 840;

/// Encode small integers into bytes using a compressed (Golomb-Rice) format.
///
/// Encode the provided source values `s` with compressed encoding. If
/// any of the source values is larger (in absolute value) than the
/// prescribed maximum L-infinity norm (see `B_INF`), then this function
/// returns `false`. If the destination buffer `d` is not large enough,
/// then this function returns `false`. Otherwise, all output buffer
/// bytes are set (padding bits/bytes of value zero are appended if
/// necessary) and this function returns `true`.
pub fn comp_encode(s: &[i16], d: &mut [u8]) -> bool {
    let mut acc = 0;
    let mut acc_len = 0;
    let mut j = 0;
    for i in 0..s.len() {
        // Invariant: acc_len <= 7 at the beginning of each iteration.

        let x = s[i] as i32;

        // Get sign and absolute value.
        let sw = (x >> 16) as u32;
        let w = ((x as u32) ^ sw).wrapping_sub(sw);
        if w > (B_INF as u32) {
            return false;
        }

        // Encode sign bit then low 7 bits of the absolute value.
        acc |= ((sw & 1) | ((w & 0x7F) << 1)) << acc_len;
        acc_len += 8;

        // Encode the high bits. Since |x| <= B_INF, the value in the high
        // bits is at most 15 (actual range is lower because |x| <= B_INF).
        let wh = w >> 7;
        acc |= 1u32 << (acc_len + wh);
        acc_len += wh + 1;

        // We appended at most 8 + 15 + 1 = 24 bits, so the total number of
        // bits still fits in the 32-bit accumulator. We output complete
        // bytes.
        while acc_len >= 8 {
            if j >= d.len() {
                return false;
            }
            d[j] = acc as u8;
            j += 1;
            acc >>= 8;
            acc_len -= 8;
        }
    }

    // Flush remaining bits (if any).
    if acc_len > 0 {
        if j >= d.len() {
            return false;
        }
        d[j] = acc as u8;
        j += 1;
    }

    // Pad with zeros.
    for k in j..d.len() {
        d[k] = 0;
    }
    true
}

/// Decode small integers from bytes using a compressed (Golomb-Rice) format.
///
/// Decode the provided source buffer `d` into signed integers `v`, using
/// the compressed encoding convention. This function returns `false` in
/// any of the following cases:
///
///  - Source does not contain enough encoded integers to fill `v` entirely.
///  - An invalid encoding for a value is encountered.
///  - Any of the remaining unused bits in `d` (after all integers have been
///    decoded) is non-zero.
///
/// This function validates that all decoded value are at most (in absolute
/// value) the maximum allowed L-infinity norm (see `B_INF`). For a given
/// sequence of integers, there is only one valid encoding as a sequence
/// of bytes (of a given length).
pub fn comp_decode(d: &[u8], v: &mut [i16]) -> bool {
    let mut j = 0;
    let mut acc = 0;
    let mut acc_len = 0;
    for i in 0..v.len() {
        // Invariant: acc_len <= 7 at the beginning of each iteration.

        // Get next 8 bits and split them into sign bit (s) and low bits
        // of the absolute value (m).
        if j >= d.len() {
            return false;
        }
        acc |= (d[j] as u32) << acc_len;
        j += 1;
        let s = acc & 1;
        let m = (acc >> 1) & 0x7F;
        acc >>= 8;

        // Find next bit of value 1. Since there should be at most 6 bits
        // of value 0, we only need one extra byte at most.
        if acc == 0 {
            if j >= d.len() {
                return false;
            }
            acc |= (d[j] as u32) << acc_len;
            j += 1;
            acc_len += 8;
            if acc == 0 {
                return false;
            }
        }
        let tz = acc.trailing_zeros();
        // Since we ensured that acc != 0, and it contains at most 15 bits
        // at this point, the computation of the mantissa cannot overflow.
        let m = m + (tz << 7);
        if m > (B_INF as u32) {
            return false;
        }
        acc >>= tz + 1;
        acc_len -= tz + 1;

        // Reject "-0" (invalid encoding).
        if (s & (m.wrapping_sub(1) >> 31)) != 0 {
            return false;
        }

        // Apply the sign to get the value.
        let sw = s.wrapping_neg();
        let w = (m ^ sw).wrapping_sub(sw);
        v[i] = w as i16;
    }

    // Check that unused bits are all zero.
    if acc != 0 {
        return false;
    }
    for k in j..d.len() {
        if d[k] != 0 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PRNG;
    use crate::shake::SHAKE256_PRNG;

    #[test]
    fn modq() {
        let mut tmp = [0u16; 2048];
        let mut bb = [0u8; 1792];
        for logn in 2..11 {
            let n = 1usize << logn;
            let (t1, tx) = tmp.split_at_mut(n);
            let (t2, _) = tx.split_at_mut(n);
            let (b1, _) = bb.split_at_mut(7 << (logn - 2));
            for r in 0..64 {
                // Generate random values in [0,q].
                let mut rng = SHAKE256_PRNG::new(&[logn as u8, r as u8]);
                for i in 0..n {
                    t1[i] = rng.next_u16() % 12289;
                }

                // Check that we can encode the value and redecode it.
                assert!(modq_encode(t1, b1) == b1.len());
                assert!(modq_decode(b1, t2).unwrap() == b1.len());
                assert!(t1 == t2);

                // Check that values not lower than 12289 cannot be decoded
                let j = (r & (n - 1)) * 14;
                for k in 0..14 {
                    let off = (j + k) >> 3;
                    let m = 1u8 << ((j + k) & 7);
                    if ((12289u32 >> k) & 1) == 0 {
                        b1[off] &= !m;
                    } else {
                        b1[off] |= m;
                    }
                }
                assert!(modq_decode(b1, t2).is_none());
            }
        }
    }

    #[test]
    fn compressed() {
        let mut tmp = [0i16; 2048];
        let mut bb = [0u8; 3850];
        for logn in 2..11 {
            let n = 1usize << logn;
            let (t1, tx) = tmp.split_at_mut(n);
            let (t2, _) = tx.split_at_mut(n);
            // A value can use up to 15 bits:
            //   1 sign bit
            //   7 low bits
            //   up to 6 bits of value zero (because 840 < 7*128)
            //   1 stop bit
            let blen = (n << 1) - (n >> 3) + 5;
            let (b1, bx) = bb.split_at_mut(blen);
            let (b2, _) = bx.split_at_mut(blen);

            for r in 0..64 {
                // Generate random values in [-B_INF,+B_INF]
                let mut rng = SHAKE256_PRNG::new(&[logn as u8, r as u8]);
                for i in 0..n {
                    let x = rng.next_u16() as i32;
                    t1[i] = (x % (1 + 2 * B_INF) - B_INF) as i16;
                }

                // Check that we can encode the value and redecode it.
                assert!(comp_encode(t1, b1));
                assert!(comp_decode(b1, t2));
                assert!(t1 == t2);

                // Locate the final non-zero byte. Check that removing all
                // extra bytes does not prevent decoding.
                let mut k = b1.len();
                while k > 0 && b1[k - 1] == 0 {
                    k -= 1;
                }
                assert!(comp_decode(&b1[..k], t2));
                assert!(t1 == t2);

                // Check that setting any of the ignored bits to 1 breaks
                // decoding. We first locate the last set data bit (bits
                // within a byte are in low-to-high order).
                let mut g = 8;
                while ((b1[k - 1] as u32) & (1u32 << (g - 1))) == 0 {
                     g -= 1;
                }
                for j in g..32 {
                    let m = 1u8 << (j & 7);
                    let off = j >> 3;
                    b1[(k - 1) + off] ^= m;
                    assert!(!comp_decode(&b1[..(k + 3)], t2));
                    b1[(k - 1) + off] ^= m;
                }

                // For the remaining tests, we modify a value whose index
                // is determined by the inner loop counter.
                let s = r & (n - 1);

                // Check that out-of-range values are properly detected.
                // We first modify one value to set it to 836, and again
                // to 837, so that we can locate the location of the changed
                // bit in the encoding.
                t1[s] = 836;
                assert!(comp_encode(t1, b1));
                t1[s] = 837;
                assert!(comp_encode(t1, b2));
                let mut pos = 0;
                let mut val;
                loop {
                    val = b1[pos] ^ b2[pos];
                    if val != 0 {
                        break;
                    }
                    pos = pos + 1;
                }

                // Check that encoding and decoding +840 and -840 works,
                // but encoding and decoding +841 and -841 is properly
                // rejected both ways.
                t1[s] = 841;
                assert!(!comp_encode(t1, b1));
                t1[s] = -841;
                assert!(!comp_encode(t1, b1));

                t1[s] = 840;
                assert!(comp_encode(t1, b1));
                assert!(comp_decode(b1, t2));
                assert!(t1 == t2);
                b1[pos] ^= val;
                assert!(!comp_decode(b1, t2));

                t1[s] = -840;
                assert!(comp_encode(t1, b1));
                assert!(comp_decode(b1, t2));
                assert!(t1 == t2);
                b1[pos] ^= val;
                assert!(!comp_decode(b1, t2));

                // Check that -0 is properly detected.
                t1[s] = 1;
                assert!(comp_encode(t1, b1));
                t1[s] = -1;
                assert!(comp_encode(t1, b2));
                let mut pos = 0;
                let mut val;
                loop {
                    val = b1[pos] ^ b2[pos];
                    if val != 0 {
                        break;
                    }
                    pos = pos + 1;
                }
                t1[s] = 0;
                assert!(comp_encode(t1, b1));
                b1[pos] ^= val;
                assert!(!comp_decode(b1, t2));
            }
        }
    }
}
