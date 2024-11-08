/// Encode small integers into bytes, with a fixed size per value.
///
/// Encode the provided sequence of signed integers `f`, with `nbits` bits per
/// value, into the destination buffer `d`. The actual number of written bytes
/// is returned. If the total encoded size is not an integral number of bytes,
/// then extra padding bits of value 0 are used.
pub fn trim_i8_encode(f: &[i8], nbits: u32, d: &mut [u8]) -> usize {
    let mut k = 0;
    let mut acc = 0;
    let mut acc_len = 0;
    let mask = (1u32 << nbits) - 1;
    for i in 0..f.len() {
        acc = (acc << nbits) | (((f[i] as u8) as u32) & mask);
        acc_len += nbits;
        while acc_len >= 8 {
            acc_len -= 8;
            d[k] = (acc >> acc_len) as u8;
            k += 1;
        }
    }
    if acc_len > 0 {
        d[k] = (acc << (8 - acc_len)) as u8;
        k += 1;
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
///  - Some bits are unused in the last byte and are not all zero.
/// 
/// The number of bits per coefficient (nbits) MUST lie between 2 and 8
/// (inclusive).
pub fn trim_i8_decode(d: &[u8], f: &mut [i8], nbits: u32) -> Option<usize> {
    let n = f.len();
    let needed = ((n * (nbits as usize)) + 7) >> 3;
    if d.len() < needed {
        return None;
    }
    let mut j = 0;
    let mut acc = 0;
    let mut acc_len = 0;
    let mask1 = (1 << nbits) - 1;
    let mask2 = 1 << (nbits - 1);
    for i in 0..needed {
        acc = (acc << 8) | (d[i] as u32);
        acc_len += 8;
        while acc_len >= nbits {
            acc_len -= nbits;
            let w = (acc >> acc_len) & mask1;
            let w = w | (w & mask2).wrapping_neg();
            if w == mask2.wrapping_neg() {
                return None;
            }
            f[j] = w as i8;
            j += 1;
            if j >= n {
                break;
            }
        }
    }
    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        // Some of the extra bits are non-zero.
        return None;
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
        let x = (x0 << 42) | (x1 << 28) | (x2 << 14) | x3;
        d[j..(j + 7)].copy_from_slice(&x.to_be_bytes()[1..8]);
        j += 7;
    }
    j
}

/// Encode integers modulo 12289 from bytes, with 14 bits per value.
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
    let x = ((d[0] as u64) << 48)
        | ((d[1] as u64) << 40)
        | ((d[2] as u64) << 32)
        | ((d[3] as u64) << 24)
        | ((d[4] as u64) << 16)
        | ((d[5] as u64) << 8)
        | (d[6] as u64);
    let h0 = ((x >> 42) as u32) & 0x3FFF;
    let h1 = ((x >> 28) as u32) & 0x3FFF;
    let h2 = ((x >> 14) as u32) & 0x3FFF;
    let h3 = (x as u32) & 0x3FFF;
    ov &= h0.wrapping_sub(12289);
    ov &= h1.wrapping_sub(12289);
    ov &= h2.wrapping_sub(12289);
    ov &= h3.wrapping_sub(12289);
    h[0] = h0 as u16;
    h[1] = h1 as u16;
    h[2] = h2 as u16;
    h[3] = h3 as u16;
    for i in 1..(n >> 2) {
        let x = u64::from_be_bytes(
            *<&[u8; 8]>::try_from(&d[(7 * i - 1)..(7 * i + 7)]).unwrap());
        let h0 = ((x >> 42) as u32) & 0x3FFF;
        let h1 = ((x >> 28) as u32) & 0x3FFF;
        let h2 = ((x >> 14) as u32) & 0x3FFF;
        let h3 = (x as u32) & 0x3FFF;
        ov &= h0.wrapping_sub(12289);
        ov &= h1.wrapping_sub(12289);
        ov &= h2.wrapping_sub(12289);
        ov &= h3.wrapping_sub(12289);
        h[4 * i + 0] = h0 as u16;
        h[4 * i + 1] = h1 as u16;
        h[4 * i + 2] = h2 as u16;
        h[4 * i + 3] = h3 as u16;
    }
    if (ov & 0x8000) == 0 {
        return None;
    }
    Some(needed)
}

/// Encode small integers into bytes using a compressed (Golomb-Rice) format.
///
/// Encode the provided source values `s` with compressed encoding. If
/// any of the source values is larger than 2047 (in absolute value),
/// then this function returns `false`. If the destination buffer `d` is
/// not large enough, then this function returns `false`. Otherwise, all
/// output buffer bytes are set (padding bits/bytes of value zero are
/// appended if necessary) and this function returns `true`.
pub fn comp_encode(s: &[i16], d: &mut [u8]) -> bool {
    let mut acc = 0;
    let mut acc_len = 0;
    let mut j = 0;
    for i in 0..s.len() {
        // Invariant: acc_len <= 7 at the beginning of each iteration.

        let x = s[i] as i32;
        if x < -2047 || x > 2047 {
            return false;
        }

        // Get sign and absolute value.
        let sw = (x >> 16) as u32;
        let w = ((x as u32) ^ sw).wrapping_sub(sw);

        // Encode sign bit then low 7 bits of the absolute value.
        acc <<= 8;
        acc |= sw & 0x80;
        acc |= w & 0x7F;
        acc_len += 8;

        // Encode the high bits. Since |x| <= 2047, the value in the high
        // bits is at most 15.
        let wh = w >> 7;
        acc <<= wh + 1;
        acc |= 1;
        acc_len += wh + 1;

        // We appended at most 8 + 15 + 1 = 24 bits, so the total number of
        // bits still fits in the 32-bit accumulator. We output complete
        // bytes.
        while acc_len >= 8 {
            acc_len -= 8;
            if j >= d.len() {
                return false;
            }
            d[j] = (acc >> acc_len) as u8;
            j += 1;
        }
    }

    // Flush remaining bits (if any).
    if acc_len > 0 {
        if j >= d.len() {
            return false;
        }
        d[j] = (acc << (8 - acc_len)) as u8;
        j += 1;
    }

    // Pad with zeros.
    for k in j..d.len() {
        d[k] = 0;
    }
    true
}

/// Encode small integers from bytes using a compressed (Golomb-Rice) format.
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
/// Valid encodings cover exactly the integers in the `[-2047,+2047]` range.
/// For a given sequence of integers, there is only one valid encoding as
/// a sequence of bytes (of a given length).
pub fn comp_decode(d: &[u8], v: &mut [i16]) -> bool {
    let mut i = 0;
    let mut acc = 0;
    let mut acc_len = 0;
    for j in 0..v.len() {
        // Invariant: acc_len <= 7 at the beginning of each iteration.

        // Get next 8 bits and split them into sign bit (s) and low bits
        // of the absolute value (m).
        if i >= d.len() {
            return false;
        }
        acc = (acc << 8) | (d[i] as u32);
        i += 1;
        let s = (acc >> (acc_len + 7)) & 1;
        let mut m = (acc >> acc_len) & 0x7F;

        // Get next bits until a 1 is reached.
        loop {
            if acc_len == 0 {
                if i >= d.len() {
                    return false;
                }
                acc = (acc << 8) | (d[i] as u32);
                i += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if ((acc >> acc_len) & 1) != 0 {
                break;
            }
            m += 0x80;
            if m > 2047 {
                return false;
            }
        }

        // Reject "-0" (invalid encoding).
        if (s & (m.wrapping_sub(1) >> 31)) != 0 {
            return false;
        }

        // Apply the sign to get the value.
        let sw = s.wrapping_neg();
        let w = (m ^ sw).wrapping_sub(sw);
        v[j] = w as i16;
    }

    // Check that unused bits are all zero.
    if acc_len > 0 {
        if (acc & ((1 << acc_len) - 1)) != 0 {
            return false;
        }
        i += 1;
    }
    for k in i..d.len() {
        if d[k] != 0 {
            return false;
        }
    }
    true
}
