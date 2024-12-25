#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

// ========================================================================
// Low-level computations modulo a small prime.
// ========================================================================

// All mp_*() functions deal with integers modulo a prime p, such that
// 1.34*2^30 < p < 2^31.
//
// The "unsigned representation" of an integer x modulo p is the unique
// matching integer in the [0, p-1] range, with the u32 type.
//
// The "signed representation" of an integer x modulo p is the unique
// matching integer in the [-p/2, p/2] range, with the i32 type.
//
// "Montgomery representation" of x modulo p is the unsigned representation
// of x*2^32 mod p (hence in the [0, p-1] range, and using the u32 type).
//
// Unless otherwise specified:
//   - When a function uses an integer modulo p as operand, it expects it
//     to be provided in unsigned representation. Such operands MUST be in
//     the proper range; overflows are not checked but may lead to incorrect
//     results.
//   - When a function outputs an integer modulo p, it returns it in unsigned
//     representation (and, in particular, in the proper [0, p-1] range).
//
// Montgomery multiplication, given a and b in unsigned representation,
// computes and returns (a*b)/2^32 mod p in unsigned representation. The
// following properties hold:
//   - If a and b are really the Montgomery representations of x and y,
//     respectively, then the returned value is the Mongomery representation
//     of x*y mod p.
//   - If a is the Montgomery representation of x, then the returned value
//     is the unsigned representation of x*b mod p.
//   - If b is the Montgomery representation of b, then the returned value
//     is the unsigned representation of a*y mod p.
//
// For a given value with unsigned representation x, its Montgomery
// representation can be obtained with a Montgomery multiplication of
// x with R2 = 2^64 mod p. In the other direction, if x is the Montgomery
// reprensentation of y, then the unsigned representation of y can be
// obtained by computing the Montgomery multiplication of y with 1.

// Return 0xFFFFFFFF if the top bit of x is 1, 0x00000000 otherwise.
#[inline(always)]
pub(crate) const fn tbmask(x: u32) -> u32 {
    ((x as i32) >> 31) as u32
}

// Given v in the [-(p-1), +(p-1)] range (signed), return x = v mod p.
#[inline(always)]
pub(crate) fn mp_set(v: i32, p: u32) -> u32 {
    let w = v as u32;
    w.wrapping_add(p & tbmask(w))
}

// Given v in the [0, 2*p-1] range (unsigned), return x = v mod p.
#[inline(always)]
pub(crate) fn mp_set_u(v: u32, p: u32) -> u32 {
    let w = v.wrapping_sub(p);
    w.wrapping_add(p & tbmask(w))
}

// Given x (integer modulo p), return its signed normalized value
// (in [-p/2, +p/2]).
#[inline(always)]
pub(crate) fn mp_norm(x: u32, p: u32) -> i32 {
    let c = tbmask(x.wrapping_sub((p + 1) >> 1));
    x.wrapping_sub(p & !c) as i32
}

// Compute R = 2^32 mod p.
#[inline(always)]
pub(crate) fn mp_R(p: u32) -> u32 {
    // Since we assume that 1.34*2^30 < p < 2^31, we have:
    //    2*p < 2^32 < 3*p
    // Hence, 2^32 = 2*p + R with 0 <= R < p.
    // We compute and return R = 2^32 - 2*p
    p.wrapping_neg() << 1
}

// Compute hR = 2^31 mod p.
#[inline(always)]
pub(crate) fn mp_hR(p: u32) -> u32 {
    // Since we assume that 1.34*2^30 < p < 2^31, we have:
    //    p < 2^31 < 2*p
    // Hence, 2^31 = p + hR with 0 <= R < p.
    // We compute and return hR = 2^31 - p
    0x80000000 - p
}

// Compute a + b mod p.
// This function is compatible with Montgomery representation: if a and b
// are the Montgomery representations of x and y, respectively, then this
// returns the Montgomery representation of x + y mod p.
#[inline(always)]
pub(crate) fn mp_add(a: u32, b: u32, p: u32) -> u32 {
    let d = a.wrapping_add(b).wrapping_sub(p);
    d.wrapping_add(p & tbmask(d))
}

// Compute a - b mod p.
// This function is compatible with Montgomery representation: if a and b
// are the Montgomery representations of x and y, respectively, then this
// returns the Montgomery representation of x - y mod p.
#[inline(always)]
pub(crate) fn mp_sub(a: u32, b: u32, p: u32) -> u32 {
    let d = a.wrapping_sub(b);
    d.wrapping_add(p & tbmask(d))
}

// Compute a / 2 mod p.
// This function is compatible with Montgomery representation: if a is the
// Montgomery representation of x, then this returns the Montgomery
// representation of x/2 mod p.
#[inline(always)]
pub(crate) fn mp_half(a: u32, p: u32) -> u32 {
    a.wrapping_add(p & (a & 1).wrapping_neg()) >> 1
}

// Compute a*b/2^32 mod p; parameter p0i is equal to -1/p mod 2^32.
// This is the "Montgomery multiplication".
#[inline(always)]
pub(crate) fn mp_mmul(a: u32, b: u32, p: u32, p0i: u32) -> u32 {
    let z = (a as u64) * (b as u64);
    let w = (z as u32).wrapping_mul(p0i);
    let d = (((z + (w as u64) * (p as u64)) >> 32) as u32).wrapping_sub(p);
    d.wrapping_add(p & tbmask(d))
}

// Compute 2^(31*e) mod p.
// Exponent e is considered non-secret.
#[inline(always)]
pub(crate) fn mp_Rx31(e: u32, p: u32, p0i: u32, R2: u32) -> u32 {
    // Set x <- 2^63 mod p
    let mut x = mp_half(R2, p);
    let mut d = 1;
    let mut e = e;
    loop {
        if (e & 1) != 0 {
            d = mp_mmul(d, x, p, p0i);
        }
        e >>= 1;
        if e == 0 {
            return d;
        }
        x = mp_mmul(x, x, p, p0i);
    }
}

// Compute x/y mod p. If y is not invertible modulo p, then 0 is returned
// (regardless of the value of x).
#[allow(dead_code)]
pub(crate) fn mp_div(x: u32, y: u32, p: u32) -> u32 {
    // We use an extended binary GCD:
    //    Initial state:
    //        a = y    u = x
    //        b = p    v = 0
    //    Invariants:
    //        a*x = u*y mod p
    //        b*x = v*y mod p
    //        b is odd
    //        0 <= u < p
    //        0 <= v < p
    //        0 <= a < p
    //        1 <= b <= p
    //    Each iteration does the following:
    //        if a is odd:
    //            if a < b:
    //                (a, u, b, v) <- (b, v, a, u)
    //            a <- a - b
    //            u <- u - v mod p
    //        a <- a/2
    //        u <- u/2 mod p
    //    We denote len(z) the length (in bits) of the non-negative
    //    integer z. The following properties hold:
    //      - If a != 0 at the start of an iteration, then len(a)+len(b)
    //        is reduced by at least 1 by the iteration.
    //      - If an iteration sets a to 0, then, upon exit of that
    //        iteration, b contains GCD(y, p).
    //      - If a = 0 at the start of an iteration, then a, b, u and v
    //        are unchanged by that iteration (and all subsequent iterations).
    //      - b is always odd, and therefore never equal to zero.
    //    Values x, y and p fit on 31 bits, hence len(a)+len(b) <= 62
    //    initially. Therefore:
    //      - If y is invertible modulo p, then after 60 iterations,
    //        b contains 1, at which point x = v*y mod p; value v is
    //        then the result value.
    //      - If y is not invertible modulo p, then after 60 iterations,
    //        a contains 0 and b contains a value strictly greater than 1.
    let mut a = y;
    let mut b = p;
    let mut u = x;
    let mut v = 0;
    for _ in 0..60 {
        let a_odd = (a & 1).wrapping_neg();
        let swap = tbmask(a.wrapping_sub(b)) & a_odd;
        let t1 = swap & (a ^ b);
        a ^= t1;
        b ^= t1;
        let t2 = swap & (u ^ v);
        u ^= t2;
        v ^= t2;
        a -= a_odd & b;
        u = mp_sub(u, a_odd & v, p);
        a >>= 1;
        u = mp_half(u, p);
    }
    // If b > 1, we want to clear the result. If p is prime, then this
    // can happen only if y = 0, in which case a was 0 all along, and v
    // already contains 0. However, we'd prefer to also support the case
    // of a non-prime modulus, for which we could have a non-zero v at
    // this point.
    v & tbmask(b.wrapping_sub(2))
}

// ========================================================================
// Pre-computed moduli and NTT.
// ========================================================================

// Each modulus is p < 2^31 such that p = 1 mod 2048. The moduli are in
// decreasing order.
//
// Since p = 1 mod 2048, there are 1024 primitive 2048-th roots of 1 modulo
// p, i.e. integers g such that g^1024 = -1 mod p. Value g is one of them,
// and ig is its inverse modulo p. It does not really matter which precise
// root is used here (this does not impact the value of the generated keys);
// in the PRIMES table, value g is obtained by taking x^((p-1)/2048) for the
// smallest x (as an integer in [0, p-1]) which is not a square modulo p.
// Values g and ig are in Montgomery representation.
//
// For each prime p_j = PRIMES[j].p, value s = PRIMES[j].s is the inverse
// of \prod_{i<j} p_i mod p. Value s is used to convert big integers from
// RNS representation to normal representation. s is in Montgomery
// representation.
//
// (The PRIMES table is later on in this file.)
#[derive(Copy, Clone, Debug)]
pub(crate) struct SmallPrime {
    pub(crate) p: u32,   // modulus
    pub(crate) p0i: u32, // -1/p mod 2^32
    pub(crate) R2: u32,  // 2^64 mod p
    pub(crate) g: u32,   // g^1024 = -1 mod p (Mont.)
    pub(crate) ig: u32,  // 1/g mod p (Mont.)
    pub(crate) s: u32,   // inverse mod p of the product of previous primes (Mont.)
}

// The first prime in PRIMES[] has a dedicated name because it is
// used directly in some functions.
pub(crate) const P0: SmallPrime = PRIMES[0];

// REV10[] contains the precomputed "bit-reversal" function over 10 bits.
pub(crate) const REV10: [u16; 1024] = [
    0, 512, 256, 768, 128, 640, 384, 896, 64, 576, 320, 832, 192, 704, 448, 960, 32, 544, 288, 800,
    160, 672, 416, 928, 96, 608, 352, 864, 224, 736, 480, 992, 16, 528, 272, 784, 144, 656, 400,
    912, 80, 592, 336, 848, 208, 720, 464, 976, 48, 560, 304, 816, 176, 688, 432, 944, 112, 624,
    368, 880, 240, 752, 496, 1008, 8, 520, 264, 776, 136, 648, 392, 904, 72, 584, 328, 840, 200,
    712, 456, 968, 40, 552, 296, 808, 168, 680, 424, 936, 104, 616, 360, 872, 232, 744, 488, 1000,
    24, 536, 280, 792, 152, 664, 408, 920, 88, 600, 344, 856, 216, 728, 472, 984, 56, 568, 312,
    824, 184, 696, 440, 952, 120, 632, 376, 888, 248, 760, 504, 1016, 4, 516, 260, 772, 132, 644,
    388, 900, 68, 580, 324, 836, 196, 708, 452, 964, 36, 548, 292, 804, 164, 676, 420, 932, 100,
    612, 356, 868, 228, 740, 484, 996, 20, 532, 276, 788, 148, 660, 404, 916, 84, 596, 340, 852,
    212, 724, 468, 980, 52, 564, 308, 820, 180, 692, 436, 948, 116, 628, 372, 884, 244, 756, 500,
    1012, 12, 524, 268, 780, 140, 652, 396, 908, 76, 588, 332, 844, 204, 716, 460, 972, 44, 556,
    300, 812, 172, 684, 428, 940, 108, 620, 364, 876, 236, 748, 492, 1004, 28, 540, 284, 796, 156,
    668, 412, 924, 92, 604, 348, 860, 220, 732, 476, 988, 60, 572, 316, 828, 188, 700, 444, 956,
    124, 636, 380, 892, 252, 764, 508, 1020, 2, 514, 258, 770, 130, 642, 386, 898, 66, 578, 322,
    834, 194, 706, 450, 962, 34, 546, 290, 802, 162, 674, 418, 930, 98, 610, 354, 866, 226, 738,
    482, 994, 18, 530, 274, 786, 146, 658, 402, 914, 82, 594, 338, 850, 210, 722, 466, 978, 50,
    562, 306, 818, 178, 690, 434, 946, 114, 626, 370, 882, 242, 754, 498, 1010, 10, 522, 266, 778,
    138, 650, 394, 906, 74, 586, 330, 842, 202, 714, 458, 970, 42, 554, 298, 810, 170, 682, 426,
    938, 106, 618, 362, 874, 234, 746, 490, 1002, 26, 538, 282, 794, 154, 666, 410, 922, 90, 602,
    346, 858, 218, 730, 474, 986, 58, 570, 314, 826, 186, 698, 442, 954, 122, 634, 378, 890, 250,
    762, 506, 1018, 6, 518, 262, 774, 134, 646, 390, 902, 70, 582, 326, 838, 198, 710, 454, 966,
    38, 550, 294, 806, 166, 678, 422, 934, 102, 614, 358, 870, 230, 742, 486, 998, 22, 534, 278,
    790, 150, 662, 406, 918, 86, 598, 342, 854, 214, 726, 470, 982, 54, 566, 310, 822, 182, 694,
    438, 950, 118, 630, 374, 886, 246, 758, 502, 1014, 14, 526, 270, 782, 142, 654, 398, 910, 78,
    590, 334, 846, 206, 718, 462, 974, 46, 558, 302, 814, 174, 686, 430, 942, 110, 622, 366, 878,
    238, 750, 494, 1006, 30, 542, 286, 798, 158, 670, 414, 926, 94, 606, 350, 862, 222, 734, 478,
    990, 62, 574, 318, 830, 190, 702, 446, 958, 126, 638, 382, 894, 254, 766, 510, 1022, 1, 513,
    257, 769, 129, 641, 385, 897, 65, 577, 321, 833, 193, 705, 449, 961, 33, 545, 289, 801, 161,
    673, 417, 929, 97, 609, 353, 865, 225, 737, 481, 993, 17, 529, 273, 785, 145, 657, 401, 913,
    81, 593, 337, 849, 209, 721, 465, 977, 49, 561, 305, 817, 177, 689, 433, 945, 113, 625, 369,
    881, 241, 753, 497, 1009, 9, 521, 265, 777, 137, 649, 393, 905, 73, 585, 329, 841, 201, 713,
    457, 969, 41, 553, 297, 809, 169, 681, 425, 937, 105, 617, 361, 873, 233, 745, 489, 1001, 25,
    537, 281, 793, 153, 665, 409, 921, 89, 601, 345, 857, 217, 729, 473, 985, 57, 569, 313, 825,
    185, 697, 441, 953, 121, 633, 377, 889, 249, 761, 505, 1017, 5, 517, 261, 773, 133, 645, 389,
    901, 69, 581, 325, 837, 197, 709, 453, 965, 37, 549, 293, 805, 165, 677, 421, 933, 101, 613,
    357, 869, 229, 741, 485, 997, 21, 533, 277, 789, 149, 661, 405, 917, 85, 597, 341, 853, 213,
    725, 469, 981, 53, 565, 309, 821, 181, 693, 437, 949, 117, 629, 373, 885, 245, 757, 501, 1013,
    13, 525, 269, 781, 141, 653, 397, 909, 77, 589, 333, 845, 205, 717, 461, 973, 45, 557, 301,
    813, 173, 685, 429, 941, 109, 621, 365, 877, 237, 749, 493, 1005, 29, 541, 285, 797, 157, 669,
    413, 925, 93, 605, 349, 861, 221, 733, 477, 989, 61, 573, 317, 829, 189, 701, 445, 957, 125,
    637, 381, 893, 253, 765, 509, 1021, 3, 515, 259, 771, 131, 643, 387, 899, 67, 579, 323, 835,
    195, 707, 451, 963, 35, 547, 291, 803, 163, 675, 419, 931, 99, 611, 355, 867, 227, 739, 483,
    995, 19, 531, 275, 787, 147, 659, 403, 915, 83, 595, 339, 851, 211, 723, 467, 979, 51, 563,
    307, 819, 179, 691, 435, 947, 115, 627, 371, 883, 243, 755, 499, 1011, 11, 523, 267, 779, 139,
    651, 395, 907, 75, 587, 331, 843, 203, 715, 459, 971, 43, 555, 299, 811, 171, 683, 427, 939,
    107, 619, 363, 875, 235, 747, 491, 1003, 27, 539, 283, 795, 155, 667, 411, 923, 91, 603, 347,
    859, 219, 731, 475, 987, 59, 571, 315, 827, 187, 699, 443, 955, 123, 635, 379, 891, 251, 763,
    507, 1019, 7, 519, 263, 775, 135, 647, 391, 903, 71, 583, 327, 839, 199, 711, 455, 967, 39,
    551, 295, 807, 167, 679, 423, 935, 103, 615, 359, 871, 231, 743, 487, 999, 23, 535, 279, 791,
    151, 663, 407, 919, 87, 599, 343, 855, 215, 727, 471, 983, 55, 567, 311, 823, 183, 695, 439,
    951, 119, 631, 375, 887, 247, 759, 503, 1015, 15, 527, 271, 783, 143, 655, 399, 911, 79, 591,
    335, 847, 207, 719, 463, 975, 47, 559, 303, 815, 175, 687, 431, 943, 111, 623, 367, 879, 239,
    751, 495, 1007, 31, 543, 287, 799, 159, 671, 415, 927, 95, 607, 351, 863, 223, 735, 479, 991,
    63, 575, 319, 831, 191, 703, 447, 959, 127, 639, 383, 895, 255, 767, 511, 1023,
];

pub(crate) const PRIMES: [SmallPrime; 308] = [
    SmallPrime {
        p: 2147473409,
        p0i: 2042615807,
        R2: 419348484,
        g: 1790111537,
        ig: 786166065,
        s: 20478,
    },
    SmallPrime {
        p: 2147389441,
        p0i: 1862176767,
        R2: 1141604340,
        g: 677655126,
        ig: 2024968256,
        s: 942807490,
    },
    SmallPrime {
        p: 2147387393,
        p0i: 1472104447,
        R2: 554514419,
        g: 563781659,
        ig: 1438853699,
        s: 511282737,
    },
    SmallPrime {
        p: 2147377153,
        p0i: 3690881023,
        R2: 269819887,
        g: 978644358,
        ig: 1971237828,
        s: 1936446844,
    },
    SmallPrime {
        p: 2147358721,
        p0i: 3720222719,
        R2: 153618407,
        g: 1882929796,
        ig: 289507384,
        s: 264920030,
    },
    SmallPrime {
        p: 2147352577,
        p0i: 2147352575,
        R2: 3145700,
        g: 875644459,
        ig: 1993867586,
        s: 1197387618,
    },
    SmallPrime {
        p: 2147346433,
        p0i: 498984959,
        R2: 154699745,
        g: 1268990641,
        ig: 1559885885,
        s: 2112514368,
    },
    SmallPrime {
        p: 2147338241,
        p0i: 2478688255,
        R2: 826591197,
        g: 304701980,
        ig: 207126964,
        s: 842573420,
    },
    SmallPrime {
        p: 2147309569,
        p0i: 1908234239,
        R2: 964657100,
        g: 1953449942,
        ig: 309167499,
        s: 75092579,
    },
    SmallPrime {
        p: 2147297281,
        p0i: 1774004223,
        R2: 1503608772,
        g: 353848817,
        ig: 1726802198,
        s: 2084007226,
    },
    SmallPrime {
        p: 2147295233,
        p0i: 1006444543,
        R2: 279363522,
        g: 632955619,
        ig: 419515149,
        s: 38880066,
    },
    SmallPrime {
        p: 2147239937,
        p0i: 2881243135,
        R2: 1383813014,
        g: 710717957,
        ig: 756383674,
        s: 706593520,
    },
    SmallPrime {
        p: 2147235841,
        p0i: 867973119,
        R2: 848351122,
        g: 1627458017,
        ig: 1867341538,
        s: 1260600213,
    },
    SmallPrime {
        p: 2147217409,
        p0i: 4277923839,
        R2: 100122496,
        g: 1700895952,
        ig: 1076153660,
        s: 370621817,
    },
    SmallPrime {
        p: 2147205121,
        p0i: 1878769663,
        R2: 1111621492,
        g: 44667394,
        ig: 1556218865,
        s: 32248737,
    },
    SmallPrime {
        p: 2147196929,
        p0i: 1543217151,
        R2: 310009707,
        g: 1302747296,
        ig: 1775932980,
        s: 1745280407,
    },
    SmallPrime {
        p: 2147178497,
        p0i: 3518715903,
        R2: 1006651223,
        g: 995615578,
        ig: 1904695444,
        s: 546877831,
    },
    SmallPrime {
        p: 2147100673,
        p0i: 1505372159,
        R2: 520918771,
        g: 32821017,
        ig: 801131396,
        s: 1402329446,
    },
    SmallPrime {
        p: 2147082241,
        p0i: 4227457023,
        R2: 385646296,
        g: 671813454,
        ig: 349022278,
        s: 1235641740,
    },
    SmallPrime {
        p: 2147074049,
        p0i: 1878638591,
        R2: 1198259916,
        g: 22548867,
        ig: 381743482,
        s: 316764378,
    },
    SmallPrime {
        p: 2147051521,
        p0i: 96036863,
        R2: 1908098729,
        g: 1744576193,
        ig: 129309952,
        s: 1045517086,
    },
    SmallPrime {
        p: 2147043329,
        p0i: 1538869247,
        R2: 440645275,
        g: 848789527,
        ig: 259769898,
        s: 74455690,
    },
    SmallPrime {
        p: 2147039233,
        p0i: 2209953791,
        R2: 2055370389,
        g: 1117428534,
        ig: 1471147502,
        s: 119673623,
    },
    SmallPrime {
        p: 2146988033,
        p0i: 1324904447,
        R2: 1363381819,
        g: 2041738204,
        ig: 478044407,
        s: 147722658,
    },
    SmallPrime {
        p: 2146963457,
        p0i: 2130186239,
        R2: 325123596,
        g: 2068278376,
        ig: 875801492,
        s: 1306038870,
    },
    SmallPrime {
        p: 2146959361,
        p0i: 2146959359,
        R2: 264240644,
        g: 872271011,
        ig: 507971579,
        s: 1990286186,
    },
    SmallPrime {
        p: 2146938881,
        p0i: 1727508479,
        R2: 1974074844,
        g: 198886428,
        ig: 561977686,
        s: 1269843026,
    },
    SmallPrime {
        p: 2146908161,
        p0i: 1672951807,
        R2: 98813339,
        g: 1770745661,
        ig: 1393783074,
        s: 1823212183,
    },
    SmallPrime {
        p: 2146885633,
        p0i: 1006034943,
        R2: 661929322,
        g: 1068953529,
        ig: 641063610,
        s: 596476372,
    },
    SmallPrime {
        p: 2146871297,
        p0i: 834054143,
        R2: 1378823498,
        g: 1788896577,
        ig: 959521530,
        s: 583621658,
    },
    SmallPrime {
        p: 2146846721,
        p0i: 196495359,
        R2: 1834738961,
        g: 827307343,
        ig: 2002269931,
        s: 1831804644,
    },
    SmallPrime {
        p: 2146834433,
        p0i: 1572214783,
        R2: 655434995,
        g: 1825957452,
        ig: 2005158872,
        s: 95719048,
    },
    SmallPrime {
        p: 2146818049,
        p0i: 1505089535,
        R2: 963224779,
        g: 1698458806,
        ig: 1152339536,
        s: 1292562110,
    },
    SmallPrime {
        p: 2146775041,
        p0i: 2532651007,
        R2: 1260858461,
        g: 1897922218,
        ig: 1980311657,
        s: 1048890741,
    },
    SmallPrime {
        p: 2146756609,
        p0i: 1840572415,
        R2: 1934326828,
        g: 1319016594,
        ig: 303348307,
        s: 309425167,
    },
    SmallPrime {
        p: 2146744321,
        p0i: 1001699327,
        R2: 1031932938,
        g: 166920536,
        ig: 125412453,
        s: 206010953,
    },
    SmallPrime {
        p: 2146738177,
        p0i: 469016575,
        R2: 1034034169,
        g: 2049530115,
        ig: 240883589,
        s: 2109942428,
    },
    SmallPrime {
        p: 2146736129,
        p0i: 1706334207,
        R2: 386311155,
        g: 1983901927,
        ig: 399193796,
        s: 1866844306,
    },
    SmallPrime {
        p: 2146713601,
        p0i: 1878278143,
        R2: 1917713332,
        g: 795783646,
        ig: 2145730902,
        s: 666529419,
    },
    SmallPrime {
        p: 2146695169,
        p0i: 3216242687,
        R2: 923528062,
        g: 410549424,
        ig: 826761640,
        s: 881662233,
    },
    SmallPrime {
        p: 2146656257,
        p0i: 468934655,
        R2: 1316739849,
        g: 819155176,
        ig: 1775281069,
        s: 769010182,
    },
    SmallPrime {
        p: 2146650113,
        p0i: 3149088767,
        R2: 1357138678,
        g: 1776223808,
        ig: 1272363648,
        s: 1075150578,
    },
    SmallPrime {
        p: 2146646017,
        p0i: 598947839,
        R2: 836424425,
        g: 861255062,
        ig: 862632924,
        s: 1452282057,
    },
    SmallPrime {
        p: 2146643969,
        p0i: 1458778111,
        R2: 1699760867,
        g: 1128852454,
        ig: 1250440960,
        s: 551264863,
    },
    SmallPrime {
        p: 2146603009,
        p0i: 4008873983,
        R2: 258845279,
        g: 1693343820,
        ig: 1370713748,
        s: 896492399,
    },
    SmallPrime {
        p: 2146572289,
        p0i: 498210815,
        R2: 1553576441,
        g: 1357574155,
        ig: 2042997788,
        s: 475091953,
    },
    SmallPrime {
        p: 2146547713,
        p0i: 2343679999,
        R2: 731429284,
        g: 874518801,
        ig: 933977652,
        s: 2038082698,
    },
    SmallPrime {
        p: 2146508801,
        p0i: 1005658111,
        R2: 1986115866,
        g: 994764483,
        ig: 1486111048,
        s: 77164992,
    },
    SmallPrime {
        p: 2146492417,
        p0i: 3153125375,
        R2: 2074458334,
        g: 1607832505,
        ig: 1814950582,
        s: 1064849124,
    },
    SmallPrime {
        p: 2146490369,
        p0i: 3383810047,
        R2: 1163389142,
        g: 1860189331,
        ig: 766301042,
        s: 1792895956,
    },
    SmallPrime {
        p: 2146459649,
        p0i: 1542479871,
        R2: 113653858,
        g: 1774578485,
        ig: 436467466,
        s: 509354151,
    },
    SmallPrime {
        p: 2146447361,
        p0i: 1995452415,
        R2: 521816115,
        g: 984131366,
        ig: 920695297,
        s: 1917290506,
    },
    SmallPrime {
        p: 2146441217,
        p0i: 2108692479,
        R2: 106094619,
        g: 1700403904,
        ig: 55841604,
        s: 574542256,
    },
    SmallPrime {
        p: 2146437121,
        p0i: 2142242815,
        R2: 2143320076,
        g: 1575554072,
        ig: 1350403963,
        s: 1873207947,
    },
    SmallPrime {
        p: 2146430977,
        p0i: 2129653759,
        R2: 84969459,
        g: 244551713,
        ig: 118889817,
        s: 571880191,
    },
    SmallPrime {
        p: 2146418689,
        p0i: 1877983231,
        R2: 1167996867,
        g: 1775456464,
        ig: 1211626453,
        s: 1434078655,
    },
    SmallPrime {
        p: 2146406401,
        p0i: 1324322815,
        R2: 1313757074,
        g: 1622299552,
        ig: 60879896,
        s: 1023260741,
    },
    SmallPrime {
        p: 2146404353,
        p0i: 1202685951,
        R2: 1813342090,
        g: 1162222118,
        ig: 193969494,
        s: 1214240996,
    },
    SmallPrime {
        p: 2146379777,
        p0i: 3383699455,
        R2: 1842644774,
        g: 237716594,
        ig: 1996303667,
        s: 1647718365,
    },
    SmallPrime {
        p: 2146363393,
        p0i: 1303308287,
        R2: 1687447266,
        g: 1850889128,
        ig: 545315431,
        s: 1827479741,
    },
    SmallPrime {
        p: 2146355201,
        p0i: 61786111,
        R2: 269635263,
        g: 691559024,
        ig: 756508884,
        s: 1699936240,
    },
    SmallPrime {
        p: 2146336769,
        p0i: 1072594943,
        R2: 654341745,
        g: 1871443110,
        ig: 107703592,
        s: 1164751303,
    },
    SmallPrime {
        p: 2146312193,
        p0i: 4226686975,
        R2: 1106990599,
        g: 230828908,
        ig: 2118815775,
        s: 547343662,
    },
    SmallPrime {
        p: 2146293761,
        p0i: 3652048895,
        R2: 1401349558,
        g: 1527866384,
        ig: 1939695340,
        s: 934813966,
    },
    SmallPrime {
        p: 2146283521,
        p0i: 653111295,
        R2: 594294152,
        g: 1585987504,
        ig: 113384110,
        s: 901617467,
    },
    SmallPrime {
        p: 2146203649,
        p0i: 128743423,
        R2: 1230019607,
        g: 2070978911,
        ig: 1602264262,
        s: 195465499,
    },
    SmallPrime {
        p: 2146154497,
        p0i: 732674047,
        R2: 1428919080,
        g: 29335864,
        ig: 1593288655,
        s: 2129713526,
    },
    SmallPrime {
        p: 2146142209,
        p0i: 2276165631,
        R2: 1819536107,
        g: 649122195,
        ig: 996268341,
        s: 667538093,
    },
    SmallPrime {
        p: 2146127873,
        p0i: 2263568383,
        R2: 2015437475,
        g: 207440004,
        ig: 1904659130,
        s: 2030659201,
    },
    SmallPrime {
        p: 2146099201,
        p0i: 1005248511,
        R2: 907637264,
        g: 559331750,
        ig: 152292400,
        s: 1381346740,
    },
    SmallPrime {
        p: 2146093057,
        p0i: 1135265791,
        R2: 453939696,
        g: 1717051717,
        ig: 781899671,
        s: 630273220,
    },
    SmallPrime {
        p: 2146091009,
        p0i: 4025139199,
        R2: 1800630758,
        g: 1086157903,
        ig: 1771609892,
        s: 1947078850,
    },
    SmallPrime {
        p: 2146078721,
        p0i: 4008349695,
        R2: 2001965478,
        g: 1399918158,
        ig: 329087331,
        s: 2118472151,
    },
    SmallPrime {
        p: 2146060289,
        p0i: 3416934399,
        R2: 279720260,
        g: 1683079797,
        ig: 1885781100,
        s: 720846962,
    },
    SmallPrime {
        p: 2146048001,
        p0i: 2645170175,
        R2: 1358862595,
        g: 455982466,
        ig: 1271329796,
        s: 1757914587,
    },
    SmallPrime {
        p: 2146041857,
        p0i: 2146041855,
        R2: 1278996706,
        g: 70834413,
        ig: 1910051359,
        s: 2005325121,
    },
    SmallPrime {
        p: 2146019329,
        p0i: 1101637631,
        R2: 1427296360,
        g: 223814614,
        ig: 804128830,
        s: 1360420507,
    },
    SmallPrime {
        p: 2145986561,
        p0i: 2846435327,
        R2: 1292076979,
        g: 1571468773,
        ig: 1576376806,
        s: 1922069675,
    },
    SmallPrime {
        p: 2145976321,
        p0i: 2145976319,
        R2: 2074996602,
        g: 755073721,
        ig: 414238476,
        s: 200778967,
    },
    SmallPrime {
        p: 2145964033,
        p0i: 3605581823,
        R2: 689794868,
        g: 1452485437,
        ig: 856502235,
        s: 416725139,
    },
    SmallPrime {
        p: 2145906689,
        p0i: 2129129471,
        R2: 921247209,
        g: 676947204,
        ig: 654865993,
        s: 1812356432,
    },
    SmallPrime {
        p: 2145875969,
        p0i: 3081205759,
        R2: 1842525491,
        g: 1326145670,
        ig: 309498173,
        s: 2087042424,
    },
    SmallPrime {
        p: 2145871873,
        p0i: 2779211775,
        R2: 962993434,
        g: 1019421319,
        ig: 1501089909,
        s: 653721111,
    },
    SmallPrime {
        p: 2145841153,
        p0i: 1592193023,
        R2: 1869982816,
        g: 214096862,
        ig: 1556972726,
        s: 503214451,
    },
    SmallPrime {
        p: 2145832961,
        p0i: 384225279,
        R2: 384678957,
        g: 669316727,
        ig: 783241415,
        s: 1108169518,
    },
    SmallPrime {
        p: 2145816577,
        p0i: 1860603903,
        R2: 1173007304,
        g: 1845637035,
        ig: 826920248,
        s: 854681726,
    },
    SmallPrime {
        p: 2145785857,
        p0i: 1571166207,
        R2: 669709063,
        g: 1939498551,
        ig: 1558887263,
        s: 633181476,
    },
    SmallPrime {
        p: 2145755137,
        p0i: 3689259007,
        R2: 1290750531,
        g: 954377268,
        ig: 91681545,
        s: 1222833471,
    },
    SmallPrime {
        p: 2145742849,
        p0i: 4008013823,
        R2: 223279603,
        g: 943919281,
        ig: 916877791,
        s: 1449746232,
    },
    SmallPrime {
        p: 2145728513,
        p0i: 1134901247,
        R2: 1222351254,
        g: 2118240515,
        ig: 1429489422,
        s: 863342952,
    },
    SmallPrime {
        p: 2145699841,
        p0i: 2745485311,
        R2: 1723896025,
        g: 1632678465,
        ig: 1030096814,
        s: 1093745233,
    },
    SmallPrime {
        p: 2145691649,
        p0i: 3517229055,
        R2: 931453090,
        g: 54415538,
        ig: 530452177,
        s: 1965948870,
    },
    SmallPrime {
        p: 2145687553,
        p0i: 1705285631,
        R2: 1809739911,
        g: 1581677400,
        ig: 1990115608,
        s: 440621047,
    },
    SmallPrime {
        p: 2145673217,
        p0i: 1541693439,
        R2: 578267174,
        g: 1396659387,
        ig: 1723941977,
        s: 1763556058,
    },
    SmallPrime {
        p: 2145630209,
        p0i: 2879633407,
        R2: 328648448,
        g: 40361658,
        ig: 1539467270,
        s: 1674729976,
    },
    SmallPrime {
        p: 2145595393,
        p0i: 1457729535,
        R2: 255202829,
        g: 1400378563,
        ig: 1431207189,
        s: 1703296854,
    },
    SmallPrime {
        p: 2145587201,
        p0i: 518197247,
        R2: 2028299732,
        g: 1486218552,
        ig: 644522534,
        s: 1270684848,
    },
    SmallPrime {
        p: 2145525761,
        p0i: 4225900543,
        R2: 1358930970,
        g: 1145038363,
        ig: 878769963,
        s: 1208930401,
    },
    SmallPrime {
        p: 2145495041,
        p0i: 3248596991,
        R2: 1641759544,
        g: 431141042,
        ig: 1250759371,
        s: 401371792,
    },
    SmallPrime {
        p: 2145466369,
        p0i: 60897279,
        R2: 4913761,
        g: 1346487656,
        ig: 1003126503,
        s: 1472826275,
    },
    SmallPrime {
        p: 2145445889,
        p0i: 2913003519,
        R2: 1950341575,
        g: 209604178,
        ig: 2010474299,
        s: 190633762,
    },
    SmallPrime {
        p: 2145390593,
        p0i: 2128613375,
        R2: 2111959069,
        g: 1977319511,
        ig: 253671817,
        s: 711951677,
    },
    SmallPrime {
        p: 2145372161,
        p0i: 1939851263,
        R2: 1176002444,
        g: 230466302,
        ig: 1564380182,
        s: 318701388,
    },
    SmallPrime {
        p: 2145361921,
        p0i: 1541382143,
        R2: 879247163,
        g: 1458754908,
        ig: 789794840,
        s: 1032907577,
    },
    SmallPrime {
        p: 2145359873,
        p0i: 1436522495,
        R2: 1349830443,
        g: 160850239,
        ig: 842688712,
        s: 977726147,
    },
    SmallPrime {
        p: 2145355777,
        p0i: 1201637375,
        R2: 246501130,
        g: 1714048525,
        ig: 1460503641,
        s: 167731422,
    },
    SmallPrime {
        p: 2145343489,
        p0i: 295655423,
        R2: 2034128553,
        g: 85533909,
        ig: 89392725,
        s: 1282860004,
    },
    SmallPrime {
        p: 2145325057,
        p0i: 2665418751,
        R2: 1621650965,
        g: 1422485923,
        ig: 288923379,
        s: 911614733,
    },
    SmallPrime {
        p: 2145318913,
        p0i: 1872689151,
        R2: 659138019,
        g: 507124624,
        ig: 1410089651,
        s: 131619480,
    },
    SmallPrime {
        p: 2145312769,
        p0i: 1004462079,
        R2: 2144542130,
        g: 601028071,
        ig: 309708965,
        s: 1694238751,
    },
    SmallPrime {
        p: 2145300481,
        p0i: 3336482815,
        R2: 1732525390,
        g: 1940872306,
        ig: 2008521418,
        s: 313780675,
    },
    SmallPrime {
        p: 2145282049,
        p0i: 4120799231,
        R2: 1238750391,
        g: 1797682851,
        ig: 557030104,
        s: 1782843353,
    },
    SmallPrime {
        p: 2145232897,
        p0i: 27109375,
        R2: 1795543839,
        g: 1037744642,
        ig: 1557646622,
        s: 900304126,
    },
    SmallPrime {
        p: 2145218561,
        p0i: 4007489535,
        R2: 1315715750,
        g: 1070968735,
        ig: 736559602,
        s: 1443800839,
    },
    SmallPrime {
        p: 2145187841,
        p0i: 1335687167,
        R2: 13023648,
        g: 1309044639,
        ig: 1866831222,
        s: 399747323,
    },
    SmallPrime {
        p: 2145181697,
        p0i: 3151814655,
        R2: 1518459244,
        g: 1993483355,
        ig: 691838010,
        s: 615546001,
    },
    SmallPrime {
        p: 2145175553,
        p0i: 597477375,
        R2: 1181348151,
        g: 703506449,
        ig: 1514472518,
        s: 488565539,
    },
    SmallPrime {
        p: 2145079297,
        p0i: 2262519807,
        R2: 1805182441,
        g: 1948507193,
        ig: 198785189,
        s: 638515383,
    },
    SmallPrime {
        p: 2145021953,
        p0i: 2396680191,
        R2: 1021023200,
        g: 896525833,
        ig: 286005075,
        s: 1441021596,
    },
    SmallPrime {
        p: 2145015809,
        p0i: 2174375935,
        R2: 2117792680,
        g: 1601002661,
        ig: 347118679,
        s: 1157904101,
    },
    SmallPrime {
        p: 2145003521,
        p0i: 1503275007,
        R2: 929358646,
        g: 1668692954,
        ig: 37145528,
        s: 641759047,
    },
    SmallPrime {
        p: 2144960513,
        p0i: 1071218687,
        R2: 2014663077,
        g: 813829821,
        ig: 819596313,
        s: 63874550,
    },
    SmallPrime {
        p: 2144944129,
        p0i: 4023992319,
        R2: 1528910090,
        g: 1405891381,
        ig: 2038603849,
        s: 1893894911,
    },
    SmallPrime {
        p: 2144935937,
        p0i: 1004085247,
        R2: 1020776636,
        g: 1264145057,
        ig: 131908564,
        s: 1538042171,
    },
    SmallPrime {
        p: 2144894977,
        p0i: 1071153151,
        R2: 117657395,
        g: 1658068046,
        ig: 1863791040,
        s: 315971662,
    },
    SmallPrime {
        p: 2144888833,
        p0i: 3583535103,
        R2: 1035349752,
        g: 631245709,
        ig: 221833619,
        s: 2112295623,
    },
    SmallPrime {
        p: 2144880641,
        p0i: 3952625663,
        R2: 2014869161,
        g: 1728523150,
        ig: 1503761981,
        s: 2007376047,
    },
    SmallPrime {
        p: 2144864257,
        p0i: 4288153599,
        R2: 1298675209,
        g: 544582669,
        ig: 1272986021,
        s: 1915075671,
    },
    SmallPrime {
        p: 2144827393,
        p0i: 3080157183,
        R2: 1123663006,
        g: 160045786,
        ig: 473495242,
        s: 813254440,
    },
    SmallPrime {
        p: 2144806913,
        p0i: 1234642943,
        R2: 731069394,
        g: 2014053847,
        ig: 1766552348,
        s: 857353667,
    },
    SmallPrime {
        p: 2144796673,
        p0i: 2144796671,
        R2: 1796197228,
        g: 54648661,
        ig: 347997993,
        s: 2024676365,
    },
    SmallPrime {
        p: 2144778241,
        p0i: 1536604159,
        R2: 685152946,
        g: 1271425633,
        ig: 321887990,
        s: 1348054165,
    },
    SmallPrime {
        p: 2144759809,
        p0i: 248934399,
        R2: 154114551,
        g: 1526637592,
        ig: 1903326258,
        s: 1432928978,
    },
    SmallPrime {
        p: 2144757761,
        p0i: 1972791295,
        R2: 1931452899,
        g: 132970580,
        ig: 1653105390,
        s: 1502698593,
    },
    SmallPrime {
        p: 2144729089,
        p0i: 3751147519,
        R2: 319799485,
        g: 856415206,
        ig: 2139235838,
        s: 1528560673,
    },
    SmallPrime {
        p: 2144727041,
        p0i: 1054207999,
        R2: 456984744,
        g: 648538322,
        ig: 1211291222,
        s: 1040592824,
    },
    SmallPrime {
        p: 2144696321,
        p0i: 2543155199,
        R2: 117528426,
        g: 396088388,
        ig: 1351318511,
        s: 1705928562,
    },
    SmallPrime {
        p: 2144667649,
        p0i: 798296063,
        R2: 1911610943,
        g: 338234827,
        ig: 1761076141,
        s: 1009985854,
    },
    SmallPrime {
        p: 2144573441,
        p0i: 2509477887,
        R2: 1537057360,
        g: 570563298,
        ig: 647497611,
        s: 1089716523,
    },
    SmallPrime {
        p: 2144555009,
        p0i: 2261995519,
        R2: 1259090311,
        g: 1645617705,
        ig: 28737134,
        s: 311642518,
    },
    SmallPrime {
        p: 2144550913,
        p0i: 4023599103,
        R2: 852574554,
        g: 787018986,
        ig: 2112202798,
        s: 1495324375,
    },
    SmallPrime {
        p: 2144536577,
        p0i: 1335035903,
        R2: 1561905341,
        g: 2144070617,
        ig: 1829236274,
        s: 1925884510,
    },
    SmallPrime {
        p: 2144524289,
        p0i: 1771231231,
        R2: 418502709,
        g: 1096979205,
        ig: 1715236225,
        s: 4942642,
    },
    SmallPrime {
        p: 2144512001,
        p0i: 1905436671,
        R2: 486401965,
        g: 371227774,
        ig: 621999585,
        s: 248381878,
    },
    SmallPrime {
        p: 2144468993,
        p0i: 2144468991,
        R2: 1685175757,
        g: 1750820831,
        ig: 1117048683,
        s: 375676619,
    },
    SmallPrime {
        p: 2144458753,
        p0i: 428988415,
        R2: 481506649,
        g: 208627545,
        ig: 1669824636,
        s: 994022373,
    },
    SmallPrime {
        p: 2144421889,
        p0i: 3683731455,
        R2: 111545270,
        g: 490157982,
        ig: 598291463,
        s: 1506819637,
    },
    SmallPrime {
        p: 2144409601,
        p0i: 1301354495,
        R2: 1696205610,
        g: 1773221211,
        ig: 1190821653,
        s: 703296234,
    },
    SmallPrime {
        p: 2144370689,
        p0i: 1070628863,
        R2: 410368360,
        g: 1852155417,
        ig: 1241424587,
        s: 1916372058,
    },
    SmallPrime {
        p: 2144348161,
        p0i: 2039490559,
        R2: 2058332258,
        g: 380925864,
        ig: 1763931741,
        s: 1080707148,
    },
    SmallPrime {
        p: 2144335873,
        p0i: 2140141567,
        R2: 189861841,
        g: 1779816687,
        ig: 1155526432,
        s: 1839197694,
    },
    SmallPrime {
        p: 2144329729,
        p0i: 2077220863,
        R2: 782112649,
        g: 526684710,
        ig: 1471877186,
        s: 752775607,
    },
    SmallPrime {
        p: 2144327681,
        p0i: 2039470079,
        R2: 1046835057,
        g: 1247119374,
        ig: 1480573420,
        s: 1180445680,
    },
    SmallPrime {
        p: 2144309249,
        p0i: 1322225663,
        R2: 655091351,
        g: 1601388861,
        ig: 546007835,
        s: 774279999,
    },
    SmallPrime {
        p: 2144296961,
        p0i: 466575359,
        R2: 478811653,
        g: 1358954307,
        ig: 277575578,
        s: 1153736907,
    },
    SmallPrime {
        p: 2144290817,
        p0i: 4220471295,
        R2: 845002172,
        g: 1883197481,
        ig: 20750133,
        s: 894854412,
    },
    SmallPrime {
        p: 2144243713,
        p0i: 1859031039,
        R2: 134828934,
        g: 37546773,
        ig: 2020974628,
        s: 1786100430,
    },
    SmallPrime {
        p: 2144237569,
        p0i: 663648255,
        R2: 981840700,
        g: 819447626,
        ig: 828884995,
        s: 1801721724,
    },
    SmallPrime {
        p: 2144161793,
        p0i: 1187860479,
        R2: 1312055195,
        g: 492584100,
        ig: 284208050,
        s: 991575551,
    },
    SmallPrime {
        p: 2144155649,
        p0i: 3280812031,
        R2: 1909512015,
        g: 1038118142,
        ig: 557855457,
        s: 351830619,
    },
    SmallPrime {
        p: 2144137217,
        p0i: 516747263,
        R2: 1231150697,
        g: 1145329724,
        ig: 1222551687,
        s: 1031682140,
    },
    SmallPrime {
        p: 2144120833,
        p0i: 2261561343,
        R2: 1725803932,
        g: 85962159,
        ig: 1987475484,
        s: 1541754604,
    },
    SmallPrime {
        p: 2144071681,
        p0i: 4274778111,
        R2: 1126468398,
        g: 956241311,
        ig: 2057260329,
        s: 1928592240,
    },
    SmallPrime {
        p: 2144065537,
        p0i: 965466111,
        R2: 1878788832,
        g: 1053853819,
        ig: 587985232,
        s: 409128944,
    },
    SmallPrime {
        p: 2144028673,
        p0i: 998983679,
        R2: 2034483463,
        g: 85221004,
        ig: 692082439,
        s: 2038010847,
    },
    SmallPrime {
        p: 2144010241,
        p0i: 2144010239,
        R2: 842246168,
        g: 579253174,
        ig: 1365083779,
        s: 893394979,
    },
    SmallPrime {
        p: 2143952897,
        p0i: 4224327679,
        R2: 754017578,
        g: 344456872,
        ig: 574149142,
        s: 951344542,
    },
    SmallPrime {
        p: 2143940609,
        p0i: 3200905215,
        R2: 1412359304,
        g: 691093159,
        ig: 1240091757,
        s: 209561083,
    },
    SmallPrime {
        p: 2143918081,
        p0i: 1971951615,
        R2: 1479162717,
        g: 1879554798,
        ig: 1607927459,
        s: 1573571606,
    },
    SmallPrime {
        p: 2143899649,
        p0i: 3335081983,
        R2: 1640239719,
        g: 1873544500,
        ig: 512920036,
        s: 980684517,
    },
    SmallPrime {
        p: 2143891457,
        p0i: 382283775,
        R2: 1157894649,
        g: 1152913815,
        ig: 2082762113,
        s: 174332902,
    },
    SmallPrime {
        p: 2143885313,
        p0i: 3448313855,
        R2: 77697446,
        g: 1272010615,
        ig: 639087423,
        s: 788921708,
    },
    SmallPrime {
        p: 2143854593,
        p0i: 466132991,
        R2: 1365712904,
        g: 234096830,
        ig: 1624926716,
        s: 267754392,
    },
    SmallPrime {
        p: 2143836161,
        p0i: 3783809023,
        R2: 200636173,
        g: 802456521,
        ig: 972626486,
        s: 1579347589,
    },
    SmallPrime {
        p: 2143762433,
        p0i: 1669806079,
        R2: 1374323479,
        g: 122119316,
        ig: 523389252,
        s: 528105857,
    },
    SmallPrime {
        p: 2143756289,
        p0i: 3150389247,
        R2: 226179777,
        g: 2014672070,
        ig: 977903451,
        s: 205998472,
    },
    SmallPrime {
        p: 2143713281,
        p0i: 2810607615,
        R2: 674480231,
        g: 499335673,
        ig: 1923111979,
        s: 170087335,
    },
    SmallPrime {
        p: 2143690753,
        p0i: 4224065535,
        R2: 1119041321,
        g: 293184621,
        ig: 548955895,
        s: 1709245285,
    },
    SmallPrime {
        p: 2143670273,
        p0i: 3066417151,
        R2: 966374918,
        g: 1855603277,
        ig: 1939385627,
        s: 1369708529,
    },
    SmallPrime {
        p: 2143666177,
        p0i: 1875230719,
        R2: 1768658380,
        g: 1592043954,
        ig: 626312185,
        s: 1973259130,
    },
    SmallPrime {
        p: 2143645697,
        p0i: 4005916671,
        R2: 1369531559,
        g: 1496045094,
        ig: 868812782,
        s: 743685730,
    },
    SmallPrime {
        p: 2143641601,
        p0i: 2613403647,
        R2: 836342892,
        g: 137205166,
        ig: 1106494107,
        s: 1904307099,
    },
    SmallPrime {
        p: 2143635457,
        p0i: 2609203199,
        R2: 1360942100,
        g: 611274460,
        ig: 1430230424,
        s: 634419595,
    },
    SmallPrime {
        p: 2143621121,
        p0i: 3737456639,
        R2: 190915397,
        g: 456284400,
        ig: 1315071924,
        s: 1321642891,
    },
    SmallPrime {
        p: 2143598593,
        p0i: 998553599,
        R2: 155040255,
        g: 1748188596,
        ig: 1338143543,
        s: 1507236419,
    },
    SmallPrime {
        p: 2143567873,
        p0i: 1875132415,
        R2: 1411420224,
        g: 961363405,
        ig: 100809682,
        s: 4006593,
    },
    SmallPrime {
        p: 2143561729,
        p0i: 964962303,
        R2: 1285824486,
        g: 1745824462,
        ig: 52145752,
        s: 1898334618,
    },
    SmallPrime {
        p: 2143553537,
        p0i: 1065617407,
        R2: 1589845870,
        g: 642609604,
        ig: 876094006,
        s: 1160521531,
    },
    SmallPrime {
        p: 2143541249,
        p0i: 3112425471,
        R2: 912656057,
        g: 832462820,
        ig: 1196335625,
        s: 50513987,
    },
    SmallPrime {
        p: 2143531009,
        p0i: 3871584255,
        R2: 917220898,
        g: 733999433,
        ig: 1060086084,
        s: 957280110,
    },
    SmallPrime {
        p: 2143522817,
        p0i: 3468922879,
        R2: 1098374569,
        g: 2134640637,
        ig: 1812047677,
        s: 957540519,
    },
    SmallPrime {
        p: 2143506433,
        p0i: 2260946943,
        R2: 933735606,
        g: 453429574,
        ig: 1461625836,
        s: 1505133897,
    },
    SmallPrime {
        p: 2143488001,
        p0i: 1333987327,
        R2: 1985268644,
        g: 2074073649,
        ig: 1479394204,
        s: 1064535019,
    },
    SmallPrime {
        p: 2143469569,
        p0i: 4022517759,
        R2: 1477872272,
        g: 1513292205,
        ig: 1862896587,
        s: 1004190392,
    },
    SmallPrime {
        p: 2143426561,
        p0i: 495065087,
        R2: 186028039,
        g: 1375811092,
        ig: 173677829,
        s: 2089274222,
    },
    SmallPrime {
        p: 2143383553,
        p0i: 1858170879,
        R2: 887211384,
        g: 2134877926,
        ig: 1608809321,
        s: 1661543915,
    },
    SmallPrime {
        p: 2143377409,
        p0i: 2978043903,
        R2: 1281348890,
        g: 1288031453,
        ig: 483115862,
        s: 1970346133,
    },
    SmallPrime {
        p: 2143363073,
        p0i: 1002512383,
        R2: 1950991422,
        g: 1122143235,
        ig: 1166724603,
        s: 1788468869,
    },
    SmallPrime {
        p: 2143260673,
        p0i: 1321177087,
        R2: 2069683714,
        g: 1805244102,
        ig: 1261092720,
        s: 903254409,
    },
    SmallPrime {
        p: 2143246337,
        p0i: 293558271,
        R2: 1176536351,
        g: 1950051640,
        ig: 309589975,
        s: 1529083832,
    },
    SmallPrime {
        p: 2143209473,
        p0i: 58640383,
        R2: 1560740565,
        g: 218139536,
        ig: 1255708568,
        s: 1698136215,
    },
    SmallPrime {
        p: 2143203329,
        p0i: 3334385663,
        R2: 1971538547,
        g: 1999593400,
        ig: 1859827267,
        s: 1956345089,
    },
    SmallPrime {
        p: 2143160321,
        p0i: 2675836927,
        R2: 477597631,
        g: 884313283,
        ig: 2113130436,
        s: 1457071330,
    },
    SmallPrime {
        p: 2143129601,
        p0i: 2394787839,
        R2: 546440653,
        g: 1295503643,
        ig: 2080414454,
        s: 1206105984,
    },
    SmallPrime {
        p: 2143123457,
        p0i: 394098687,
        R2: 612601193,
        g: 1693130333,
        ig: 43008062,
        s: 16697358,
    },
    SmallPrime {
        p: 2143100929,
        p0i: 1002250239,
        R2: 591926265,
        g: 1101885974,
        ig: 315537419,
        s: 1388418046,
    },
    SmallPrime {
        p: 2143092737,
        p0i: 2143092735,
        R2: 1205498739,
        g: 1071117401,
        ig: 276869279,
        s: 1816776329,
    },
    SmallPrime {
        p: 2143082497,
        p0i: 2306660351,
        R2: 1658985163,
        g: 2126748415,
        ig: 1783080325,
        s: 1909268843,
    },
    SmallPrime {
        p: 2143062017,
        p0i: 2004649983,
        R2: 806738297,
        g: 1026831688,
        ig: 2035800522,
        s: 754902198,
    },
    SmallPrime {
        p: 2143051777,
        p0i: 1539071999,
        R2: 1644097744,
        g: 1553535853,
        ig: 2052185358,
        s: 1958510946,
    },
    SmallPrime {
        p: 2143025153,
        p0i: 1065089023,
        R2: 48408341,
        g: 1525464941,
        ig: 1852830390,
        s: 755368639,
    },
    SmallPrime {
        p: 2143006721,
        p0i: 3871059967,
        R2: 1620020706,
        g: 2138083553,
        ig: 30951415,
        s: 1336294009,
    },
    SmallPrime {
        p: 2142996481,
        p0i: 2273019903,
        R2: 576994614,
        g: 1383533,
        ig: 1219848252,
        s: 1992320100,
    },
    SmallPrime {
        p: 2142976001,
        p0i: 2742761471,
        R2: 1018092510,
        g: 1458681506,
        ig: 608641646,
        s: 190719147,
    },
    SmallPrime {
        p: 2142965761,
        p0i: 515575807,
        R2: 359250737,
        g: 1354388786,
        ig: 2131235811,
        s: 1323949132,
    },
    SmallPrime {
        p: 2142916609,
        p0i: 649744383,
        R2: 1208571887,
        g: 1878268755,
        ig: 1560639011,
        s: 1431405645,
    },
    SmallPrime {
        p: 2142892033,
        p0i: 3199856639,
        R2: 340166218,
        g: 771047236,
        ig: 1294387139,
        s: 1350670764,
    },
    SmallPrime {
        p: 2142885889,
        p0i: 2574899199,
        R2: 1416994273,
        g: 869163275,
        ig: 1050539694,
        s: 503308105,
    },
    SmallPrime {
        p: 2142871553,
        p0i: 3686375423,
        R2: 823272682,
        g: 1330177723,
        ig: 1618603945,
        s: 680882765,
    },
    SmallPrime {
        p: 2142861313,
        p0i: 3615062015,
        R2: 185662521,
        g: 59302870,
        ig: 1086768468,
        s: 733960061,
    },
    SmallPrime {
        p: 2142830593,
        p0i: 2142830591,
        R2: 1184916005,
        g: 1079082138,
        ig: 801265712,
        s: 1392890675,
    },
    SmallPrime {
        p: 2142803969,
        p0i: 2776143871,
        R2: 1898723413,
        g: 612877597,
        ig: 748398044,
        s: 719565838,
    },
    SmallPrime {
        p: 2142785537,
        p0i: 1723355135,
        R2: 1938177810,
        g: 901717203,
        ig: 1921085502,
        s: 1027865724,
    },
    SmallPrime {
        p: 2142779393,
        p0i: 4084742143,
        R2: 1843695270,
        g: 956271994,
        ig: 1027905184,
        s: 437886242,
    },
    SmallPrime {
        p: 2142724097,
        p0i: 465002495,
        R2: 1786272468,
        g: 2057509300,
        ig: 596569659,
        s: 833374098,
    },
    SmallPrime {
        p: 2142707713,
        p0i: 3149340671,
        R2: 1726077360,
        g: 110521970,
        ig: 490838647,
        s: 570919333,
    },
    SmallPrime {
        p: 2142658561,
        p0i: 3686162431,
        R2: 1631852094,
        g: 261726828,
        ig: 931917077,
        s: 2005364883,
    },
    SmallPrime {
        p: 2142638081,
        p0i: 3199602687,
        R2: 1965839564,
        g: 408833423,
        ig: 1753224304,
        s: 1152041797,
    },
    SmallPrime {
        p: 2142564353,
        p0i: 515174399,
        R2: 1080848266,
        g: 1517077457,
        ig: 1548531958,
        s: 823650319,
    },
    SmallPrime {
        p: 2142533633,
        p0i: 2272557055,
        R2: 392959315,
        g: 729816849,
        ig: 921579743,
        s: 129344001,
    },
    SmallPrime {
        p: 2142529537,
        p0i: 359950335,
        R2: 17286407,
        g: 1033141274,
        ig: 1935370361,
        s: 921394177,
    },
    SmallPrime {
        p: 2142527489,
        p0i: 1538547711,
        R2: 2022542562,
        g: 591503450,
        ig: 522147359,
        s: 1308604835,
    },
    SmallPrime {
        p: 2142502913,
        p0i: 2142502911,
        R2: 862145305,
        g: 1943481144,
        ig: 733213664,
        s: 364106514,
    },
    SmallPrime {
        p: 2142498817,
        p0i: 4273205247,
        R2: 1497774797,
        g: 362230737,
        ig: 2058280749,
        s: 1402886894,
    },
    SmallPrime {
        p: 2142416897,
        p0i: 1186115583,
        R2: 1820910794,
        g: 869347984,
        ig: 1125890573,
        s: 823863638,
    },
    SmallPrime {
        p: 2142363649,
        p0i: 4222738431,
        R2: 1712603348,
        g: 839133619,
        ig: 770847044,
        s: 892019817,
    },
    SmallPrime {
        p: 2142351361,
        p0i: 2796662783,
        R2: 639467496,
        g: 472998882,
        ig: 259948593,
        s: 1009074045,
    },
    SmallPrime {
        p: 2142330881,
        p0i: 2612092927,
        R2: 119930462,
        g: 898272391,
        ig: 1611927337,
        s: 1395844887,
    },
    SmallPrime {
        p: 2142314497,
        p0i: 1001463807,
        R2: 417987874,
        g: 952188691,
        ig: 1472816610,
        s: 1525176551,
    },
    SmallPrime {
        p: 2142289921,
        p0i: 4021338111,
        R2: 626441030,
        g: 1087932551,
        ig: 1833827076,
        s: 1287261065,
    },
    SmallPrime {
        p: 2142283777,
        p0i: 292595711,
        R2: 1437184719,
        g: 1990366532,
        ig: 718034518,
        s: 2141169066,
    },
    SmallPrime {
        p: 2142277633,
        p0i: 783323135,
        R2: 409102935,
        g: 1109091844,
        ig: 1748524698,
        s: 1404314290,
    },
    SmallPrime {
        p: 2142263297,
        p0i: 1634752511,
        R2: 1332648256,
        g: 1458675808,
        ig: 1235027887,
        s: 862728790,
    },
    SmallPrime {
        p: 2142208001,
        p0i: 1068466175,
        R2: 1397470467,
        g: 1098539573,
        ig: 1097351447,
        s: 1965727963,
    },
    SmallPrime {
        p: 2142164993,
        p0i: 695130111,
        R2: 1066940847,
        g: 3394841,
        ig: 337813155,
        s: 2063673696,
    },
    SmallPrime {
        p: 2142097409,
        p0i: 3064844287,
        R2: 297225318,
        g: 190118328,
        ig: 120193342,
        s: 1425544062,
    },
    SmallPrime {
        p: 2142087169,
        p0i: 23963647,
        R2: 1242139544,
        g: 508378060,
        ig: 2119898775,
        s: 1644552134,
    },
    SmallPrime {
        p: 2142078977,
        p0i: 1735231487,
        R2: 34593522,
        g: 662801663,
        ig: 1837465297,
        s: 1388457155,
    },
    SmallPrime {
        p: 2142074881,
        p0i: 393050111,
        R2: 1775241888,
        g: 546076620,
        ig: 753976398,
        s: 1286409850,
    },
    SmallPrime {
        p: 2142044161,
        p0i: 2142044159,
        R2: 1993353265,
        g: 20421055,
        ig: 1749390716,
        s: 453736187,
    },
    SmallPrime {
        p: 2142025729,
        p0i: 3144464383,
        R2: 1054015161,
        g: 216592874,
        ig: 174350842,
        s: 2000851460,
    },
    SmallPrime {
        p: 2142011393,
        p0i: 1068269567,
        R2: 1022043540,
        g: 154322400,
        ig: 1364900586,
        s: 1216790673,
    },
    SmallPrime {
        p: 2141974529,
        p0i: 4272680959,
        R2: 878244511,
        g: 450223676,
        ig: 840019780,
        s: 936239114,
    },
    SmallPrime {
        p: 2141943809,
        p0i: 4151015423,
        R2: 181002276,
        g: 1766661673,
        ig: 824377997,
        s: 898611110,
    },
    SmallPrime {
        p: 2141933569,
        p0i: 2259374079,
        R2: 921001808,
        g: 138101311,
        ig: 1597307312,
        s: 1683735850,
    },
    SmallPrime {
        p: 2141931521,
        p0i: 996886527,
        R2: 2026958630,
        g: 786548950,
        ig: 491009818,
        s: 1487647832,
    },
    SmallPrime {
        p: 2141902849,
        p0i: 3916093439,
        R2: 1774507217,
        g: 1503936548,
        ig: 2011562721,
        s: 803375820,
    },
    SmallPrime {
        p: 2141890561,
        p0i: 4050298879,
        R2: 1242184656,
        g: 1606622264,
        ig: 973689178,
        s: 1298783383,
    },
    SmallPrime {
        p: 2141857793,
        p0i: 1500129279,
        R2: 47495456,
        g: 1818547837,
        ig: 1933124842,
        s: 1327760978,
    },
    SmallPrime {
        p: 2141833217,
        p0i: 3546925055,
        R2: 534546202,
        g: 500926182,
        ig: 2118308644,
        s: 1496583315,
    },
    SmallPrime {
        p: 2141820929,
        p0i: 1969854463,
        R2: 457737750,
        g: 690473287,
        ig: 1631943651,
        s: 664359263,
    },
    SmallPrime {
        p: 2141786113,
        p0i: 1588137983,
        R2: 1837204275,
        g: 2031397019,
        ig: 1967667817,
        s: 905298889,
    },
    SmallPrime {
        p: 2141771777,
        p0i: 1231607807,
        R2: 1585138177,
        g: 54300848,
        ig: 314627109,
        s: 927112984,
    },
    SmallPrime {
        p: 2141759489,
        p0i: 2439555071,
        R2: 1154859258,
        g: 1383763879,
        ig: 1971680935,
        s: 2108097075,
    },
    SmallPrime {
        p: 2141749249,
        p0i: 1068007423,
        R2: 2080935967,
        g: 859296785,
        ig: 1197038946,
        s: 1880678306,
    },
    SmallPrime {
        p: 2141685761,
        p0i: 3345451007,
        R2: 517526213,
        g: 1550564945,
        ig: 1632439809,
        s: 954282998,
    },
    SmallPrime {
        p: 2141673473,
        p0i: 2439469055,
        R2: 21649850,
        g: 2046161117,
        ig: 552392242,
        s: 103443123,
    },
    SmallPrime {
        p: 2141669377,
        p0i: 2070366207,
        R2: 126251361,
        g: 1742664644,
        ig: 1482481206,
        s: 605966977,
    },
    SmallPrime {
        p: 2141655041,
        p0i: 2661748735,
        R2: 484235305,
        g: 1528710429,
        ig: 354771509,
        s: 593774164,
    },
    SmallPrime {
        p: 2141587457,
        p0i: 526780415,
        R2: 574888543,
        g: 955760611,
        ig: 687141330,
        s: 1030240293,
    },
    SmallPrime {
        p: 2141583361,
        p0i: 3748001791,
        R2: 1371847173,
        g: 1144908715,
        ig: 184363050,
        s: 1463331359,
    },
    SmallPrime {
        p: 2141575169,
        p0i: 1499846655,
        R2: 1229054288,
        g: 1538452901,
        ig: 324225902,
        s: 1425521960,
    },
    SmallPrime {
        p: 2141546497,
        p0i: 1164273663,
        R2: 1768171221,
        g: 430711736,
        ig: 1956344257,
        s: 358993721,
    },
    SmallPrime {
        p: 2141515777,
        p0i: 514125823,
        R2: 1883057193,
        g: 1188334395,
        ig: 254771003,
        s: 712002260,
    },
    SmallPrime {
        p: 2141495297,
        p0i: 463773695,
        R2: 1894308447,
        g: 2130610251,
        ig: 69814245,
        s: 2121489732,
    },
    SmallPrime {
        p: 2141483009,
        p0i: 3466883071,
        R2: 950896971,
        g: 1258381554,
        ig: 825951706,
        s: 195111043,
    },
    SmallPrime {
        p: 2141458433,
        p0i: 4272164863,
        R2: 566843170,
        g: 64378978,
        ig: 1469333580,
        s: 1466451638,
    },
    SmallPrime {
        p: 2141360129,
        p0i: 4003631103,
        R2: 510897768,
        g: 2054940459,
        ig: 1603364306,
        s: 1896684552,
    },
    SmallPrime {
        p: 2141325313,
        p0i: 1600260095,
        R2: 309414728,
        g: 783698702,
        ig: 845623609,
        s: 2118606683,
    },
    SmallPrime {
        p: 2141317121,
        p0i: 3714181119,
        R2: 41910923,
        g: 1219136678,
        ig: 1953984968,
        s: 1546372147,
    },
    SmallPrime {
        p: 2141286401,
        p0i: 1856073727,
        R2: 1171249093,
        g: 986447182,
        ig: 1530161498,
        s: 1359644991,
    },
    SmallPrime {
        p: 2141267969,
        p0i: 694233087,
        R2: 1211133465,
        g: 844862374,
        ig: 1144145329,
        s: 372321440,
    },
    SmallPrime {
        p: 2141255681,
        p0i: 2405496831,
        R2: 1328934139,
        g: 735916721,
        ig: 1296250995,
        s: 1612100237,
    },
    SmallPrime {
        p: 2141243393,
        p0i: 3814770687,
        R2: 520479708,
        g: 525351865,
        ig: 2026115355,
        s: 538775863,
    },
    SmallPrime {
        p: 2141214721,
        p0i: 1633703935,
        R2: 504183101,
        g: 663335303,
        ig: 715380266,
        s: 34424233,
    },
    SmallPrime {
        p: 2141212673,
        p0i: 1721782271,
        R2: 603205901,
        g: 1433302473,
        ig: 1227056696,
        s: 1431443425,
    },
    SmallPrime {
        p: 2141202433,
        p0i: 2036344831,
        R2: 1604585501,
        g: 1229299775,
        ig: 752118923,
        s: 1881364338,
    },
    SmallPrime {
        p: 2141175809,
        p0i: 1872740351,
        R2: 1733516714,
        g: 1807146636,
        ig: 363795364,
        s: 1986179172,
    },
    SmallPrime {
        p: 2141165569,
        p0i: 1432328191,
        R2: 1490189496,
        g: 1320489732,
        ig: 1641816108,
        s: 578038958,
    },
    SmallPrime {
        p: 2141073409,
        p0i: 916336639,
        R2: 873759781,
        g: 1556749288,
        ig: 651084845,
        s: 1015729028,
    },
    SmallPrime {
        p: 2141052929,
        p0i: 4221427711,
        R2: 979186233,
        g: 1762104735,
        ig: 715530680,
        s: 622504930,
    },
    SmallPrime {
        p: 2141040641,
        p0i: 647868415,
        R2: 949895441,
        g: 2025808022,
        ig: 160106133,
        s: 561883724,
    },
    SmallPrime {
        p: 2141028353,
        p0i: 1067286527,
        R2: 2135838697,
        g: 916257035,
        ig: 1402241650,
        s: 750070220,
    },
    SmallPrime {
        p: 2141011969,
        p0i: 4020060159,
        R2: 611765852,
        g: 1170281544,
        ig: 1552266705,
        s: 329393240,
    },
    SmallPrime {
        p: 2140999681,
        p0i: 3734835199,
        R2: 351284530,
        g: 998193986,
        ig: 2031434746,
        s: 1932350134,
    },
    SmallPrime {
        p: 2140997633,
        p0i: 2942109695,
        R2: 1853355265,
        g: 1185563841,
        ig: 237281087,
        s: 440781243,
    },
    SmallPrime {
        p: 2140993537,
        p0i: 1331492863,
        R2: 676775069,
        g: 495308340,
        ig: 1540448795,
        s: 750732506,
    },
    SmallPrime {
        p: 2140942337,
        p0i: 4137431039,
        R2: 1645148093,
        g: 2102068815,
        ig: 2126166725,
        s: 1570735656,
    },
    SmallPrime {
        p: 2140925953,
        p0i: 4271632383,
        R2: 759158315,
        g: 871789395,
        ig: 712612398,
        s: 1673104634,
    },
    SmallPrime {
        p: 2140917761,
        p0i: 4137406463,
        R2: 1126409570,
        g: 487401697,
        ig: 790501062,
        s: 2003679138,
    },
    SmallPrime {
        p: 2140887041,
        p0i: 3512424447,
        R2: 356555373,
        g: 692136311,
        ig: 1873117117,
        s: 2056578551,
    },
    SmallPrime {
        p: 2140837889,
        p0i: 1163565055,
        R2: 367306155,
        g: 549695576,
        ig: 1539499132,
        s: 1848189620,
    },
    SmallPrime {
        p: 2140788737,
        p0i: 2572802047,
        R2: 558045408,
        g: 1566269988,
        ig: 1578573646,
        s: 1949949243,
    },
    SmallPrime {
        p: 2140766209,
        p0i: 1067024383,
        R2: 1525495467,
        g: 488941581,
        ig: 1332090451,
        s: 1459824799,
    },
    SmallPrime {
        p: 2140764161,
        p0i: 3612964863,
        R2: 453729911,
        g: 1063914887,
        ig: 792300614,
        s: 2072819909,
    },
    SmallPrime {
        p: 2140696577,
        p0i: 1318612991,
        R2: 1154564043,
        g: 1249648119,
        ig: 1281812338,
        s: 1631278485,
    },
    SmallPrime {
        p: 2140684289,
        p0i: 1872248831,
        R2: 2118938259,
        g: 262551938,
        ig: 1786968202,
        s: 55549365,
    },
    SmallPrime {
        p: 2140653569,
        p0i: 4082616319,
        R2: 1285628803,
        g: 80889460,
        ig: 220865202,
        s: 1452802925,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[inline]
    fn mmul(a: u32, b: u32, p: u32) -> u32 {
        (((a as u64) * (b as u64)) % (p as u64)) as u32
    }

    #[test]
    fn check_small_primes() {
        let mut sh = Sha256::new();
        for i in 0..PRIMES.len() {
            let p = PRIMES[i].p;
            // 1438814045 = 1 + floor(1.34*2^30)
            assert!(1438814045 <= p && p <= 0x7FFFFFFF);

            // We hash all primes to verify against a reference value.
            sh.update(&p.to_le_bytes());

            // p0i = -1/p mod 2^32
            assert!(p.wrapping_mul(PRIMES[i].p0i) == 0xFFFFFFFF);

            // R2 = 2^64 mod p
            assert!((PRIMES[i].R2 as u128) == (1u128 << 64) % (p as u128));

            // Compute 1/2^32 mod p
            let mut iR = 1u32;
            for _ in 0..32 {
                iR += (iR & 1).wrapping_neg() & p;
                iR >>= 1;
            }
            assert!(((iR as u64) << 32) % (p as u64) == 1);

            // g^1024 = -1 mod p
            // ig = 1/g mod p
            // g and ig are in Montgomery representation
            let mut g = mmul(PRIMES[i].g, iR, p);
            let ig = mmul(PRIMES[i].ig, iR, p);
            assert!(mmul(g, ig, p) == 1);
            for _ in 0..10 {
                g = mmul(g, g, p);
            }
            assert!(g == p - 1);

            // s = 1 / prod_{j<i} p_j mod p
            let mut s = mmul(PRIMES[i].s, iR, p);
            if i == 0 {
                assert!(s == 1);
            } else {
                for j in 0..i {
                    s = mmul(s, PRIMES[j].p, p);
                }
                assert!(s == 1);
            }
        }
        let rh = hex::decode("383babc06a50dafbc446cecc9043ee30ac56d598e3ef057f4ab88e0ef0368f54")
            .unwrap();
        assert!(sh.finalize()[..] == rh);
    }
}
