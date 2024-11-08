#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use fn_dsa_comm::shake::SHAKE256x4;

// ========================================================================
// Gaussian sampling for (f,g)
// ========================================================================

// This code samples the secret polynomials f and g deterministically
// from a given seed. The polynomial coefficients follow a given
// Gaussian distribution centred on zero. SHAKE256x4 is used to produce
// random 16-bit samples which are then used in a CDT table.

const GTAB_8: [u16; 48] = [
        1,     3,     6,    11,    22,    40,    73,   129,
      222,   371,   602,   950,  1460,  2183,  3179,  4509,
     6231,  8395, 11032, 14150, 17726, 21703, 25995, 30487,
    35048, 39540, 43832, 47809, 51385, 54503, 57140, 59304,
    61026, 62356, 63352, 64075, 64585, 64933, 65164, 65313,
    65406, 65462, 65495, 65513, 65524, 65529, 65532, 65534,
];

const GTAB_9: [u16; 34] = [
        1,     4,    11,    28,    65,   146,   308,   615,
     1164,  2083,  3535,  5692,  8706, 12669, 17574, 23285,
    29542, 35993, 42250, 47961, 52866, 56829, 59843, 62000,
    63452, 64371, 64920, 65227, 65389, 65470, 65507, 65524,
    65531, 65534,
];

const GTAB_10: [u16; 24] = [
        2,     8,    28,    94,   280,   742,  1761,  3753,
     7197, 12472, 19623, 28206, 37329, 45912, 53063, 58338,
    61782, 63774, 64793, 65255, 65441, 65507, 65527, 65533
];

// Sample the f (or g) polynomial, using the provided SHAKE256x4 PRNG,
// for a given degree n = 2^logn (with 1 <= logn <= 10). This function
// ensures that the returned polynomial has odd parity.
pub(crate) fn sample_f(logn: u32, rng: &mut SHAKE256x4, f: &mut [i8]) {
    assert!(1 <= logn && logn <= 10);
    let n = 1 << logn;
    assert!(f.len() == n);
    let (tab, zz) = match logn {
        9 => (&GTAB_9[..], 1),
        10 => (&GTAB_10[..], 1),
        _ => (&GTAB_8[..], 1 << (8 - logn)),
    };
    let kmax = (tab.len() >> 1) as i32;

    loop {
        let mut parity = 0;
        let mut i = 0;
        while i < n {
            let mut v = 0;
            for _ in 0..zz {
                let y = rng.next_u16() as u32;
                v -= kmax;
                for k in 0..tab.len() {
                    v += (((tab[k] as u32).wrapping_sub(y)) >> 31) as i32;
                }
            }
            // For reduced/test degrees 2^6 or less, the value may be outside
            // of [-127, +127], which we do not want. This cannot happen for
            // degrees 2^7 and more, in particular for the "normal" degrees
            // 512 and 1024.
            if v < -127 || v > 127 {
                continue;
            }
            f[i] = v as i8;
            i += 1;
            parity ^= v as u32;
        }

        // We need an odd parity (so that the resultant of f with X^n+1 is
        // an odd integer).
        if (parity & 1) != 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn check_sample_f(logn: u32, expected: &str) {
        let n = 1 << logn;
        let mut rng = SHAKE256x4::new(&[logn as u8]);
        let mut f = [0i8; 1024];
        sample_f(logn, &mut rng, &mut f[..n]);
        let mut t = [0u8; 1024];
        for i in 0..n {
            t[i] = f[i] as u8;
        }
        assert!(t[..n] == hex::decode(expected).unwrap());
    }

    #[test]
    fn sample_tv() {
        check_sample_f(2,  "d916f113");
        check_sample_f(3,  "01032314a907ea3a");
        check_sample_f(4,  "1eecf605d71bfb010ae0d8fcf41ef9ef");
        check_sample_f(5,  "0dfb011602f1141c0cf0ec0af1f5f2e1f10202020f0213f301ecdc0cf9211811");
        check_sample_f(6,  "1300030510fe100406f2ee0a05fc000af909f80a030309110f080b09000800faf5fe03ff04f901050a130efd0a1b0112fa030cfafa000afbfcfa0703fc021f01");
        check_sample_f(7,  "02eff5f908ffffff0c0507f2faf20bf50a05ff09fafff4f6f0f7fb0dfef80509fd05fcf7fffbfe0509f8f9020a05fdfd0103f4fa11080404f900f400080a02fb0308f6010ffefc0a08f9fd09e9030bf8fdfcf2f9fd02fb01fe0304f5f3fa0c04fbf9070006f609050cf5fbf806f9fa09faf90008f9f3f20f030cef0e04faf80a");
        check_sample_f(8,  "01fff9fb05fd0d18f9010806fff50cfe050802fc070005fff9f402fbfc0204fcf9020100fd02f50004f50803fff50308030c01f902fd01f7fffcfefbfffa0903ff02010301f808fcf707fb0007fa080504f6070afefcf7fe02fc080afeff0406fc05fcfcfff60501ff09f3f800030303f40bfd04f3fe04fdf50400f6f9050202f901f80000fafdfa0b00fc040df90103f8fb0108f8fffb040206f50205fd020d09fff80807fb03020cf90606fbff02fcfbf405fff8fffb07fa0002f80af8ff05f801fcfe03060603000c08020105050502fc05f90afc05fa0106090cf8fffafc02fcff0103f4f90009030202fdff08fa09fffd07f80709fefc0602fa0509fdfd");
        check_sample_f(9,  "fbfffa0001f8030bfffe01f90503fdfcfffe01fd00feffff01050303fd01fdfe07000502fd030608fb010102000501fdfdfdf9f9fd04fe04060203fc03fafffb0704fb05ff04fc02fcf7070406f9f9fbfc020008fdfd040000fc070008fd010309f9ff0402fefd04f8fefd0000feff05fd04fa01ff00f8fd0301f800fffdff00020306f606fffdfffef901ff0afcfb020201fc0205ff08fdff000400fcfc03fe020502fdfe01fc0306fafe000000ff03fc01fe07fc09fd02fdff02fefcfefeff02ff030005fb00fc03fb04f7fd03fb030004fbfe08ff050805fefefafffa0000050606f50104f8fd01fe060404ff0002fefefdfe06fa0203fd01fcff04000cfdff0b03ff05fb0107000704000505fe01fdf602ff0200fffbfdf501030501fd0000ff01fef9fcfc0303feff0006fc02010101fef8060004030300fdfcfd08fb04020701fcfffb060608fd04fc0502fd0603fffff5fb00ff03fff9000500fffe0003ff01010100fc0302fb0406fb0506fef6000000fffbffffff050300fcfdfd02fafd06000301f8f8ff010602fc0304fefdfc06f9fe000508ff01f803fd0300fd03fdfbfd0308fc02effdfc00020403fe04fafe00fdff00040000fd06fb0803010601fef803fefffd00fefefa02060002fa000205fefdfffb01fb050303fefe03fe03f90501fb06fd0303fe0801f900fe01040603050102fa04fdfffdfffffe02");
        check_sample_f(10, "040101010101fdfc01fd01ff07fdfe0003fffd01fe03fefffe010203fe03fa0201fffffe01000305020005ff01fafe00fffeffff0202fb010101000402fffefffe05ff04fcff0300fdfcfefe03fffbfffc03fffb010601ff01fdfefefe00fefffdfcff00ffff00fe040100feff00fc0602fe00fcfff9fefe000003fdf70202fdfdfdff00fffc02fefe03000502fafe0502fffdff00ff0300000101fffcff030606fd00020204fdfafffe0201030301fdfe07ff000100fb0000fafefe000105fdfe02000300fffcfc0203010201fc0601030303ff00000102ff01fd01fefffdfcfe030201fc0102fb01000006fffa0000ff040002fd0303fe02ff03fffefcfefe0102ffff00fe0200ff04fb00000400fb0301010000fe000401fffefe0400fc04010402fdfcfe00fefffcff05fdfb0301050303fefeff02fbff00fcfefa040504fd0104fcfefffbfc01ff0204fa0001fd03fc010100000101fbffff020100fcffffff0201fa0402010303feff0300ff050503fffdfc0101fdfd00000200fafefe0101fe00fefafb01020200010100000100fbfc0302fc06020104fb0000ff060200fb0403fdfe0502030101ff06fe0001000101fafe0900fdfe0000fd00fc03ff0402fdfdfeff02fc060401fefd0101fe00fc02020304fe0001f9fdfc0004ff05fd070303fd01040001fb01feff01fe00fc0203fe01fefc01ff0003000404fffd00fdf7fd0303ffff0202fefc0005fa03000100f90402fe0204020103fbfefd01fffffcfdfffc06ff0100fc0405fdfd0102fefa0102000402010004fd050202fc0403ff00fb05000100010504000501fb0101fe0104010401fe00030300fffefafa030002fd00fffd00000000fafffc01fc0200010104fb030501fe04fdfffefe02fd04fc01ff0003fe01fc05ffff010200fdffff0301feff05fffefd0101fe05010101000304ff0102ffff01fefe03fffc0204ff01fbfc02fdfcfffe030101fe00fffb00fcfffeff01010402fa02fc020201fcfffdfe0302fb00fcfdfefd00fc02fefc02fffd0001fc01feff0100f8000403020000fefffe02fffefd020201fefe0000fc00ff020007fd0304fc03030404fefdf9fdfffdfdfdfcfd04fe00ff05020001010102000308ff020203ff000403fc0205000600fb0301fefcfefeff00fffd04fffffffc04020001fe030300feff0900010206feff000100fcfffc0600ff02ff0101ff03fffd00020002fbfd0202fe020403ff0102feff0101fe0401fefb07fc02030601fe000103fe0205fefeff03020500f9050501fe03fd03fd000001050102ff0001fd00ff00fefe01020300fd0103fbfc02ff0001040005fb0503feff010201fdff0000020104fdfe00fc0200fd04ff04fe05fb0000fdfc01ff03f9020200ff0003fe00fd0202050100ff0203010203fd00fe050403fbff01ffff");
    }
}
