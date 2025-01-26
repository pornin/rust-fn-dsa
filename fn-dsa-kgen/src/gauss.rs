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

// Sample the f (or g) polynomial, using the provided PRNG,
// for a given degree n = 2^logn (with 1 <= logn <= 10). This function
// ensures that the returned polynomial has odd parity.
pub(crate) fn sample_f<T: PRNG>(logn: u32, rng: &mut T, f: &mut [i8]) {
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
    #[cfg(feature = "shake256x4")]
    use fn_dsa_comm::shake::SHAKE256x4;
    #[cfg(not(feature = "shake256x4"))]
    use fn_dsa_comm::shake::SHAKE256_PRNG;

    fn check_sample_f(logn: u32, expected: &str) {
        let n = 1 << logn;

        #[cfg(feature = "shake256x4")]
        let mut rng = SHAKE256x4::new(&[logn as u8]);
        #[cfg(not(feature = "shake256x4"))]
        let mut rng = <SHAKE256_PRNG as PRNG>::new(&[logn as u8]);

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
        #[cfg(feature = "shake256x4")]
        {
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

        #[cfg(not(feature = "shake256x4"))]
        {
            check_sample_f(2,  "e70c150d");
            check_sample_f(3,  "d11108c2093007f9");
            check_sample_f(4,  "071f280109f0f9fca611f6080020f8ef");
            check_sample_f(5,  "19fa150a1008f5011110010d04ec0df50b090c18fd0cfce904f2ea10101120fd");
            check_sample_f(6,  "f8ecf40606fdee0903040a0208ff0b150f04ed040601f808f4f4ecf5f6f8fdedfc06fef9f8f4f1ebf6fdf7f515fb06fffcf808ef03090a0803fb010201011210");
            check_sample_f(7,  "03fdfaff010303f8fa030f0008f80a060300f615f6080cf5fbff030dfcf9f9010305f7e60700fdf3faf8eef6f91403f5fafcfefe040311f110030a0408faf7fa0e0201fc03f9010cfd06f6f504f3f4fffef802f60415fdfc06fa06f800fc040900fd02f6fff90efbf700f1070209fcfc00040204ff04fc0108f70afdfc05f502");
            check_sample_f(8,  "f9ff0606fffefffdfc07080806f9000a040a040200fbf7000202fb0406010f030206fc0100fa05f8fcfefc02080601fa04fb00fff2f80802fffc000302fc03fe03f2fdfd02010003fcf908f1f9ef0602fe030afb00fe040904040c0207fa0606060004f5040c05fbfafe0407f8fa050402f9f9f901fefd02fbebfcfeffff00fb0005030b07fbfdfbfcfc06fff9fe000301fffe0201060100fdfcf305fa0001fb00fc040d030203f3fd03fafb000806ff010006f90afd0bfb0705070dfb07ff01fd0408fc0103fc0109fff2f805fb01fafe0805fff80407fd0aff04fa01070700f00b0008f3ff07fc08faf101fc0404fe01fd04080af80b0a0804fffb090102fe");
            check_sample_f(9,  "04010403fcff0603fafa00fefdfbfe030100f801fd0700fb0408030704f604fbfd01fff905ffffff0303ff05030501fe03fe0601fef6fffcfdfb070102ff0dfc04fc0205fc0200fd02ff01fb00fffbfcfefafa0401fbfd0808fe0200040008fdfefef7fbf9fcf901ff000100030107ff03000103fdfc0701fe03fa01fa0603fefcfe01fffc0403fe04fc03030001050303fefc01f9fe04fdfefd06f901fc03fbfe000200fc03fe0106fc0507fe0301fefdf904ff00f8f8fe03020001f8fa00fffe0404fdfdfdfffd03fefc00fffa0504fffdfbfffefdfdff04fc0700fe0201fefc0000ff00ff00f804f700ffffff01fef9fe02ff000103fc010803fffcff010100f9ff02000703030002fffbfafafffefffcfb01f9030002fbfbfd030400fe01030afc00fffc00fa0400fefdfa01fdfe000101fefd0afef9fd01fefd02fbfbfbfffdfc00fdfaff02fe01ff04fc0304fcfbf80004fe030c00fdfffdfafc00fc03090507fe060402fffffef9010202fc0702fe02feff08fffd0002fd0205fffafefb0100000701fafffe030600fc030008020302fffb0602010400fffe03000505f9f802fe02fd030300070805f900fffb06fffefdfc02fa0006fc00fbfcf802f60201fff9fb01ff040bfdfe00f8ff0405fd01f7fbfafd0401010002fdfd0800020301f904f8fe01020607fd07fa02fafffc010107fef9ff0102fffcfd03fe0203");
            check_sample_f(10, "fffbfefffffeffff01fc01fbfcfd00000103ffff02feff00fcff02fd010301ffff03fe00ff02fffcfe03fb0000fe02030200fd0500fd0204fdfefe00fd0202fb0101fe0000feffff000006fefcfffffd050000ff01ff00fc0404fc030302ff02fffd0501fafd02fcfe01fffefc02fcff01ff03010004ff010103010000fe04020103010103ff00fdfe07fd03010500010603fe0302fe0005fffdfbfc0402050104fbfffd02fd0401fa01fe04feff010203ffff0004090301fd0102f7fefb0200000403fcfe02fffeff0003010004fffcfdff00fe000302fd01000500fe00fffc0601fd000401010101ff0105fefd03000303fffe030301ffff02020003010000fd00fc01fbfffefffc0100fe02fc00030401fcfffd0300ffff020100fe0302010400060002fc00ff0501010103ff00fe06fc020502030200fcff00ff04ff0002ff01fefdfffd01ff04fe01fc0301fd01fdfd010000fffc0401fb03fbff0300000100fe00ff02fdff000602fc00fc0408020300ff0403030201fcfd0004010002fffe020000fffa0601020301fc0000fb00fd010000fffcfefd02fc08fffefe020200080301ff030300ff0305fafffb050203fd01fc040303fe01fd02fa01fffe05fd01fc0100ff05010005ffff0106fd0002ff00ff00fefeffff0403fefe0201ff00ff04fffcfdfffbff0102080007fcf8fdfb00020404fc04fd04fe03fe0201ff0101f9fdfcfeff01ff02fdfe0302fffc0105fc02fffe01fb0000010501fcf9000202030401fd0500fffdfdff00fe05ff02ff0300fc0400030002fefdff01000203fd03fd01fe02fefe0301fc0302fd00fe0501fe040003ff01010404ff00ff04ff0203fb050300fcfd01ff06fdfc00ff0400fe0401010002fd00ffff05050603ff0201ff020101fc010000050200fdfe04040102ff00fb0001ff010303f8fffffe04040004fe02fa0407ffff0401fe01fe0002000000fe02fd02ff01ff02fffdfffffeff0501fffb0100fc03fefdffff00fd01fdfcfefdfbff02fd05fffd0101fc010000fefb01fd0303fe010102ff0002fc00feff00ffffffff0104fffe02fefd05020001fb01feff040004fffe02fc0001fefdff00fffe0203fbff00fe00ff0102fefdfe0302fd020202fd0301fffdfd01fc00fd0302fe01fffeffff00fffcfe05ff050200020602fbfc01feff05020203010003ffff060100ff0200f80102fb02020103020404fd01fff802f8fe050100fe0104fe01fdfffefbfffefd0301010000fa0000000200fffdfefe000106fe00ff00fffb0304fb0001ff01fd0006fe030304000304fe0107080202fd0302fd0005ff0203fdfefc02030000030001fb0202030002fb03fd01040003fe00fefb00fe02fcff00fef901ff06fffe03020300fcfefdfbfdffff04ff04fd020301fe0301ff02f9ff05fc000000000002");
        }
    }
}
