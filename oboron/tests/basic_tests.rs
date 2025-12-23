#[cfg(feature = "adgs")]
use oboron::Adgs;
use oboron::ObMulti;
#[cfg(feature = "upbc")]
use oboron::UpbcC32;
#[cfg(feature = "zfbcx")]
use oboron::ZfbcxC32;

#[test]
#[cfg(feature = "zfbcx")]
fn test_zfbcx_basic() {
    let original = "hello world";
    let ob = ZfbcxC32::new_keyless().unwrap();
    let ot = ob.enc(original).unwrap();
    let pt2 = ob.dec_strict(&ot).unwrap();

    assert_eq!(original, pt2);
    assert!(ot.len() > 0);
}

#[test]
#[cfg(feature = "zfbcx")]
fn test_empty_string() {
    let original = "";
    let ob = ZfbcxC32::new_keyless().unwrap();
    assert!(ob.enc(original).is_err());
}

#[test]
#[cfg(feature = "zfbcx")]
fn test_zfbcx_all_printable_ascii() {
    let original = (32..127).map(|c| c as u8 as char).collect::<String>();
    let ob = ZfbcxC32::new_keyless().unwrap();
    let ot = ob.enc(&original).unwrap();
    let pt2 = ob.dec_strict(&ot).unwrap();

    assert_eq!(original, pt2);
}

#[test]
#[cfg(feature = "zfbcx")]
fn test_convenience_functions() {
    let original = "convenience test";

    let ot_zfbcx = oboron::enc_keyless(original, "zfbcx.c32").unwrap();
    let pt2_zfbcx = oboron::dec_keyless(&ot_zfbcx, "zfbcx.c32").unwrap();
    assert_eq!(original, pt2_zfbcx);

    let autodecd_zfbcx = oboron::autodec_keyless(&ot_zfbcx).unwrap();
    assert_eq!(original, autodecd_zfbcx);
}

#[test]
#[cfg(feature = "adgs")]
fn test_adgs_deterministic() {
    let original = "deterministic test";
    let ob = Adgs::new_keyless().unwrap();

    let ot1 = ob.enc(original).unwrap();
    let ot2 = ob.enc(original).unwrap();

    // adgs is deterministic - same input produces same output
    assert_eq!(ot1, ot2);

    let pt2 = ob.dec_strict(&ot1).unwrap();
    assert_eq!(original, pt2);
}

#[test]
#[cfg(feature = "upbc")]
fn test_upbc_probabilistic() {
    let original = "probabilistic test";
    let ob = UpbcC32::new_keyless().unwrap();

    let ot1 = ob.enc(original).unwrap();
    let ot2 = ob.enc(original).unwrap();

    // upbc is probabilistic - same input produces different output
    assert_ne!(ot1, ot2);

    let pt21 = ob.dec_strict(&ot1).unwrap();
    let pt22 = ob.dec_strict(&ot2).unwrap();
    assert_eq!(original, pt21);
    assert_eq!(original, pt22);
}

#[test]
fn test_autodetect_all_formats() {
    let original = "autodetect all";
    let ob = ObMulti::new_keyless().unwrap();

    #[cfg(feature = "zfbcx")]
    {
        let ot = ob.enc(original, "zfbcx.c32").unwrap();
        let pt2 = ob.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format zfbcx");
    }
    #[cfg(feature = "upbc")]
    {
        let ot = ob.enc(original, "upbc.c32").unwrap();
        let pt2 = ob.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format upbc");
    }
    #[cfg(feature = "adgs")]
    {
        let ot = ob.enc(original, "adgs.c32").unwrap();
        let pt2 = ob.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format adgs");
    }
    #[cfg(feature = "apgs")]
    {
        let ot = ob.enc(original, "apgs.c32").unwrap();
        let pt2 = ob.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format apgs");
    }
    #[cfg(feature = "adsv")]
    {
        let ot = ob.enc(original, "adsv.c32").unwrap();
        let pt2 = ob.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format adsv");
    }
    #[cfg(feature = "apsv")]
    {
        let ot = ob.enc(original, "apsv.c32").unwrap();
        let pt2 = ob.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format apsv");
    }
}
