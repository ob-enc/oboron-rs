#[cfg(feature = "adgs")]
use oboron::Adgs;
#[cfg(feature = "upc")]
use oboron::UpcC32;
#[cfg(feature = "zdc")]
use oboron::ZdcC32;
use oboron::{ObMulti, ObtextCodec};

#[test]
#[cfg(feature = "zdc")]
fn test_zdc_basic() {
    let original = "hello world";
    let ob = ZdcC32::new_keyless().unwrap();
    let ot = ob.enc(original).unwrap();
    let pt2 = ob.dec_strict(&ot).unwrap();

    assert_eq!(original, pt2);
    assert!(ot.len() > 0);
}

#[test]
#[cfg(feature = "zdc")]
fn test_empty_string() {
    let original = "";
    let ob = ZdcC32::new_keyless().unwrap();
    assert!(ob.enc(original).is_err());
}

#[test]
#[cfg(feature = "zdc")]
fn test_zdc_all_printable_ascii() {
    let original = (32..127).map(|c| c as u8 as char).collect::<String>();
    let ob = ZdcC32::new_keyless().unwrap();
    let ot = ob.enc(&original).unwrap();
    let pt2 = ob.dec_strict(&ot).unwrap();

    assert_eq!(original, pt2);
}

#[test]
#[cfg(feature = "zdc")]
fn test_convenience_functions() {
    let original = "convenience test";

    let ot_zdc = oboron::enc_keyless(original, "zdc.c32").unwrap();
    let pt2_zdc = oboron::dec_keyless(&ot_zdc, "zdc.c32").unwrap();
    assert_eq!(original, pt2_zdc);

    let autodecd_zdc = oboron::autodec_keyless(&ot_zdc).unwrap();
    assert_eq!(original, autodecd_zdc);
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
#[cfg(feature = "upc")]
fn test_upc_probabilistic() {
    let original = "probabilistic test";
    let ob = UpcC32::new_keyless().unwrap();

    let ot1 = ob.enc(original).unwrap();
    let ot2 = ob.enc(original).unwrap();

    // upc is probabilistic - same input produces different output
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

    #[cfg(feature = "zdc")]
    {
        let ot = ob.enc(original, "zdc.c32").unwrap();
        let pt2 = ob.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format zdc");
    }
    #[cfg(feature = "upc")]
    {
        let ot = ob.enc(original, "upc.c32").unwrap();
        let pt2 = ob.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format upc");
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
