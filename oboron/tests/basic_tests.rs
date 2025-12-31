#[cfg(feature = "aags")]
use oboron::AagsC32;
use oboron::Omnib;
#[cfg(feature = "upbc")]
use oboron::UpbcC32;
#[cfg(feature = "zrbcx")]
use oboron::ZrbcxC32;

#[test]
#[cfg(feature = "zrbcx")]
fn test_zrbcx_basic() {
    let original = "hello world";
    let ob = ZrbcxC32::new_keyless().unwrap();
    let ot = ob.enc(original).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(original, pt2);
    assert!(ot.len() > 0);
}

#[test]
#[cfg(feature = "zrbcx")]
fn test_empty_string() {
    let original = "";
    let ob = ZrbcxC32::new_keyless().unwrap();
    assert!(ob.enc(original).is_err());
}

#[test]
#[cfg(feature = "zrbcx")]
fn test_zrbcx_all_printable_ascii() {
    let original = (32..127).map(|c| c as u8 as char).collect::<String>();
    let ob = ZrbcxC32::new_keyless().unwrap();
    let ot = ob.enc(&original).unwrap();
    let pt2 = ob.dec(&ot).unwrap();

    assert_eq!(original, pt2);
}

#[test]
#[cfg(feature = "zrbcx")]
fn test_convenience_functions() {
    let original = "convenience test";

    let ot = oboron::enc_keyless(original, "aasv.c32").unwrap();
    let pt2 = oboron::dec_keyless(&ot, "aasv.c32").unwrap();
    assert_eq!(original, pt2);

    let pt3 = oboron::autodec_keyless(&ot).unwrap();
    assert_eq!(original, pt3);
}

#[test]
#[cfg(feature = "aags")]
fn test_aags_deterministic() {
    let original = "deterministic test";
    let ob = AagsC32::new_keyless().unwrap();

    let ot1 = ob.enc(original).unwrap();
    let ot2 = ob.enc(original).unwrap();

    // aags is deterministic - same input produces same output
    assert_eq!(ot1, ot2);

    let pt2 = ob.dec(&ot1).unwrap();
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

    let pt21 = ob.dec(&ot1).unwrap();
    let pt22 = ob.dec(&ot2).unwrap();
    assert_eq!(original, pt21);
    assert_eq!(original, pt22);
}

#[test]
fn test_autodetect_all_formats() {
    let original = "autodetect all";
    let obm = Omnib::new_keyless().unwrap();

    #[cfg(feature = "zrbcx")]
    {
        let ot = obm.enc(original, "zrbcx.c32").unwrap();
        let pt2 = obm.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format zrbcx");
    }
    #[cfg(feature = "upbc")]
    {
        let ot = obm.enc(original, "upbc.c32").unwrap();
        let pt2 = obm.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format upbc");
    }
    #[cfg(feature = "aags")]
    {
        let ot = obm.enc(original, "aags.c32").unwrap();
        let pt2 = obm.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format aags");
    }
    #[cfg(feature = "apgs")]
    {
        let ot = obm.enc(original, "apgs.c32").unwrap();
        let pt2 = obm.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format apgs");
    }
    #[cfg(feature = "aasv")]
    {
        let ot = obm.enc(original, "aasv.c32").unwrap();
        let pt2 = obm.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format aasv");
    }
    #[cfg(feature = "apsv")]
    {
        let ot = obm.enc(original, "apsv.c32").unwrap();
        let pt2 = obm.autodec(&ot).unwrap();
        assert_eq!(original, pt2, "Failed for format apsv");
    }
}
