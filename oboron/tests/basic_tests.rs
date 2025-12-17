#[cfg(feature = "ob01")]
use oboron::Ob01;
#[cfg(feature = "ob21p")]
use oboron::Ob21p;
#[cfg(feature = "ob31")]
use oboron::Ob31;
use oboron::{ObMulti, Oboron};

#[test]
#[cfg(feature = "ob01")]
fn test_ob01_basic() {
    let original = "hello world";
    let ob = Ob01::new_keyless().unwrap();
    let encd = ob.enc(original).unwrap();
    let decd = ob.dec_strict(&encd).unwrap();

    assert_eq!(original, decd);
    assert!(encd.len() > 0);
}

#[test]
#[cfg(feature = "ob01")]
fn test_empty_string() {
    let original = "";
    let ob = Ob01::new_keyless().unwrap();
    assert!(ob.enc(original).is_err());
}

#[test]
#[cfg(feature = "ob01")]
fn test_ob01_all_printable_ascii() {
    let original = (32..127).map(|c| c as u8 as char).collect::<String>();
    let ob = Ob01::new_keyless().unwrap();
    let encd = ob.enc(&original).unwrap();
    let decd = ob.dec_strict(&encd).unwrap();

    assert_eq!(original, decd);
}

#[test]
#[cfg(feature = "ob01")]
fn test_convenience_functions() {
    let original = "convenience test";

    let encd_ob01 = oboron::enc_keyless(original, "ob01:c32").unwrap();
    let decd_ob01 = oboron::dec_keyless(&encd_ob01, "ob01:c32").unwrap();
    assert_eq!(original, decd_ob01);

    let autodecd_ob01 = oboron::autodec_keyless(&encd_ob01).unwrap();
    assert_eq!(original, autodecd_ob01);
}

#[test]
#[cfg(feature = "ob31")]
fn test_ob31_deterministic() {
    let original = "deterministic test";
    let ob = Ob31::new_keyless().unwrap();

    let encd1 = ob.enc(original).unwrap();
    let encd2 = ob.enc(original).unwrap();

    // ob31 is deterministic - same input produces same output
    assert_eq!(encd1, encd2);

    let decd = ob.dec_strict(&encd1).unwrap();
    assert_eq!(original, decd);
}

#[test]
#[cfg(feature = "ob21p")]
fn test_ob21p_probabilistic() {
    let original = "probabilistic test";
    let ob = Ob21p::new_keyless().unwrap();

    let encd1 = ob.enc(original).unwrap();
    let encd2 = ob.enc(original).unwrap();

    // ob21p is probabilistic - same input produces different output
    assert_ne!(encd1, encd2);

    let decd1 = ob.dec_strict(&encd1).unwrap();
    let decd2 = ob.dec_strict(&encd2).unwrap();
    assert_eq!(original, decd1);
    assert_eq!(original, decd2);
}

#[test]
fn test_autodetect_all_formats() {
    let original = "autodetect all";
    let ob = ObMulti::new_keyless().unwrap();

    #[cfg(feature = "ob01")]
    {
        let encd = ob.enc(original, "ob01:c32").unwrap();
        let decd = ob.autodec(&encd).unwrap();
        assert_eq!(original, decd, "Failed for format ob01");
    }
    #[cfg(feature = "ob21p")]
    {
        let encd = ob.enc(original, "ob21p:c32").unwrap();
        let decd = ob.autodec(&encd).unwrap();
        assert_eq!(original, decd, "Failed for format ob21p");
    }
    #[cfg(feature = "ob31")]
    {
        let encd = ob.enc(original, "ob31:c32").unwrap();
        let decd = ob.autodec(&encd).unwrap();
        assert_eq!(original, decd, "Failed for format ob31");
    }
    #[cfg(feature = "ob31p")]
    {
        let encd = ob.enc(original, "ob31p:c32").unwrap();
        let decd = ob.autodec(&encd).unwrap();
        assert_eq!(original, decd, "Failed for format ob31p");
    }
    #[cfg(feature = "ob32")]
    {
        let encd = ob.enc(original, "ob32:c32").unwrap();
        let decd = ob.autodec(&encd).unwrap();
        assert_eq!(original, decd, "Failed for format ob32");
    }
    #[cfg(feature = "ob32p")]
    {
        let encd = ob.enc(original, "ob32p:c32").unwrap();
        let decd = ob.autodec(&encd).unwrap();
        assert_eq!(original, decd, "Failed for format ob32p");
    }
}
