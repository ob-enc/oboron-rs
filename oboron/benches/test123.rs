use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(feature = "legacy")]
use oboron::LegacyC32;
use oboron::{AagsC32, AasvC32, ApgsC32, ApsvC32, ObMulti, ObtextCodec, UpbcC32, ZrbcxC32};
#[cfg(feature = "mock")]
use oboron::{Mock1C32, Mock2C32};

// Baseline benchmarks - no crypto, just encoding overhead
#[cfg(feature = "mock")]
fn benchmark_mock2_enc(c: &mut Criterion) {
    let ob = Mock2C32::new_keyless().unwrap();
    c.bench_function("test123/Mock2C32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "mock")]
fn benchmark_mock1_enc(c: &mut Criterion) {
    let ob = Mock1C32::new_keyless().unwrap();
    c.bench_function("test123/Mock2C32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "mock")]
fn benchmark_mock2_dec(c: &mut Criterion) {
    let ob = Mock2C32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_mock2", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

#[cfg(feature = "mock")]
fn benchmark_mock1_dec(c: &mut Criterion) {
    let ob = Mock1C32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_mock1", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

// Crypto scheme benchmarks
#[cfg(feature = "legacy")]
fn benchmark_legacy_enc(c: &mut Criterion) {
    let ob = LegacyC32::new_keyless().unwrap();
    c.bench_function("enc_legacy", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_zrbcx_enc(c: &mut Criterion) {
    let ob = ZrbcxC32::new_keyless().unwrap();
    c.bench_function("enc_zrbcx", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_aasv_enc(c: &mut Criterion) {
    let ob = AagsC32::new_keyless().unwrap();
    c.bench_function("enc_aasv", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_aasv_enc(c: &mut Criterion) {
    let ob = AasvC32::new_keyless().unwrap();
    c.bench_function("enc_aasv", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_upbc_enc(c: &mut Criterion) {
    let ob = UpbcC32::new_keyless().unwrap();
    c.bench_function("enc_upbc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_apsv_enc(c: &mut Criterion) {
    let ob = ApgsC32::new_keyless().unwrap();
    c.bench_function("enc_apsv", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_apsv_enc(c: &mut Criterion) {
    let ob = ApsvC32::new_keyless().unwrap();
    c.bench_function("enc_apsv", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "legacy")]
fn benchmark_legacy_dec(c: &mut Criterion) {
    let ob = LegacyC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_legacy", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_zrbcx(c: &mut Criterion) {
    let ob = ZrbcxC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_zrbcx", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_apgs(c: &mut Criterion) {
    let ob = AagsC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_apgs", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_aasv(c: &mut Criterion) {
    let ob = AasvC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_aasv", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_upbc(c: &mut Criterion) {
    let ob = UpbcC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_upbc", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_apgs(c: &mut Criterion) {
    let ob = ApgsC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_apgs", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_apsv(c: &mut Criterion) {
    let ob = ApsvC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_apsv", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_aasv_obm_enc(c: &mut Criterion) {
    let ob = ObMulti::new_keyless().unwrap();
    c.bench_function("auto_encode_aasv", |b| {
        b.iter(|| ob.enc(black_box("test123"), "aasv.c32").unwrap());
    });
}

fn benchmark_aasv_obm_autodec(c: &mut Criterion) {
    let ob = ObMulti::new_keyless().unwrap();
    let ot = ob.enc("test123", "aasv.c32").unwrap();
    c.bench_function("auto_decode_aasv", |b| {
        b.iter(|| ob.autodec(black_box(&ot)).unwrap());
    });
}

criterion_group!(
    benches,
    benchmark_aasv_enc,
    benchmark_aasv_enc,
    benchmark_apsv_enc,
    benchmark_apsv_enc,
    benchmark_dec_aasv,
    benchmark_dec_apgs,
    benchmark_dec_apgs,
    benchmark_dec_apsv,
    benchmark_dec_upbc,
    benchmark_dec_zrbcx,
    benchmark_legacy_dec,
    benchmark_legacy_enc,
    benchmark_mock1_dec,
    benchmark_mock1_enc,
    benchmark_mock2_dec,
    benchmark_mock2_enc,
    benchmark_upbc_enc,
    benchmark_zrbcx_enc,
    // ObMulti
    benchmark_aasv_obm_autodec
    benchmark_aasv_obm_enc,
);
criterion_main!(benches);
