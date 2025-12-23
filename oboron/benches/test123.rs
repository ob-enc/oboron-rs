use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(feature = "legacy")]
use oboron::LegacyC32;
use oboron::{AdgsC32, AdsvC32, ApgsC32, ApsvC32, ObMulti, ObtextCodec, UpbcC32, ZfbcxC32};
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

fn benchmark_zfbcx_enc(c: &mut Criterion) {
    let ob = ZfbcxC32::new_keyless().unwrap();
    c.bench_function("enc_zfbcx", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_adsv_enc(c: &mut Criterion) {
    let ob = AdgsC32::new_keyless().unwrap();
    c.bench_function("enc_adsv", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_adsv_enc(c: &mut Criterion) {
    let ob = AdsvC32::new_keyless().unwrap();
    c.bench_function("enc_adsv", |b| {
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

fn benchmark_dec_zfbcx(c: &mut Criterion) {
    let ob = ZfbcxC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_zfbcx", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_apgs(c: &mut Criterion) {
    let ob = AdgsC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_apgs", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_adsv(c: &mut Criterion) {
    let ob = AdsvC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_adsv", |b| {
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

fn benchmark_adsv_obm_enc(c: &mut Criterion) {
    let ob = ObMulti::new_keyless().unwrap();
    c.bench_function("auto_encode_adsv", |b| {
        b.iter(|| ob.enc(black_box("test123"), "adsv.c32").unwrap());
    });
}

fn benchmark_adsv_obm_autodec(c: &mut Criterion) {
    let ob = ObMulti::new_keyless().unwrap();
    let ot = ob.enc("test123", "adsv.c32").unwrap();
    c.bench_function("auto_decode_adsv", |b| {
        b.iter(|| ob.autodec(black_box(&ot)).unwrap());
    });
}

criterion_group!(
    benches,
    benchmark_adsv_enc,
    benchmark_adsv_enc,
    benchmark_apsv_enc,
    benchmark_apsv_enc,
    benchmark_dec_adsv,
    benchmark_dec_apgs,
    benchmark_dec_apgs,
    benchmark_dec_apsv,
    benchmark_dec_upbc,
    benchmark_dec_zfbcx,
    benchmark_legacy_dec,
    benchmark_legacy_enc,
    benchmark_mock1_dec,
    benchmark_mock1_enc,
    benchmark_mock2_dec,
    benchmark_mock2_enc,
    benchmark_upbc_enc,
    benchmark_zfbcx_enc,
    // ObMulti
    benchmark_adsv_obm_autodec
    benchmark_adsv_obm_enc,
);
criterion_main!(benches);
