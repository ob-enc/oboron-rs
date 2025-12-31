use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(feature = "legacy")]
use oboron::{AagsC32, AasvC32, ApgsC32, ApsvC32, Omnib, UpbcC32};
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

fn benchmark_aags_enc(c: &mut Criterion) {
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

fn benchmark_apgs_enc(c: &mut Criterion) {
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

fn benchmark_dec_aags(c: &mut Criterion) {
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
    let ob = Omnib::new_keyless().unwrap();
    c.bench_function("auto_encode_aasv", |b| {
        b.iter(|| ob.enc(black_box("test123"), "aasv.c32").unwrap());
    });
}

fn benchmark_aasv_obm_autodec(c: &mut Criterion) {
    let ob = Omnib::new_keyless().unwrap();
    let ot = ob.enc("test123", "aasv.c32").unwrap();
    c.bench_function("auto_decode_aasv", |b| {
        b.iter(|| ob.autodec(black_box(&ot)).unwrap());
    });
}

criterion_group!(
    benches,
    benchmark_aags_enc,
    benchmark_aasv_enc,
    benchmark_apgs_enc,
    benchmark_apsv_enc,
    benchmark_dec_aasv,
    benchmark_dec_aags,
    benchmark_dec_apgs,
    benchmark_dec_apsv,
    benchmark_dec_upbc,
    benchmark_mock1_dec,
    benchmark_mock1_enc,
    benchmark_mock2_dec,
    benchmark_mock2_enc,
    benchmark_upbc_enc,
    // Omnib
    benchmark_aasv_obm_autodec
    benchmark_aasv_obm_enc,
);
criterion_main!(benches);
