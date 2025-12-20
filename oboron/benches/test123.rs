use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oboron::{Ob00, Ob31, Ob31p, Ob32, Ob32p, Ob70, Ob71, ObMulti, Oboron, UpcC32, ZdcC32};

// Baseline benchmarks - no crypto, just encoding overhead
fn benchmark_enc_tdr(c: &mut Criterion) {
    let ob = Ob71::new_keyless().unwrap();
    c.bench_function("test123/Ob71/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enc_tdi(c: &mut Criterion) {
    let ob = Ob70::new_keyless().unwrap();
    c.bench_function("test123/Ob71/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_dec_tdr(c: &mut Criterion) {
    let ob = Ob71::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_tdr", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_tdi(c: &mut Criterion) {
    let ob = Ob70::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_tdi", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

// Crypto scheme benchmarks
fn benchmark_enc_ob00(c: &mut Criterion) {
    let ob = Ob00::new_keyless().unwrap();
    c.bench_function("enc_ob00", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enc_zdc(c: &mut Criterion) {
    let ob = ZdcC32::new_keyless().unwrap();
    c.bench_function("enc_zdc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enc_adsv(c: &mut Criterion) {
    let ob = Ob31::new_keyless().unwrap();
    c.bench_function("enc_adsv", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enc_adsv(c: &mut Criterion) {
    let ob = Ob32::new_keyless().unwrap();
    c.bench_function("enc_adsv", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enc_upc(c: &mut Criterion) {
    let ob = UpcC32::new_keyless().unwrap();
    c.bench_function("enc_upc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enc_apsv(c: &mut Criterion) {
    let ob = Ob31p::new_keyless().unwrap();
    c.bench_function("enc_apsv", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enc_apsv(c: &mut Criterion) {
    let ob = Ob32p::new_keyless().unwrap();
    c.bench_function("enc_apsv", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_dec_ob00(c: &mut Criterion) {
    let ob = Ob00::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_ob00", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_zdc(c: &mut Criterion) {
    let ob = ZdcC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_zdc", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_adgs(c: &mut Criterion) {
    let ob = Ob31::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_adgs", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_adsv(c: &mut Criterion) {
    let ob = Ob32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_adsv", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_upc(c: &mut Criterion) {
    let ob = UpcC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_upc", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_apgs(c: &mut Criterion) {
    let ob = Ob31p::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_apgs", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_dec_apsv(c: &mut Criterion) {
    let ob = Ob32p::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("dec_apsv", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_auto_encode_ob32(c: &mut Criterion) {
    let ob = ObMulti::new_keyless().unwrap();
    c.bench_function("auto_encode_ob32", |b| {
        b.iter(|| ob.enc(black_box("test123"), "ob32:c32").unwrap());
    });
}

fn benchmark_auto_decode_ob32(c: &mut Criterion) {
    let ob = ObMulti::new_keyless().unwrap();
    let ot = ob.enc("test123", "ob32:c32").unwrap();
    c.bench_function("auto_decode_ob32", |b| {
        b.iter(|| ob.autodec(black_box(&ot)).unwrap());
    });
}

criterion_group!(
    benches,
    // Baseline - encoding overhead only (no crypto)
    benchmark_enc_tdr,
    benchmark_enc_tdi,
    benchmark_dec_tdr,
    benchmark_dec_tdi,
    // Crypto schemes
    benchmark_enc_ob00,
    benchmark_enc_zdc,
    benchmark_enc_adsv,
    benchmark_enc_adsv,
    benchmark_enc_upc,
    benchmark_enc_apsv,
    benchmark_enc_apsv,
    benchmark_dec_ob00,
    benchmark_dec_zdc,
    benchmark_dec_adgs,
    benchmark_dec_adsv,
    benchmark_dec_upc,
    benchmark_dec_apgs,
    benchmark_dec_apsv,
    // ObMulti
    benchmark_auto_encode_ob32,
    benchmark_auto_decode_ob32
);
criterion_main!(benches);
