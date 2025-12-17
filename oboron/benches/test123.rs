use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oboron::{Ob00, Ob01, Ob21p, Ob31, Ob31p, Ob32, Ob32p, Ob70, Ob71, ObMulti, Oboron};

// Baseline benchmarks - no crypto, just encoding overhead
fn benchmark_enob71(c: &mut Criterion) {
    let ob = Ob71::new_keyless().unwrap();
    c.bench_function("test123/Ob71/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enob70(c: &mut Criterion) {
    let ob = Ob70::new_keyless().unwrap();
    c.bench_function("test123/Ob71/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_deob71(c: &mut Criterion) {
    let ob = Ob71::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("deob71", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_deob70(c: &mut Criterion) {
    let ob = Ob70::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("deob70", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

// Crypto scheme benchmarks
fn benchmark_enob00(c: &mut Criterion) {
    let ob = Ob00::new_keyless().unwrap();
    c.bench_function("enob00", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enob01(c: &mut Criterion) {
    let ob = Ob01::new_keyless().unwrap();
    c.bench_function("enob01", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enob31(c: &mut Criterion) {
    let ob = Ob31::new_keyless().unwrap();
    c.bench_function("enob31", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enob32(c: &mut Criterion) {
    let ob = Ob32::new_keyless().unwrap();
    c.bench_function("enob32", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enob21p(c: &mut Criterion) {
    let ob = Ob21p::new_keyless().unwrap();
    c.bench_function("enob21p", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enob31p(c: &mut Criterion) {
    let ob = Ob31p::new_keyless().unwrap();
    c.bench_function("enob31p", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_enob32p(c: &mut Criterion) {
    let ob = Ob32p::new_keyless().unwrap();
    c.bench_function("enob32p", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

fn benchmark_deob00(c: &mut Criterion) {
    let ob = Ob00::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("deob00", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_deob01(c: &mut Criterion) {
    let ob = Ob01::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("deob01", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_deob31(c: &mut Criterion) {
    let ob = Ob31::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("deob31", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_deob32(c: &mut Criterion) {
    let ob = Ob32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("deob32", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_deob21p(c: &mut Criterion) {
    let ob = Ob21p::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("deob21p", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_deob31p(c: &mut Criterion) {
    let ob = Ob31p::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("deob31p", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

fn benchmark_deob32p(c: &mut Criterion) {
    let ob = Ob32p::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("deob32p", |b| {
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
    benchmark_enob71,
    benchmark_enob70,
    benchmark_deob71,
    benchmark_deob70,
    // Crypto schemes
    benchmark_enob00,
    benchmark_enob01,
    benchmark_enob31,
    benchmark_enob32,
    benchmark_enob21p,
    benchmark_enob31p,
    benchmark_enob32p,
    benchmark_deob00,
    benchmark_deob01,
    benchmark_deob31,
    benchmark_deob32,
    benchmark_deob21p,
    benchmark_deob31p,
    benchmark_deob32p,
    // ObMulti
    benchmark_auto_encode_ob32,
    benchmark_auto_decode_ob32
);
criterion_main!(benches);
