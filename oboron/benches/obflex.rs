use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oboron::{ObFlex, Oboron};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct BenchmarkSpec {
    id: String,
    operation: String,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    encoding: Option<String>,
    #[serde(default)]
    plaintext: Option<String>,
    #[serde(default)]
    precompute: Option<PrecomputeSpec>,
    #[allow(dead_code)]
    description: String,
}

#[derive(Debug, Deserialize)]
struct PrecomputeSpec {
    #[allow(dead_code)]
    operation: String,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    encoding: Option<String>,
    plaintext: String,
}

fn load_benchmark_specs() -> Vec<BenchmarkSpec> {
    let possible_paths = vec![
        PathBuf::from("benches/benchmarks_obflex.jsonl"),
        PathBuf::from("oboron/benches/benchmarks_obflex.jsonl"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/benchmarks_obflex.jsonl"),
    ];

    for path in &possible_paths {
        if path.exists() {
            eprintln!("Found obflex benchmarks at: {:?}", path);
            let data = fs::read_to_string(path).expect("Failed to read benchmarks_obflex.jsonl");
            let specs: Vec<BenchmarkSpec> = data
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).expect("Failed to parse benchmark spec"))
                .collect();
            eprintln!("Loaded {} obflex benchmark specifications", specs.len());
            return specs;
        }
    }

    eprintln!("Warning: benchmarks_obflex.jsonl not found");
    vec![]
}

fn precompute_value(spec: &PrecomputeSpec, ob: &mut ObFlex) -> String {
    if let Some(ref format) = spec.format {
        ob.set_format(format.as_str()).unwrap();
    }
    ob.enc(&spec.plaintext).unwrap()
}

fn run_obflex_benchmarks(c: &mut Criterion) {
    let specs = load_benchmark_specs();

    if specs.is_empty() {
        eprintln!("No obflex specs loaded");
        return;
    }

    // Create ObFlex once, OUTSIDE the timed loop
    let mut ob = ObFlex::new_keyless("ob70:c32").unwrap();

    let mut bench_count = 0;
    for spec in specs {
        match spec.operation.as_str() {
            "enc" => {
                let format = match spec.format {
                    Some(f) => f,
                    None => {
                        eprintln!("Skipping {} - no format", spec.id);
                        continue;
                    }
                };

                if let Some(plaintext) = spec.plaintext {
                    // Set format outside timed loop
                    ob.set_format(format.as_str()).unwrap();
                    bench_count += 1;

                    // Only the enc operation is timed
                    c.bench_function(&spec.id, |b| {
                        b.iter(|| ob.enc(black_box(&plaintext)).unwrap());
                    });
                }
            }
            "dec_strict" => {
                let format = match spec.format {
                    Some(f) => f,
                    None => {
                        eprintln!("Skipping {} - no format", spec.id);
                        continue;
                    }
                };

                if let Some(precompute) = spec.precompute {
                    // Precompute and set format outside timed loop
                    ob.set_format(format.as_str()).unwrap();
                    let ot = precompute_value(&precompute, &mut ob);
                    ob.set_format(format.as_str()).unwrap();
                    bench_count += 1;

                    // Only the dec_strict operation is timed
                    c.bench_function(&spec.id, |b| {
                        b.iter(|| ob.dec_strict(black_box(&ot)).unwrap());
                    });
                }
            }
            _ => {
                eprintln!(
                    "Skipping {} - unsupported operation: {}",
                    spec.id, spec.operation
                );
            }
        }
    }
    eprintln!("Registered {} obflex benchmarks", bench_count);
}

criterion_group!(benches, run_obflex_benchmarks);
criterion_main!(benches);
