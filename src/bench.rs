//! Benchmark the performance of updating witnesses with respect to a variable
//! bucket size of elements with turnover.
use clacc::{
    Accumulator, Update, Witness, RawSerializer as Raw,
    blake2::Mapper as Map,
    gmp::BigInt,
    typenum::U16,
};
use criterion::{
    BatchSize::SmallInput,
    Bencher,
    BenchmarkId,
    Criterion,
    SamplingMode,
    Throughput,
    criterion_group, criterion_main,
};
use core::time::Duration;
use crossbeam::thread;
use num_cpus;
use rand::RngCore;
use std::sync::{Arc, Mutex};

mod primes;

struct UpdateWitnessesParams {
    bucket_size: usize,
    deletions_count: usize,
    additions_count: usize,
}

fn update_witnesses<'r, 's, 't0>(
    bencher: &'r mut Bencher<'s>,
    params: &'t0 UpdateWitnessesParams,
) {
    let staticels_count = params.bucket_size - params.deletions_count;
    bencher.iter_batched(|| {
        let mut rng = rand::thread_rng();
        let mut deletions: Vec<(Vec<u8>, Witness<BigInt>)> = vec![
            Default::default(); params.deletions_count
        ];
        let mut additions: Vec<(Vec<u8>, Witness<BigInt>)> = vec![
            Default::default(); params.additions_count
        ];
        let mut staticels: Vec<(Vec<u8>, Witness<BigInt>)> = vec![
            Default::default(); staticels_count
        ];
        // Generate 8 random bytes for each element.
        let mut bytes = vec![0; 8];
        for deletion in deletions.iter_mut() {
            rng.fill_bytes(&mut bytes);
            deletion.0 = bytes.clone();
        }
        for addition in additions.iter_mut() {
            rng.fill_bytes(&mut bytes);
            addition.0 = bytes.clone();
        }
        for staticel in staticels.iter_mut() {
            rng.fill_bytes(&mut bytes);
            staticel.0 = bytes.clone();
        }
        // Create accumulator.
        let mut acc = Accumulator::<BigInt>::with_private_key(
            primes::P.to_vec().as_slice().into(),
            primes::Q.to_vec().as_slice().into(),
        );
        // Accumulate bucket elements.
        for deletion in deletions.iter() {
            acc.add::<Map, U16, Raw, _>(&deletion.0);
        }
        for stat in staticels.iter() {
            acc.add::<Map, U16, Raw, _>(&stat.0);
        }
        // Generate witnesses for static elements.
        for stat in staticels.iter_mut() {
            stat.1 = acc.prove::<Map, U16, Raw, _>(
                &stat.0,
            ).unwrap();
        }
        // Save accumulation at current state.
        let prev = acc.clone();
        // Accumulate deletions.
        for del in deletions.iter_mut() {
            del.1 = acc.prove::<Map, U16, Raw, _>(&del.0).unwrap();
            acc.del::<Map, U16, Raw, _>(&del.0, &del.1).unwrap();
        }
        // Accumulate additions.
        for addition in additions.iter_mut() {
            addition.1 = acc.add::<Map, U16, Raw, _>(&addition.0);
            // Use the saved accumulation as the witness value.
            addition.1.set_value(prev.get_value());
        }
        // Batch updates.
        let mut update = Update::new();
        for deletion in deletions.iter() {
            update.del::<Map, U16, Raw, _>(
                &deletion.0,
                &deletion.1,
            );
        }
        for addition in additions.iter() {
            update.add::<Map, U16, Raw, _>(
                &addition.0,
                &addition.1,
            );
        }
        (acc, update, additions, staticels)
    }, |mut input| {
        // Update witnesses.
        let acc = input.0;
        let update = input.1;
        let additions = Arc::new(Mutex::new(input.2.iter_mut()));
        let staticels = Arc::new(Mutex::new(input.3.iter_mut()));
        thread::scope(|scope| {
            for _ in 0..num_cpus::get() {
                let acc = acc.clone();
                let u = update.clone();
                let additions = Arc::clone(&additions);
                let staticels = Arc::clone(&staticels);
                scope.spawn(move |_| {
                    u.update_witnesses::<Map, U16, Raw, _, _>(
                        &acc,
                        additions,
                        staticels,
                    );
                });
            }
        }).unwrap();
    }, SmallInput);
}

fn bench(c: &mut Criterion) {
    // Benchmark constants.
    const BUCKET_SIZES: [usize; 5] = [8, 16, 32, 64, 128];
    const DELETIONS_FACTOR: f32 = 0.05;
    const ADDITIONS_FACTOR: f32 = 0.20;
    const SAMPLE_SIZE: usize = 10;
    // Run benchmark.
    let mut group = c.benchmark_group("update_witnesses");
    for bucket_size in BUCKET_SIZES {
        let params = UpdateWitnessesParams {
            bucket_size: bucket_size,
            deletions_count: (bucket_size as f32 * DELETIONS_FACTOR) as usize,
            additions_count: (bucket_size as f32 * ADDITIONS_FACTOR) as usize,
        };
        group.sample_size(SAMPLE_SIZE);
        group.sampling_mode(SamplingMode::Flat);
        group.throughput(Throughput::Elements(bucket_size as u64));
        group.measurement_time(Duration::from_secs(20));
        group.bench_with_input(
            BenchmarkId::from_parameter(bucket_size),
            &params,
            update_witnesses,
        );
    }
    group.finish();
}
 
criterion_group!(benches, bench);
criterion_main!(benches);
