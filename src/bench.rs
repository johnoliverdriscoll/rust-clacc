//! Benchmark the performance of updating witnesses with respect to a variable
//! bucket size of static elements and turnover amount.
use clacc::{
    Accumulator, Update, Witness, RawSerializer as Raw,
    blake2::Mapper,
    gmp::BigInt,
    typenum::U16,
};
use criterion::{
    BenchmarkId,
    Criterion,
    SamplingMode,
    Throughput,
    criterion_group, criterion_main,
};
use num_cpus;
use rand::RngCore;

mod primes;

fn bench(c: &mut Criterion) {
    let additions_factor = 0.20;
    let deletions_factor = 0.05;
    let mut group = c.benchmark_group("update_witnesses");
    for bucket_size in [8, 16, 32, 64, 128].iter() {
        group.sampling_mode(SamplingMode::Flat);
        group.sample_size(50);
        group.throughput(Throughput::Elements(*bucket_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(bucket_size),
            bucket_size,
            |b, _| {
                // Calculate witness counts.
                let additions_count = ((*bucket_size as f32) *
                                       additions_factor) as usize;
                let deletions_count = ((*bucket_size as f32) *
                                       deletions_factor) as usize;
                let statics_count = (*bucket_size as usize) - deletions_count;
                // Create accumulator with pregenerated primes.
                let mut acc = Accumulator::<BigInt>::with_private_key(
                    primes::P.to_vec().as_slice().into(),
                    primes::Q.to_vec().as_slice().into(),
                );
                // Create storage for element-witness pairs.
                let mut deletions: Vec<(Vec<u8>, Witness<BigInt>)> = vec![
                    Default::default(); deletions_count
                ];
                let mut statics: Vec<(Vec<u8>, Witness<BigInt>)> = vec![
                    Default::default(); statics_count
                ];
                let mut additions: Vec<(Vec<u8>, Witness<BigInt>)> = vec![
                    Default::default(); additions_count
                ];
                let mut rng = rand::thread_rng();
                // Generate 8 random bytes for each element.
                let mut bytes = vec![0; 8];
                for deletion in deletions.iter_mut() {
                    rng.fill_bytes(&mut bytes);
                    deletion.0 = bytes.clone();
                }
                for stat in statics.iter_mut() {
                    rng.fill_bytes(&mut bytes);
                    stat.0 = bytes.clone();
                }
                for addition in additions.iter_mut() {
                    rng.fill_bytes(&mut bytes);
                    addition.0 = bytes.clone();
                }
                // Accumulate bucket elements.
                for deletion in deletions.iter() {
                    acc.add::<Mapper, U16, Raw, _>(&deletion.0);
                }
                for stat in statics.iter() {
                    acc.add::<Mapper, U16, Raw, _>(&stat.0);
                }
                // Generate witnesses for static elements.
                for stat in statics.iter_mut() {
                    stat.1 = acc.prove::<Mapper, U16, Raw, _>(
                        &stat.0,
                    ).unwrap();
                }
                // Save accumulation at current state.
                let prev = acc.clone();
                // Accumulate deletions.
                for del in deletions.iter_mut() {
                    del.1 = acc.prove::<Mapper, U16, Raw, _>(&del.0).unwrap();
                    acc.del::<Mapper, U16, Raw, _>(&del.0, &del.1).unwrap();
                }
                // Accumulate additions.
                for addition in additions.iter_mut() {
                    addition.1 = acc.add::<Mapper, U16, Raw, _>(&addition.0);
                    // Use the saved accumulation as the witness value.
                    addition.1.set_value(prev.get_value());
                }
                // Batch updates.
                let mut update = Update::new();
                for deletion in deletions.iter() {
                    update.del::<Mapper, U16, Raw, _>(
                        &deletion.0,
                        &deletion.1,
                    );
                }
                for addition in additions.iter() {
                    update.add::<Mapper, U16, Raw, _>(
                        &addition.0,
                        &addition.1,
                    );
                }
                // Update.
                b.iter(|| update.update_witnesses::<Mapper, U16, Raw, _, _, _>(
                    &acc,
                    statics.iter_mut(),
                    additions.iter_mut(),
                    num_cpus::get(),
                ).unwrap());
            },
        );
    }
    group.finish();
}
 
criterion_group!(benches, bench);
criterion_main!(benches);
