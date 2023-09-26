//! Benchmark the performance of updating witnesses with respect to a variable
//! bucket size of elements with turnover.
use clacc::{
    Accumulator,
    Update,
};
use criterion::{
    BatchSize::SmallInput,
    Bencher,
    BenchmarkId,
    Criterion,
    SamplingMode,
    Throughput,
    criterion_group,
    criterion_main,
};
use crossbeam::thread;
use gmp::mpz::Mpz;
use num_bigint::BigInt;
use num_cpus;
use rand::RngCore;
use std::sync::{Arc, Mutex};

struct UpdateWitnessesParams {
    element_size: usize,
    bucket_size: usize,
    deletions_count: usize,
    additions_count: usize,
}

const P: [u8; 192] = [
    0xdf, 0x02, 0x4a, 0x0a, 0x60, 0x19, 0xdf, 0x89,
    0xd0, 0x2f, 0xf1, 0x0d, 0xfa, 0xb3, 0x97, 0x86,
    0xe4, 0x2e, 0xad, 0x87, 0xb0, 0xf8, 0x56, 0x57,
    0x50, 0x82, 0x23, 0x10, 0x73, 0x39, 0xb5, 0xe3,
    0x8c, 0xb7, 0x32, 0x97, 0x90, 0x7c, 0x17, 0xa5,
    0xe1, 0xec, 0x71, 0xf1, 0x0e, 0xd2, 0xfe, 0xfc,
    0x0c, 0x0f, 0x54, 0x9f, 0x0c, 0x0d, 0x53, 0x06,
    0x57, 0xbd, 0x55, 0x92, 0x56, 0xf7, 0x6d, 0x7c,
    0xe1, 0x7d, 0x5f, 0x4e, 0x8e, 0x00, 0xa4, 0x9d,
    0xdc, 0xda, 0x19, 0xc9, 0xc6, 0xef, 0xdc, 0xc1,
    0xfb, 0x5b, 0x2e, 0x20, 0xc9, 0x2f, 0x70, 0x56,
    0xcc, 0x4c, 0x16, 0xb8, 0x96, 0xa5, 0x67, 0x3f,
    0xf0, 0x7c, 0xbc, 0x22, 0x75, 0x29, 0x91, 0xbf,
    0x01, 0xae, 0x0f, 0x37, 0xce, 0x57, 0xe1, 0x29,
    0x07, 0x48, 0x7b, 0x07, 0x7d, 0x00, 0x85, 0x3b,
    0xe6, 0xbc, 0x7a, 0x7d, 0xd9, 0xb0, 0x69, 0x93,
    0x11, 0xff, 0x9f, 0x7d, 0x62, 0x72, 0xfb, 0x89,
    0x2e, 0x71, 0x39, 0x57, 0x34, 0x23, 0x1d, 0xaf,
    0xae, 0x00, 0x82, 0x86, 0xc2, 0x62, 0x9a, 0xc1,
    0x41, 0xdd, 0x31, 0xd3, 0x45, 0xa7, 0xbe, 0x83,
    0x3c, 0x5f, 0x72, 0xfd, 0x1c, 0x72, 0x17, 0x76,
    0x42, 0x06, 0xc1, 0x49, 0x6f, 0xcf, 0x4c, 0x4a,
    0x18, 0x59, 0x5b, 0x57, 0x1d, 0x0f, 0x3b, 0x90,
    0xc6, 0x3c, 0x07, 0xf7, 0x65, 0x40, 0x46, 0xbb,
];

const Q: [u8; 192] = [
    0xad, 0x77, 0x4a, 0xe1, 0x00, 0xe0, 0x44, 0x08,
    0x9e, 0xfe, 0xa2, 0x11, 0x54, 0xe7, 0x98, 0x48,
    0x43, 0x02, 0x4a, 0x4d, 0xa0, 0xf2, 0xb5, 0xfc,
    0xac, 0x03, 0x04, 0xd0, 0x80, 0xc1, 0x24, 0x84,
    0x8b, 0x10, 0x6e, 0x05, 0x32, 0xa9, 0x4f, 0xca,
    0x56, 0x79, 0xca, 0xf4, 0xa3, 0xc8, 0xb8, 0xc7,
    0x4a, 0xe6, 0x61, 0xf7, 0xd9, 0x7a, 0xde, 0xdd,
    0x5d, 0x9d, 0xc5, 0x65, 0x30, 0x92, 0x64, 0xca,
    0x5d, 0x01, 0xfb, 0xf0, 0xb7, 0x30, 0x07, 0x12,
    0x30, 0x08, 0x94, 0x20, 0xf2, 0xf3, 0xf6, 0xda,
    0x37, 0xed, 0x22, 0x3e, 0x29, 0xe0, 0x0f, 0x6b,
    0x78, 0x2b, 0x62, 0x7b, 0x9b, 0x6f, 0x12, 0xe4,
    0xc7, 0x1e, 0x57, 0x48, 0x6c, 0xa2, 0x5f, 0x9f,
    0x52, 0xee, 0x8d, 0xf6, 0x4e, 0x00, 0x37, 0x0c,
    0xfc, 0xb2, 0x83, 0x25, 0x0b, 0x0c, 0x05, 0x13,
    0xfd, 0x78, 0x0b, 0x64, 0x2e, 0xb1, 0xcb, 0x49,
    0x6d, 0xda, 0xe8, 0x0c, 0x21, 0xf5, 0x85, 0x6b,
    0x94, 0xdc, 0x96, 0x59, 0xa1, 0x31, 0x77, 0x8f,
    0x67, 0x72, 0x5d, 0xb2, 0xa6, 0xea, 0xf7, 0x03,
    0x79, 0xeb, 0x54, 0x3b, 0x0d, 0xa8, 0x00, 0xa2,
    0x0b, 0xb9, 0xd7, 0xd9, 0x83, 0xa2, 0x4e, 0x2c,
    0x3c, 0x01, 0xcd, 0x01, 0x28, 0x38, 0xb2, 0x3d,
    0xcd, 0x53, 0x1d, 0x00, 0xc4, 0xcc, 0x88, 0xd1,
    0x95, 0x0d, 0xbf, 0x4d, 0xc4, 0xc4, 0x01, 0xc7,
];

fn update_witnesses_bench<'r, 's, 't0, T: clacc::BigInt>(
    bencher: &'r mut Bencher<'s>,
    params: &'t0 UpdateWitnessesParams,
) {
    let staticels_count = params.bucket_size - params.deletions_count;
    bencher.iter_batched(|| {
        let mut deletions: Vec<(T, T)> = vec![
            (T::from_i64(0), T::from_i64(0)); params.deletions_count
        ];
        let mut additions: Vec<(T, T)> = vec![
            (T::from_i64(0), T::from_i64(0)); params.additions_count
        ];
        let mut staticels: Vec<(T, T)> = vec![
            (T::from_i64(0), T::from_i64(0)); staticels_count
        ];
        // Generate random elements.
        let del = Arc::new(Mutex::new(deletions.iter_mut()));
        let add = Arc::new(Mutex::new(additions.iter_mut()));
        let sta = Arc::new(Mutex::new(staticels.iter_mut()));
        thread::scope(|scope| {
            for _ in 0..num_cpus::get() {
                let del = Arc::clone(&del);
                let add = Arc::clone(&add);
                let sta = Arc::clone(&sta);
                scope.spawn(move |_| {
                    let mut rng = rand::thread_rng();
                    loop {
                        let x = match del.lock().unwrap().next() {
                            Some((x, _)) => x,
                            None => match sta.lock().unwrap().next() {
                                Some((x, _)) => x,
                                None => match add.lock().unwrap().next() {
                                    Some((x, _)) => x,
                                    None => break,
                                }
                            }
                        };
                        let mut bytes = vec![0; params.element_size];
                        rng.fill_bytes(&mut bytes);
                        let e = T::from_bytes_be(bytes.as_slice());
                        *x = e.next_prime();
                    }
                });
            }
        }).unwrap();
        // Create accumulator.
        let mut acc = Accumulator::<T>::with_private_key(
            T::from_bytes_be(P.to_vec().as_slice()),
            T::from_bytes_be(Q.to_vec().as_slice()),
        );
        // Accumulate bucket elements.
        for (x, _) in deletions.iter() {
            acc.add(x);
        }
        for (x, _) in staticels.iter() {
            acc.add(x);
        }
        // Generate witnesses for deletions and static elements.
        let del = Arc::new(Mutex::new(deletions.iter_mut()));
        let sta = Arc::new(Mutex::new(staticels.iter_mut()));
        thread::scope(|scope| {
            for _ in 0..num_cpus::get() {
                let acc = acc.clone();
                let del = Arc::clone(&del);
                let sta = Arc::clone(&sta);
                scope.spawn(move |_| {
                    loop {
                        let (x, w) = match del.lock().unwrap().next() {
                            Some(pair) => pair,
                            None => match sta.lock().unwrap().next() {
                                Some(pair) => pair,
                                None => break,
                            }
                        };
                        *w = acc.prove(x).unwrap();
                    }
                });
            }
        }).unwrap();
        // Save accumulation at current state.
        let prev = acc.clone();
        // Remove deletions.
        for (x, _) in deletions.iter_mut() {
            acc.del(x).unwrap();
        }
        // Accumulate additions.
        for (x, w) in additions.iter_mut() {
            acc.add(&x);
            // Use the saved accumulation as the witness value.
            *w = prev.get_value();
        }
        // Batch updates.
        let mut update = Update::new(&acc);
        for (x, _) in deletions.iter() {
            update.del(x);
        }
        for (x, _) in additions.iter() {
            update.add(x);
        }
        (update, additions, staticels)
    }, |(update, mut additions, mut staticels)| {
        let additions = Arc::new(Mutex::new(additions.iter_mut()));
        let staticels = Arc::new(Mutex::new(staticels.iter_mut()));
        thread::scope(|scope| {
            for _ in 0..num_cpus::get() {
                let u = update.clone();
                let add = Arc::clone(&additions);
                let sta = Arc::clone(&staticels);
                scope.spawn(move |_| u.update_witnesses(add, sta));
            }
        }).unwrap();
    }, SmallInput);
}

fn bench(c: &mut Criterion) {
    // Benchmark constants.
    const ELEMENT_SIZE: usize = 16;
    const BUCKETS_COUNT: usize = 16;
    const DELETIONS_FACTOR: f32 = 0.05;
    const ADDITIONS_FACTOR: f32 = 0.20;
    // Create benchmark groups.
    let mut group = c.benchmark_group("update_witnesses");
    // Create bucket sizes.
    for e in 0..BUCKETS_COUNT {
        let bucket_size = 1 << e;
        let params = UpdateWitnessesParams {
            element_size: ELEMENT_SIZE,
            bucket_size: bucket_size,
            deletions_count: (bucket_size as f32 * DELETIONS_FACTOR) as usize,
            additions_count: (bucket_size as f32 * ADDITIONS_FACTOR) as usize,
        };
        group.sampling_mode(SamplingMode::Flat);
        group.throughput(Throughput::Elements(bucket_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("BigInt/{}", bucket_size)),
            &params,
            update_witnesses_bench::<BigInt>,
        );
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Mpz/{}", bucket_size)),
            &params,
            update_witnesses_bench::<Mpz>,
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
