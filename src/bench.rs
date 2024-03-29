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
    Throughput,
    criterion_group,
    criterion_main,
};
use crossbeam::thread;
use gmp::mpz::Mpz;
use num_bigint::{BigInt, ToBigInt};
use num_cpus;
use num_prime::nt_funcs::next_prime;
use rand::RngCore;
use std::sync::{Arc, Mutex};

// Number of benchmarks to perform.
const BUCKETS_COUNT: usize = 6;

// Number of witnesses to be updated.
const BUCKET_SIZE: usize = 100;

// Byte size of elements.
const ELEMENT_SIZE: usize = 16;

// Number of deletions over total number of elements in bucket.
const DEL_FACTOR: f32 = 0.01;

// Number of additions over total number of elements in bucket.
const ADD_FACTOR: f32 = 0.05;

// Percentage of updates that are additions.
const ADD_PERCENT: f32 = ADD_FACTOR / (DEL_FACTOR + ADD_FACTOR);

struct UpdateWitnessesParams {
    staticels_count: usize,
    deletions_count: usize,
    additions_count: usize,
}

const N: [u8; 384] = [
    0x97, 0x1c, 0x77, 0x54, 0x18, 0xf1, 0x98, 0x41,
    0xe3, 0x6d, 0xde, 0x21, 0x38, 0x14, 0xdd, 0x59,
    0x23, 0x96, 0x61, 0xb0, 0x64, 0x45, 0x6d, 0x76,
    0x3f, 0xbf, 0x55, 0x76, 0x72, 0x8f, 0xa0, 0x35,
    0x3c, 0xcb, 0xda, 0xab, 0xe6, 0x13, 0x0d, 0x9c,
    0xb3, 0x84, 0x30, 0x16, 0x60, 0x5c, 0x20, 0x1a,
    0xc2, 0x85, 0x01, 0xce, 0x19, 0xcb, 0xe2, 0x1c,
    0xf2, 0x6c, 0x66, 0x7b, 0xd7, 0x1c, 0x2f, 0xbd,
    0x78, 0x04, 0x77, 0x6d, 0xdf, 0xca, 0x3a, 0x35,
    0xaa, 0x60, 0x85, 0xf9, 0x0d, 0xd9, 0x00, 0x47,
    0xb6, 0xe3, 0x15, 0x92, 0xff, 0x13, 0x05, 0x2f,
    0x53, 0xee, 0xad, 0xc2, 0x06, 0x34, 0x6b, 0xa6,
    0x9a, 0x16, 0x9d, 0xe4, 0x5f, 0x4c, 0x61, 0x16,
    0x04, 0xf3, 0x7c, 0xb5, 0xc1, 0x98, 0x8d, 0xeb,
    0x8f, 0x33, 0x55, 0xbd, 0x08, 0x03, 0x87, 0x97,
    0x34, 0xef, 0xcb, 0xa3, 0x09, 0x31, 0x23, 0x65,
    0xc8, 0xdb, 0xe5, 0xc8, 0x26, 0x26, 0x1a, 0x5c,
    0x4c, 0xe9, 0xd3, 0x51, 0xf4, 0x6f, 0xa7, 0x0e,
    0x4a, 0x13, 0x87, 0xd3, 0xfa, 0x45, 0xdb, 0x4a,
    0xff, 0x6d, 0xd2, 0x13, 0xe9, 0xde, 0x04, 0x47,
    0xc2, 0xc9, 0x84, 0xdd, 0x39, 0xd3, 0xc0, 0xc1,
    0x02, 0x93, 0x59, 0x50, 0xe1, 0x87, 0xd1, 0xee,
    0xc5, 0x45, 0x86, 0x89, 0x05, 0xeb, 0x63, 0xba,
    0x36, 0xa5, 0x64, 0xda, 0x7b, 0x87, 0xb4, 0xd2,
    0x01, 0xe0, 0x87, 0x51, 0x24, 0xab, 0x8d, 0x57,
    0x55, 0x5e, 0x26, 0x75, 0xdb, 0xbc, 0xa4, 0x8f,
    0x26, 0x4f, 0x3b, 0x09, 0x71, 0xdb, 0xca, 0x9a,
    0xda, 0x64, 0xb4, 0xa4, 0x8a, 0x48, 0x20, 0xe9,
    0xfe, 0x0a, 0x79, 0x36, 0x52, 0x08, 0x30, 0xe3,
    0xd2, 0xcb, 0x93, 0x85, 0xa2, 0x0d, 0xf3, 0xba,
    0x59, 0xd7, 0x96, 0xfb, 0xdd, 0xb1, 0x71, 0x10,
    0x16, 0x41, 0x0c, 0x32, 0x65, 0x4a, 0x94, 0x9f,
    0x6e, 0xee, 0xa8, 0x03, 0x1a, 0x43, 0x87, 0x71,
    0xe6, 0x44, 0xab, 0xbd, 0xca, 0x8c, 0x73, 0x87,
    0x6a, 0xb2, 0x95, 0xe2, 0x23, 0xd4, 0xc8, 0x37,
    0x6d, 0x6e, 0xb7, 0xaf, 0x5b, 0xa5, 0x3f, 0x83,
    0x5f, 0xb0, 0x39, 0x61, 0xfc, 0xc8, 0x6a, 0x7f,
    0xd5, 0x48, 0x95, 0x34, 0x9a, 0x31, 0x32, 0xb9,
    0x0b, 0x6f, 0x18, 0xb0, 0x0d, 0xcd, 0xdf, 0xbd,
    0xb6, 0x58, 0x5d, 0x46, 0xf6, 0x03, 0x4e, 0x54,
    0xa7, 0xcd, 0xbf, 0x8b, 0xef, 0xf3, 0x82, 0x12,
    0x62, 0x48, 0x07, 0x49, 0xfc, 0xac, 0x05, 0x25,
    0x95, 0xe0, 0x0c, 0x95, 0x43, 0x5b, 0xb5, 0x08,
    0x84, 0xd9, 0x1d, 0x85, 0xb0, 0x69, 0x0a, 0x14,
    0x15, 0x46, 0x58, 0x71, 0x69, 0x2b, 0xf8, 0x00,
    0x01, 0x03, 0xde, 0x97, 0x52, 0xfd, 0x21, 0x50,
    0xc0, 0x10, 0x34, 0x5e, 0x40, 0x40, 0x38, 0x6d,
    0xaf, 0x3a, 0xaf, 0x51, 0x48, 0x69, 0xb6, 0x5d,
];

const D: [u8; 384] = [
    0x97, 0x1c, 0x77, 0x54, 0x18, 0xf1, 0x98, 0x41,
    0xe3, 0x6d, 0xde, 0x21, 0x38, 0x14, 0xdd, 0x59,
    0x23, 0x96, 0x61, 0xb0, 0x64, 0x45, 0x6d, 0x76,
    0x3f, 0xbf, 0x55, 0x76, 0x72, 0x8f, 0xa0, 0x35,
    0x3c, 0xcb, 0xda, 0xab, 0xe6, 0x13, 0x0d, 0x9c,
    0xb3, 0x84, 0x30, 0x16, 0x60, 0x5c, 0x20, 0x1a,
    0xc2, 0x85, 0x01, 0xce, 0x19, 0xcb, 0xe2, 0x1c,
    0xf2, 0x6c, 0x66, 0x7b, 0xd7, 0x1c, 0x2f, 0xbd,
    0x78, 0x04, 0x77, 0x6d, 0xdf, 0xca, 0x3a, 0x35,
    0xaa, 0x60, 0x85, 0xf9, 0x0d, 0xd9, 0x00, 0x47,
    0xb6, 0xe3, 0x15, 0x92, 0xff, 0x13, 0x05, 0x2f,
    0x53, 0xee, 0xad, 0xc2, 0x06, 0x34, 0x6b, 0xa6,
    0x9a, 0x16, 0x9d, 0xe4, 0x5f, 0x4c, 0x61, 0x16,
    0x04, 0xf3, 0x7c, 0xb5, 0xc1, 0x98, 0x8d, 0xeb,
    0x8f, 0x33, 0x55, 0xbd, 0x08, 0x03, 0x87, 0x97,
    0x34, 0xef, 0xcb, 0xa3, 0x09, 0x31, 0x23, 0x65,
    0xc8, 0xdb, 0xe5, 0xc8, 0x26, 0x26, 0x1a, 0x5c,
    0x4c, 0xe9, 0xd3, 0x51, 0xf4, 0x6f, 0xa7, 0x0e,
    0x4a, 0x13, 0x87, 0xd3, 0xfa, 0x45, 0xdb, 0x4a,
    0xff, 0x6d, 0xd2, 0x13, 0xe9, 0xde, 0x04, 0x47,
    0xc2, 0xc9, 0x84, 0xdd, 0x39, 0xd3, 0xc0, 0xc1,
    0x02, 0x93, 0x59, 0x50, 0xe1, 0x87, 0xd1, 0xee,
    0xc5, 0x45, 0x86, 0x89, 0x05, 0xeb, 0x63, 0xba,
    0x36, 0xa5, 0x64, 0xda, 0x7b, 0x87, 0xb4, 0xd0,
    0x75, 0x66, 0xf2, 0x65, 0xc3, 0xb1, 0x69, 0xc4,
    0xe6, 0x2f, 0x93, 0x56, 0x8c, 0x21, 0x74, 0xbf,
    0xff, 0x1e, 0x43, 0x34, 0x1f, 0xf0, 0xbe, 0x46,
    0xdd, 0xdf, 0x8c, 0xc3, 0x96, 0x4d, 0x46, 0x81,
    0xe6, 0x42, 0xd8, 0x99, 0x8e, 0xe2, 0xc9, 0x73,
    0x9a, 0x65, 0x56, 0x9f, 0xef, 0x72, 0x3b, 0xf7,
    0x02, 0xe1, 0xe0, 0x64, 0xf8, 0x29, 0x3f, 0x2c,
    0x60, 0xe5, 0xf1, 0x3a, 0xdd, 0xc0, 0xc2, 0x58,
    0x30, 0x6f, 0x4c, 0xc3, 0xd5, 0x12, 0xdb, 0xc1,
    0xd9, 0x61, 0xfd, 0xd3, 0x10, 0xa8, 0x9f, 0xeb,
    0x37, 0x6a, 0x45, 0x83, 0x30, 0xc5, 0x48, 0x75,
    0x28, 0xf7, 0x3e, 0x7b, 0x29, 0x90, 0xc5, 0x5e,
    0xa8, 0x15, 0x25, 0xf7, 0x1a, 0xfc, 0x79, 0x21,
    0x80, 0xab, 0xf8, 0x06, 0x7d, 0xd9, 0x1a, 0x83,
    0x07, 0x74, 0x1a, 0x83, 0x85, 0xc1, 0x55, 0x6d,
    0xd2, 0x23, 0xd7, 0x64, 0xed, 0xa1, 0x19, 0x78,
    0x27, 0xf3, 0x38, 0x02, 0x6b, 0x8b, 0x01, 0x1d,
    0x9e, 0xfa, 0x37, 0x99, 0x27, 0x57, 0x6f, 0xe6,
    0x80, 0x6d, 0x2c, 0x5b, 0xda, 0x0e, 0x23, 0x43,
    0xc9, 0x10, 0x97, 0x77, 0x5d, 0x19, 0x4a, 0xee,
    0xcd, 0x2d, 0x0d, 0x9a, 0xc9, 0x17, 0x92, 0x5d,
    0x82, 0xfb, 0x50, 0x4c, 0xba, 0xf5, 0x22, 0xc8,
    0xda, 0x63, 0xbc, 0x06, 0x5e, 0x64, 0x74, 0x0b,
    0x53, 0xf0, 0xe8, 0x0c, 0x1e, 0x65, 0x6d, 0xdc,
];

trait MapPrime {
    fn map_prime(self: &Self) -> Self;
}

impl MapPrime for BigInt {
    fn map_prime(self: &BigInt) -> BigInt {
        next_prime(
            &self.to_biguint().unwrap(),
            None,
        ).unwrap().to_bigint().unwrap()
    }
}

impl MapPrime for Mpz {
    fn map_prime(self: &Mpz) -> Mpz {
        Mpz::nextprime(self)
    }
}

fn update_witnesses_bench<'r, 's, 't0, T: clacc::BigInt + MapPrime>(
    bencher: &'r mut Bencher<'s>,
    params: &'t0 UpdateWitnessesParams,
) {
    bencher.iter_batched(|| {
        let mut deletions: Vec<(T, T)> = vec![
            (T::from_i64(0), T::from_i64(0)); params.deletions_count
        ];
        let mut additions: Vec<(T, T)> = vec![
            (T::from_i64(0), T::from_i64(0)); params.additions_count
        ];
        let mut staticels: Vec<(T, T)> = vec![
            (T::from_i64(0), T::from_i64(0)); params.staticels_count
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
                        let mut bytes = vec![0; ELEMENT_SIZE];
                        rng.fill_bytes(&mut bytes);
                        let e = T::from_bytes_be(bytes.as_slice());
                        *x = <T as MapPrime>::map_prime(&e);
                    }
                });
            }
        }).unwrap();
        // Create accumulator.
        let mut acc = Accumulator::<T>::with_private_key(
            &T::from_bytes_be(N.to_vec().as_slice()),
            &T::from_bytes_be(D.to_vec().as_slice()),
        );
        // Accumulate bucket elements.
        for (x, _) in deletions.iter() {
            acc.add(x);
        }
        for (x, _) in staticels.iter() {
            acc.add(x);
        }
        // Generate witnesses for static elements.
        let sta = Arc::new(Mutex::new(staticels.iter_mut()));
        thread::scope(|scope| {
            for _ in 0..num_cpus::get() {
                let acc = acc.clone();
                let sta = sta.clone();
                scope.spawn(move |_| {
                    loop {
                        let (x, w) = match sta.lock().unwrap().next() {
                            Some(pair) => pair,
                            None => break,
                        };
                        *w = acc.prove(x).unwrap();
                    }
                });
            }
        }).unwrap();
        // Save accumulation at current state.
        let z = acc.get_value();
        // Remove deletions.
        for (x, _) in deletions.iter_mut() {
            acc.del(x).unwrap();
        }
        // Accumulate additions.
        for (x, w) in additions.iter_mut() {
            acc.add(&x);
            // Use the saved accumulation as the witness value.
            *w = z.clone();
        }
        // Batch updates.
        let add = Arc::new(Mutex::new(additions.iter()));
        let del = Arc::new(Mutex::new(deletions.iter()));
        let add_update = Arc::new(Mutex::new(Update::new(&acc)));
        let del_update = Arc::new(Mutex::new(Update::new(&acc)));
        thread::scope(|scope| {
            // Additions and deletions can be batched in parallel.
            let add = add.clone();
            let add_update = add_update.clone();
            scope.spawn(move |_| {
                let mut add = add.lock().unwrap();
                let mut add_update = add_update.lock().unwrap();
                while let Some((x, _)) = add.next() {
                    add_update.add(x);
                }
            });
            let del = del.clone();
            let del_update = del_update.clone();
            scope.spawn(move |_| {
                let mut del = del.lock().unwrap();
                let mut del_update = del_update.lock().unwrap();
                while let Some((x, _)) = del.next() {
                    del_update.del(x);
                }
            });
        }).unwrap();
        // Create combined update.
        let update = Update::from_products(
            &acc,
            &add_update.lock().unwrap().get_add(),
            &del_update.lock().unwrap().get_del(),
        );
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
    let mut group = c.benchmark_group("update_witnesses");
    for e in 0..BUCKETS_COUNT {
        let updates_count = 4 << e;
        let add_count = (updates_count as f32 * ADD_PERCENT) as usize;
        let del_count = updates_count - add_count;
        let params = UpdateWitnessesParams {
            staticels_count: BUCKET_SIZE,
            deletions_count: del_count,
            additions_count: add_count,
        };
        group.throughput(Throughput::Elements(BUCKET_SIZE as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("BigInt/{}", updates_count)),
            &params,
            update_witnesses_bench::<BigInt>,
        );
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("Mpz/{}", updates_count)),
            &params,
            update_witnesses_bench::<Mpz>,
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
