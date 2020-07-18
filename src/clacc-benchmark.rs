//! Benchmark the performance of updating witnesses with respect to a variable
//! bucket size of static elements and turnover amount.
//! Run `clacc-benchmark -h` for options.
use std::time::Instant;
use num_cpus;
use rand::RngCore;
use structopt::StructOpt;
use clacc::mapper::MapBlake2b;
use clacc::typenum::U16;
use clacc::bigint::BigIntGmp;
use clacc::{Accumulator, Update};

mod primes;

#[derive(StructOpt)]
struct Cli {
    #[structopt(default_value = "0", short)]
    thread_count: usize,
    #[structopt(default_value = "4096", short)]
    bucket_size: usize,
    #[structopt(default_value = "0.20", short)]
    additions_factor: f32,
    #[structopt(default_value = "0.05", short)]
    deletions_factor: f32,
    #[structopt(help = "Verify results", short)]
    verify: bool,
}

fn main() -> Result<(), &'static str> {

    //
    // PROGRAM SETUP
    //

    // Parse command line options.
    let args = Cli::from_args();
    let additions_count = ((args.bucket_size as f32) *
                           args.additions_factor) as usize;
    let deletions_count = ((args.bucket_size as f32) *
                           args.deletions_factor) as usize;
    let mut thread_count = args.thread_count;
    if thread_count == 0 {
        thread_count = num_cpus::get();
    }

    //
    // SIMULATION SETUP
    //

    // Create accumulator with pregenerated primes.
    let mut acc = Accumulator::<BigIntGmp>::with_private_key(
        primes::P.to_vec().as_slice().into(),
        primes::Q.to_vec().as_slice().into(),
    );
    // Create digests.
    let mut digests: Vec<Vec<u8>> =
        Vec::with_capacity(args.bucket_size + additions_count);
    let mut rng = rand::thread_rng();
    for _ in 0..(args.bucket_size + additions_count) {
        // Generate 8 random bytes for each element.
        let mut bytes = vec![0; 8];
        rng.fill_bytes(&mut bytes);
        digests.push(bytes);
    }
    // Initialize witnesses.
    let mut witnesses = vec![
        Default::default();
        args.bucket_size + additions_count
    ];
    // Accumulate elements.
    for i in 0..args.bucket_size {
        acc.add::<MapBlake2b, U16>(&digests[i]);
    }
    // Generate witnesses for static elements.
    for i in deletions_count..args.bucket_size {
        witnesses[i] = acc.prove::<MapBlake2b, U16>(&digests[i]).unwrap();
    }
    // Save accumulation at current state.
    let prev = acc.clone();
    // Accumulate deletions.
    for i in 0..deletions_count {
        witnesses[i] = acc.prove::<MapBlake2b, U16>(&digests[i]).unwrap();
        acc.del::<MapBlake2b, U16>(&digests[i], &witnesses[i]).unwrap();
    }
    // Accumulate additions.
    for i in args.bucket_size..(args.bucket_size + additions_count) {
        witnesses[i] = acc.add::<MapBlake2b, U16>(&digests[i]);
        // Use the saved accumulation as the witness value.
        witnesses[i].u = prev.z.clone();
    }

    //
    // RUN SIMULATION
    //

    // Batch updates.
    let mut update = Update::new();
    for i in 0..deletions_count {
        update.del::<MapBlake2b, U16>(&digests[i], &witnesses[i]);
    }
    for i in args.bucket_size..(args.bucket_size + additions_count)  {
        update.add::<MapBlake2b, U16>(&digests[i], &witnesses[i]);
    }
    // Update witnesses.
    let x = digests.as_ptr();
    let w = witnesses.as_mut_ptr();
    let now = Instant::now();
    unsafe {
        match update.update_witnesses::<MapBlake2b, U16>(
            w.add(deletions_count),
            w.add(args.bucket_size),
            &acc,
            x.add(deletions_count),
            w.add(deletions_count),
            args.bucket_size - deletions_count,
            x.add(args.bucket_size),
            w.add(args.bucket_size),
            additions_count,
            thread_count
        ) {
            Ok(_) => {},
            x => {
                return x;
            },
        }
    }
    let duration_micros = now.elapsed().as_micros();
    // Verify results.
    if args.verify {
        for i in deletions_count..(args.bucket_size + additions_count) {
            match acc.verify::<MapBlake2b, U16>(&digests[i], &witnesses[i]) {
                Ok(()) => {},
                x => {
                    return x;
                },
            }
        }
    }

    //
    // REPORT RESULTS
    //

    let updated_witness_count = args.bucket_size - deletions_count
        + additions_count;
    let seconds_spent_updating_witnesses = duration_micros as f32 / 1000000.;
    let witnesses_updated_per_second = updated_witness_count as f32
        / seconds_spent_updating_witnesses;
    println!("thread_count={}", thread_count);
    println!("bucket_size={}", args.bucket_size);
    println!("additions_factor={}", args.additions_factor);
    println!("deletions_factor={}", args.deletions_factor);
    println!("verify={}", args.verify);
    println!("additions_count={}", additions_count);
    println!("deletions_count={}", deletions_count);
    println!("updated_witness_count={}", updated_witness_count);
    println!("seconds_spent_updating_witnesses={}",
             seconds_spent_updating_witnesses);
    println!("witnesses_updated_per_second={}",
             witnesses_updated_per_second);

    Ok(())
}
