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
use clacc::{Accumulator, Update, Witness};

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
    let statics_count = args.bucket_size - deletions_count;
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
    // Create storage for element-witness pairs.
    let mut deletions: Vec<(Vec<u8>, Witness<BigIntGmp>)> = vec![
        Default::default(); deletions_count
    ];
    let mut statics: Vec<(Vec<u8>, Witness<BigIntGmp>)> = vec![
        Default::default(); statics_count
    ];
    let mut additions: Vec<(Vec<u8>, Witness<BigIntGmp>)> = vec![
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
        acc.add::<MapBlake2b, U16>(&deletion.0);
    }
    for stat in statics.iter() {
        acc.add::<MapBlake2b, U16>(&stat.0);
    }
    // Generate witnesses for static elements.
    for stat in statics.iter_mut() {
        stat.1 = acc.prove::<MapBlake2b, U16>(&stat.0).unwrap();
    }
    // Save accumulation at current state.
    let prev = acc.clone();
    // Accumulate deletions.
    for deletion in deletions.iter_mut() {
        deletion.1 = acc.prove::<MapBlake2b, U16>(&deletion.0).unwrap();
        acc.del::<MapBlake2b, U16>(&deletion.0, &deletion.1).unwrap();
    }
    // Accumulate additions.
    for addition in additions.iter_mut() {
        addition.1 = acc.add::<MapBlake2b, U16>(&addition.0);
        // Use the saved accumulation as the witness value.
        addition.1.set_value(prev.get_value());
    }

    //
    // RUN SIMULATION
    //

    // Batch updates.
    let mut update = Update::new();
    for deletion in deletions.iter() {
        update.del::<MapBlake2b, U16>(&deletion.0, &deletion.1);
    }
    for addition in additions.iter() {
        update.add::<MapBlake2b, U16>(&addition.0, &addition.1);
    }
    // Update witnesses.
    let now = Instant::now();
    update.update_witnesses::<MapBlake2b, U16, _, _>(
        &acc,
        statics.iter_mut(),
        additions.iter_mut(),
        thread_count
    )?;
    let duration_micros = now.elapsed().as_micros();
    // Verify results.
    if args.verify {
        for stat in statics.iter() {
            acc.verify::<MapBlake2b, U16>(&stat.0, &stat.1).unwrap();
        }
        for addition in additions.iter() {
            acc.verify::<MapBlake2b, U16>(&addition.0, &addition.1).unwrap();
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
