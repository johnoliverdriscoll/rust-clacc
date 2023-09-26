//! This is a Rust implementanion of a CL universal accumulator as described
//! in [Efficient oblivious transfer with membership verification][1].
//!
//! An accumulation is a fixed size digest that, along with the witness of an
//! element's addition, can be used to prove an element is a member of a set.
//! The drawback to this solution is that any state changes to the
//! accumulation invalidate the witneses of the other elements in the set,
//! requiring computational resources to update them.
//!
//! The benefit of CL accumulators is that they support efficient untrusted 
//! witness updates. The resource intensive task of updating witnesses can be
//! outsourced to an untrusted party without sacrificing the integrity of the
//! accumulator.
//!
//! This project is focused on a use case where a central authority is both
//! memory- and processing-constrained. The authority controls the private key
//! and is able to add and delete elements while untrusted workers are able to
//! recalculate witnesses provided they have access to the previous witnesses,
//! the current state of the accumulator, and its public key.
//!
//! # Backends
//! This crate is built with a modular integer type backend. Integer types must
//! implement the [`BigInt`] trait. 
//!
//! # Optional Features
//! - `bigint` (default): Enable this feature to support
//!   [`::num_bigint::BigInt`] as an integer type. [`::num_bigint`] is
//!   a pure Rust big integer library.
//! - `gmp`: Enable this feature to support [`::gmp::mpz::Mpz`] as an
//!   integer type. [`::gmp`] is not a pure Rust library, but it is
//!   currently more performant than [`::num_bigint`].
//!
//! [1]: https://journals.sagepub.com/doi/pdf/10.1177/1550147719875645
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::sync::{Arc, Mutex};

#[cfg(feature = "gmp")]
pub mod gmp;

#[cfg(feature = "bigint")]
pub mod bigint;

/// The accumulator base.
const BASE: i64 = 65537;

/// A trait describing an arbitrary precision integer.
pub trait BigInt:
    Clone
    + Sized
    + Send
    + Sync
    + Eq
    + PartialOrd
    + std::ops::Neg
    + std::ops::Add<Output = Self>
    + std::ops::Sub<Output = Self>
    + std::ops::Mul<Output = Self>
    + std::ops::Rem<Output = Self>
    + std::ops::MulAssign
    + std::ops::DivAssign
{
    /// Constructs a [`BigInt`] from an i64.
    fn from_i64(v: i64) -> Self;

    /// Constructs a [`BigInt`] from a slice of bytes, with the most
    /// significant byte first.
    fn from_bytes_be(bytes: &[u8]) -> Self;

    /// Constructs a byte vector of the [`BigInt`] with the most significant
    /// byte first.
    fn to_bytes_be(&self) -> Vec<u8>;

    /// Returns (g, a, b) where `g` is the greatest common divisor of `self`
    /// and `y` satisfying `g = a * self + b * y`.
    fn gcdext<'a>(&self, y: &'a Self) -> (Self, Self, Self);

    /// Returns `self^e (mod m)`.
    fn powm<'a>(&self, e: &'a Self, m: &Self) -> Self;

    /// Returns the next prime greater than `self`.
    fn next_prime(&self) -> Self;

    /// Returns the size of `self` in bits.
    fn size_in_bits(&self) -> usize;
}

/// An accumulator.
///
/// Elements may be added and deleted from the acculumator without increasing
/// the size of its internal parameters. That is, the bit depth in the
/// accumulation `z` will never exceed the bit depth in the modulus `n`.
#[derive(Clone)]
pub struct Accumulator<T: BigInt> {

    /// Private exponent.
    d: Option<T>,

    /// Modulus.
    n: T,

    /// The current accumulation value.
    z: T,
}

impl<T: BigInt> Accumulator<T> {

    /// Initialize an accumulator from private key parameters. All
    /// accumulators are able to add elements and verify witnesses. An
    /// accumulator constructed from a private key is able to delete elements
    /// and prove elements after their addition.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let acc = Accumulator::<BigInt>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// ```
    pub fn with_private_key(p: T, q: T) -> Self {
        let bn1 = T::from_i64(1);
        Accumulator {
            d: Some((p.clone() - bn1.clone()) * (q.clone() - bn1.into())),
            n: p * q,
            z: T::from_i64(BASE),
        }
    }

    /// Create an accumulator from a randomly generated private key and return
    /// it along with the generated key parameters.
    ///
    /// If `key_bits` is `None`, the bit size of the generated modulus is
    /// 3072.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     BigInt as BigIntTrait,
    /// };
    /// use num_bigint::BigInt;
    /// use rand::RngCore;
    /// let mut rng = rand::thread_rng();
    /// let acc = Accumulator::<BigInt>::with_random_key(
    ///     |bytes| rng.fill_bytes(bytes),
    ///     Some(256),
    /// ).0;
    /// assert_eq!(acc.get_public_key().size_in_bits(), 256);
    /// ```
    pub fn with_random_key<F: FnMut(&mut [u8])>(
        mut fill_bytes: F,
        key_bits: Option<usize>,
    ) -> (Self, T, T) {
        let mod_bits = match key_bits {
            Some(bits) => bits,
            None => 3072,
        };
        let prime_bytes = (mod_bits + 7) / 16;
        let mut p;
        let mut q;
        let mut bytes = vec![0; prime_bytes];
        loop {
            fill_bytes(&mut bytes);
            p = T::from_bytes_be(bytes.as_slice()).next_prime();
            fill_bytes(&mut bytes);
            q = T::from_bytes_be(bytes.as_slice()).next_prime();
            if (p.clone() * q.clone()).size_in_bits() != mod_bits {
                continue;
            }
            if p.clone() < q.clone() {
                std::mem::swap(&mut p, &mut q);
            }
            break;
        }
        (Accumulator::<T>::with_private_key(p.clone(), q.clone()), p, q)
    }

    /// Initialize an accumulator from a public key. An accumulator
    /// constructed from a public key is only able to add elements and verify
    /// witnesses.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// let n = vec![0x0c, 0xa1];
    /// let acc = Accumulator::<BigInt>::with_public_key(
    ///    <BigInt as clacc::BigInt>::from_bytes_be( n.as_slice()),
    /// );
    /// ```
    pub fn with_public_key(n: T) -> Self {
        Accumulator {
            d: None,
            n: n,
            z: T::from_i64(BASE),
        }
    }

    /// Get an accumulator's public key.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// assert_eq!(
    ///   acc.get_public_key(),
    ///   <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice()),
    /// );
    /// ```
    pub fn get_public_key(&self) -> T {
        self.n.clone()
    }

    /// Add a prime to an accumulator.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// use rand::RngCore;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice()),
    /// );
    /// let x = <BigInt as clacc::BigInt>::from_i64(3);
    /// let w = acc.add(&x);
    /// assert!(acc.verify(&x, &w).is_ok());
    /// ```
    ///
    /// This works with accumulators constructed from a public key or a
    /// private key.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// let x = <BigInt as clacc::BigInt>::from_i64(3);
    /// let w = acc.add(&x);
    /// assert!(acc.verify(&x, &w).is_ok());
    /// ```
    pub fn add(
        &mut self,
        x: &T,
    ) -> T {
        let w = self.z.clone();
        self.z = self.z.powm(&x, &self.n);
        w
    }

    /// Delete a prime from an accumulator.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// let x = <BigInt as clacc::BigInt>::from_i64(7);
    /// let w = acc.add(&x);
    /// assert!(acc.del(&x).is_ok());
    /// assert!(acc.verify(&x, &w).is_err());
    /// ```
    ///
    /// This will only succeed with an accumulator constructed from a private
    /// key.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice())
    /// );
    /// let x = <BigInt as clacc::BigInt>::from_i64(3);
    /// acc.add(&x);
    /// assert!(acc.del(&x).is_err());
    /// ```
    pub fn del(
        &mut self,
        x: &T,
    ) -> Result<T, Error> {
        let d = match self.d.as_ref() {
            Some(d) => d,
            None => {
                return Err(Error { source: Box::new(ErrorMissingPrivateKey) });
            },
        };
        let x_i = x.powm(&T::from_i64(-1), &d);
        self.z = self.z.powm(&x_i, &self.n);
        Ok(self.z.clone())
    }

    /// Generate a witness to a prime's addition to the accumulation.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// let x = <BigInt as clacc::BigInt>::from_i64(7);
    /// acc.add(&x);
    /// let u = acc.prove(&x).unwrap();
    /// assert!(acc.verify(&x, &u).is_ok());
    /// ```
    ///
    /// This will only succeed with an accumulator constructed from a private
    /// key.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice()),
    /// );
    /// let x = <BigInt as clacc::BigInt>::from_i64(7);
    /// acc.add(&x);
    /// assert!(acc.prove(&x).is_err());
    /// ```
    pub fn prove(
        &self,
        x: &T,
    ) -> Result<T, Error> {
        match self.d.as_ref() {
            Some(d) => {
                let x_i = x.powm(&T::from_i64(-1), &d);
                Ok(self.z.powm(&x_i, &self.n))
            },
            None => Err(Error { source: Box::new(ErrorMissingPrivateKey) })
        }
    }

    /// Verify a prime is a member of an accumulator.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice()),
    /// );
    /// let x = <BigInt as clacc::BigInt>::from_i64(3);
    /// let u = acc.add(&x);
    /// assert!(acc.verify(&x, &u).is_ok());
    /// ```
    ///
    /// This works with accumulators constructed from a public key or a
    /// private key.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// let x = <BigInt as clacc::BigInt>::from_i64(3);
    /// let w = acc.add(&x);
    /// assert!(acc.verify(&x, &w).is_ok());
    /// ```
    pub fn verify(
        &self,
        x: &T,
        w: &T,
    ) -> Result<(), Error> {
        let w_x = w.powm(x, &self.n);
        if self.z != w_x {
            Err(Error { source: Box::new(ErrorElementNotFound) })
        } else {
            Ok(())
        }
    }

    /// Return the accumulation value as a [`BigInt`].
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice()),
    /// );
    /// let x = <BigInt as clacc::BigInt>::from_i64(3);
    /// let y = <BigInt as clacc::BigInt>::from_i64(5);
    /// // Add an element.
    /// acc.add(&x);
    /// // Save the current accumulation. This value is effectively
    /// // a witness for the next element added.
    /// let w = acc.get_value().clone();
    /// // Add another element.
    /// acc.add(&y);
    /// // Verify that `w` is a witness for `y`.
    /// assert!(acc.verify(&y, &w).is_ok());
    /// ```
    pub fn get_value(
        &self,
    ) -> T {
        self.z.clone()
    }

    /// Set the accumulation value from a [`BigInt`].
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc_prv = Accumulator::<BigInt>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc_pub = Accumulator::<BigInt>::with_public_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice()),
    /// );
    /// let x = <BigInt as clacc::BigInt>::from_i64(3);
    /// let w = acc_prv.add(&x);
    /// acc_pub.set_value(&acc_prv.get_value());
    /// assert!(acc_prv.verify(&x, &w).is_ok());
    /// ```
    pub fn set_value(
        &mut self,
        z: &T,
    ) {
        self.z = z.clone();
    }

}

/// A sum of updates to be applied to witnesses.
#[derive(Default)]
#[derive(Clone)]
pub struct Update<T: BigInt> {
    n: T,
    z: T,
    pi_a: T,
    pi_d: T,
}

impl<'u, T: 'u + BigInt> Update<T> {

    /// Create a new batched update.
    pub fn new(
        acc: &Accumulator<T>,
    ) -> Self {
        let bn1 = T::from_i64(1);
        Update {
            n: acc.get_public_key(),
            z: acc.get_value(),
            pi_a: bn1.clone(),
            pi_d: bn1.clone(),
        }
    }

    /// Absorb a prime that must be added to a witness.
    pub fn add(
        &mut self,
        x: &T,
    ) {
        self.pi_a *= x.clone();
    }

    /// Absorb a prime that must be deleted from a witness.
    pub fn del(
        &mut self,
        x: &T,
    ) {
        self.pi_d *= x.clone();
    }

    /// Undo an absorbed prime's addition into an update.
    pub fn undo_add(
        &mut self,
        x: &T,
    ) {
        self.pi_a /= x.clone();
    }

    /// Undo an absorbed prime's deletion from an update.
    pub fn undo_del(
        &mut self,
        x: &T,
    ) {
        self.pi_d /= x.clone();
    }

    /// Update a witness. The update will include all additions and deletions
    /// previously absorbed into this update struct.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     Update,
    /// };
    /// use num_bigint::BigInt;
    /// // In this example, the update will include a deletion, so the
    /// // accumulator must be created with a private key.
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// // Create the static elements.
    /// let xs = <BigInt as clacc::BigInt>::from_i64(5);
    /// // Create the deletion.
    /// let xd = <BigInt as clacc::BigInt>::from_i64(7);
    /// // Create the addition.
    /// let xa = <BigInt as clacc::BigInt>::from_i64(11);
    /// // Add the deletion element.
    /// acc.add(&xd);
    /// // Add the static element to the accumulator.
    /// let mut wxs = acc.add(&xs);
    /// // Delete the deletion element from the accumulator.
    /// acc.prove(&xd).unwrap();
    /// acc.del(&xd).unwrap();
    /// // Add the addition element to the accumulator.
    /// acc.add(&xa);
    /// // Create an update object and absorb the addition and deletion.
    /// let mut u = Update::new(&acc);
    /// u.del(&xd);
    /// u.add(&xa);
    /// // Update the static element's witness.
    /// wxs = u.update_witness(&xs, &wxs);
    /// assert!(acc.verify(&xs, &wxs).is_ok());
    /// ```
    pub fn update_witness(
        &self,
        x: &T,
        w: &T,
    ) -> T {
        let (_, a, b) = self.pi_d.gcdext(&x);
        (w.powm(&(a * self.pi_a.clone()), &self.n)
         * self.z.powm(&b, &self.n))
            % self.n.clone()
    }

    /// Thread-safe method that updates multiple witnesses.
    ///
    /// It is assumed that the additional elements have been absorbed by the
    /// update and that their witnesses are the accumulator's value before any
    /// of the additions or deletions absorbed by this update were applied.
    /// Updating the witnesses for each of these additional elements is thus
    /// achieved by simply removing its respective element from the update and
    /// applying the result to its witness.
    ///
    /// This method operates on atomic references to iterators over collections
    /// of element-witness pairs. An invocation will run until the referenced
    /// iterators have reached the end of their collections. To update
    /// witnesses concurrently, simply invoke this method from multiple threads
    /// using references to the same iterators.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     BigInt as BigIntTrait,
    ///     Update,
    /// };
    /// use num_bigint::BigInt;
    /// use crossbeam::thread;
    /// use num_cpus;
    /// use rand::RngCore;
    /// use std::sync::{Arc, Mutex};
    /// // Create elements.
    /// const BUCKET_SIZE: usize = 20;
    /// const DELETIONS_COUNT: usize = 2;
    /// const ADDITIONS_COUNT: usize = 10;
    /// const STATICELS_COUNT: usize = BUCKET_SIZE - DELETIONS_COUNT;
    /// let mut deletions: Vec<(BigInt, BigInt)> = vec![
    ///     Default::default(); DELETIONS_COUNT
    /// ];
    /// let mut additions: Vec<(BigInt, BigInt)> = vec![
    ///     Default::default(); ADDITIONS_COUNT
    /// ];
    /// let mut staticels: Vec<(BigInt, BigInt)> = vec![
    ///     Default::default(); STATICELS_COUNT
    /// ];
    /// let mut rng = rand::thread_rng();
    /// let mut bytes = vec![0; 8];
    /// for deletion in deletions.iter_mut() {
    ///     rng.fill_bytes(&mut bytes);
    ///     let x = <BigInt as clacc::BigInt>::from_bytes_be(bytes.as_slice());
    ///     deletion.0 = x.next_prime();
    /// }
    /// for addition in additions.iter_mut() {
    ///     rng.fill_bytes(&mut bytes);
    ///     let x = <BigInt as clacc::BigInt>::from_bytes_be(bytes.as_slice());
    ///     addition.0 = x.next_prime();
    /// }
    /// for staticel in staticels.iter_mut() {
    ///     rng.fill_bytes(&mut bytes);
    ///     let x = <BigInt as clacc::BigInt>::from_bytes_be(bytes.as_slice());
    ///     staticel.0 = x.next_prime();
    /// }
    /// // Create accumulator with private key.
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// // Accumulate elements.
    /// for (x, _) in deletions.iter() {
    ///     acc.add(&x);
    /// }
    /// for (x, _) in staticels.iter() {
    ///     acc.add(&x);
    /// }
    /// // Generate witnesses for static elements.
    /// for (x, w) in staticels.iter_mut() {
    ///     *w = acc.prove(&x).unwrap()
    /// }
    /// // Save accumulation at current state.
    /// let prev = acc.clone();
    /// // Accumulate deletions.
    /// for (x, w) in deletions.iter_mut() {
    ///     *w = acc.prove(&x).unwrap();
    ///     acc.del(&x).unwrap();
    /// }
    /// // Accumulate additions.
    /// for (x, w) in additions.iter_mut() {
    ///     acc.add(&x);
    ///     // Use the saved accumulation as the witness value.
    ///     *w = prev.get_value();
    /// }
    /// // Batch updates.
    /// let mut update = Update::new(&acc);
    /// for (x, _) in deletions.iter() {
    ///     update.del(&x);
    /// }
    /// for (x, _) in additions.iter() {
    ///     update.add(&x);
    /// }
    /// // Update all witnesses concurrently.
    /// let additions_iter = Arc::new(Mutex::new(additions.iter_mut()));
    /// let staticels_iter = Arc::new(Mutex::new(staticels.iter_mut()));
    /// thread::scope(|scope| {
    ///     for _ in 0..num_cpus::get() {
    ///         let u = update.clone();
    ///         let add = Arc::clone(&additions_iter);
    ///         let sta = Arc::clone(&staticels_iter);
    ///         scope.spawn(move |_| u.update_witnesses(add, sta));
    ///     }
    /// }).unwrap();
    /// // Verify all updated witnesses.
    /// for (x, w) in additions.iter() {
    ///     assert!(acc.verify(&x, &w).is_ok());
    /// }
    /// for (x, w) in staticels.iter() {
    ///     assert!(acc.verify(&x, &w).is_ok());
    /// }
    /// ```
    pub fn update_witnesses<
        IA: Iterator<Item = &'u mut (T, T)> + Send,
        IS: Iterator<Item = &'u mut (T, T)> + Send
    >(
        &self,
        additions: Arc<Mutex<IA>>,
        staticels: Arc<Mutex<IS>>,
    ) {
        loop {
            let (x, w, is_static) = {
                match staticels.lock().unwrap().next() {
                    Some((x, w)) => (x, w, true),
                    None => {
                        match additions.lock().unwrap().next() {
                            Some((x, w)) => (x, w, false),
                            None => break,
                        }
                    }
                }
            };
            let mut u = self;
            let mut clone;
            if !is_static {
                clone = self.clone();
                clone.undo_add(x);
                u = &clone;
            }
            *w = u.update_witness(&x, &w);
        }
    }
}

trait DisplayError: std::fmt::Display + std::fmt::Debug {}

/// The error type which is returned from peforming accumulator operations.
#[derive(Debug)]
pub struct Error {
    source: Box<dyn DisplayError>,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&*self.source, f)
    }
}

#[derive(Debug)]
struct ErrorMissingPrivateKey;

impl DisplayError for ErrorMissingPrivateKey {}

impl std::fmt::Display for ErrorMissingPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Missing private key")
    }
}

#[derive(Debug)]
struct ErrorElementNotFound;

impl DisplayError for ErrorElementNotFound {}

impl std::fmt::Display for ErrorElementNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Element not found")
    }
}
