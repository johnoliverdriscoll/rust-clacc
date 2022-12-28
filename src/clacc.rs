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
//! [1]: https://journals.sagepub.com/doi/pdf/10.1177/1550147719875645
use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};

#[cfg(feature = "blake2")]
pub mod blake2;

#[cfg(feature = "rust-gmp")]
pub mod gmp;

#[cfg(feature = "velocypack")]
pub mod velocypack;

/// The accumulator base.
const BASE: i64 = 65537;

/// A trait describing an arbitrary precision integer.
pub trait BigInt<'bi>:
    Default
    + From<i64>
    + for<'a> From<&'a [u8]>
    + Clone
    + Sized
    + Send
    + Sync
    + Eq
    + PartialOrd
    + Serialize
    + for <'de> Deserialize<'de>
    + std::fmt::Debug
    + std::fmt::Display
    + std::fmt::LowerHex
    + std::fmt::UpperHex
{
    /// Returns `self + other`.
    fn add<'a>(&self, other: &'a Self) -> Self;

    /// Returns `self - other`.
    fn sub<'a>(&self, other: &'a Self) -> Self;

    /// Returns `self * other`.
    fn mul<'a>(&self, other: &'a Self) -> Self;

    /// Returns `self / other`.
    fn div<'a>(&self, other: &'a Self) -> Self;

    /// Returns the greatest common divisor of `self` and the coefficients `a`
    /// and `b` satisfying `a*x + b*y = g`.
    fn gcdext<'a>(&self, y: &'a Self) -> (Self, Self, Self);

    /// Return the modulus of `self / m`.
    fn modulus<'a>(&self, m: &'a Self) -> Self;

    /// Returns `self^e mod m`.
    fn powm<'a>(&self, e: &'a Self, m: &Self) -> Self;

    /// Returns `self^-1 mod m`.
    fn invert<'a>(&self, m: &'a Self) -> Option<Self>;

    /// Returns the next prime greater than `self`.
    fn next_prime(&self) -> Self;

    /// Returns the size of the number in bits.
    fn size_in_bits(&self) -> usize;

    /// Export the number as a u8 vector.
    fn to_vec(&self) -> Vec<u8>;
}

/// A trait describing a method for converting some arbitrary data to a BigInt.
pub trait Mapper {
    fn map<T>(x: &[u8]) -> T where T: for<'a> BigInt<'a>;
}

/// An accumulator.
///
/// Elements may be added and deleted from the acculumator without increasing
/// the size of its internal parameters. That is, the number of digits in the
/// accumulation `z` will never exceed the number of digits in the modulus
/// `n`.
#[derive(Clone, Debug)]
pub struct Accumulator<T> where T: for<'a> BigInt<'a> {

    /// The current accumulation value.
    z: T,

    /// Private exponent.
    d: Option<T>,

    /// Modulus.
    n: T,
}

impl<T> Accumulator<T> where T: for<'a> BigInt<'a> {

    /// Initialize an accumulator from private key parameters. All
    /// accumulators are able to add elements and verify witnesses. An
    /// accumulator constructed from a private key is able to delete elements
    /// and prove elements after their addition.
    ///
    /// ```
    /// use clacc::{Accumulator, gmp::BigInt};
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let acc = Accumulator::<BigInt>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// ```
    pub fn with_private_key(p: T, q: T) -> Self {
        Accumulator {
            d: Some(p.sub(&1.into()).mul(&q.sub(&1.into()))),
            n: p.mul(&q),
            z: BASE.into(),
        }
    }

    /// Create an accumulator from a randomly generated private key and return
    /// it along with the generated key parameters.
    ///
    /// If `key_bits` is `None`, the bit size of the generated modulus is
    /// 3072.
    ///
    /// ```
    /// use clacc::{Accumulator, BigInt as BigIntTrait, gmp::BigInt};
    /// use rand::RngCore;
    /// let mut rng = rand::thread_rng();
    /// assert_eq!(
    ///   Accumulator::<BigInt>::with_random_key(
    ///     |bytes| rng.fill_bytes(bytes),
    ///     None,
    ///   ).0.get_public_key().size_in_bits(),
    ///   3072,
    /// );
    /// assert_eq!(
    ///   Accumulator::<BigInt>::with_random_key(
    ///     |bytes| rng.fill_bytes(bytes),
    ///     Some(1024),
    ///   ).0.get_public_key().size_in_bits(),
    ///   1024,
    /// );
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
            p = T::from(bytes.as_slice()).next_prime();
            fill_bytes(&mut bytes);
            q = T::from(bytes.as_slice()).next_prime();
            if p.mul(&q).size_in_bits() != mod_bits {
                continue;
            }
            if p < q {
                std::mem::swap(&mut p, &mut q);
            }
            break;
        }
        (Accumulator::with_private_key(p.clone(), q.clone()), p, q)
    }

    /// Initialize an accumulator from a public key. An accumulator
    /// constructed from a public key is only able to add elements and verify
    /// witnesses.
    ///
    /// ```
    /// use clacc::{Accumulator, gmp::BigInt};
    /// let n = vec![0x0c, 0xa1];
    /// let acc = Accumulator::<BigInt>::with_public_key(n.as_slice().into());
    /// ```
    pub fn with_public_key(n: T) -> Self {
        Accumulator {
            d: None,
            n: n,
            z: BASE.into(),
        }
    }

    /// Get an accumulator's public key.
    pub fn get_public_key(&self) -> &T {
        &self.n
    }

    /// Add an element to an accumulator.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator, RawSerializer as Raw,
    ///     blake2::Mapper,
    ///     gmp::BigInt,
    /// };
    /// type Map = Mapper<16>;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     n.as_slice().into()
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc.add::<Map, Raw, _>(&x);
    /// assert!(acc.verify::<Map, Raw, _>(&x, &w).is_ok());
    /// ```
    ///
    /// This works with accumulators constructed from a public key or a
    /// private key.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator, RawSerializer as Raw,
    ///     blake2::Mapper,
    ///     gmp::BigInt,
    /// };
    /// type Map = Mapper<16>;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc.add::<Map, Raw, _>(&x);
    /// assert!(acc.verify::<Map, Raw, _>(&x, &w).is_ok());
    /// ```
    pub fn add<'a, M, S, V>(&mut self, v: &'a V) -> Witness<T>
    where M: Mapper, V: 'a, S: ElementSerializer<V>, {
        let s = S::serialize_element(v);
        let x = M::map::<T>(&s);
        let x_p = x.next_prime();
        let w = Witness {
            u: self.z.clone(),
            nonce: x_p.sub(&x),
        };
        self.z = self.z.powm(&x_p, &self.n);
        w
    }

    /// Delete an element from an accumulator.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator, RawSerializer as Raw,
    ///     blake2::Mapper,
    ///     gmp::BigInt,
    /// };
    /// type Map = Mapper<16>;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc.add::<Map, Raw, _>(&x);
    /// assert!(acc.del::<Map, Raw, _>(&x, &w).is_ok());
    /// assert!(acc.verify::<Map, Raw, _>(&x, &w).is_err());
    /// assert!(acc.del::<Map, Raw, _>(&x, &w).is_err());
    /// ```
    ///
    /// This will only succeed with an accumulator constructed from a private
    /// key.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator, RawSerializer as Raw,
    ///     blake2::Mapper,
    ///     gmp::BigInt,
    /// };
    /// type Map = Mapper<16>;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     n.as_slice().into()
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc.add::<Map, Raw, _>(&x);
    /// assert!(acc.del::<Map, Raw, _>(&x, &w).is_err());
    /// ```
    pub fn del<'a, M, S, V>(&mut self, v: &'a V, w: &Witness<T>)
                            -> Result<T, &'static str>
    where M: Mapper, V: 'a, S: ElementSerializer<V> {
        let d = match self.d.as_ref() {
            Some(d) => d,
            None => {
                return Err("d is None");
            },
        };
        let s = S::serialize_element(v);
        let x_p = M::map::<T>(&s).add(&w.nonce);
        if self.z != w.u.powm(&x_p, &self.n) {
            return Err("x not in z");
        }
        let x_i = match x_p.invert(d) {
            Some(x_i) => x_i,
            None => {
                return Err("x has no inverse");
            },
        };
        self.z = self.z.powm(&x_i, &self.n);
        Ok(self.z.clone())
    }

    /// Generate a witness to an element's addition to the accumulation.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator, RawSerializer as Raw,
    ///     blake2::Mapper,
    ///     gmp::BigInt,
    /// };
    /// type Map = Mapper<16>;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// let x = b"abc".to_vec();
    /// acc.add::<Map, Raw, _>(&x);
    /// let w = acc.prove::<Map, Raw, _>(&x).unwrap();
    /// assert!(acc.verify::<Map, Raw, _>(&x, &w).is_ok());
    /// ```
    ///
    /// This will only succeed with an accumulator constructed from a private
    /// key.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator, RawSerializer as Raw,
    ///     blake2::Mapper,
    ///     gmp::BigInt,
    /// };
    /// type Map = Mapper<16>;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     n.as_slice().into()
    /// );
    /// let x = b"abc".to_vec();
    /// acc.add::<Map, Raw, _>(&x);
    /// assert!(acc.prove::<Map, Raw, _>(&x).is_err());
    /// ```
    pub fn prove<'a, M, S, V>(&self, v: &'a V)
                              -> Result<Witness<T>, &'static str>
    where M: Mapper, V: 'a, S: ElementSerializer<V> {
        let d = match self.d.as_ref() {
            Some(d) => d,
            None => {
                return Err("d is None");
            },
        };
        let s = S::serialize_element(v);
        let x = M::map::<T>(&s);
        let x_p = x.next_prime();
        let x_i = match x_p.invert(d) {
            Some(x_i) => x_i,
            None => {
                return Err("x has no inverse");
            },
        };
        Ok(Witness {
            u: self.z.powm(&x_i, &self.n),
            nonce: x_p.sub(&x),
        })
    }

    /// Verify an element is a member of an accumulator.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator, RawSerializer as Raw,
    ///     blake2::Mapper,
    ///     gmp::BigInt,
    /// };
    /// type Map = Mapper<16>;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     n.as_slice().into()
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc.add::<Map, Raw, _>(&x);
    /// assert!(acc.verify::<Map, Raw, _>(&x, &w).is_ok());
    /// ```
    ///
    /// This works with accumulators constructed from a public key or a
    /// private key.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator, RawSerializer as Raw,
    ///     blake2::Mapper,
    ///     gmp::BigInt,
    /// };
    /// type Map = Mapper<16>;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc.add::<Map, Raw, _>(&x);
    /// assert!(acc.verify::<Map, Raw, _>(&x, &w).is_ok());
    /// ```
    pub fn verify<'a, M, S, V>(&self, v: &'a V, w: &Witness<T>)
                               -> Result<(), &'static str>
    where M: Mapper, V: 'a, S: ElementSerializer<V> {
        let s = S::serialize_element(v);
        let x_p = M::map::<T>(&s).add(&w.nonce);
        if self.z != w.u.powm(&x_p, &self.n) {
            Err("x not in z")
        } else {
            Ok(())
        }
    }

    /// Return the accumulation value as a BigInt.
    pub fn get_value(&self) -> &T {
        &self.z
    }

    /// Set the accumulation value from a BigInt.
    pub fn set_value(&mut self, z: &T) {
        self.z = z.clone();
    }

}

impl<T> std::fmt::Display for Accumulator<T>
where T: for<'a> BigInt<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>)
           -> Result<(), std::fmt::Error> {
        match self.d.as_ref() {
            Some(d) => f.write_fmt(format_args!("({:x}, {:x}, {:x})", d,
                                                self.n, self.z)),
            None => f.write_fmt(format_args!("({:x}, {:x})", self.n, self.z)),
        }
    }
}

/// A witness of an element's membership in an accumulator.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound = "T: Serialize, for<'a> T: Deserialize<'a>")]
pub struct Witness<T> where T: for<'a> BigInt<'a> {

    /// The accumulation value less the element.
    pub u: T,

    /// A number that, when added to the element, uniquely maps the element to
    /// a prime.
    pub nonce: T,
}

impl<T> Witness<T> where T: for<'a> BigInt<'a> {

    /// Return the witness value as a BigInt.
    pub fn get_value(&self) -> T {
        self.u.clone()
    }

    /// Set the witness value from a BigInt.
    pub fn set_value(&mut self, u: &T) {
        self.u = u.clone();
    }

}

impl<T> std::fmt::Display for Witness<T> where T: for<'a> BigInt<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>)
           -> Result<(), std::fmt::Error> {
        f.write_fmt(format_args!("({:x}, {:x})", self.u, self.nonce))
    }
}

/// A sum of updates to be applied to witnesses.
#[derive(Clone, Debug, Default)]
pub struct Update<T> where T: for<'a> BigInt<'a> {
    pi_a: T,
    pi_d: T,
}

impl<T> Update<T> where for<'a> T: 'a + BigInt<'a> {

    /// Create a new batched update.
    pub fn new() -> Self {
        Update {
            pi_a: 1.into(),
            pi_d: 1.into(),
        }
    }

    /// Absorb an element that must be added to a witness.
    pub fn add<'a, M, S, V>(
        &mut self,
        v: &'a V,
        w: &Witness<T>,
    )
    where M: Mapper, V: 'a, S: ElementSerializer<V> {
        let s = S::serialize_element(v);
        let x_p = M::map::<T>(&s).add(&w.nonce);
        self.pi_a = self.pi_a.mul(&x_p);
    }

    /// Absorb an element that must be deleted from a witness.
    pub fn del<'a, M, S, V>(
        &mut self,
        v: &'a V,
        w: &Witness<T>,
    )
    where M: Mapper, V: 'a, S: ElementSerializer<V> {
        let s = S::serialize_element(v);
        let x_p = M::map::<T>(&s).add(&w.nonce);
        self.pi_d = self.pi_d.mul(&x_p);
    }

    /// Undo an absorbed element's addition into an update.
    pub fn undo_add<'a, M, S, V>(
        &mut self,
        v: &'a V,
        w: &Witness<T>,
    )
    where M: Mapper, V: 'a, S: ElementSerializer<V> {
        let s = S::serialize_element(v);
        let x_p = M::map::<T>(&s).add(&w.nonce);
        self.pi_a = self.pi_a.div(&x_p);
    }

    /// Undo an absorbed element's deletion from an update.
    pub fn undo_del<'a, M, S, V>(
        &mut self,
        v: &'a V,
        w: &Witness<T>,
    )
    where M: Mapper, V: 'a, S: ElementSerializer<V> {
        let s = S::serialize_element(v);
        let x_p = M::map::<T>(&s).add(&w.nonce);
        self.pi_d = self.pi_a.div(&x_p);
    }

    /// Update a witness. The update will include all additions and deletions
    /// previously absorbed into this update struct.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator, Update, RawSerializer as Raw,
    ///     blake2::Mapper,
    ///     gmp::BigInt,
    /// };
    /// type Map = Mapper<16>;
    /// // In this example, the update will include a deletion, so the
    /// // accumulator must be created with a private key.
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// // Create the static element.
    /// let xs = b"abc".to_vec();
    /// // Create the deletion.
    /// let xd = b"def".to_vec();
    /// // Create the addition.
    /// let xa = b"ghi".to_vec();
    /// // Add the deletion element.
    /// acc.add::<Map, Raw, _>(&xd);
    /// // Add the static element to the accumulator.
    /// let mut wxs = acc.add::<Map, Raw, _>(&xs);
    /// // Delete the deletion element from the accumulator.
    /// let wxd = acc.prove::<Map, Raw, _>(&xd).unwrap();
    /// acc.del::<Map, Raw, _>(&xd, &wxd).unwrap();
    /// // Create an update object and absorb the addition and deletion.
    /// let mut u = Update::new();
    /// u.del::<Map, Raw, _>(&xd, &wxd);
    /// u.add::<Map, Raw, _>(&xa, &acc.add::<Map, Raw, _>(&xa));
    /// // Update the static element's witness.
    /// wxs = u.update_witness::<Map, Raw, _>(&acc, &xs, &wxs);
    /// assert!(acc.verify::<Map, Raw, _>(&xs, &wxs).is_ok());
    /// ```
    pub fn update_witness<'a, M, S, V>(
        &self,
        acc: &Accumulator<T>,
        v: &'a V,
        w: &Witness<T>,
    ) -> Witness<T>
    where M: Mapper, V: 'a, S: ElementSerializer<V> {
        let s = S::serialize_element(v);
        let x_p = M::map::<T>(&s).add(&w.nonce);
        let (_, a, b) = self.pi_d.gcdext(&x_p);
        Witness {
            u: w.u.powm(&a.mul(&self.pi_a), &acc.n)
                .mul(&acc.z.powm(&b, &acc.n)).modulus(&acc.n),
            nonce: w.nonce.clone(),
        }
    }

    /// Thread-safe method that updates multiple witnesses.
    ///
    /// It is assumed that the additional elements have been absorbed by the
    /// update and that their witnesses are the accumulator's value before any
    /// of the additions or deletions absorbed by this update were applied.
    /// Updating the witnesses for each of these additional elements is thus
    /// acheived by simply removing its respective element from the update and
    /// applying the result to its witness.
    ///
    /// This method operates on atomic references to iterators over collections
    /// of element-witness pairs. An invocation will run until the referenced
    /// iterators have reached the end of their collections. To update witnesses
    /// concurrently, simply invoke this method from multiple threads using
    /// references to the same iterators.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator, Update, Witness, RawSerializer as Raw,
    ///     blake2::Mapper,
    ///     gmp::BigInt,
    /// };
    /// use crossbeam::thread;
    /// use num_cpus;
    /// use rand::RngCore;
    /// use std::sync::{Arc, Mutex};
    /// type Map = Mapper<16>;
    /// // Create elements.
    /// const BUCKET_SIZE: usize = 20;
    /// const DELETIONS_COUNT: usize = 2;
    /// const ADDITIONS_COUNT: usize = 10;
    /// const STATICELS_COUNT: usize = BUCKET_SIZE - DELETIONS_COUNT;
    /// let mut deletions: Vec<(Vec<u8>, Witness<BigInt>)> = vec![
    ///     Default::default(); DELETIONS_COUNT
    /// ];
    /// let mut additions: Vec<(Vec<u8>, Witness<BigInt>)> = vec![
    ///     Default::default(); ADDITIONS_COUNT
    /// ];
    /// let mut staticels: Vec<(Vec<u8>, Witness<BigInt>)> = vec![
    ///     Default::default(); STATICELS_COUNT
    /// ];
    /// let mut rng = rand::thread_rng();
    /// let mut bytes = vec![0; 8];
    /// for deletion in deletions.iter_mut() {
    ///     rng.fill_bytes(&mut bytes);
    ///     deletion.0 = bytes.clone();
    /// }
    /// for addition in additions.iter_mut() {
    ///     rng.fill_bytes(&mut bytes);
    ///     addition.0 = bytes.clone();
    /// }
    /// for staticel in staticels.iter_mut() {
    ///     rng.fill_bytes(&mut bytes);
    ///     staticel.0 = bytes.clone();
    /// }
    /// // Create accumulator with private key.
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// // Accumulate elements.
    /// for (element, _) in deletions.iter() {
    ///     acc.add::<Map, Raw, _>(element);
    /// }
    /// for (element, _) in staticels.iter() {
    ///     acc.add::<Map, Raw, _>(element);
    /// }
    /// // Generate witnesses for static elements.
    /// for (element, witness) in staticels.iter_mut() {
    ///     *witness = acc.prove::<Map, Raw, _>(element).unwrap()
    /// }
    /// // Save accumulation at current state.
    /// let prev = acc.clone();
    /// // Accumulate deletions.
    /// for (element, witness) in deletions.iter_mut() {
    ///     *witness = acc.prove::<Map, Raw, _>(element).unwrap();
    ///     acc.del::<Map, Raw, _>(element, witness).unwrap();
    /// }
    /// // Accumulate additions.
    /// for (element, witness) in additions.iter_mut() {
    ///     *witness = acc.add::<Map, Raw, _>(element);
    ///     // Use the saved accumulation as the witness value.
    ///     witness.set_value(prev.get_value());
    /// }
    /// // Batch updates.
    /// let mut update = Update::new();
    /// for (element, witness) in deletions.iter() {
    ///     update.del::<Map, Raw, _>(element, witness);
    /// }
    /// for (element, witness) in additions.iter() {
    ///     update.add::<Map, Raw, _>(element, witness);
    /// }
    /// // Update all witnesses concurrently.
    /// let additions_iter = Arc::new(Mutex::new(additions.iter_mut()));
    /// let staticels_iter = Arc::new(Mutex::new(staticels.iter_mut()));
    /// thread::scope(|scope| {
    ///     for _ in 0..num_cpus::get() {
    ///         let acc = acc.clone();
    ///         let u = update.clone();
    ///         let additions_iter = Arc::clone(&additions_iter);
    ///         let staticels_iter = Arc::clone(&staticels_iter);
    ///         scope.spawn(move |_| {
    ///             u.update_witnesses::<Map, Raw, _, _>(
    ///                 &acc,
    ///                 additions_iter,
    ///                 staticels_iter,
    ///             );
    ///         });
    ///     }
    /// }).unwrap();
    /// // Verify all updated witnesses.
    /// for (element, witness) in additions.iter() {
    ///     assert!(acc.verify::<Map, Raw, _>(element, witness).is_ok());
    /// }
    /// for (element, witness) in staticels.iter() {
    ///     assert!(acc.verify::<Map, Raw, _>(element, witness).is_ok());
    /// }
    /// ```
    pub fn update_witnesses<'a, M, S, V, I>(
        &self,
        acc: &Accumulator<T>,
        additions: Arc<Mutex<I>>,
        staticels: Arc<Mutex<I>>,
    )
    where
        M: Mapper,
        V: 'a,
        S: ElementSerializer<V>,
        I: Iterator<Item = &'a mut (V, Witness<T>)> + 'a + Send {
        loop {
            let (element, witness, is_static) = {
                let mut s = staticels.lock().unwrap();
                match s.next() {
                    Some(next) => {
                        let (element, witness) = next;
                        (element, witness, true)
                    },
                    None => {
                        let mut a = additions.lock().unwrap();
                        match a.next() {
                            Some(next) => {
                                let (element, witness) = next;
                                (element, witness, false)
                            },
                            None => break,
                        }
                    }
                }
            };
            let mut u = self;
            let mut clone;
            if !is_static {
                clone = self.clone();
                clone.undo_add::<M, S, V>(element, witness);
                u = &clone;
            }
            *witness = u.update_witness::<M, S, V>(acc, element, witness);
        }
    }
}

impl<T> std::fmt::Display for Update<T>
where T: for<'a> BigInt<'a> {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        f.write_fmt(format_args!("({:x}, {:x})", self.pi_a, self.pi_d))
    }
}

/// A trait describing a method for serializing an arbitrary data type.
pub trait ElementSerializer<V> {
    fn serialize_element(x: &V) -> Vec<u8>;
}

/// An element serializer that returns a clone of the element.
pub struct RawSerializer;

impl ElementSerializer<Vec<u8>> for RawSerializer {
    fn serialize_element(x: &Vec<u8>) -> Vec<u8> {
        x.clone()
    }
}
