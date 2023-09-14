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
//! This crate is built with modular integer type and cryptographic hash
//! backends. Integer types must implement the [`BigInt`] trait. Hash functions
//! must implement the [`Map`] trait.
//!
//! # Optional Features
//! - `bigint` (default): Enable this feature to support
//!   [`::num_bigint::BigInt`] as an integer type. [`::num_bigint`] is
//!   a pure Rust big integer library.
//! - `gmp`: Enable this feature to support [`::gmp::mpz::Mpz`] as an
//!   integer type. [`::gmp`] is not a pure Rust library, but it is
//!   currently more performant than [`::num_bigint`].
//! - `serde`: Enable this feature to support [`::serde::ser::Serialize`] and
//!   [`::serde::de::Deserialize`] for [`Witness`]. If using your own
//!   [`BigInt`] implementation, it must also support these traits.
//! - `sha3` (default): Enable this feature to support [`sha3::Shake128`]
//!   and [`sha3::Shake256`] as hash functions via [`::sha3`].
//!
//! [1]: https://journals.sagepub.com/doi/pdf/10.1177/1550147719875645
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
#[cfg(feature = "serde")]
use ::serde::{Serialize, Deserialize};

#[cfg(feature = "gmp")]
pub mod gmp;

#[cfg(feature = "bigint")]
pub mod bigint;

#[cfg(feature = "sha3")]
pub mod sha3;

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

/// A trait describing a conversion from an arbitrary type to a fixed size
/// byte vector.
pub trait Map: Clone {

    /// Convert an arbitrary type to a deterministic, fixed size byte vector.
    fn map<V: Into<Vec<u8>>>(v: V) -> Vec<u8>;
}

/// An accumulator.
///
/// Elements may be added and deleted from the acculumator without increasing
/// the size of its internal parameters. That is, the number of digits in the
/// accumulation `z` will never exceed the number of digits in the modulus
/// `n`.
#[derive(Clone)]
pub struct Accumulator<T: BigInt, M: Map> {

    /// The current accumulation value.
    z: T,

    /// Private exponent.
    d: Option<T>,

    /// Modulus.
    n: T,

    /// Mapper marker.
    map: PhantomData<M>,
}

impl<T: BigInt, M: Map> Accumulator<T, M> {

    /// Initialize an accumulator from private key parameters. All
    /// accumulators are able to add elements and verify witnesses. An
    /// accumulator constructed from a private key is able to delete elements
    /// and prove elements after their addition.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let acc = Accumulator::<BigInt, Map>::with_private_key(
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
            map: PhantomData,
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
    ///     sha3::Shake128 as Map,
    ///     BigInt as BigIntTrait,
    /// };
    /// use num_bigint::BigInt;
    /// use rand::RngCore;
    /// let mut rng = rand::thread_rng();
    /// let acc = Accumulator::<BigInt, Map>::with_random_key(
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
        (Accumulator::<T, M>::with_private_key(p.clone(), q.clone()), p, q)
    }

    /// Initialize an accumulator from a public key. An accumulator
    /// constructed from a public key is only able to add elements and verify
    /// witnesses.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let n = vec![0x0c, 0xa1];
    /// let acc = Accumulator::<BigInt, Map>::with_public_key(
    ///    <BigInt as clacc::BigInt>::from_bytes_be( n.as_slice()),
    /// );
    /// ```
    pub fn with_public_key(n: T) -> Self {
        Accumulator {
            d: None,
            n: n,
            z: T::from_i64(BASE),
            map: PhantomData,
        }
    }

    /// Get an accumulator's public key.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt, Map>::with_private_key(
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

    /// Add an element to an accumulator.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt, Map>::with_public_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice()),
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc.add(x.clone());
    /// assert!(acc.verify(x.clone(), w).is_ok());
    /// ```
    ///
    /// This works with accumulators constructed from a public key or a
    /// private key.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt, Map>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc.add(x.clone());
    /// assert!(acc.verify(x.clone(), w).is_ok());
    /// ```
    pub fn add<V: Into<Vec<u8>>>(
        &mut self,
        v: V,
    ) -> Witness<T> {
        let x = T::from_bytes_be(M::map(v).as_slice());
        let x_p = x.next_prime();
        let w = Witness {
            u: self.z.clone(),
            nonce: x_p.clone() - x,
        };
        self.z = self.z.powm(&x_p, &self.n);
        w
    }

    /// Delete an element from an accumulator.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt, Map>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc.add(x.clone());
    /// assert!(acc.del(x.clone(), w.clone()).is_ok());
    /// assert!(acc.verify(x.clone(), w.clone()).is_err());
    /// assert!(acc.del(x.clone(), w.clone()).is_err());
    /// ```
    ///
    /// This will only succeed with an accumulator constructed from a private
    /// key.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt, Map>::with_public_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice())
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc.add(x.clone());
    /// assert!(acc.del(x.clone(), w).is_err());
    /// ```
    pub fn del<V: Into<Vec<u8>>>(
        &mut self,
        v: V,
        w: Witness<T>,
    ) -> Result<T, Error> {
        let d = match self.d.as_ref() {
            Some(d) => d,
            None => {
                return Err(Error { source: Box::new(ErrorMissingPrivateKey) });
            },
        };
        let x = T::from_bytes_be(M::map(v).as_slice());
        let x_p = x + w.nonce.clone();
        if self.z != w.u.powm(&x_p, &self.n) {
            return Err(Error { source: Box::new(ErrorElementNotFound) });
        }
        let x_i = x_p.powm(&T::from_i64(-1), &d);
        self.z = self.z.powm(&x_i, &self.n);
        Ok(self.z.clone())
    }

    /// Generate a witness to an element's addition to the accumulation.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt, Map>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// let x = b"abc".to_vec();
    /// acc.add(x.clone());
    /// let w = acc.prove(x.clone()).unwrap();
    /// assert!(acc.verify(x.clone(), w).is_ok());
    /// ```
    ///
    /// This will only succeed with an accumulator constructed from a private
    /// key.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt, Map>::with_public_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice()),
    /// );
    /// let x = b"abc".to_vec();
    /// acc.add(x.clone());
    /// assert!(acc.prove(x.clone()).is_err());
    /// ```
    pub fn prove<V: Into<Vec<u8>>>(
        &self,
        v: V,
    ) -> Result<Witness<T>, Error> {
        match self.d.as_ref() {
            Some(d) => {
                let x = T::from_bytes_be(M::map(v).as_slice());
                let x_p = x.next_prime();
                let x_i = x_p.powm(&T::from_i64(-1), &d);
                Ok(Witness {
                    u: self.z.powm(&x_i, &self.n),
                    nonce: x_p - x,
                })
            },
            None => Err(Error { source: Box::new(ErrorMissingPrivateKey) })
        }
    }

    /// Verify an element is a member of an accumulator.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt, Map>::with_public_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice()),
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc.add(x.clone());
    /// assert!(acc.verify(x.clone(), w).is_ok());
    /// ```
    ///
    /// This works with accumulators constructed from a public key or a
    /// private key.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt, Map>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc.add(x.clone());
    /// assert!(acc.verify(x.clone(), w).is_ok());
    /// ```
    pub fn verify<V: Into<Vec<u8>>>(
        &self,
        v: V,
        w: Witness<T>,
    ) -> Result<(), Error> {
        let x = T::from_bytes_be(M::map(v).as_slice());
        let x_p = x + w.nonce.clone();
        if self.z != w.u.powm(&x_p, &self.n) {
            Err(Error { source: Box::new(ErrorElementNotFound) })
        } else {
            Ok(())
        }
    }

    /// Return the accumulation value as a [`BigInt`].
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     Witness,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt, Map>::with_public_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice()),
    /// );
    /// let x = b"abc".to_vec();
    /// let y = b"def".to_vec();
    /// // Add an element.
    /// acc.add(x);
    /// // Save the current accumulation. This value is effectively
    /// // a witness for the next element added.
    /// let u = acc.get_value().clone();
    /// // Add another element.
    /// let nonce = acc.add(y.clone()).nonce;
    /// let w = Witness {
    ///     u: u,
    ///     nonce: nonce,
    /// };
    /// // Verify that `w` is a witness for `y`.
    /// assert!(acc.verify(y.clone(), w).is_ok());
    /// ```
    pub fn get_value(&self) -> T {
        self.z.clone()
    }

    /// Set the accumulation value from a [`BigInt`].
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc_prv = Accumulator::<BigInt, Map>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc_pub = Accumulator::<BigInt, Map>::with_public_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(n.as_slice()),
    /// );
    /// let x = b"abc".to_vec();
    /// let w = acc_prv.add(x.clone());
    /// acc_pub.set_value(acc_prv.get_value());
    /// assert!(acc_prv.verify(x.clone(), w).is_ok());
    /// ```
    pub fn set_value(&mut self, z: T) {
        self.z = z;
    }

}

/// A witness of an element's membership in an accumulator.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = "T: Serialize, for<'a> T: Deserialize<'a>"))]
pub struct Witness<T: BigInt> {

    /// The accumulation value less the element.
    pub u: T,

    /// A number that, when added to the element, uniquely maps the element to
    /// a prime.
    pub nonce: T,
}

impl<T: BigInt> Witness<T> {

    /// Return the witness value as a [`BigInt`].
    pub fn get_value(&self) -> T {
        self.u.clone()
    }

    /// Set the witness value from a [`BigInt`].
    pub fn set_value(&mut self, u: T) {
        self.u = u;
    }

}

impl<T: BigInt> Default for Witness<T> {
    fn default() -> Self {
        let bn0 = T::from_i64(0);
        Witness {
            u: bn0.clone(),
            nonce: bn0.clone(),
        }
    }
}

/// A sum of updates to be applied to witnesses.
#[derive(Default)]
pub struct Update<T: BigInt, M: Map> {
    pi_a: T,
    pi_d: T,
    map: PhantomData<M>,
}

impl<T: BigInt, M: Map> Clone for Update<T, M> {
    fn clone(&self) -> Update<T, M> {
        Update {
            pi_a: self.pi_a.clone(),
            pi_d: self.pi_d.clone(),
            map: PhantomData,
        }
    }
}

impl<'u, T: 'u + BigInt, M: Map> Update<T, M> {

    /// Create a new batched update.
    pub fn new() -> Self {
        let bn1 = T::from_i64(1);
        Update {
            pi_a: bn1.clone(),
            pi_d: bn1.clone(),
            map: PhantomData,
        }
    }

    /// Absorb an element that must be added to a witness.
    pub fn add<V: Into<Vec<u8>>>(
        &mut self,
        v: V,
        w: Witness<T>,
    ) {
        let x = T::from_bytes_be(M::map(v).as_slice());
        let x_p = x + w.nonce.clone();
        self.pi_a *= x_p;
    }

    /// Absorb an element that must be deleted from a witness.
    pub fn del<V: Into<Vec<u8>>>(
        &mut self,
        v: V,
        w: Witness<T>,
    ) {
        let x = T::from_bytes_be(M::map(v).as_slice());
        let x_p = x + w.nonce.clone();
        self.pi_d *= x_p;
    }

    /// Undo an absorbed element's addition into an update.
    pub fn undo_add<V: Into<Vec<u8>>>(
        &mut self,
        v: V,
        w: Witness<T>,
    ) {
        let x = T::from_bytes_be(M::map(v).as_slice());
        let x_p = x + w.nonce.clone();
        self.pi_a /= x_p;
    }

    /// Undo an absorbed element's deletion from an update.
    pub fn undo_del<V: Into<Vec<u8>>>(
        &mut self,
        v: V,
        w: Witness<T>,
    ) {
        let x = T::from_bytes_be(M::map(v).as_slice());
        let x_p = x + w.nonce.clone();
        self.pi_d /= x_p;
    }

    /// Update a witness. The update will include all additions and deletions
    /// previously absorbed into this update struct.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator,
    ///     Update,
    ///     sha3::Shake128 as Map,
    /// };
    /// use num_bigint::BigInt;
    /// // In this example, the update will include a deletion, so the
    /// // accumulator must be created with a private key.
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt, Map>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// // Create the static element.
    /// let xs = b"abc".to_vec();
    /// // Create the deletion.
    /// let xd = b"def".to_vec();
    /// // Create the addition.
    /// let xa = b"ghi".to_vec();
    /// // Add the deletion element.
    /// acc.add(xd.clone());
    /// // Add the static element to the accumulator.
    /// let mut wxs = acc.add(xs.clone());
    /// // Delete the deletion element from the accumulator.
    /// let wxd = acc.prove(xd.clone()).unwrap();
    /// acc.del(xd.clone(), wxd.clone()).unwrap();
    /// // Create an update object and absorb the addition and deletion.
    /// let mut u = Update::new();
    /// u.del(xd.clone(), wxd.clone());
    /// u.add(xa.clone(), acc.add(xa.clone()));
    /// // Update the static element's witness.
    /// wxs = u.update_witness(&acc, xs.clone(), wxs.clone());
    /// assert!(acc.verify(xs.clone(), wxs.clone()).is_ok());
    /// ```
    pub fn update_witness<V: Into<Vec<u8>>>(
        &self,
        acc: &Accumulator<T, M>,
        v: V,
        w: Witness<T>,
    ) -> Witness<T> {
        let x = T::from_bytes_be(M::map(v).as_slice());
        let x_p = x + w.nonce.clone();
        let (_, a, b) = self.pi_d.gcdext(&x_p);
        Witness {
            u: (w.u.powm(&(a * self.pi_a.clone()), &acc.n)
                * acc.z.powm(&b, &acc.n))
                % acc.n.clone(),
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
    ///     Accumulator,
    ///     Update,
    ///     Witness,
    ///     sha3::Shake128 as Map,
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
    /// let mut deletions: Vec<(Vec<u8>, Witness<_>)> = vec![
    ///     Default::default(); DELETIONS_COUNT
    /// ];
    /// let mut additions: Vec<(Vec<u8>, Witness<_>)> = vec![
    ///     Default::default(); ADDITIONS_COUNT
    /// ];
    /// let mut staticels: Vec<(Vec<u8>, Witness<_>)> = vec![
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
    /// let mut acc = Accumulator::<BigInt, Map>::with_private_key(
    ///     <BigInt as clacc::BigInt>::from_bytes_be(p.as_slice()),
    ///     <BigInt as clacc::BigInt>::from_bytes_be(q.as_slice()),
    /// );
    /// // Accumulate elements.
    /// for (element, _) in deletions.iter() {
    ///     acc.add(element.clone());
    /// }
    /// for (element, _) in staticels.iter() {
    ///     acc.add(element.clone());
    /// }
    /// // Generate witnesses for static elements.
    /// for (element, witness) in staticels.iter_mut() {
    ///     *witness = acc.prove(element.clone()).unwrap()
    /// }
    /// // Save accumulation at current state.
    /// let prev = acc.clone();
    /// // Accumulate deletions.
    /// for (element, witness) in deletions.iter_mut() {
    ///     *witness = acc.prove(element.clone()).unwrap();
    ///     acc.del(element.clone(), witness.clone()).unwrap();
    /// }
    /// // Accumulate additions.
    /// for (element, witness) in additions.iter_mut() {
    ///     *witness = acc.add(element.clone());
    ///     // Use the saved accumulation as the witness value.
    ///     witness.set_value(prev.get_value());
    /// }
    /// // Batch updates.
    /// let mut update = Update::new();
    /// for (element, witness) in deletions.iter() {
    ///     update.del(element.clone(), witness.clone());
    /// }
    /// for (element, witness) in additions.iter() {
    ///     update.add(element.clone(), witness.clone());
    /// }
    /// // Update all witnesses concurrently.
    /// let additions_iter = Arc::new(Mutex::new(additions.iter_mut()));
    /// let staticels_iter = Arc::new(Mutex::new(staticels.iter_mut()));
    /// thread::scope(|scope| {
    ///     for _ in 0..num_cpus::get() {
    ///         let acc = acc.clone();
    ///         let u = update.clone();
    ///         let add = Arc::clone(&additions_iter);
    ///         let sta = Arc::clone(&staticels_iter);
    ///         scope.spawn(move |_| u.update_witnesses(&acc, add, sta));
    ///     }
    /// }).unwrap();
    /// // Verify all updated witnesses.
    /// for (element, witness) in additions.iter() {
    ///     assert!(acc.verify(element.clone(), witness.clone()).is_ok());
    /// }
    /// for (element, witness) in staticels.iter() {
    ///     assert!(acc.verify(element.clone(), witness.clone()).is_ok());
    /// }
    /// ```
    pub fn update_witnesses<
        V: 'u + Clone + Into<Vec<u8>>,
        IA: Iterator<Item = &'u mut (V, Witness<T>)> + Send,
        IS: Iterator<Item = &'u mut (V, Witness<T>)> + Send
    >(
        &self,
        acc: &Accumulator<T, M>,
        additions: Arc<Mutex<IA>>,
        staticels: Arc<Mutex<IS>>,
    ) {
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
                clone.undo_add(element.clone(), witness.clone());
                u = &clone;
            }
            *witness = u.update_witness(
                acc,
                element.clone(),
                witness.clone(),
            );
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
