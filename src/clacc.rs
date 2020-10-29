//! This is a Rust implementanion of a CL universal accumulator as described
//! [here](http://groups.csail.mit.edu/cis/pubs/lysyanskaya/cl02a.pdf).
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
use crossbeam::thread;
use generic_array::{ArrayLength, GenericArray};
use rand::RngCore;
use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};

pub use typenum;

#[cfg(feature = "blake2")]
pub mod blake2;

#[cfg(feature = "rust-gmp")]
pub mod gmp;

#[cfg(feature = "velocypack")]
pub mod velocypack;

/// The accumulator base.
const BASE: i64 = 65537;

/// A trait describing an arbitrary precision integer.
pub trait BigInt:
    'static
    + Default
    + From<i64>
    + for<'a> From<&'a [u8]>
    + Clone
    + Sized
    + Send
    + Sync
    + Eq
    + PartialOrd
    + BigIntSub<i64, Output = Self>
    + for<'a> BigIntAdd<&'a Self, Output = Self>
    + for<'a> BigIntSub<&'a Self, Output = Self>
    + for<'a> BigIntMul<&'a Self, Output = Self>
    + for<'a> BigIntDiv<&'a Self, Output = Self>
    + Serialize
    + for <'de> Deserialize<'de>
    + std::fmt::Debug
    + std::fmt::Display
    + std::fmt::LowerHex
    + std::fmt::UpperHex
{
    /// Returns the next prime greater than `self`.
    fn next_prime(&self) -> Self;

    /// Returns the greatest common divisor of `self` and the coefficients `a`
    /// and `b` satisfying `a*x + b*y = g`.
    fn gcdext<'a>(&self, y: &'a Self) -> (Self, Self, Self);

    /// Return the modulus of `self / m`.
    fn modulus<'a>(&self, m: &'a Self) -> Self;

    /// Returns `self^e mod m`.
    fn powm<'a>(&self, e: &'a Self, m: &Self) -> Self;

    /// Returns `self^-1 mod m`.
    fn invert<'a>(&self, m: &'a Self) -> Option<Self>;

    /// Returns the size of the number in bits.
    fn size_in_bits(&self) -> usize;

    /// Export the number as a u8 vector.
    fn to_vec(&self) -> Vec<u8>;
}

/// A trait describing [BigInt](trait.BigInt.html) addition.
pub trait BigIntAdd<T> {
    type Output;
    fn add(&self, other: T) -> Self::Output;
}

/// A trait describing [BigInt](trait.BigInt.html) subtraction.
pub trait BigIntSub<T> {
    type Output;
    fn sub(&self, other: T) -> Self::Output;
}

/// A trait describing [BigInt](trait.BigInt.html) multiplication.
pub trait BigIntMul<T> {
    type Output;
    fn mul(&self, other: T) -> Self::Output;
}

/// A trait describing [BigInt](trait.BigInt.html) division.
pub trait BigIntDiv<T> {
    type Output;
    fn div(&self, other: T) -> Self::Output;
}

/// Helper function that converts a GenericArray to a BigInt.
fn to_bigint<T: BigInt, N: ArrayLength<u8>>(x: GenericArray<u8, N>) -> T {
    x.as_slice().into()
}

/// A trait describing a method for converting some arbitrary data to a fixed
/// sized digest.
pub trait Mapper {
    fn map<N>(x: &[u8]) -> GenericArray<u8, N>
    where N: ArrayLength<u8>;
}

/// An accumulator.
///
/// Elements may be added and deleted from the acculumator without increasing
/// the size of its internal parameters. That is, the number of digits in the
/// accumulation `z` will never exceed the number of digits in the modulus
/// `n`.
#[derive(Clone, Debug)]
pub struct Accumulator<T> where T: BigInt {

    /// The current accumulation value.
    z: T,

    /// Private exponent.
    d: Option<T>,

    /// Modulus.
    n: T,
}

impl<T> Accumulator<T> where T: BigInt {

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
            d: Some(p.sub(1).mul(&q.sub(1))),
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
    /// assert_eq!(Accumulator::<BigInt>::with_random_key(None)
    ///            .0
    ///            .get_public_key()
    ///            .size_in_bits(), 3072);
    /// assert_eq!(Accumulator::<BigInt>::with_random_key(Some(4096))
    ///            .0
    ///            .get_public_key()
    ///            .size_in_bits(), 4096);
    /// ```
    pub fn with_random_key(
        key_bits: Option<usize>
    ) -> (Accumulator<T>, T, T) {
        let mut rng = rand::thread_rng();
        let mod_bits = match key_bits {
            Some(bits) => bits,
            None => 3072,
        };
        let prime_bytes = (mod_bits + 7) / 16;
        let mut p;
        let mut q;
        let mut bytes = vec![0; prime_bytes];
        loop {
            rng.fill_bytes(&mut bytes);
            p = T::from(bytes.as_slice()).next_prime();
            rng.fill_bytes(&mut bytes);
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
    /// let acc = Accumulator::<BigInt>::with_public_key(
    ///     n.as_slice().into()
    /// );
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
    /// use clacc::{Accumulator, blake2::Mapper, gmp::BigInt, typenum::U16};
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     n.as_slice().into()
    /// );
    /// let x = b"abc";
    /// let w = acc.add::<Mapper, U16>(x);
    /// assert!(acc.verify::<Mapper, U16>(x, &w).is_ok());
    /// ```
    ///
    /// This works with accumulators constructed from a public key or a
    /// private key.
    ///
    /// ```
    /// use clacc::{Accumulator, blake2::Mapper, gmp::BigInt, typenum::U16};
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// let x = b"abc";
    /// let w = acc.add::<Mapper, U16>(x);
    /// assert!(acc.verify::<Mapper, U16>(x, &w).is_ok());
    /// ```
    pub fn add<M, N>(&mut self, x: &[u8]) -> Witness<T>
    where M: Mapper, N: ArrayLength<u8> {
        let x = to_bigint::<T, N>(M::map(x));
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
    /// use clacc::{Accumulator, blake2::Mapper, gmp::BigInt, typenum::U16};
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// let x = b"abc";
    /// let w = acc.add::<Mapper, U16>(x);
    /// assert!(acc.del::<Mapper, U16>(x, &w).is_ok());
    /// assert!(acc.verify::<Mapper, U16>(x, &w).is_err());
    /// assert!(acc.del::<Mapper, U16>(x, &w).is_err());
    /// ```
    ///
    /// This will only succeed with an accumulator constructed from a private
    /// key.
    ///
    /// ```
    /// use clacc::{Accumulator, blake2::Mapper, gmp::BigInt, typenum::U16};
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     n.as_slice().into()
    /// );
    /// let x = b"abc";
    /// let w = acc.add::<Mapper, U16>(x);
    /// assert!(acc.del::<Mapper, U16>(x, &w).is_err());
    /// ```
    pub fn del<M, N>(&mut self, x: &[u8], w: &Witness<T>)
                     -> Result<T, &'static str>
    where M: Mapper, N: ArrayLength<u8> {
        let d = match self.d.as_ref() {
            Some(d) => d,
            None => {
                return Err("d is None");
            },
        };
        let x_p = to_bigint::<T, N>(M::map(x)).add(&w.nonce);
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
    /// use clacc::{Accumulator, blake2::Mapper, gmp::BigInt, typenum::U16};
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// let x = b"abc";
    /// acc.add::<Mapper, U16>(x);
    /// let w = acc.prove::<Mapper, U16>(x).unwrap();
    /// assert!(acc.verify::<Mapper, U16>(x, &w).is_ok());
    /// ```
    ///
    /// This will only succeed with an accumulator constructed from a private
    /// key.
    ///
    /// ```
    /// use clacc::{Accumulator, blake2::Mapper, gmp::BigInt, typenum::U16};
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     n.as_slice().into()
    /// );
    /// let x = b"abc";
    /// acc.add::<Mapper, U16>(x);
    /// assert!(acc.prove::<Mapper, U16>(x).is_err());
    /// ```
    pub fn prove<M, N>(&self, x: &[u8]) -> Result<Witness<T>, &'static str>
    where M: Mapper, N: ArrayLength<u8> {
        let d = match self.d.as_ref() {
            Some(d) => d,
            None => {
                return Err("d is None");
            },
        };
        let x = to_bigint::<T, N>(M::map(x));
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
    /// use clacc::{Accumulator, blake2::Mapper, gmp::BigInt, typenum::U16};
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigInt>::with_public_key(
    ///     n.as_slice().into()
    /// );
    /// let x = b"abc";
    /// let w = acc.add::<Mapper, U16>(x);
    /// assert!(acc.verify::<Mapper, U16>(x, &w).is_ok());
    /// ```
    ///
    /// This works with accumulators constructed from a public key or a
    /// private key.
    ///
    /// ```
    /// use clacc::{Accumulator, blake2::Mapper, gmp::BigInt, typenum::U16};
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// let x = b"abc";
    /// let w = acc.add::<Mapper, U16>(x);
    /// assert!(acc.verify::<Mapper, U16>(x, &w).is_ok());
    /// ```
    pub fn verify<M, N>(&self, x: &[u8], w: &Witness<T>)
                        -> Result<(), &'static str>
    where M: Mapper, N: ArrayLength<u8> {
        let x_p = to_bigint::<T, N>(M::map(x)).add(&w.nonce);
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

impl<T> std::fmt::Display for Accumulator<T> where T: BigInt {
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
pub struct Witness<T> where T: BigInt {

    /// The accumulation value less the element.
    pub u: T,

    /// A number that, when added to the element, uniquely maps the element to
    /// a prime.
    pub nonce: T,
}

impl<T> Witness<T> where T: BigInt{

    /// Return the witness value as a BigInt.
    pub fn get_value(&self) -> T {
        self.u.clone()
    }

    /// Set the witness value from a BigInt.
    pub fn set_value(&mut self, u: &T) {
        self.u = u.clone();
    }

}

impl<T> std::fmt::Display for Witness<T> where T: BigInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>)
           -> Result<(), std::fmt::Error> {
        f.write_fmt(format_args!("({:x}, {:x})", self.u, self.nonce))
    }
}

/// A sum of updates to be applied to witnesses.
#[derive(Clone, Debug)]
pub struct Update<T> where T: BigInt {
    pi_a: T,
    pi_d: T,
}

impl<T> Update<T> where T: BigInt{

    /// Create a new batched update.
    pub fn new() -> Self {
        Update {
            pi_a: 1.into(),
            pi_d: 1.into(),
        }
    }

    /// Absorb an element that must be added to a witness.
    pub fn add<M, N>(&mut self, x: &[u8], w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8> {
        let x_p = to_bigint::<T, N>(M::map(x)).add(&w.nonce);
        self.pi_a = self.pi_a.mul(&x_p);
    }

    /// Absorb an element that must be deleted from a witness.
    pub fn del<M, N>(&mut self, x: &[u8], w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8> {
        let x_p = to_bigint::<T, N>(M::map(x)).add(&w.nonce);
        self.pi_d = self.pi_d.mul(&x_p);
    }

    /// Undo an absorbed element's addition into an update.
    pub fn undo_add<M, N>(&mut self, x: &[u8], w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8> {
        let x_p = to_bigint::<T, N>(M::map(x)).add(&w.nonce);
        self.pi_a = self.pi_a.div(&x_p);
    }

    /// Undo an absorbed element's deletion from an update.
    pub fn undo_del<M, N>(&mut self, x: &[u8], w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8> {
        let x_p = to_bigint::<T, N>(M::map(x)).add(&w.nonce);
        self.pi_d = self.pi_a.div(&x_p);
    }

    /// Update a witness. The update will include all additions and deletions
    /// previously absorbed into this update struct.
    ///
    /// ```
    /// use clacc::{
    ///     Accumulator, Update,
    ///     blake2::Mapper,
    ///     gmp::BigInt,
    ///     typenum::U16,
    /// };
    /// // In this example, the update will include a deletion, so the
    /// // accumulator must be created with a private key.
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigInt>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// // Create the static element.
    /// let xs = b"abc";
    /// // Create the deletion.
    /// let xd = b"def";
    /// // Create the addition.
    /// let xa = b"ghi";
    /// // Add the deletion element.
    /// acc.add::<Mapper, U16>(xd);
    /// // Add the static element to the accumulator.
    /// let mut wxs = acc.add::<Mapper, U16>(xs);
    /// // Delete the deletion element from the accumulator.
    /// let wxd = acc.prove::<Mapper, U16>(xd).unwrap();
    /// acc.del::<Mapper, U16>(xd, &wxd).unwrap();
    /// // Create an update object and absorb the addition and deletion.
    /// let mut u = Update::new();
    /// u.del::<Mapper, U16>(xd, &wxd);
    /// u.add::<Mapper, U16>(xa, &acc.add::<Mapper, U16>(xa));
    /// // Update the static element's witness.
    /// wxs = u.update_witness::<Mapper, U16>(&acc, xs, &wxs);
    /// assert!(acc.verify::<Mapper, U16>(xs, &wxs).is_ok());
    /// ```
    pub fn update_witness<M, N>(
        &self,
        acc: &Accumulator<T>,
        x: &[u8],
        w: &Witness<T>
    ) -> Witness<T>
    where M: Mapper, N: ArrayLength<u8> {
        let x_p = to_bigint::<T, N>(M::map(x)).add(&w.nonce);
        let (_, a, b) = self.pi_d.gcdext(&x_p);
        Witness {
            u: w.u.powm(&a.mul(&self.pi_a), &acc.n)
                .mul(&acc.z.powm(&b, &acc.n)).modulus(&acc.n),
            nonce: w.nonce.clone(),
        }
    }

    /// Multithreaded version of `update_witness` that can update multiple
    /// witnesses and automatically manage updates applied to newly added
    /// elements.
    ///
    /// It is assumed that the additional elements have been absorbed by the
    /// update and that their witnesses are the accumulator's value before any
    /// of the additions or deletions absorbed by this update were applied.
    /// Updating the witnesses for each of these additional elements is thus
    /// acheived by simply removing its respective element from the update and
    /// applying the result to its witness.
    ///
    /// Arguments
    ///
    /// * `acc` - The current accumulator.
    /// * `s` - Iterator to element-witness pairs of static elements.
    /// * `a` - Iterator to element-witness pairs of added elements.
    /// * `thread_count` - The number of threads to use. Returns an error if 0.
    pub fn update_witnesses<'a, M, N, IS, IA>(
        &self,
        acc: &Accumulator<T>,
        s: IS,
        a: IA,
        thread_count: usize
    ) -> Result<(), &'static str>
    where
        M: Mapper,
        N: ArrayLength<u8>,
        IS: Iterator<Item = &'a mut (Vec<u8>, Witness<T>)> + 'a + Send,
        IA: Iterator<Item = &'a mut (Vec<u8>, Witness<T>)> + 'a + Send {
        struct Raw;
        impl ElementSerializer<Vec<u8>> for Raw {
            fn serialize_element(x: &Vec<u8>) -> Vec<u8> {
                x.clone()
            }
        }
        self.serialized_update_witnesses::<M, N, Vec<u8>, Raw, IS, IA>(
            acc,
            s,
            a,
            thread_count
        )
    }

    /// Serialized version of [update_witnesses](#method.update_witnesses).
    ///
    /// Arguments
    ///
    /// * `acc` - The current accumulator.
    /// * `s` - Iterator to element-witness pairs of static elements.
    /// * `a` - Iterator to element-witness pairs of added elements.
    /// * `thread_count` - The number of threads to use. Returns an error if 0.
    pub fn serialized_update_witnesses<'a, M, N, V, S, IS, IA>(
        &self,
        acc: &Accumulator<T>,
        s: IS,
        a: IA,
        thread_count: usize
    ) -> Result<(), &'static str>
    where
        M: Mapper,
        N: ArrayLength<u8>,
        V: 'a,
        S: ElementSerializer<V>,
        IS: Iterator<Item = &'a mut (V, Witness<T>)> + 'a + Send,
        IA: Iterator<Item = &'a mut (V, Witness<T>)> + 'a + Send {
        // Wrap iterator as atomic pointer.
        let s = Arc::new(Mutex::new(s));
        let a = Arc::new(Mutex::new(a));
        // Sanity check thread count.
        if thread_count == 0 {
            return Err("thread_count is 0");
        }
        // Create threads.
        match thread::scope(|scope| {
            for _ in 0..thread_count {
                let update = self.clone();
                let acc = acc.clone();
                let s = Arc::clone(&s);
                let a = Arc::clone(&a);
                scope.spawn(move |_| {
                    loop {
                        let pair;
                        let is_static;
                        {
                            let mut s = s.lock().unwrap();
                            let mut a = a.lock().unwrap();
                            match s.next() {
                                Some(next) => {
                                    pair = next;
                                    is_static = true;
                                },
                                None => {
                                    match a.next() {
                                        Some(next) => {
                                            pair = next;
                                            is_static = false;
                                        },
                                        None => break,
                                    }
                                }
                            };
                        }
                        let element = S::serialize_element(&pair.0);
                        if is_static {
                            pair.1 = update.update_witness::<M, N>(
                                &acc,
                                &element,
                                &pair.1
                            );
                        } else {
                            let mut u = update.clone();
                            u.undo_add::<M, N>(&element, &pair.1);
                            pair.1 = u.update_witness::<M, N>(
                                &acc,
                                &element,
                                &pair.1
                            );
                        }
                    }
                });
            }
        }) {
            Ok(()) => Ok(()),
            Err(_) => Err("error occured in thread"),
        }
    }
}

/// A trait describing a method for serializing an arbitrary data type.
pub trait ElementSerializer<V> {
    fn serialize_element(x: &V) -> Vec<u8>;
}
