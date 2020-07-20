//! This is a Rust implementanion of a CL universal accumulator as described
//! [here](http://groups.csail.mit.edu/cis/pubs/lysyanskaya/cl02a.pdf).
//!
//! An accumulation is a fixed size digest that, along with the witness of an
//! element's addition, can be used to prove an element is a member of a set.
//! The drawback to this solution is that any state changes to the accumulation
//! invalidate the witneses of the other elements in the set, requiring
//! computational resources to update them.
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
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicPtr;
use crossbeam::thread;
use generic_array::{ArrayLength, GenericArray};
use rand::RngCore;
use serde::{Serialize, Deserialize};

pub use typenum;
pub mod bigint;
pub mod mapper;
pub mod ser;

use bigint::BigInt;
use mapper::Mapper;
use ser::{VpackAccumulator, VpackUpdate};

/// The accumulator base.
const BASE: i64 = 65537;

/// Helper function that converts a GenericArray to a BigInt.
fn to_bigint<T: BigInt, N: ArrayLength<u8>>(x: GenericArray<u8, N>) -> T {
    x.as_slice().into()
}

/// An accumulator.
///
/// Elements may be added and deleted from the acculumator without increasing
/// the size of its internal parameters. That is, the number of digits in the
/// accumulation `z` will never exceed the number of digits in the modulus `n`.
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

    /// Initialize an accumulator from private key parameters. All accumulators
    /// are able to add elements and verify witnesses. An accumulator
    /// constructed from a private key is able to delete elements and prove
    /// elements after their addition.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let acc = Accumulator::<BigIntGmp>::with_private_key(
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
    /// ```
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// Accumulator::<BigIntGmp>::with_random_key();
    /// ```
    pub fn with_random_key() -> (Accumulator<T>, T, T) {
        let mut rng = rand::thread_rng();
        let mut bytes = vec![0; 192];
        rng.fill_bytes(&mut bytes);
        let mut p = T::from(bytes.as_slice()).next_prime();
        rng.fill_bytes(&mut bytes);
        let mut q = T::from(bytes.as_slice()).next_prime();
        if p < q {
            std::mem::swap(&mut p, &mut q);
        }
        (Accumulator::with_private_key(p.clone(), q.clone()), p, q)
    }

    /// Initialize an accumulator from a public key. An accumulator constructed
    /// from a public key is only able to add elements and verify witnesses.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// let n = vec![0x0c, 0xa1];
    /// let acc = Accumulator::<BigIntGmp>::with_public_key(
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
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// use clacc::mapper::MapBlake2b;
    /// use clacc::typenum::U16;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigIntGmp>::with_public_key(
    ///     n.as_slice().into()
    /// );
    /// let x = b"abc";
    /// let w = acc.add::<MapBlake2b, U16>(x);
    /// assert!(acc.verify::<MapBlake2b, U16>(x, &w).is_ok());
    /// ```
    ///
    /// This works with accumulators constructed from a public key or a private
    /// key.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// use clacc::mapper::MapBlake2b;
    /// use clacc::typenum::U16;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigIntGmp>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// let x = b"abc";
    /// let w = acc.add::<MapBlake2b, U16>(x);
    /// assert!(acc.verify::<MapBlake2b, U16>(x, &w).is_ok());
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
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// use clacc::mapper::MapBlake2b;
    /// use clacc::typenum::U16;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigIntGmp>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// let x = b"abc";
    /// let w = acc.add::<MapBlake2b, U16>(x);
    /// assert!(acc.del::<MapBlake2b, U16>(x, &w).is_ok());
    /// assert!(acc.verify::<MapBlake2b, U16>(x, &w).is_err());
    /// assert!(acc.del::<MapBlake2b, U16>(x, &w).is_err());
    /// ```
    ///
    /// This will only succeed with an accumulator constructed from a private
    /// key.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// use clacc::mapper::MapBlake2b;
    /// use clacc::typenum::U16;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigIntGmp>::with_public_key(
    ///     n.as_slice().into()
    /// );
    /// let x = b"abc";
    /// let w = acc.add::<MapBlake2b, U16>(x);
    /// assert!(acc.del::<MapBlake2b, U16>(x, &w).is_err());
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
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// use clacc::mapper::MapBlake2b;
    /// use clacc::typenum::U16;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigIntGmp>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// let x = b"abc";
    /// acc.add::<MapBlake2b, U16>(x);
    /// let w = acc.prove::<MapBlake2b, U16>(x).unwrap();
    /// assert!(acc.verify::<MapBlake2b, U16>(x, &w).is_ok());
    /// ```
    ///
    /// This will only succeed with an accumulator constructed from a private
    /// key.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// use clacc::mapper::MapBlake2b;
    /// use clacc::typenum::U16;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigIntGmp>::with_public_key(
    ///     n.as_slice().into()
    /// );
    /// let x = b"abc";
    /// acc.add::<MapBlake2b, U16>(x);
    /// assert!(acc.prove::<MapBlake2b, U16>(x).is_err());
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
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// use clacc::mapper::MapBlake2b;
    /// use clacc::typenum::U16;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigIntGmp>::with_public_key(
    ///     n.as_slice().into()
    /// );
    /// let x = b"abc";
    /// let w = acc.add::<MapBlake2b, U16>(x);
    /// assert!(acc.verify::<MapBlake2b, U16>(x, &w).is_ok());
    /// ```
    ///
    /// This works with accumulators constructed from a public key or a private
    /// key.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// use clacc::mapper::MapBlake2b;
    /// use clacc::typenum::U16;
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigIntGmp>::with_private_key(
    ///     p.as_slice().into(),
    ///     q.as_slice().into()
    /// );
    /// let x = b"abc";
    /// let w = acc.add::<MapBlake2b, U16>(x);
    /// assert!(acc.verify::<MapBlake2b, U16>(x, &w).is_ok());
    /// ```
    pub fn verify<M, N>(&self, x: &[u8], w: &Witness<T>)
                        -> Result<(), &'static str>
    where M: Mapper, N: ArrayLength<u8> {
        let x_p = to_bigint::<T, N>(M::map(x)).add(&w.nonce);
        if self.z != w.u.powm(&x_p, &self.n) {
            return Err("x not in z");
        }
        Ok(())
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

impl<T> VpackAccumulator<T> for Accumulator<T> where T: BigInt {

    fn ser_add<M, N, S>(&mut self, x: &S) -> Witness<T>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.add::<M, N>(&velocypack::to_bytes(x).unwrap())
    }

    fn ser_del<M, N, S>(&mut self, x: &S, w: &Witness<T>)
                        -> Result<T, &'static str>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.del::<M, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_prove<M, N, S>(&self, x: &S)
                          -> Result<Witness<T>, &'static str>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.prove::<M, N>(&velocypack::to_bytes(x).unwrap())
    }

    fn ser_verify<M, N, S>(&self, x: &S, w: &Witness<T>)
                           -> Result<(), &'static str>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.verify::<M, N>(&velocypack::to_bytes(x).unwrap(), w)
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
    /// use clacc::Accumulator;
    /// use clacc::Update;
    /// use clacc::bigint::BigIntGmp;
    /// use clacc::mapper::MapBlake2b;
    /// use clacc::typenum::U16;
    /// // In this example, the update will include a deletion, so the
    /// // accumulator must be created with a private key.
    /// let p = vec![0x3d];
    /// let q = vec![0x35];
    /// let mut acc = Accumulator::<BigIntGmp>::with_private_key(
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
    /// acc.add::<MapBlake2b, U16>(xd);
    /// // Add the static element to the accumulator.
    /// let mut wxs = acc.add::<MapBlake2b, U16>(xs);
    /// // Delete the deletion element from the accumulator.
    /// let wxd = acc.prove::<MapBlake2b, U16>(xd).unwrap();
    /// acc.del::<MapBlake2b, U16>(xd, &wxd).unwrap();
    /// // Create an update object and absorb the addition and deletion.
    /// let mut u = Update::new();
    /// u.del::<MapBlake2b, U16>(xd, &wxd);
    /// u.add::<MapBlake2b, U16>(xa, &acc.add::<MapBlake2b, U16>(xa));
    /// // Update the static element's witness.
    /// wxs = u.update_witness::<MapBlake2b, U16>(&acc, xs, &wxs);
    /// assert!(acc.verify::<MapBlake2b, U16>(xs, &wxs).is_ok());
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
    pub fn update_witnesses<'a, M, N, I>(
        &self,
        acc: &Accumulator<T>,
        s: I,
        a: I,
        thread_count: usize
    ) -> Result<(), &'static str>
    where
        M: Mapper,
        N: ArrayLength<u8>,
        I: Iterator<Item = &'a mut (Vec<u8>, Witness<T>)> + 'a {
        struct Raw;
        impl ElementSerializer<Vec<u8>> for Raw {
            fn serialize_element(x: &Vec<u8>) -> Vec<u8> {
                x.clone()
            }
        }
        self.map_update_witnesses::<M, N, Vec<u8>, Raw, I>(
            acc,
            s,
            a,
            thread_count
        )
    }

    fn map_update_witnesses<'a, M, N, V, S, I>(
        &self,
        acc: &Accumulator<T>,
        mut s: I,
        mut a: I,
        thread_count: usize
    ) -> Result<(), &'static str>
    where
        M: Mapper,
        N: ArrayLength<u8>,
        V: 'a,
        S: ElementSerializer<V>,
        I: Iterator<Item = &'a mut (V, Witness<T>)> + 'a {
        // Wrap iterator as atomic pointer.
        let s = Arc::new(Mutex::new(AtomicPtr::new(&mut s)));
        let a = Arc::new(Mutex::new(AtomicPtr::new(&mut a)));
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
                            let iter_s: &mut I;
                            let iter_a: &mut I;
                            unsafe {
                                iter_s = s.get_mut().as_mut().unwrap();
                                iter_a = a.get_mut().as_mut().unwrap();
                            }
                            match iter_s.next() {
                                Some(next) => {
                                    pair = next;
                                    is_static = true;
                                },
                                None => {
                                    match iter_a.next() {
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

trait ElementSerializer<V> {
    fn serialize_element(x: &V) -> Vec<u8>;
}

impl<T: BigInt> VpackUpdate<T> for Update<T> {

    fn ser_add<M, N, S>(&mut self, x: &S, w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.add::<M, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_del<M, N, S>(&mut self, x: &S, w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.del::<M, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_undo_add<M, N, S>(&mut self, x: &S, w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.undo_add::<M, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_undo_del<M, N, S>(&mut self, x: &S, w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.undo_del::<M, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_update_witness<M, N, S>(
        &self,
        acc: &Accumulator<T>,
        x: &S,
        w: &Witness<T>
    ) -> Witness<T>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.update_witness::<M, N>(
            acc,
            &velocypack::to_bytes(x).unwrap(),
            w
        )
    }

    fn ser_update_witnesses<'a, M, N, S, I>(
        &self,
        acc: &Accumulator<T>,
        s: I,
        a: I,
        thread_count: usize
    ) -> Result<(), &'static str>
    where
        M: Mapper,
        N: ArrayLength<u8>,
        S: Serialize + 'a,
        I: Iterator<Item = &'a mut (S, Witness<T>)> + 'a {
        self.map_update_witnesses::<
            M,
            N,
            S,
            VpackSerializer<S>,
            I,
         >(acc, s, a, thread_count)
    }
}

struct VpackSerializer<S> {
    phantom: std::marker::PhantomData<S>,
}

impl<S> ElementSerializer<S> for VpackSerializer<S> where S: Serialize {
    fn serialize_element(x: &S) -> Vec<u8> {
        velocypack::to_bytes(x).unwrap()
    }
}

impl<T> std::fmt::Display for Update<T> where T: BigInt {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        f.write_fmt(format_args!("({:x}, {:x})", self.pi_a, self.pi_d))
    }
}
