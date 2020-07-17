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
use generic_array::{ArrayLength, GenericArray};

pub use typenum;
pub mod bigint;
pub mod mapper;

use bigint::BigInt;
use mapper::Mapper;

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
pub struct Accumulator<T: BigInt> {

    /// The current accumulation value.
    pub z: T,

    /// Private exponent.
    d: Option<T>,

    /// Modulus.
    n: T,
}

impl<T: BigInt> Accumulator<T> {

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
    /// let acc = Accumulator::<BigIntGmp>::with_private_key(&p, &q);
    /// ```
    pub fn with_private_key(p: &[u8], q: &[u8]) -> Self {
        let p: T = p.into();
        let q: T = q.into();
        Accumulator {
            d: Some(p.sub(1).mul(&q.sub(1))),
            n: p.mul(&q),
            z: BASE.into(),
        }
    }

    /// Initialize an accumulator from a public key. An accumulator constructed
    /// from a public key is only able to add elements and verify witnesses.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// let n = vec![0x0c, 0xa1];
    /// let acc = Accumulator::<BigIntGmp>::with_public_key(&n);
    /// ```
    pub fn with_public_key(n: &[u8]) -> Self {
        Accumulator {
            d: None,
            n: n.into(),
            z: BASE.into(),
        }
    }

    /// Add an element to an accumulator.
    ///
    /// ```
    /// use clacc::Accumulator;
    /// use clacc::bigint::BigIntGmp;
    /// use clacc::mapper::MapBlake2b;
    /// use clacc::typenum::U16;
    /// let n = vec![0x0c, 0xa1];
    /// let mut acc = Accumulator::<BigIntGmp>::with_public_key(&n);
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
    /// let mut acc = Accumulator::<BigIntGmp>::with_private_key(&p, &q);
    /// let x = b"abc";
    /// let w = acc.add::<MapBlake2b, U16>(x);
    /// assert!(acc.verify::<MapBlake2b, U16>(x, &w).is_ok());
    /// ```
    pub fn add<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &[u8]
    ) -> Witness<T> {
        let x = to_bigint::<T, N>(Map::map(x));
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
    /// let mut acc = Accumulator::<BigIntGmp>::with_private_key(&p, &q);
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
    /// let mut acc = Accumulator::<BigIntGmp>::with_public_key(&n);
    /// let x = b"abc";
    /// let w = acc.add::<MapBlake2b, U16>(x);
    /// assert!(acc.del::<MapBlake2b, U16>(x, &w).is_err());
    /// ```
    pub fn del<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &[u8],
        w: &Witness<T>
    ) -> Result<(), &'static str> {
        let d = match self.d.as_ref() {
            Some(d) => d,
            None => {
                return Err("d is None");
            },
        };
        let x_p = to_bigint::<T, N>(Map::map(x)).add(&w.nonce);
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
        Ok(())
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
    /// let mut acc = Accumulator::<BigIntGmp>::with_private_key(&p, &q);
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
    /// let mut acc = Accumulator::<BigIntGmp>::with_public_key(&n);
    /// let x = b"abc";
    /// acc.add::<MapBlake2b, U16>(x);
    /// assert!(acc.prove::<MapBlake2b, U16>(x).is_err());
    /// ```
    pub fn prove<Map: Mapper, N: ArrayLength<u8>>(
        &self,
        x: &[u8]
    ) -> Result<Witness<T>, &'static str> {
        let d = match self.d.as_ref() {
            Some(d) => d,
            None => {
                return Err("d is None");
            },
        };
        let x = to_bigint::<T, N>(Map::map(x));
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
    /// let mut acc = Accumulator::<BigIntGmp>::with_public_key(&n);
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
    /// let mut acc = Accumulator::<BigIntGmp>::with_private_key(&p, &q);
    /// let x = b"abc";
    /// let w = acc.add::<MapBlake2b, U16>(x);
    /// assert!(acc.verify::<MapBlake2b, U16>(x, &w).is_ok());
    /// ```
    pub fn verify<Map: Mapper, N: ArrayLength<u8>>(
        &self,
        x: &[u8],
        w: &Witness<T>
    ) -> Result<(), &'static str> {
        let x_p = to_bigint::<T, N>(Map::map(x)).add(&w.nonce);
        if self.z != w.u.powm(&x_p, &self.n) {
            return Err("x not in z");
        }
        Ok(())
    }

}

impl<T: BigInt> std::fmt::Display for Accumulator<T> {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        match self.d.as_ref() {
            Some(d) => f.write_fmt(format_args!("({:x}, {:x}, {:x})", d,
                                                 self.n, self.z)),
            None => f.write_fmt(format_args!("({:x}, {:x})", self.n, self.z)),
        }
    }
}

/// A witness of an element's membership in an accumulator.
#[derive(Clone, Debug, Default)]
pub struct Witness<T: BigInt> {

    /// The accumulation value less the element.
    pub u: T,

    /// A number that, when added to the element, uniquely maps the element to
    /// a prime.
    pub nonce: T,
}

impl<T: BigInt> std::fmt::Display for Witness<T> {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        f.write_fmt(format_args!("({:x}, {:x})", self.u, self.nonce))
    }
}

/// A sum of updates to be applied to witnesses.
#[derive(Clone, Debug)]
pub struct Update<T: BigInt> {
    pi_a: T,
    pi_d: T,
}

impl<T: BigInt> Update<T> {

    /// Create a new batched update.
    pub fn new() -> Self {
        Update {
            pi_a: 1.into(),
            pi_d: 1.into(),
        }
    }

    /// Absorb an element that must be added to a witness.
    pub fn add<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &[u8],
        w: &Witness<T>
    ) {
        let x_p = to_bigint::<T, N>(Map::map(x)).add(&w.nonce);
        self.pi_a = self.pi_a.mul(&x_p);
    }

    /// Absorb an element that must be deleted from a witness.
    pub fn del<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &[u8],
        w: &Witness<T>
    ) {
        let x_p = to_bigint::<T, N>(Map::map(x)).add(&w.nonce);
        self.pi_d = self.pi_d.mul(&x_p);
    }

    /// Undo an absorbed element's addition into an update.
    pub fn undo_add<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &[u8],
        w: &Witness<T>
    ) {
        let x_p = to_bigint::<T, N>(Map::map(x)).add(&w.nonce);
        self.pi_a = self.pi_a.div(&x_p);
    }

    /// Undo an absorbed element's deletion from an update.
    pub fn undo_del<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &[u8],
        w: &Witness<T>
    ) {
        let x_p = to_bigint::<T, N>(Map::map(x)).add(&w.nonce);
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
    /// let mut acc = Accumulator::<BigIntGmp>::with_private_key(&p, &q);
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
    pub fn update_witness<Map: Mapper, N: ArrayLength<u8>>(
        &self,
        acc: &Accumulator<T>,
        x: &[u8],
        w: &Witness<T>
    ) -> Witness<T> {
        let x_p = to_bigint::<T, N>(Map::map(x)).add(&w.nonce);
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
    /// * `r` - Receives updated witnesses for static elements.
    /// * `ra` - Receives update witnesse for added elements.
    /// * `acc` - The current accumulator.
    /// * `x` - Pointer to static elements.
    /// * `w` - Pointer to the witnesses of the static elements.
    /// * `n` - The number of static elements.
    /// * `xa` - Pointer to added elements.
    /// * `wa` - Pointer to the witnesses of the added elements.
    /// * `na` - The number of added elements.
    /// * `thread_count` - The number of threads to use. Returns an error if 0.
    pub fn update_witnesses<Map: Mapper, N: ArrayLength<u8>>(
        &self,
        r: *mut Witness<T>,
        ra: *mut Witness<T>,
        acc: &Accumulator<T>,
        x: *const Vec<u8>,
        w: *const Witness<T>,
        n: usize,
        xa: *const Vec<u8>,
        wa: *const Witness<T>,
        na: usize,
        thread_count: usize
    ) -> Result<(), &'static str> {
        // Sanity check thread count.
        if thread_count == 0 {
            return Err("thread_count is 0");
        }
        // Create a mutex marking the index of the current job.
        let job_index = Arc::new(Mutex::<usize>::new(0));
        // Create shareable pointers for the inputs and outputs.
        let r = Arc::new(Mutex::new(AtomicPtr::new(r)));
        let ra = Arc::new(Mutex::new(AtomicPtr::new(ra)));
        let x = Arc::new(Mutex::new(AtomicPtr::new(x as *mut Vec<u8>)));
        let w = Arc::new(Mutex::new(AtomicPtr::new(w as *mut Witness<T>)));
        let xa = Arc::new(Mutex::new(AtomicPtr::new(xa as *mut Vec<u8>)));
        let wa = Arc::new(Mutex::new(AtomicPtr::new(wa as *mut Witness<T>)));
        // Create vector that will store the threads.
        let mut threads = Vec::with_capacity(thread_count);
        // Create threads.
        for _ in 0..thread_count {
            threads.push(self.clone().create_thread::<Map, N>(
                Arc::clone(&r),
                Arc::clone(&ra),
                acc.clone(),
                Arc::clone(&job_index),
                Arc::clone(&x),
                Arc::clone(&w),
                n,
                Arc::clone(&xa),
                Arc::clone(&wa),
                na
            ));
        }
        // Join threads and note if an error occurs.
        let mut errors = false;
        for thread in threads {
            match thread.join() {
                Ok(_) => {},
                Err(_) => {
                    errors = true;
                },
            }
        }
        if errors {
            return Err("error occured joining worker threads");
        }
        Ok(())
    }

    /// Helper function for `update_witnesses` that creates a worker thread.
    fn create_thread<Map: Mapper, N: ArrayLength<u8>>(
        self,
        r: Arc<Mutex<AtomicPtr<Witness<T>>>>,
        ra: Arc<Mutex<AtomicPtr<Witness<T>>>>,
        acc: Accumulator<T>,
        job_index: Arc<Mutex<usize>>,
        x: Arc<Mutex<AtomicPtr<Vec<u8>>>>,
        w: Arc<Mutex<AtomicPtr<Witness<T>>>>,
        n: usize,
        xa: Arc<Mutex<AtomicPtr<Vec<u8>>>>,
        wa: Arc<Mutex<AtomicPtr<Witness<T>>>>,
        na: usize
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            loop {
                let mut i;
                {
                    // Get the current job index.
                    let mut job_index = job_index.lock().unwrap();
                    // Check if there are any more jobs left.
                    if *job_index == n + na {
                        break;
                    }
                    // Save the current job index outside this scope so that
                    // the mutex can be released as soon as possible.
                    i = *job_index;
                    // Increment the job index.
                    *job_index += 1;
                }
                if i < n {
                    // If i < n, perform update on a static element.
                    unsafe {
                        // Get pointers.
                        let x = &*x.lock().unwrap().get_mut().add(i);
                        let w = &*w.lock().unwrap().get_mut().add(i);
                        let r = r.lock().unwrap().get_mut().add(i);
                        // Update witness.
                        *r = self.update_witness::<Map, N>(&acc, x, w);
                    }
                } else {
                    // Otherwise, perform update on an added element.
                    i -= n;
                    unsafe {
                        // Get pointers.
                        let x = &*xa.lock().unwrap().get_mut().add(i);
                        let w = &*wa.lock().unwrap().get_mut().add(i);
                        let r = ra.lock().unwrap().get_mut().add(i);
                        // Create a clone of the update.
                        let mut u = self.clone();
                        // Remove the addition from the update.
                        u.undo_add::<Map, N>(x, &w);
                        // Update witness.
                        *r = u.update_witness::<Map, N>(&acc, x, w);
                    }
                }
            }
        })
    }

}

impl<T: BigInt> std::fmt::Display for Update<T> {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        f.write_fmt(format_args!("({:x}, {:x})", self.pi_a, self.pi_d))
    }
}
