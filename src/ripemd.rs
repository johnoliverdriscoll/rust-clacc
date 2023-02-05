//! Module for implementations using [ripemd](https://docs.rs/ripemd).
use ripemd::{Digest, Ripemd128};

impl<const N: usize> crate::Map<N> for Vec<u8> {
    fn map<T>(&self) -> T
    where T: for<'a> crate::BigInt<'a> {
        if N != 128 {
            panic!()
        }
        let mut hasher = Ripemd128::new();
        hasher.update(self.as_slice());
        hasher.finalize().as_slice().into()
    }
}
