//! Module for implementations using [ripemd](https://docs.rs/ripemd).
use ripemd::{Digest, Ripemd128};

impl crate::Map for crate::D128 {
    fn map<T, V>(v: V) -> T
    where V: Into<Vec<u8>>,
          T: crate::BigInt {
        let mut hasher = Ripemd128::new();
        hasher.update(<V as Into<Vec<u8>>>::into(v).as_slice());
        hasher.finalize().as_slice().into()
    }
}
