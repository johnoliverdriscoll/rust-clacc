//! Module for implementations using [ripemd](https://docs.rs/ripemd).
use crate::{BigInt, Digest, Map};
use ripemd::{Digest, Ripemd128};

impl Map for D128 {
    fn map<T: BigInt, V: Into<Vec<u8>>>(v: V) -> T {
        let mut hasher = Ripemd128::new();
        hasher.update(<V as Into<Vec<u8>>>::into(v).as_slice());
        hasher.finalize().as_slice().into()
    }
}
