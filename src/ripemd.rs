//! Module for implementations using [ripemd](https://docs.rs/ripemd).
use ripemd::{Digest, Ripemd128};

#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "ripemd")))]
pub struct Map;

impl crate::Map for Map {
    fn map<T: crate::BigInt, V: Into<Vec<u8>>>(v: V) -> T {
        let mut hasher = Ripemd128::new();
        hasher.update(<V as Into<Vec<u8>>>::into(v).as_slice());
        hasher.finalize().as_slice().into()
    }
}
