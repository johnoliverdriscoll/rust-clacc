//! Module for implementations using [`::ripemd`].
use ripemd::{Digest, Ripemd128};

#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "ripemd")))]
pub struct Map;

impl crate::Map for Map {
    fn map<V: Into<Vec<u8>>>(v: V) -> Vec<u8> {
        let mut hasher = Ripemd128::new();
        hasher.update(<V as Into<Vec<u8>>>::into(v).as_slice());
        hasher.finalize().to_vec()
    }
}
