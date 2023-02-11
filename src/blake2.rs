//! Module for implementations using [blake2](https://docs.rs/blake2).
use blake2::{Blake2bVar, digest::{Update, VariableOutput}};

#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "blake2")))]
pub struct Map<const B: usize = 128>;

impl<const B: usize> crate::Map for Map<B> {
    fn map<V: Into<Vec<u8>>>(v: V) -> Vec<u8> {
        let mut hasher = Blake2bVar::new((B + 7) / 8).unwrap();
        hasher.update(<V as Into<Vec<u8>>>::into(v).as_slice());
        let mut buf = vec![Default::default(); (B + 7) / 8];
        hasher.finalize_variable(&mut buf).unwrap();
        buf
    }
}
