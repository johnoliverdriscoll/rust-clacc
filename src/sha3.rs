//! Module for implementations using [`::sha3`].
use sha3::digest::{Update, ExtendableOutput, XofReader};

#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "sha3")))]
pub struct Shake128<const B: usize = 128>;

#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "sha3")))]
pub struct Shake256<const B: usize = 256>;

impl<const B: usize> crate::Map for Shake128<B> {
    fn map<V: Into<Vec<u8>>>(v: V) -> Vec<u8> {
        let mut hasher = ::sha3::Shake128::default();
        hasher.update(<V as Into<Vec<u8>>>::into(v).as_slice());
        let mut reader = hasher.finalize_xof();
        let mut buf = vec![Default::default(); (B + 7) / 8];
        reader.read(&mut buf);
        buf
    }
}

impl<const B: usize> crate::Map for Shake256<B> {
    fn map<V: Into<Vec<u8>>>(v: V) -> Vec<u8> {
        let mut hasher = ::sha3::Shake256::default();
        hasher.update(<V as Into<Vec<u8>>>::into(v).as_slice());
        let mut reader = hasher.finalize_xof();
        let mut buf = vec![Default::default(); (B + 7) / 8];
        reader.read(&mut buf);
        buf
    }
}
