//! Module for implementations using [blake2](https://docs.rs/blake2).
use blake2::{Blake2bVar, digest::{Update, VariableOutput}};

impl<D> crate::Map for D
where D: crate::Digest {
    fn map<T, V>(v: V) -> T
    where V: Into<Vec<u8>>,
          T: for<'a> crate::BigInt<'a> {
        let mut hasher = Blake2bVar::new(D::bytes()).unwrap();
        hasher.update(<V as Into<Vec<u8>>>::into(v).as_slice());
        let mut buf = vec![Default::default(); D::bytes()];
        hasher.finalize_variable(&mut buf).unwrap();
        buf.as_slice().into()
    }
}
