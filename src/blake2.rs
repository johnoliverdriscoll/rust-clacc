//! Module for implementations using [blake2](https://docs.rs/blake2).
use crate::{BigInt, Map, Digest, DigestSizer as DS, Sizer};
use blake2::{Blake2bVar, digest::{Update, VariableOutput}};

impl<D> Map for D
where D: Digest {
    fn map<T, V>(v: V) -> T
    where V: Into<Vec<u8>>,
          T: for<'a> BigInt<'a> {
        let mut hasher = Blake2bVar::new(<DS<D> as Sizer>::BYTES).unwrap();
        hasher.update(<V as Into<Vec<u8>>>::into(v).as_slice());
        let mut buf = vec![Default::default(); <DS<D> as Sizer>::BYTES];
        hasher.finalize_variable(&mut buf).unwrap();
        buf.as_slice().into()
    }
}
