//! Module for implementations using [blake2](https://docs.rs/blake2).
use blake2::{Blake2bVar, digest::{Update, VariableOutput}};

impl<const N: usize> crate::Map<N> for Vec<u8> {
    fn map<T>(&self) -> T
    where T: for<'a> crate::BigInt<'a> {
        let mut hasher = Blake2bVar::new(N / 8).unwrap();
        hasher.update(self.as_slice());
        let mut buf = vec![Default::default(); N / 8];
        hasher.finalize_variable(&mut buf).unwrap();
        buf.as_slice().into()
    }
}
