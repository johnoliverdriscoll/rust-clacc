//! Module for implementations using [blake2](https://docs.rs/blake2).
use blake2::{Blake2bVar, digest::{Update, VariableOutput}};

/// An implementation of [Mapper](trait.Mapper.html) using
/// [blake2](https://docs.rs/blake2).
pub struct Mapper<const N: usize>;

impl<const N: usize> crate::Mapper for Mapper<N> {
    fn map<T>(x: &[u8]) -> T
    where T: for<'a> crate::BigInt<'a> {
        let mut hasher = Blake2bVar::new(N).unwrap();
        hasher.update(x);
        let mut buf = [0u8; N];
        hasher.finalize_variable(&mut buf).unwrap();
        buf.as_slice().into()
    }
}
