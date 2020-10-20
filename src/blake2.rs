//! Module for implementations using [blake2](https://docs.rs/blake2).
use blake2::{VarBlake2b, digest::{Update, VariableOutput}};
use generic_array::{ArrayLength, GenericArray};

/// An implementation of [Mapper](trait.Mapper.html) using
/// [blake2](https://docs.rs/blake2).
pub struct Mapper;

impl crate::Mapper for Mapper {
    fn map<N>(x: &[u8]) -> GenericArray<u8, N>
    where N: ArrayLength<u8> {
        let mut hasher = VarBlake2b::new(N::to_usize()).unwrap();
        hasher.update(x);
        let mut array = None;
        hasher.finalize_variable(|digest| {
            array = Some(GenericArray::<u8, N>::clone_from_slice(digest));
        });
        array.unwrap()
    }
}
