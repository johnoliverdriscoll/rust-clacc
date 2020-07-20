//! Data to element mapper module.
//!
//! A mapper is responsible for uniquely mapping arbitrary data to a fixed size
//! digest using a cryptographic hash function. The implementation provided by
//! this package is [MapBlake2b](struct.MapBlake2b.html) which uses the
//! [Blake2b compression algorithm](https://blake2.net/blake2.pdf).
use blake2::VarBlake2b;
use blake2::digest::{Update, VariableOutput};
use generic_array::{ArrayLength, GenericArray};

/// A trait describing a method for converting some arbitrary data to a fixed
/// sized digest.
pub trait Mapper {
    fn map<N>(x: &[u8]) -> GenericArray<u8, N>
    where N: ArrayLength<u8>;
}

/// An implementation of [Mapper](trait.Mapper.html) using
/// [blake2](https://docs.rs/blake2).
pub struct MapBlake2b;

impl Mapper for MapBlake2b {
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
