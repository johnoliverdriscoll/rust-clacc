//! Provides methods for [Accumulator](../struct.Accumulator.html) and
//! [Update](../struct.Update.html) that automatically serialize the element.
use generic_array::ArrayLength;
use serde::Serialize;
use crate::{Accumulator, Witness, BigInt, Mapper};

/// Trait for an accumulator that automatically serializes elements into
/// [VelocyPack](https://github.com/arangodb/velocypack) format.
pub trait VpackAccumulator<T> where T: BigInt {

    fn ser_add<M, N, S>(&mut self, x: &S) -> Witness<T>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize;

    fn ser_del<M, N, S>(&mut self, x: &S, w: &Witness<T>)
                        -> Result<T, &'static str>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize;

    fn ser_prove<M, N, S>(&self, x: &S) -> Result<Witness<T>, &'static str>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize;

    fn ser_verify<M, N, S>(&self, x: &S, w: &Witness<T>)
                           -> Result<(), &'static str>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize;
}

/// Trait for an update that automatically serializes elements into
/// [VelocyPack](https://github.com/arangodb/velocypack) format.
pub trait VpackUpdate<T: BigInt> {

    fn ser_add<M, N, S>(&mut self, x: &S, w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8>, S: Serialize;

    fn ser_del<M, N, S>(&mut self, x: &S, w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8>, S: Serialize;

    fn ser_undo_add<M, N, S>(&mut self, x: &S, w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8>, S: Serialize ;

    fn ser_undo_del<M, N, S>(&mut self, x: &S, w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8>, S: Serialize ;

    fn ser_update_witness<M, N, S>(
        &self,
        acc: &Accumulator<T>,
        x: &S,
        w: &Witness<T>
    ) -> Witness<T>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize;

    fn ser_update_witnesses<'a, M, N, S, IS, IA>(
        &self,
        acc: &Accumulator<T>,
        s: IS,
        a: IA,
        thread_count: usize
    ) -> Result<(), &'static str>
    where
        M: Mapper,
        N: ArrayLength<u8>,
        S: Serialize + 'a,
        IS: Iterator<Item = &'a mut (S, Witness<T>)> + 'a + Send,
        IA: Iterator<Item = &'a mut (S, Witness<T>)> + 'a + Send;
}
