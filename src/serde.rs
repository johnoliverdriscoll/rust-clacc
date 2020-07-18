//! Provides overloaded methods for
//! [Accumulator](../struct.Accumulator.html) and
//! [Update](../struct.Update.html) that automatically serialize the element.
use generic_array::ArrayLength;
use serde::Serialize;
use crate::bigint::BigInt;
use crate::{Witness};
use crate::mapper::Mapper;

/// Trait for an accumulator that automatically serializes elements into
/// [VelocyPack](https://github.com/arangodb/velocypack) format.
pub trait VpackAccumulator<T: BigInt> {

    fn add<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &impl Serialize
    ) -> Witness<T>;

    fn del<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &impl Serialize,
        w: &Witness<T>
    ) -> Result<(), &'static str>;

    fn prove<Map: Mapper, N: ArrayLength<u8>>(
        &self,
        x: &impl Serialize
    ) -> Result<Witness<T>, &'static str>;

    fn verify<Map: Mapper, N: ArrayLength<u8>>(
        &self,
        x: &impl Serialize,
        w: &Witness<T>
    ) -> Result<(), &'static str>;
}

/// Trait for an update that automatically serializes elements into
/// [VelocyPack](https://github.com/arangodb/velocypack) format.
pub trait VpackUpdate<T: BigInt> {

    fn add<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &impl Serialize,
        w: &Witness<T>
    );

    fn del<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &impl Serialize,
        w: &Witness<T>
    );

    fn undo_add<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &impl Serialize,
        w: &Witness<T>
    );

    fn undo_del<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &impl Serialize,
        w: &Witness<T>
    );
}
