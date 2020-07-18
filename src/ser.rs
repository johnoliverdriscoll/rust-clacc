//! Provides overloaded methods for
//! [Accumulator](../struct.Accumulator.html) and
//! [Update](../struct.Update.html) that automatically serialize the element.
use generic_array::ArrayLength;
use serde::Serialize;
use crate::{Accumulator, Update, Witness};
use crate::bigint::BigInt;
use crate::mapper::Mapper;

/// Trait for an accumulator that automatically serializes elements into
/// [VelocyPack](https://github.com/arangodb/velocypack) format.
pub trait VpackAccumulator<T: BigInt> {

    fn ser_add<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &mut self,
        x: &S
    ) -> Witness<T>;

    fn ser_del<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &mut self,
        x: &S,
        w: &Witness<T>
    ) -> Result<(), &'static str>;

    fn ser_prove<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &self,
        x: &S
    ) -> Result<Witness<T>, &'static str>;

    fn ser_verify<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &self,
        x: &S,
        w: &Witness<T>
    ) -> Result<(), &'static str>;
}

/// Trait for an update that automatically serializes elements into
/// [VelocyPack](https://github.com/arangodb/velocypack) format.
pub trait VpackUpdate<T: BigInt> {

    fn ser_add<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &mut self,
        x: &S,
        w: &Witness<T>
    );

    fn ser_del<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &mut self,
        x: &S,
        w: &Witness<T>
    );

    fn ser_undo_add<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &mut self,
        x: &S,
        w: &Witness<T>
    );

    fn ser_undo_del<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &mut self,
        x: &S,
        w: &Witness<T>
    );
}

impl<T: BigInt> VpackAccumulator<T> for Accumulator<T> {

    fn ser_add<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &mut self,
        x: &S
    ) -> Witness<T> {
        self.add::<Map, N>(&velocypack::to_bytes(x).unwrap())
    }

    fn ser_del<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &mut self,
        x: &S,
        w: &Witness<T>
    ) -> Result<(), &'static str> {
        self.del::<Map, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_prove<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &self,
        x: &S
    ) -> Result<Witness<T>, &'static str> {
        self.prove::<Map, N>(&velocypack::to_bytes(x).unwrap())
    }

    fn ser_verify<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &self,
        x: &S,
        w: &Witness<T>
    ) -> Result<(), &'static str> {
        self.verify::<Map, N>(&velocypack::to_bytes(x).unwrap(), w)
    }
}

impl<T: BigInt> VpackUpdate<T> for Update<T> {

    fn ser_add<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &mut self,
        x: &S,
        w: &Witness<T>
    ) {
        self.add::<Map, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_del<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &mut self,
        x: &S,
        w: &Witness<T>
    ) {
        self.del::<Map, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_undo_add<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &mut self,
        x: &S,
        w: &Witness<T>
    ) {
        self.undo_add::<Map, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_undo_del<Map: Mapper, N: ArrayLength<u8>, S: Serialize>(
        &mut self,
        x: &S,
        w: &Witness<T>
    ) {
        self.undo_del::<Map, N>(&velocypack::to_bytes(x).unwrap(), w)
    }
}
