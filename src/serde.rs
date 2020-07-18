//! Provides overloaded methods for
//! [Accumulator](../struct.Accumulator.html) and
//! [Update](../struct.Update.html) that automatically serialize the element.
use generic_array::ArrayLength;
use serde::Serialize;
use crate::bigint::BigInt;
use crate::{Accumulator, Update, Witness};
use crate::mapper::Mapper;

/// Trait for an accumulator that automatically serializes elements into
/// [VelocyPack](https://github.com/arangodb/velocypack) format.
trait VpackAccumulator<T: BigInt> {

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

impl<T: BigInt> VpackAccumulator<T> for Accumulator<T> {

    fn add<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &impl Serialize
    ) -> Witness<T> {
        self.add::<Map, N>(&velocypack::to_bytes(x).unwrap())
    }

    fn del<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &impl Serialize,
        w: &Witness<T>
    ) -> Result<(), &'static str> {
        self.del::<Map, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn prove<Map: Mapper, N: ArrayLength<u8>>(
        &self,
        x: &impl Serialize
    ) -> Result<Witness<T>, &'static str> {
        self.prove::<Map, N>(&velocypack::to_bytes(x).unwrap())
    }

    fn verify<Map: Mapper, N: ArrayLength<u8>>(
        &self,
        x: &impl Serialize,
        w: &Witness<T>
    ) -> Result<(), &'static str> {
        self.verify::<Map, N>(&velocypack::to_bytes(x).unwrap(), w)
    }
}

/// Trait for an update that automatically serializes elements into
/// [VelocyPack](https://github.com/arangodb/velocypack) format.
trait VpackUpdate<T: BigInt> {

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

impl<T: BigInt> VpackUpdate<T> for Update<T> {

    fn add<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &impl Serialize,
        w: &Witness<T>
    ) {
        self.add::<Map, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn del<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &impl Serialize,
        w: &Witness<T>
    ) {
        self.del::<Map, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn undo_add<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &impl Serialize,
        w: &Witness<T>
    ) {
        self.undo_add::<Map, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn undo_del<Map: Mapper, N: ArrayLength<u8>>(
        &mut self,
        x: &impl Serialize,
        w: &Witness<T>
    ) {
        self.undo_del::<Map, N>(&velocypack::to_bytes(x).unwrap(), w)
    }
}
