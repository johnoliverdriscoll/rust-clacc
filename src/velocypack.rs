//! Module for implementations using [velocypack](https://docs.rs/velocypack).
use generic_array::ArrayLength;
use serde::Serialize;
use crate::{Accumulator, Witness, Update, ElementSerializer, BigInt, Mapper};

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

impl<T> VpackAccumulator<T> for Accumulator<T> where T: BigInt {

    fn ser_add<M, N, S>(&mut self, x: &S) -> Witness<T>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.add::<M, N>(&velocypack::to_bytes(x).unwrap())
    }

    fn ser_del<M, N, S>(&mut self, x: &S, w: &Witness<T>)
                        -> Result<T, &'static str>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.del::<M, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_prove<M, N, S>(&self, x: &S)
                          -> Result<Witness<T>, &'static str>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.prove::<M, N>(&velocypack::to_bytes(x).unwrap())
    }

    fn ser_verify<M, N, S>(&self, x: &S, w: &Witness<T>)
                           -> Result<(), &'static str>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.verify::<M, N>(&velocypack::to_bytes(x).unwrap(), w)
    }
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

impl<T: BigInt> VpackUpdate<T> for Update<T> {

    fn ser_add<M, N, S>(&mut self, x: &S, w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.add::<M, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_del<M, N, S>(&mut self, x: &S, w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.del::<M, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_undo_add<M, N, S>(&mut self, x: &S, w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.undo_add::<M, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_undo_del<M, N, S>(&mut self, x: &S, w: &Witness<T>)
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.undo_del::<M, N>(&velocypack::to_bytes(x).unwrap(), w)
    }

    fn ser_update_witness<M, N, S>(
        &self,
        acc: &Accumulator<T>,
        x: &S,
        w: &Witness<T>
    ) -> Witness<T>
    where M: Mapper, N: ArrayLength<u8>, S: Serialize {
        self.update_witness::<M, N>(
            acc,
            &velocypack::to_bytes(x).unwrap(),
            w
        )
    }

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
        IA: Iterator<Item = &'a mut (S, Witness<T>)> + 'a + Send {
        self.serialized_update_witnesses::<
            M,
            N,
            S,
            VpackSerializer<S>,
            IS,
            IA,
         >(acc, s, a, thread_count)
    }
}

struct VpackSerializer<S> {
    phantom: std::marker::PhantomData<S>,
}

impl<S> ElementSerializer<S> for VpackSerializer<S> where S: Serialize {
    fn serialize_element(x: &S) -> Vec<u8> {
        velocypack::to_bytes(x).unwrap()
    }
}

impl<T> std::fmt::Display for Update<T> where T: BigInt {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        f.write_fmt(format_args!("({:x}, {:x})", self.pi_a, self.pi_d))
    }
}
