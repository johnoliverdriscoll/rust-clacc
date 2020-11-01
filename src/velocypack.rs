//! Module for implementations using [velocypack](https://docs.rs/velocypack).
use serde::Serialize;
use crate::ElementSerializer;

/// An element serializer that uses
/// [VelocyPack](https://github.com/arangodb/velocypack) for serialization.
pub struct VpackSerializer<V> {
    phantom: std::marker::PhantomData<V>,
}

impl<V> ElementSerializer<V> for VpackSerializer<V> where V: Serialize {
    fn serialize_element(x: &V) -> Vec<u8> {
        velocypack::to_bytes(x).unwrap()
    }
}
