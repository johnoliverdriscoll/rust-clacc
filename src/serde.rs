//! Module for implementations using [serde](https://docs.rs/serde).
use serde::{
    Serialize, Deserialize,
    ser::{Serializer, SerializeSeq},
    de::{Deserializer, Visitor, SeqAccess},
};
use crate::{
    BigInt as BigIntTrait,
    gmp::BigInt,
};

impl Serialize for BigInt {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let vec = self.to_vec();
        let mut seq = serializer.serialize_seq(Some(vec.len()))?;
        for byte in vec {
            seq.serialize_element(&byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for BigInt {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        struct BigIntVisitor;
        impl<'de> Visitor<'de> for BigIntVisitor {
            type Value = BigInt;
            fn visit_seq<V: SeqAccess<'de>>(
                self,
                mut visitor: V,
            ) -> Result<BigInt, V::Error> {
                let mut vec: Vec<u8> = Vec::new();
                while match visitor.next_element()? {
                    Some(byte) => {
                        vec.push(byte);
                        true
                    },
                    None => false,
                } {}
                Ok(vec.as_slice().into())
            }
            fn expecting(
                &self,
                f: &mut std::fmt::Formatter<'_>,
            ) -> Result<(), std::fmt::Error> {
                write!(f, "a bigint")
            }
        }
        deserializer.deserialize_seq(BigIntVisitor)
    }
}
