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
    fn serialize<S>(&self, serializer: S)
                    -> Result<S::Ok, S::Error> where S: Serializer {
        let vec = self.to_vec();
        let mut seq = serializer.serialize_seq(Some(vec.len()))?;
        for byte in vec {
            seq.serialize_element(&byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for BigInt {
    fn deserialize<D>(deserializer: D)
                      -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        struct BigIntVisitor;
        impl<'de> Visitor<'de> for BigIntVisitor {
            type Value = BigInt;
            fn visit_seq<V>(self, mut visitor: V)
                            -> Result<BigInt, V::Error>
            where V: SeqAccess<'de> {
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
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>)
                         -> Result<(), std::fmt::Error> {
                write!(f, "a bigint")
            }
        }
        deserializer.deserialize_seq(BigIntVisitor)
    }
}
