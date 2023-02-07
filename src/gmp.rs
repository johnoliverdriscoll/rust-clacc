//! Module for implementations using [rust-gmp](https://docs.rs/rust-gmp).
use gmp::mpz::Mpz;
use crate::{
    BigInt as BigIntTrait,
};

/// Implementation of [`BigInt`] using [rust-gmp](https://docs.rs/rust-gmp).
pub struct BigInt {
    v: Mpz,
}

impl Default for BigInt {
    fn default() -> Self {
        BigInt {
            v: 0.into(),
        }
    }
}

impl From<Mpz> for BigInt {
    fn from(other: Mpz) -> Self {
        BigInt {
            v: other,
        }
    }
}

impl From<&Mpz> for BigInt {
    fn from(other: &Mpz) -> Self {
        BigInt {
            v: other.clone(),
        }
    }
}

impl From<i64> for BigInt {
    fn from(other: i64) -> Self {
        BigInt {
            v: other.into(),
        }
    }
}

impl<'a> From<&'a [u8]> for BigInt {
    fn from(other: &'a [u8]) -> Self {
        BigInt {
            v: other.into(),
        }
    }
}

impl Clone for BigInt {
    fn clone(&self) -> Self {
        BigInt {
            v: self.v.clone(),
        }
    }
}

impl Eq for BigInt {}

impl PartialEq for BigInt {
    fn eq(&self, other: &Self) -> bool {
        self.v == other.v
    }
}

impl PartialOrd for BigInt {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.v.partial_cmp(&other.v)
    }
}

impl BigIntTrait for BigInt {

    /// ```
    /// use clacc::{BigInt as BigIntTrait, gmp::BigInt};
    /// let a: BigInt = 18.into();
    /// let b: BigInt = 2.into();
    /// let c = a.add(&b);
    /// assert_eq!(c, (18 + 2).into());
    /// ```
    fn add(&self, other: &Self) -> Self {
        (&self.v + &other.v).into()
    }

    /// ```
    /// use clacc::{BigInt as BigIntTrait, gmp::BigInt};
    /// let a: BigInt = 18.into();
    /// let b: BigInt = 2.into();
    /// let c = a.sub(&b);
    /// assert_eq!(c, (18 - 2).into());
    /// ```
    fn sub(&self, other: &Self) -> Self {
        (&self.v - &other.v).into()
    }

    /// ```
    /// use clacc::{BigInt as BigIntTrait, gmp::BigInt};
    /// let a: BigInt = 18.into();
    /// let b: BigInt = 2.into();
    /// let c = a.mul(&b);
    /// assert_eq!(c, (18 * 2).into());
    /// ```
    fn mul(&self, other: &Self) -> Self {
        (&self.v * &other.v).into()
    }

    /// ```
    /// use clacc::{BigInt as BigIntTrait, gmp::BigInt};
    /// let a: BigInt = 18.into();
    /// let b: BigInt = 2.into();
    /// let c = a.div(&b);
    /// assert_eq!(c, (18 / 2).into());
    /// ```
    fn div(&self, other: &Self) -> Self {
        (&self.v / &other.v).into()
    }

    /// ```
    /// use clacc::{BigInt as BigIntTrait, gmp::BigInt};
    /// let x: BigInt = 240.into();
    /// let y: clacc::gmp::BigInt = 46.into();
    /// let (g, a, b) = x.gcdext(&y);
    /// assert_eq!(g, 2.into());
    /// assert_eq!(a, (-9).into());
    /// assert_eq!(b, 47.into());
    /// ```
    fn gcdext(&self, y: &Self) -> (Self, Self, Self) {
        let (g, a, b) = self.v.gcdext(&y.v);
        (g.into(), a.into(), b.into())
    }

    /// ```
    /// use clacc::{BigInt as BigIntTrait, gmp::BigInt};
    /// let b: BigInt = 11.into();
    /// let n: BigInt = 7.into();
    /// let m = b.modulus(&n);
    /// assert_eq!(m, 4.into());
    /// ```
    fn modulus(&self, m: &Self) -> Self {
        BigInt {
            v: self.v.modulus(&m.v),
        }
    }

    /// ```
    /// use clacc::{BigInt as BigIntTrait, gmp::BigInt};
    /// let b: BigInt = 5.into();
    /// let e: BigInt = 3.into();
    /// let m: BigInt = 13.into();
    /// let c = b.powm(&e, &m);
    /// assert_eq!(c, 8.into());
    /// ```
    fn powm(&self, e: &Self, m: &Self) -> Self {
        BigInt {
            v: self.v.powm(&e.v, &m.v),
        }
    }

    /// ```
    /// use clacc::{BigInt as BigIntTrait, gmp::BigInt};
    /// let a: BigInt = 123.into();
    /// let n: BigInt = 4567.into();
    /// let i = a.invert(&n).unwrap();
    /// assert_eq!(i, 854.into());
    /// ```
    fn invert(&self, m: &Self) -> Option<Self> {
        match self.v.invert(&m.v) {
            Some(v) => Some(v.into()),
            None => None,
        }
    }

    /// ```
    /// use clacc::{BigInt as BigIntTrait, gmp::BigInt};
    /// let x: BigInt = 32.into();
    /// let p = x.next_prime();
    /// assert_eq!(p, 37.into());
    /// ```
    fn next_prime(&self) -> Self {
        self.v.nextprime().into()
    }

    /// ```
    /// use clacc::{BigInt as BigIntTrait, gmp::BigInt};
    /// let a: BigInt = 3.into();
    /// assert_eq!(a.size_in_bits(), 2);
    /// let b: BigInt = 256.into();
    /// assert_eq!(b.size_in_bits(), 9);
    /// ```
    fn size_in_bits(&self) -> usize {
        self.v.size_in_base(2)
    }

    /// ```
    /// use clacc::{BigInt as BigIntTrait, gmp::BigInt};
    /// let x: BigInt = 15.into();
    /// assert_eq!(x.to_vec(), vec![0x0f]);
    /// ```
    fn to_vec(&self) -> Vec<u8> {
        (&self.v).into()
    }
}

enum HexCase {
    Upper,
    Lower,
}

impl BigInt {

    fn to_hex(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        case: HexCase
    ) -> Result<(), std::fmt::Error> {
        let bytes: Vec::<u8> = (&self.v).into();
        for byte in bytes {
            match case {
                HexCase::Upper => f.write_fmt(format_args!("{:02X}", byte))?,
                HexCase::Lower => f.write_fmt(format_args!("{:02x}", byte))?,
            }
        }
        Ok(())
    }

}

impl std::fmt::Debug for BigInt {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        self.to_hex(f, HexCase::Lower)
    }
}

impl std::fmt::Display for BigInt {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        self.to_hex(f, HexCase::Lower)
    }
}

impl std::fmt::LowerHex for BigInt {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        self.to_hex(f, HexCase::Lower)
    }
}

impl std::fmt::UpperHex for BigInt {
    fn fmt(
        &self, f:
        &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        self.to_hex(f, HexCase::Upper)
    }
}
