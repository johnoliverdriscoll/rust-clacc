//! Arbitrary precision integer module.
//!
//! The implementation provided by this package is
//! [BigIntGmp](struct.BigIntGmp.html) which uses
//! [rust-gmp](https://docs.rs/rust-gmp).
use gmp::mpz::Mpz;

/// A trait describing an arbitrary precision integer.
pub trait BigInt:
    'static
    + Default
    + From<i64>
    + for<'a> From<&'a [u8]>
    + Clone
    + Sized
    + Send
    + Sync
    + Eq
    + BigIntSub<i64, Output = Self>
    + for<'a> BigIntAdd<&'a Self, Output = Self>
    + for<'a> BigIntSub<&'a Self, Output = Self>
    + for<'a> BigIntMul<&'a Self, Output = Self>
    + for<'a> BigIntDiv<&'a Self, Output = Self>
    + std::fmt::Debug
    + std::fmt::Display
    + std::fmt::LowerHex
    + std::fmt::UpperHex
{
    /// Returns the next prime greater than `self`.
    fn next_prime(&self) -> Self;

    /// Returns the greatest common divisor of `self` and the coefficients `a`
    /// and `b` satisfying `a*x + b*y = g`.
    fn gcdext<'a>(&self, y: &'a Self) -> (Self, Self, Self);

    /// Return the modulus of `self / m`.
    fn modulus<'a>(&self, m: &'a Self) -> Self;

    /// Returns `self^e mod m`.
    fn powm<'a>(&self, e: &'a Self, m: &Self) -> Self;

    /// Returns `self^-1 mod m`.
    fn invert<'a>(&self, m: &'a Self) -> Option<Self>;

    /// Export the number as a u8 vector.
    fn to_vec(&self) -> Vec<u8>;
}

/// A trait describing [BigInt](trait.BigInt.html) addition.
pub trait BigIntAdd<T> {
    type Output;
    fn add(&self, other: T) -> Self::Output;
}

/// A trait describing [BigInt](trait.BigInt.html) subtraction.
pub trait BigIntSub<T> {
    type Output;
    fn sub(&self, other: T) -> Self::Output;
}

/// A trait describing [BigInt](trait.BigInt.html) multiplication.
pub trait BigIntMul<T> {
    type Output;
    fn mul(&self, other: T) -> Self::Output;
}

/// A trait describing [BigInt](trait.BigInt.html) division.
pub trait BigIntDiv<T> {
    type Output;
    fn div(&self, other: T) -> Self::Output;
}

/// An implementation of [BigInt](trait.BigInt.html) using
/// [rust-gmp](https://docs.rs/rust-gmp).
pub struct BigIntGmp {
    v: Mpz,
}

impl Default for BigIntGmp {
    fn default() -> Self {
        BigIntGmp {
            v: 0.into(),
        }
    }
}

impl From<Mpz> for BigIntGmp {
    fn from(other: Mpz) -> Self {
        BigIntGmp {
            v: other,
        }
    }
}

impl From<&Mpz> for BigIntGmp {
    fn from(other: &Mpz) -> Self {
        BigIntGmp {
            v: other.clone(),
        }
    }
}

impl From<i64> for BigIntGmp {
    fn from(other: i64) -> Self {
        BigIntGmp {
            v: other.into(),
        }
    }
}

impl<'a> From<&'a [u8]> for BigIntGmp {
    fn from(other: &'a [u8]) -> Self {
        BigIntGmp {
            v: other.into(),
        }
    }
}

impl Clone for BigIntGmp {
    fn clone(&self) -> Self {
        BigIntGmp {
            v: self.v.clone(),
        }
    }
}

impl Eq for BigIntGmp {}

impl PartialEq for BigIntGmp {
    fn eq(&self, other: &Self) -> bool {
        self.v == other.v
    }
}

impl BigIntSub<i64> for BigIntGmp {
    type Output = Self;
    fn sub(&self, other: i64) -> Self {
        (&self.v - Mpz::from(other)).into()
    }
}

impl<'a> BigIntAdd<&'a BigIntGmp> for BigIntGmp {
    type Output = Self;
    fn add(&self, other: &'a Self) -> Self {
        (&self.v + &other.v).into()
    }
}

impl<'a> BigIntSub<&'a BigIntGmp> for BigIntGmp {
    type Output = Self;
    fn sub(&self, other: &'a Self) -> Self {
        (&self.v - &other.v).into()
    }
}

impl<'a> BigIntMul<&'a BigIntGmp> for BigIntGmp {
    type Output = Self;
    fn mul(&self, other: &'a Self) -> Self {
        (&self.v * &other.v).into()
    }
}

impl<'a> BigIntDiv<&'a BigIntGmp> for BigIntGmp {
    type Output = Self;
    fn div(&self, other: &'a Self) -> Self {
        (&self.v / &other.v).into()
    }
}

impl BigInt for BigIntGmp {

    /// ```
    /// use clacc::bigint::{BigInt, BigIntGmp};
    /// let x: BigIntGmp = 32.into();
    /// let p = x.next_prime();
    /// assert_eq!(p, 37.into());
    /// ```
    fn next_prime(&self) -> Self {
        self.v.nextprime().into()
    }

    /// ```
    /// use clacc::bigint::{BigInt, BigIntGmp};
    /// let x: BigIntGmp = 240.into();
    /// let y: BigIntGmp = 46.into();
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
    /// use clacc::bigint::{BigInt, BigIntGmp};
    /// let b: BigIntGmp = 11.into();
    /// let n: BigIntGmp = 7.into();
    /// let m = b.modulus(&n);
    /// assert_eq!(m, 4.into());
    /// ```
    fn modulus(&self, m: &Self) -> Self {
        BigIntGmp {
            v: self.v.modulus(&m.v),
        }
    }

    /// ```
    /// use clacc::bigint::{BigInt, BigIntGmp};
    /// let b: BigIntGmp = 5.into();
    /// let e: BigIntGmp = 3.into();
    /// let m: BigIntGmp = 13.into();
    /// let c = b.powm(&e, &m);
    /// assert_eq!(c, 8.into());
    /// ```
    fn powm(&self, e: &Self, m: &Self) -> Self {
        BigIntGmp {
            v: self.v.powm(&e.v, &m.v),
        }
    }

    /// ```
    /// use clacc::bigint::{BigInt, BigIntGmp};
    /// let a: BigIntGmp = 123.into();
    /// let n: BigIntGmp = 4567.into();
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
    /// use clacc::bigint::{BigInt, BigIntGmp};
    /// let x: BigIntGmp = 15.into();
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

impl BigIntGmp {

    fn to_hex(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        case: HexCase
    ) -> Result<(), std::fmt::Error> {
        let bytes: Vec::<u8> = (&self.v).into();
        for byte in bytes {
            match match case {
                HexCase::Upper => f.write_fmt(format_args!("{:02X}", byte)),
                HexCase::Lower => f.write_fmt(format_args!("{:02x}", byte)),
            } {
                Ok(()) => {},
                Err(error) => {
                    return Err(error);
                },
            }
        }
        Ok(())
    }

}

impl std::fmt::Debug for BigIntGmp {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        self.to_hex(f, HexCase::Lower)
    }
}

impl std::fmt::Display for BigIntGmp {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        self.to_hex(f, HexCase::Lower)
    }
}

impl std::fmt::LowerHex for BigIntGmp {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        self.to_hex(f, HexCase::Lower)
    }
}

impl std::fmt::UpperHex for BigIntGmp {
    fn fmt(
        &self, f:
        &mut std::fmt::Formatter<'_>
    ) -> Result<(), std::fmt::Error> {
        self.to_hex(f, HexCase::Upper)
    }
}
