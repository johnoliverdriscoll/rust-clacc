//! Module for implementations using [`::num_bigint`].
use num_bigint::{
    BigInt,
    Sign,
    ToBigInt,
};
use num_integer::Integer;
use num_modular::ModularUnaryOps;
use num_prime::nt_funcs::next_prime;
use std::ops::Neg;

#[cfg_attr(docsrs, doc(cfg(feature = "bigint")))]
impl crate::BigInt for BigInt {

    /// ```
    /// use num_bigint::BigInt;
    /// let x: BigInt = <BigInt as clacc::BigInt>::from_i64(256);
    /// let y: BigInt = 256.into();
    /// assert_eq!(x, y);
    /// ```
    fn from_i64(v: i64) -> Self {
        return v.into()
    }

    /// ```
    /// use num_bigint::BigInt;
    /// let x: BigInt = <BigInt as clacc::BigInt>::from_bytes_be(
    ///     vec![0x01, 0x00].as_slice(),
    /// );
    /// let y: BigInt = 256.into();
    /// assert_eq!(x, y);
    /// ```
    fn from_bytes_be(bytes: &[u8]) -> Self {
        BigInt::from_bytes_be(Sign::Plus, bytes)
    }

    /// ```
    /// use num_bigint::BigInt;
    /// let x = vec![0x01, 0x00];
    /// let y: BigInt = 256.into();
    /// assert_eq!(x, <BigInt as clacc::BigInt>::to_bytes_be(&y));
    /// ```
    fn to_bytes_be(&self) -> Vec<u8> {
        BigInt::to_bytes_be(self).1
    }

    /// ```
    /// use num_bigint::BigInt;
    /// let x: BigInt = 240.into();
    /// let y: BigInt = 46.into();
    /// let (g, a, b) = <BigInt as clacc::BigInt>::gcdext(&x, &y);
    /// assert_eq!(g, 2.into());
    /// assert_eq!(a, (-9).into());
    /// assert_eq!(b, 47.into());
    /// ```
    fn gcdext(&self, y: &Self) -> (Self, Self, Self) {
        let gcd = self.extended_gcd(y);
        (gcd.gcd, gcd.x, gcd.y)
    }

    /// ```
    /// use num_bigint::BigInt;
    /// let b: BigInt = 5.into();
    /// let e: BigInt = 3.into();
    /// let m: BigInt = 13.into();
    /// let c = <BigInt as clacc::BigInt>::powm(&b, &e, &m);
    /// assert_eq!(c, 8.into());
    /// ```
    fn powm(&self, e: &Self, m: &Self) -> Self {
        match e.sign() {
            Sign::Plus | Sign::NoSign => self.modpow(e, m),
            Sign::Minus => {
                self.to_biguint().unwrap().invm(
                    &m.to_biguint().unwrap(),
                ).unwrap().to_bigint().unwrap().modpow(&e.neg(), m)
            },
        }
    }

    /// ```
    /// use num_bigint::BigInt;
    /// let x: BigInt = 32.into();
    /// let p = <BigInt as clacc::BigInt>::next_prime(&x);
    /// assert_eq!(p, 37.into());
    /// ```
    fn next_prime(&self) -> Self {
        next_prime(
            &self.to_biguint().unwrap(),
            None,
        ).unwrap().to_bigint().unwrap()
    }

    /// ```
    /// use num_bigint::BigInt;
    /// let a: BigInt = 3.into();
    /// assert_eq!(<BigInt as clacc::BigInt>::size_in_bits(&a), 2);
    /// let b: BigInt = 256.into();
    /// assert_eq!(<BigInt as clacc::BigInt>::size_in_bits(&b), 9);
    /// ```
    fn size_in_bits(&self) -> usize {
        BigInt::bits(self) as usize
    }
}
