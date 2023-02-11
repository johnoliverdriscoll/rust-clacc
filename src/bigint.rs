//! Module for implementations using [num-bigint](https://docs.rs/num-bigint).
use num_bigint_dig::{
    BigInt,
    ExtendedGcd,
    ModInverse,
    Sign,
    ToBigInt,
    prime::next_prime,
};

/// Implementation of [`BigInt`] using [num-bigint](https://docs.rs/num-bigint).
#[cfg_attr(docsrs, doc(cfg(feature = "bigint")))]
impl crate::BigInt for BigInt {

    /// ```
    /// use num_bigint_dig::BigInt;
    /// let x: BigInt = <BigInt as clacc::BigInt>::from_i64(256);
    /// let y: BigInt = 256.into();
    /// assert_eq!(x, y);
    /// ```
    fn from_i64(v: i64) -> Self {
        return v.into()
    }

    /// ```
    /// use num_bigint_dig::BigInt;
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
    /// use num_bigint_dig::BigInt;
    /// let x = vec![0x01, 0x00];
    /// let y: BigInt = 256.into();
    /// assert_eq!(x, <BigInt as clacc::BigInt>::to_bytes_be(&y));
    /// ```
    fn to_bytes_be(&self) -> Vec<u8> {
        BigInt::to_bytes_be(self).1
    }

    /// ```
    /// use num_bigint_dig::BigInt;
    /// let x: BigInt = 240.into();
    /// let y: BigInt = 46.into();
    /// let (g, a, b) = <BigInt as clacc::BigInt>::gcdext(&x, &y);
    /// assert_eq!(g, 2.into());
    /// assert_eq!(a, (-9).into());
    /// assert_eq!(b, 47.into());
    /// ```
    fn gcdext(&self, y: &Self) -> (Self, Self, Self) {
        <BigInt as ExtendedGcd<_>>::extended_gcd(self.clone(), y)
    }

    /// ```
    /// use num_bigint_dig::BigInt;
    /// let b: BigInt = 5.into();
    /// let e: BigInt = 3.into();
    /// let m: BigInt = 13.into();
    /// let c = <BigInt as clacc::BigInt>::powm(&b, &e, &m);
    /// assert_eq!(c, 8.into());
    /// ```
    fn powm(&self, e: &Self, m: &Self) -> Self {
        if e.sign() == Sign::Plus {
            BigInt::modpow(self, e, m)
        } else {
            BigInt::modpow(
                &<BigInt as ModInverse<_>>::mod_inverse(
                    self.clone(),
                    m,
                ).unwrap(),
                &(e * -1),
                m,
            )
        }
    }

    /// ```
    /// use num_bigint_dig::BigInt;
    /// let a: BigInt = 123.into();
    /// let n: BigInt = 4567.into();
    /// let i = <BigInt as clacc::BigInt>::invert(&a, &n).unwrap();
    /// assert_eq!(i, 854.into());
    /// ```
    fn invert(&self, m: &Self) -> Option<Self> {
        <BigInt as ModInverse<_>>::mod_inverse(self.clone(), m)
    }

    /// ```
    /// use num_bigint_dig::BigInt;
    /// let x: BigInt = 32.into();
    /// let p = <BigInt as clacc::BigInt>::next_prime(&x);
    /// assert_eq!(p, 37.into());
    /// ```
    fn next_prime(&self) -> Self {
        next_prime(&self.to_biguint().unwrap()).to_bigint().unwrap()
    }

    /// ```
    /// use num_bigint_dig::BigInt;
    /// let a: BigInt = 3.into();
    /// assert_eq!(<BigInt as clacc::BigInt>::size_in_bits(&a), 2);
    /// let b: BigInt = 256.into();
    /// assert_eq!(<BigInt as clacc::BigInt>::size_in_bits(&b), 9);
    /// ```
    fn size_in_bits(&self) -> usize {
        BigInt::bits(self)
    }
}
