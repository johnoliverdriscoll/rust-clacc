//! Module for implementations using [`::gmp`].
use gmp::mpz::Mpz;

#[cfg_attr(docsrs, doc(cfg(feature = "gmp")))]
impl crate::BigInt for Mpz {

    /// ```
    /// use gmp::mpz::Mpz;
    /// let x: Mpz = <Mpz as clacc::BigInt>::from_i64(256);
    /// let y: Mpz = 256.into();
    /// assert_eq!(x, y);
    /// ```
    fn from_i64(v: i64) -> Self {
        return v.into()
    }

    /// ```
    /// use gmp::mpz::Mpz;
    /// let x: Mpz = <Mpz as clacc::BigInt>::from_bytes_be(
    ///     vec![0x01, 0x00].as_slice(),
    /// );
    /// let y: Mpz = 256.into();
    /// assert_eq!(x, y);
    /// ```
    fn from_bytes_be(bytes: &[u8]) -> Self {
        bytes.into()
    }

    /// ```
    /// use gmp::mpz::Mpz;
    /// let x = vec![0x01, 0x00];
    /// let y: Mpz = 256.into();
    /// assert_eq!(x, <Mpz as clacc::BigInt>::to_bytes_be(&y));
    /// ```
    fn to_bytes_be(&self) -> Vec<u8> {
        self.into()
    }

    /// ```
    /// use gmp::mpz::Mpz;
    /// let x: Mpz = 240.into();
    /// let y: Mpz = 46.into();
    /// let (g, a, b) = <Mpz as clacc::BigInt>::gcdext(&x, &y);
    /// assert_eq!(g, 2.into());
    /// assert_eq!(a, (-9).into());
    /// assert_eq!(b, 47.into());
    /// ```
    fn gcdext(&self, y: &Self) -> (Self, Self, Self) {
        let (g, a, b) = Mpz::gcdext(self, y);
        (g.into(), a.into(), b.into())
    }

    /// ```
    /// use gmp::mpz::Mpz;
    /// let b: Mpz = 5.into();
    /// let e: Mpz = 3.into();
    /// let m: Mpz = 13.into();
    /// let c = <Mpz as clacc::BigInt>::powm(&b, &e, &m);
    /// assert_eq!(c, 8.into());
    /// ```
    fn powm(&self, e: &Self, m: &Self) -> Self {
        Mpz::powm(self, e, m)
    }

    /// ```
    /// use gmp::mpz::Mpz;
    /// let a: Mpz = 123.into();
    /// let n: Mpz = 4567.into();
    /// let i = <Mpz as clacc::BigInt>::invert(&a, &n).unwrap();
    /// assert_eq!(i, 854.into());
    /// ```
    fn invert(&self, m: &Self) -> Option<Self> {
        Mpz::invert(self, m)
    }

    /// ```
    /// use gmp::mpz::Mpz;
    /// let x: Mpz = 32.into();
    /// let p = <Mpz as clacc::BigInt>::next_prime(&x);
    /// assert_eq!(p, 37.into());
    /// ```
    fn next_prime(&self) -> Self {
        Mpz::nextprime(self)
    }

    /// ```
    /// use gmp::mpz::Mpz;
    /// let a: Mpz = 3.into();
    /// assert_eq!(<Mpz as clacc::BigInt>::size_in_bits(&a), 2);
    /// let b: Mpz = 256.into();
    /// assert_eq!(<Mpz as clacc::BigInt>::size_in_bits(&b), 9);
    /// ```
    fn size_in_bits(&self) -> usize {
        Mpz::size_in_base(self, 2)
    }
}
