use std::io::Write;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use strobe_rs::{SecParam, Strobe};

pub struct Committer<W> {
    strobe: Strobe,
    h: RistrettoPoint,
    inner: W,
}

impl<W> Committer<W>
where
    W: Write,
{
    pub fn new(inner: W) -> Committer<W> {
        // Initialize the STROBE protocol.
        let mut strobe = Strobe::new(b"rando.commit", SecParam::B128);

        // Extract a generator point from the first 64 bytes of PRF output.
        let mut h = [0u8; 64];
        strobe.prf(&mut h, false);
        let h = RistrettoPoint::from_uniform_bytes(&h);

        // Prep the protocol for streaming SEND_CLR operations.
        strobe.send_clr(&[], false);

        Committer { strobe, h, inner }
    }

    pub fn commit(self) -> (W, RistrettoPoint, Scalar) {
        let mut strobe = self.strobe;

        // Generate a random scalar.
        let r = Scalar::random(&mut rand::thread_rng());

        // Extract a scalar from the PRF output.
        let mut x = [0u8; 64];
        strobe.prf(&mut x, false);
        let x = Scalar::from_bytes_mod_order_wide(&x);

        // Calculate C=xG+rH.
        let c = RistrettoPoint::multiscalar_mul([&x, &r], [&G, &self.h]);

        (self.inner, c, r)
    }
}

impl<W> Write for Committer<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.strobe.send_clr(buf, true);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub struct Verifier<W> {
    strobe: Strobe,
    h: RistrettoPoint,
    inner: W,
}

impl<W> Verifier<W>
where
    W: Write,
{
    pub fn new(inner: W) -> Verifier<W> {
        // Initialize the STROBE protocol.
        let mut strobe = Strobe::new(b"rando.commit", SecParam::B128);

        // Extract a generator point from the first 64 bytes of PRF output.
        let mut h = [0u8; 64];
        strobe.prf(&mut h, false);
        let h = RistrettoPoint::from_uniform_bytes(&h);

        // Prep the protocol for streaming RECV_CLR operations.
        strobe.recv_clr(&[], false);

        Verifier { strobe, h, inner }
    }

    pub fn verify(self, c: &RistrettoPoint, r: &Scalar) -> (W, bool) {
        let mut strobe = self.strobe;

        // Extract a scalar from the PRF output.
        let mut x_p = [0u8; 64];
        strobe.prf(&mut x_p, false);
        let x_p = Scalar::from_bytes_mod_order_wide(&x_p);

        // Calculate C'=x'G+rH.
        let c_p = RistrettoPoint::multiscalar_mul([&x_p, r], [&G, &self.h]);

        // Return the inner writer and C == C'.
        (self.inner, c == &c_p)
    }
}

impl<W> Write for Verifier<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.strobe.recv_clr(buf, true);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn commit_and_reveal() {
        let out = Cursor::new(Vec::new());
        let mut committer = Committer::new(out);

        write!(committer, "this is a secret").unwrap();
        write!(committer, " value I guess").unwrap();

        let (out, c, r) = committer.commit();
        assert_eq!(out.into_inner(), b"this is a secret value I guess");

        let out = Cursor::new(Vec::new());
        let mut verifier = Verifier::new(out);

        write!(verifier, "this is a secret value I guess").unwrap();

        let (out, verified) = verifier.verify(&c, &r);
        assert_eq!(out.into_inner(), b"this is a secret value I guess");
        assert!(verified);
    }

    #[test]
    fn wrong_value() {
        let out = Cursor::new(Vec::new());
        let mut committer = Committer::new(out);

        write!(committer, "this is a secret").unwrap();
        write!(committer, " value I guess").unwrap();

        let (out, c, r) = committer.commit();
        assert_eq!(out.into_inner(), b"this is a secret value I guess");

        let out = Cursor::new(Vec::new());
        let mut verifier = Verifier::new(out);

        write!(verifier, "this is NOT a secret value I guess").unwrap();

        let (out, verified) = verifier.verify(&c, &r);
        assert_eq!(out.into_inner(), b"this is NOT a secret value I guess");
        assert!(!verified);
    }

    #[test]
    fn wrong_commitment() {
        let out = Cursor::new(Vec::new());
        let mut committer = Committer::new(out);

        write!(committer, "this is a secret").unwrap();
        write!(committer, " value I guess").unwrap();

        let (out, _, r) = committer.commit();
        assert_eq!(out.into_inner(), b"this is a secret value I guess");

        let out = Cursor::new(Vec::new());
        let mut verifier = Verifier::new(out);

        write!(verifier, "this is NOT a secret value I guess").unwrap();

        let c = RistrettoPoint::random(&mut rand::thread_rng());
        let (out, verified) = verifier.verify(&c, &r);
        assert_eq!(out.into_inner(), b"this is NOT a secret value I guess");
        assert!(!verified);
    }

    #[test]
    fn wrong_opening() {
        let out = Cursor::new(Vec::new());
        let mut committer = Committer::new(out);

        write!(committer, "this is a secret").unwrap();
        write!(committer, " value I guess").unwrap();

        let (out, c, _) = committer.commit();
        assert_eq!(out.into_inner(), b"this is a secret value I guess");

        let out = Cursor::new(Vec::new());
        let mut verifier = Verifier::new(out);

        write!(verifier, "this is NOT a secret value I guess").unwrap();

        let r = Scalar::random(&mut rand::thread_rng());
        let (out, verified) = verifier.verify(&c, &r);
        assert_eq!(out.into_inner(), b"this is NOT a secret value I guess");
        assert!(!verified);
    }
}
