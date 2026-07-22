use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Constant-time equality for MAC / verifier compares.
pub fn secure_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

#[derive(Clone, Zeroize)]
pub struct SecureBytes {
    inner: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureBytes(len={})", self.inner.len())
    }
}

impl SecureBytes {
    pub fn new(len: usize) -> Self {
        Self {
            inner: Zeroizing::new(vec![0u8; len]),
        }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            inner: Zeroizing::new(data.to_vec()),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}
