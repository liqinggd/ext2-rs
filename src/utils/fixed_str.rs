// SPDX-License-Identifier: MPL-2.0

use alloc::str::Utf8Error;
use core::{
    ffi::{CStr, FromBytesWithNulError},
    fmt::Debug,
};
use pod::Pod;

/// An owned C-compatible string with a fixed capacity of `N`.
///
/// The string is terminated with a null byte.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Pod)]
pub struct FixedCStr<const N: usize>([u8; N]);

impl<const N: usize> FixedCStr<N> {
    pub fn len(&self) -> usize {
        self.0.iter().position(|&b| b == 0).unwrap()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_str(&self) -> Result<&str, Utf8Error> {
        alloc::str::from_utf8(self.as_bytes())
    }

    pub fn as_cstr(&self) -> Result<&CStr, FromBytesWithNulError> {
        CStr::from_bytes_with_nul(self.as_bytes_with_nul())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[0..self.len()]
    }

    pub fn as_bytes_with_nul(&self) -> &[u8] {
        &self.0[0..=self.len()]
    }
}

impl<'a, const N: usize> From<&'a [u8]> for FixedCStr<N> {
    fn from(bytes: &'a [u8]) -> Self {
        assert!(N > 0);

        let mut inner = [0u8; N];
        let len = {
            let mut nul_byte_idx = match bytes.iter().position(|&b| b == 0) {
                Some(idx) => idx,
                None => bytes.len(),
            };
            if nul_byte_idx >= N {
                nul_byte_idx = N - 1;
            }
            nul_byte_idx
        };
        inner[0..len].copy_from_slice(&bytes[0..len]);
        Self(inner)
    }
}

impl<'a, const N: usize> From<&'a str> for FixedCStr<N> {
    fn from(string: &'a str) -> Self {
        let bytes = string.as_bytes();
        Self::from(bytes)
    }
}

impl<'a, const N: usize> From<&'a CStr> for FixedCStr<N> {
    fn from(cstr: &'a CStr) -> Self {
        let bytes = cstr.to_bytes_with_nul();
        Self::from(bytes)
    }
}

impl<const N: usize> Default for FixedCStr<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Debug for FixedCStr<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self.as_cstr() {
            Ok(cstr) => write!(f, "{:?}", cstr),
            Err(_) => write!(f, "{:?}", self.as_bytes()),
        }
    }
}

/// An owned string with a fixed capacity of `N`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Pod)]
pub struct FixedStr<const N: usize>([u8; N]);

impl<const N: usize> FixedStr<N> {
    pub fn len(&self) -> usize {
        self.0.iter().position(|&b| b == 0).unwrap_or(N)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_str(&self) -> Result<&str, Utf8Error> {
        alloc::str::from_utf8(self.as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[0..self.len()]
    }
}

impl<'a, const N: usize> From<&'a [u8]> for FixedStr<N> {
    fn from(bytes: &'a [u8]) -> Self {
        let mut inner = [0u8; N];
        let len = {
            let mut nul_byte_idx = match bytes.iter().position(|&b| b == 0) {
                Some(idx) => idx,
                None => bytes.len(),
            };
            if nul_byte_idx > N {
                nul_byte_idx = N;
            }
            nul_byte_idx
        };
        inner[0..len].copy_from_slice(&bytes[0..len]);
        Self(inner)
    }
}

impl<'a, const N: usize> From<&'a str> for FixedStr<N> {
    fn from(string: &'a str) -> Self {
        let bytes = string.as_bytes();
        Self::from(bytes)
    }
}

impl<const N: usize> Default for FixedStr<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Debug for FixedStr<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self.as_str() {
            Ok(string) => write!(f, "{}", string),
            Err(_) => write!(f, "{:?}", self.as_bytes()),
        }
    }
}
