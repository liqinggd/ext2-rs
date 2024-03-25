// SPDX-License-Identifier: MPL-2.0

/// An extension trait for Rust integer types, including `u8`, `u16`, `u32`,
/// `u64`, and `usize`, to provide methods to make integers aligned to a
/// power of two.
pub trait AlignExt {
    /// returns whether the number is a power of two
    fn is_power_of_two(&self) -> bool;

    /// Returns to the smallest number that is greater than or equal to
    /// `self` and is a multiple of the given power of two.
    ///
    /// The method panics if `power_of_two` is not a
    /// power of two or is smaller than 2 or the calculation overflows
    /// because `self` is too large.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::align_ext::AlignExt;
    /// assert_eq!(12usize.align_up(2), 12);
    /// assert_eq!(12usize.align_up(4), 12);
    /// assert_eq!(12usize.align_up(8), 16);
    /// assert_eq!(12usize.align_up(16), 16);
    /// ```
    fn align_up(self, power_of_two: Self) -> Self;

    /// Returns to the greatest number that is smaller than or equal to
    /// `self` and is a multiple of the given power of two.
    ///
    /// The method panics if `power_of_two` is not a
    /// power of two or is smaller than 2 or the calculation overflows
    /// because `self` is too large. In release mode,
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::align_ext::AlignExt;
    /// assert_eq!(12usize.align_down(2), 12);
    /// assert_eq!(12usize.align_down(4), 12);
    /// assert_eq!(12usize.align_down(8), 8);
    /// assert_eq!(12usize.align_down(16), 0);
    /// ```
    fn align_down(self, power_of_two: Self) -> Self;
}

macro_rules! impl_align_ext {
    ($( $uint_type:ty ),+,) => {
        $(
            impl AlignExt for $uint_type {
                #[inline]
                fn is_power_of_two(&self) -> bool {
                    (*self != 0) && ((*self & (*self - 1)) == 0)
                }

                #[inline]
                fn align_up(self, align: Self) -> Self {
                    assert!(align.is_power_of_two() && align >= 2);
                    self.checked_add(align - 1).unwrap() & !(align - 1)
                }

                #[inline]
                fn align_down(self, align: Self) -> Self {
                    assert!(align.is_power_of_two() && align >= 2);
                    self & !(align - 1)
                }
            }
        )*
    }
}

impl_align_ext! {
    u8,
    u16,
    u32,
    u64,
    usize,
}
