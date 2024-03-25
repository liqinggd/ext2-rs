// SPDX-License-Identifier: MPL-2.0

use core::ops::MulAssign;

pub trait IsPowerOf: Copy + Sized + MulAssign + PartialOrd {
    /// Returns true if and only if `self == x^k` for some `k` where `k > 0`.
    ///
    /// The `x` must be a positive value.
    fn is_power_of(&self, x: Self) -> bool {
        let mut power = x;
        while power < *self {
            power *= x;
        }

        power == *self
    }
}

macro_rules! impl_ipo_for {
    ($($ipo_ty:ty),*) => {
        $(impl IsPowerOf for $ipo_ty {})*
    };
}

impl_ipo_for!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, isize, usize);
