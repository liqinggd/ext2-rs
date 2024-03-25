// SPDX-License-Identifier: MPL-2.0

use core::time::Duration;
use pod::Pod;

/// Unix time measures time by the number of seconds that have elapsed since
/// the Unix epoch, without adjustments made due to leap seconds.
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, Pod)]
pub struct UnixTime {
    pub sec: u32,
}

impl UnixTime {
    pub const ZERO: Self = Self { sec: 0 };
}

impl From<Duration> for UnixTime {
    fn from(duration: Duration) -> Self {
        Self {
            sec: duration.as_secs() as u32,
        }
    }
}

impl From<UnixTime> for Duration {
    fn from(time: UnixTime) -> Self {
        Duration::from_secs(time.sec as _)
    }
}

pub trait TimeProvider: Send + Sync {
    fn now(&self) -> UnixTime;
}
