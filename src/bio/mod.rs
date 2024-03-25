// SPDX-License-Identifier: MPL-2.0

pub use self::block_buf::BlockBuf;
pub use self::block_device::{BlockDevice, BlockDeviceExt};

pub type Bid = u64;
pub const BLOCK_SIZE: usize = 4096;
pub const BLOCK_SIZE_LOG2: u8 = 12;

mod block_buf;
mod block_device;
