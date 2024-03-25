// SPDX-License-Identifier: MPL-2.0

use pod::Pod;
use rcore_fs::util::BlockIter;

use crate::prelude::*;

use super::{Bid, BlockBuf, BLOCK_SIZE, BLOCK_SIZE_LOG2};

pub trait BlockDevice: Send + Sync {
    /// Returns the total number of blocks in the device.
    fn total_blocks(&self) -> usize;

    /// Reads blocks starting from the `bid`.
    fn read_blocks(&self, bid: Bid, blocks: &mut [&mut [u8]]) -> Result<()>;

    /// Writes blocks starting from the `bid`.
    fn write_blocks(&self, bid: Bid, blocks: &[&[u8]]) -> Result<()>;

    /// Synchronizes the blocks in the device.
    fn sync(&self) -> Result<()>;
}

impl dyn BlockDevice {
    /// Reads one block indicated by the `bid`.
    pub fn read_block(&self, bid: Bid, block: &mut [u8]) -> Result<()> {
        self.read_blocks(bid, &mut [block])
    }

    /// Writes one block indicated by the `bid`.
    pub fn write_block(&self, bid: Bid, block: &[u8]) -> Result<()> {
        self.write_blocks(bid, &[block])
    }

    /// Returns the total number of bytes in the device.
    pub fn total_bytes(&self) -> usize {
        self.total_blocks() * BLOCK_SIZE
    }
}

pub trait BlockDeviceExt {
    /// Reads a specified number of bytes at a specified offset into a given buffer.
    fn read_bytes(&self, offset: usize, buf: &mut [u8]) -> Result<()>;

    /// Write a specified number of bytes from a given buffer at a specified offset.
    fn write_bytes(&self, offset: usize, buf: &[u8]) -> Result<()>;

    /// Reads a value of a specified type at a specified offset.
    fn read_val<T: Pod>(&self, offset: usize) -> Result<T> {
        let mut val = T::new_uninit();
        self.read_bytes(offset, val.as_bytes_mut())?;
        Ok(val)
    }

    /// Writes a value of a specified type at a specified offset.
    fn write_val<T: Pod>(&self, offset: usize, new_val: &T) -> Result<()> {
        self.write_bytes(offset, new_val.as_bytes())
    }
}

impl BlockDeviceExt for dyn BlockDevice {
    fn read_bytes(&self, offset: usize, buf: &mut [u8]) -> Result<()> {
        let max_offset = offset.checked_add(buf.len()).ok_or(FsError::InvalidParam)?;
        if max_offset > self.total_bytes() {
            return Err(FsError::InvalidParam);
        }

        let iter = BlockIter {
            begin: offset,
            end: max_offset,
            block_size_log2: BLOCK_SIZE_LOG2,
        };

        let mut buf_offset = 0;
        for range in iter {
            if range.is_full() {
                self.read_block(
                    range.block as Bid,
                    &mut buf[buf_offset..buf_offset + BLOCK_SIZE],
                )?;
            } else {
                let mut block_buf = BlockBuf::new_uninit();
                self.read_block(range.block as Bid, block_buf.as_mut_slice())?;
                block_buf
                    .read_bytes(range.begin, &mut buf[buf_offset..buf_offset + range.len()])?;
            }
            buf_offset += range.len();
        }

        Ok(())
    }

    fn write_bytes(&self, offset: usize, buf: &[u8]) -> Result<()> {
        let max_offset = offset.checked_add(buf.len()).ok_or(FsError::InvalidParam)?;
        if max_offset > self.total_bytes() {
            return Err(FsError::InvalidParam);
        }

        let iter = BlockIter {
            begin: offset,
            end: max_offset,
            block_size_log2: BLOCK_SIZE_LOG2,
        };

        let mut buf_offset = 0;
        for range in iter {
            if range.is_full() {
                self.write_block(
                    range.block as Bid,
                    &buf[buf_offset..buf_offset + BLOCK_SIZE],
                )?;
            } else {
                let mut block_buf = BlockBuf::new_uninit();
                self.read_block(range.block as Bid, block_buf.as_mut_slice())?;
                block_buf.write_bytes(range.begin, &buf[buf_offset..buf_offset + range.len()])?;
                self.write_block(range.block as Bid, block_buf.as_slice())?;
            }
            buf_offset += range.len();
        }

        Ok(())
    }
}
