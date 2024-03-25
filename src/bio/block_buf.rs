// SPDX-License-Identifier: MPL-2.0

use pod::Pod;

use crate::prelude::*;

use super::BLOCK_SIZE;

#[derive(Clone, Debug)]
pub struct BlockBuf(Box<[u8]>);

impl BlockBuf {
    pub fn new_uninit() -> Self {
        let buf = unsafe { Box::<[u8]>::new_uninit_slice(BLOCK_SIZE).assume_init() };
        Self(buf)
    }

    pub fn new_zeroed() -> Self {
        let buf = unsafe { Box::<[u8]>::new_zeroed_slice(BLOCK_SIZE).assume_init() };
        Self(buf)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }

    pub fn read_bytes(&self, offset: usize, buf: &mut [u8]) -> Result<()> {
        let max_offset = offset.checked_add(buf.len()).ok_or(FsError::InvalidParam)?;
        if max_offset > BLOCK_SIZE {
            return Err(FsError::InvalidParam);
        }
        buf[..].copy_from_slice(&self.as_slice()[offset..max_offset]);
        Ok(())
    }

    pub fn write_bytes(&mut self, offset: usize, buf: &[u8]) -> Result<()> {
        let max_offset = offset.checked_add(buf.len()).ok_or(FsError::InvalidParam)?;
        if max_offset > BLOCK_SIZE {
            return Err(FsError::InvalidParam);
        }
        self.as_mut_slice()[offset..max_offset].copy_from_slice(&buf[..]);
        Ok(())
    }

    pub fn read_val<T: Pod>(&self, offset: usize) -> Result<T> {
        let mut val = T::new_uninit();
        self.read_bytes(offset, val.as_bytes_mut())?;
        Ok(val)
    }

    pub fn write_val<T: Pod>(&mut self, offset: usize, new_val: &T) -> Result<()> {
        self.write_bytes(offset, new_val.as_bytes())
    }
}
