// SPDX-License-Identifier: MPL-2.0

use core::ops::Deref;

use crate::{
    bio::BlockCache,
    block_group::{BlockGroup, GroupDescriptor},
    inode::{FilePerm, FileType, Inode, InodeDesc, RawInode},
    prelude::*,
    super_block::{RawSuperBlock, SuperBlock, SUPER_BLOCK_OFFSET},
    utils::{Dirty, TimeProvider},
};

/// The root inode number.
const ROOT_INO: u32 = 2;

/// The Ext2 filesystem.
pub struct Ext2 {
    block_device: Arc<dyn BlockDevice>,
    super_block: RwLock<Dirty<SuperBlock>>,
    time_provider: Arc<dyn TimeProvider>,
    block_groups: Vec<BlockGroup>,
    inodes_per_group: u32,
    blocks_per_group: u32,
    inode_size: usize,
    block_size: usize,
    group_descriptors: RwLock<Vec<BlockBuf>>,
    self_ref: Weak<Self>,
}

impl Ext2 {
    /// Opens and loads an Ext2 from the `block_device`.
    pub fn open(
        block_device: Arc<dyn BlockDevice>,
        time_provider: Arc<dyn TimeProvider>,
    ) -> Result<Arc<Self>> {
        let block_device = BlockCache::new(block_device);
        // Load the superblock
        // TODO: if the main superblock is corrupted, should we load the backup?
        let super_block = {
            let raw_super_block = block_device.read_val::<RawSuperBlock>(SUPER_BLOCK_OFFSET)?;
            SuperBlock::try_from(raw_super_block)?
        };
        assert!(super_block.block_size() == BLOCK_SIZE);

        let group_descriptors = {
            let nblocks = ((super_block.block_groups_count() as usize)
                * size_of::<GroupDescriptor>())
            .div_ceil(BLOCK_SIZE);

            let mut bufs = Vec::with_capacity(nblocks);
            for _ in 0..nblocks {
                let block_buf = BlockBuf::new_uninit();
                bufs.push(block_buf);
            }
            let mut buf_slices: Vec<&mut [u8]> = bufs
                .iter_mut()
                .map(|block_buf| block_buf.as_mut_slice())
                .collect();
            block_device
                .read_blocks(super_block.group_descriptors_bid(0) as Bid, &mut buf_slices)?;
            bufs
        };

        // Load the block groups information
        let load_block_groups = |fs: Weak<Ext2>,
                                 block_device: &Arc<dyn BlockDevice>,
                                 group_descriptors: &Vec<BlockBuf>|
         -> Result<Vec<BlockGroup>> {
            let block_groups_count = super_block.block_groups_count() as usize;
            let mut block_groups = Vec::with_capacity(block_groups_count);
            for idx in 0..block_groups_count {
                let block_group = BlockGroup::load(
                    group_descriptors,
                    idx,
                    block_device,
                    &super_block,
                    fs.clone(),
                )?;
                block_groups.push(block_group);
            }
            Ok(block_groups)
        };

        let ext2 = Arc::new_cyclic(|weak_ref| Self {
            time_provider,
            inodes_per_group: super_block.inodes_per_group(),
            blocks_per_group: super_block.blocks_per_group(),
            inode_size: super_block.inode_size(),
            block_size: super_block.block_size(),
            block_groups: load_block_groups(weak_ref.clone(), &block_device, &group_descriptors)
                .unwrap(),
            block_device,
            super_block: RwLock::new(Dirty::new(super_block)),
            group_descriptors: RwLock::new(group_descriptors),
            self_ref: weak_ref.clone(),
        });
        Ok(ext2)
    }

    /// Returns the block device.
    pub fn block_device(&self) -> &Arc<dyn BlockDevice> {
        &self.block_device
    }

    /// Returns the size of block.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Returns the size of inode.
    pub fn inode_size(&self) -> usize {
        self.inode_size
    }

    /// Returns the number of inodes in each block group.
    pub fn inodes_per_group(&self) -> u32 {
        self.inodes_per_group
    }

    /// Returns the number of blocks in each block group.
    pub fn blocks_per_group(&self) -> u32 {
        self.blocks_per_group
    }

    /// Returns the super block.
    pub fn super_block(&self) -> RwLockReadGuard<'_, Dirty<SuperBlock>> {
        self.super_block.read()
    }

    /// Returns the root inode.
    pub fn root_inode(&self) -> Result<Arc<Inode>> {
        self.lookup_inode(ROOT_INO)
    }

    pub(super) fn time_provider(&self) -> &Arc<dyn TimeProvider> {
        &self.time_provider
    }

    /// Finds and returns the inode by `ino`.
    pub(super) fn lookup_inode(&self, ino: u32) -> Result<Arc<Inode>> {
        let (_, block_group) = self.block_group_of_ino(ino)?;
        let inode_idx = self.inode_idx(ino);
        block_group.lookup_inode(inode_idx)
    }

    /// Creates a new inode.
    pub(super) fn create_inode(
        &self,
        dir_block_group_idx: usize,
        file_type: FileType,
        file_perm: FilePerm,
    ) -> Result<Arc<Inode>> {
        let (block_group_idx, ino) =
            self.alloc_ino(dir_block_group_idx, file_type == FileType::Dir)?;
        let inode = {
            let time = self.time_provider.now();
            let inode_desc = InodeDesc::new(file_type, file_perm, time);
            Inode::new(ino, block_group_idx, inode_desc, self.self_ref.clone())
        };
        let block_group = &self.block_groups[block_group_idx];
        block_group.insert_cache(self.inode_idx(ino), inode.clone());
        Ok(inode)
    }

    /// Allocates a new inode number, internally used by `new_inode`.
    ///
    /// Attempts to allocate from the `dir_block_group_idx` group first.
    /// If allocation is not possible from this group, then search the remaining groups.
    fn alloc_ino(&self, dir_block_group_idx: usize, is_dir: bool) -> Result<(usize, u32)> {
        let mut block_group_idx = dir_block_group_idx;
        if block_group_idx >= self.block_groups.len() {
            return Err(FsError::InvalidParam);
        }

        for _ in 0..self.block_groups.len() {
            if block_group_idx >= self.block_groups.len() {
                block_group_idx = 0;
            }
            let block_group = &self.block_groups[block_group_idx];
            if let Some(inode_idx) = block_group.alloc_inode(is_dir) {
                let ino = block_group_idx as u32 * self.inodes_per_group + inode_idx + 1;
                self.super_block
                    .upgradeable_read()
                    .upgrade()
                    .dec_free_inodes();
                return Ok((block_group_idx, ino));
            }
            block_group_idx += 1;
        }

        Err(FsError::NoDeviceSpace)
    }

    /// Frees an inode.
    pub(super) fn free_inode(&self, ino: u32, is_dir: bool) -> Result<()> {
        let (_, block_group) = self.block_group_of_ino(ino)?;
        let inode_idx = self.inode_idx(ino);
        // In order to prevent value underflow, it is necessary to increment
        // the free inode counter prior to freeing the inode.
        self.super_block
            .upgradeable_read()
            .upgrade()
            .inc_free_inodes();
        block_group.free_inode(inode_idx, is_dir);
        Ok(())
    }

    /// Writes back the metadata of inode.
    pub(super) fn sync_inode(&self, ino: u32, inode: &InodeDesc) -> Result<()> {
        let (_, block_group) = self.block_group_of_ino(ino)?;
        let inode_idx = self.inode_idx(ino);
        block_group.sync_raw_inode(inode_idx, &RawInode::from(inode))?;
        Ok(())
    }

    /// Writes back the block group descriptor to the descriptors table.
    pub(super) fn sync_group_descriptor(
        &self,
        block_group_idx: usize,
        descriptor: &GroupDescriptor,
    ) -> Result<()> {
        let (blk_idx, blk_offset) = {
            let offset = block_group_idx * size_of::<GroupDescriptor>();
            (offset / BLOCK_SIZE, offset % BLOCK_SIZE)
        };
        self.group_descriptors.upgradeable_read().upgrade()[blk_idx]
            .write_val(blk_offset, descriptor)?;
        Ok(())
    }

    /// Allocates a consecutive range of blocks.
    ///
    /// The returned allocated range size may be smaller than the requested `count` if
    /// insufficient consecutive blocks are available.
    ///
    /// Attempts to allocate blocks from the `block_group_idx` group first.
    /// If allocation is not possible from this group, then search the remaining groups.
    pub(super) fn alloc_blocks(
        &self,
        mut block_group_idx: usize,
        count: u32,
    ) -> Option<Range<u32>> {
        if count > self.super_block.read().free_blocks_count() {
            return None;
        }

        let mut remaining_count = count;
        let mut allocated_range: Option<Range<u32>> = None;
        for _ in 0..self.block_groups.len() {
            if remaining_count == 0 {
                break;
            }

            if block_group_idx >= self.block_groups.len() {
                block_group_idx = 0;
            }
            let block_group = &self.block_groups[block_group_idx];
            if let Some(range_in_group) = block_group.alloc_blocks(remaining_count) {
                let device_range = {
                    let start =
                        (block_group_idx as u32) * self.blocks_per_group + range_in_group.start;
                    start..start + (range_in_group.len() as u32)
                };
                match allocated_range {
                    Some(ref mut range) => {
                        if range.end == device_range.start {
                            // Accumulate consecutive bids
                            range.end = device_range.end;
                            remaining_count -= range_in_group.len() as u32;
                        } else {
                            block_group.free_blocks(range_in_group);
                            break;
                        }
                    }
                    None => {
                        allocated_range = Some(device_range);
                    }
                }
            }
            block_group_idx += 1;
        }

        if let Some(range) = allocated_range.as_ref() {
            self.super_block
                .upgradeable_read()
                .upgrade()
                .dec_free_blocks(range.len() as u32);
        }
        allocated_range
    }

    /// Frees a range of blocks.
    pub(super) fn free_blocks(&self, range: Range<u32>) -> Result<()> {
        let mut current_range = range.clone();
        while !current_range.is_empty() {
            let (_, block_group) = self.block_group_of_bid(current_range.start)?;
            let range_in_group = {
                let start = self.block_idx(current_range.start);
                let len = (current_range.len() as u32).min(self.blocks_per_group - start);
                start..start + len
            };
            // In order to prevent value underflow, it is necessary to increment
            // the free block counter prior to freeing the block.
            self.super_block
                .upgradeable_read()
                .upgrade()
                .inc_free_blocks(range_in_group.len() as u32);
            block_group.free_blocks(range_in_group.clone());
            current_range.start += range_in_group.len() as u32;
        }

        Ok(())
    }

    /// Writes back the metadata to the block device.
    pub fn sync_metadata(&self) -> Result<()> {
        // If the superblock is clean, the block groups must be clean.
        if !self.super_block.read().is_dirty() {
            return Ok(());
        }

        let mut super_block = self.super_block.upgradeable_read().upgrade();
        // Writes back the metadata of block groups
        for block_group in &self.block_groups {
            block_group.sync_metadata()?;
        }

        // Writes back the main superblock and group descriptor table.
        let raw_super_block = RawSuperBlock::from((*super_block).deref());
        self.block_device
            .write_bytes(SUPER_BLOCK_OFFSET, raw_super_block.as_bytes())?;
        let group_descriptors = self.group_descriptors.read();
        let group_descriptors_slice: Vec<&[u8]> = group_descriptors
            .iter()
            .map(|block_buf| block_buf.as_slice())
            .collect();
        self.block_device.write_blocks(
            super_block.group_descriptors_bid(0) as Bid,
            &group_descriptors_slice,
        )?;

        // Writes back the backups of superblock and group descriptor table.
        let mut raw_super_block_backup = raw_super_block;
        for idx in 1..super_block.block_groups_count() {
            if super_block.is_backup_group(idx as usize) {
                raw_super_block_backup.block_group_idx = idx as u16;
                self.block_device.write_bytes(
                    super_block.bid(idx as usize) as usize * BLOCK_SIZE,
                    raw_super_block_backup.as_bytes(),
                )?;
                self.block_device.write_blocks(
                    super_block.group_descriptors_bid(idx as usize) as Bid,
                    &group_descriptors_slice,
                )?;
            }
        }

        // Reset to clean.
        super_block.clear_dirty();
        Ok(())
    }

    /// Writes back all the cached inodes to the block device.
    pub fn sync_all_inodes(&self) -> Result<()> {
        for block_group in &self.block_groups {
            block_group.sync_all_inodes()?;
        }
        Ok(())
    }

    #[inline]
    fn block_group_of_bid(&self, bid: u32) -> Result<(usize, &BlockGroup)> {
        let block_group_idx = (bid / self.blocks_per_group) as usize;
        if block_group_idx >= self.block_groups.len() {
            return Err(FsError::EntryNotFound);
        }
        Ok((block_group_idx, &self.block_groups[block_group_idx]))
    }

    #[inline]
    fn block_group_of_ino(&self, ino: u32) -> Result<(usize, &BlockGroup)> {
        let block_group_idx = ((ino - 1) / self.inodes_per_group) as usize;
        if block_group_idx >= self.block_groups.len() {
            return Err(FsError::EntryNotFound);
        }
        Ok((block_group_idx, &self.block_groups[block_group_idx]))
    }

    #[inline]
    fn inode_idx(&self, ino: u32) -> u32 {
        (ino - 1) % self.inodes_per_group
    }

    #[inline]
    fn block_idx(&self, bid: u32) -> u32 {
        bid % self.blocks_per_group
    }
}

impl Debug for Ext2 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Ext2")
            .field("super_block", &self.super_block.read())
            .finish()
    }
}
