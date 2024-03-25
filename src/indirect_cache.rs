// SPDX-License-Identifier: MPL-2.0

use lru::LruCache;

use crate::{block_ptr::BID_SIZE, fs::Ext2, prelude::*};

/// `IndirectCache` is a caching structure that stores `IndirectBlock` objects for Ext2.
///
/// This cache uses an `LruCache` to manage the indirect blocks, ensuring that frequently accessed
/// blocks remain in memory for quick retrieval, while less used blocks can be evicted to make room
/// for new blocks.
#[derive(Debug)]
pub struct IndirectCache {
    cache: LruCache<u32, IndirectBlock>,
    fs: Weak<Ext2>,
}

impl IndirectCache {
    /// The upper bound on the size of the cache.
    ///
    /// Use the same value as `BH_LRU_SIZE`.
    const MAX_SIZE: usize = 16;

    /// Creates a new cache.
    pub fn new(fs: Weak<Ext2>) -> Self {
        Self {
            cache: LruCache::unbounded(),
            fs,
        }
    }

    /// Retrieves a reference to an `IndirectBlock` by its `bid`.
    ///
    /// If the block is not present in the cache, it will be loaded from the disk.
    pub fn find(&mut self, bid: u32) -> Result<&IndirectBlock> {
        self.try_shrink()?;

        let fs = self.fs();
        let load_block = || -> IndirectBlock {
            let mut block = IndirectBlock::alloc_uninit();
            fs.block_device()
                .read_block(bid as Bid, block.buf.as_mut_slice())
                .unwrap();
            block.state = State::UpToDate;
            block
        };
        Ok(self.cache.get_or_insert(bid, load_block))
    }

    /// Retrieves a mutable reference to an `IndirectBlock` by its `bid`.
    ///
    /// If the block is not present in the cache, it will be loaded from the disk.
    pub fn find_mut(&mut self, bid: u32) -> Result<&mut IndirectBlock> {
        self.try_shrink()?;

        let fs = self.fs();
        let load_block = || -> IndirectBlock {
            let mut block = IndirectBlock::alloc_uninit();
            fs.block_device()
                .read_block(bid as Bid, block.buf.as_mut_slice())
                .unwrap();
            block.state = State::UpToDate;
            block
        };
        Ok(self.cache.get_or_insert_mut(bid, load_block))
    }

    /// Inserts or updates an `IndirectBlock` in the cache with the specified `bid`.
    pub fn insert(&mut self, bid: u32, block: IndirectBlock) -> Result<()> {
        self.try_shrink()?;
        self.cache.put(bid, block);
        Ok(())
    }

    /// Removes and returns the `IndirectBlock` corresponding to the `bid`
    /// from the cache or `None` if does not exist.
    pub fn remove(&mut self, bid: u32) -> Option<IndirectBlock> {
        self.cache.pop(&bid)
    }

    /// Evicts all blocks from the cache, persisting any with a 'Dirty' state to the disk.
    pub fn evict_all(&mut self) -> Result<()> {
        loop {
            let Some((bid, block)) = self.cache.pop_lru() else {
                break;
            };

            if block.is_dirty() {
                self.fs()
                    .block_device()
                    .write_block(bid as Bid, block.buf.as_slice())?;
            }
        }

        Ok(())
    }

    /// Attempts to shrink the cache size if it exceeds the maximum allowed cache size.
    fn try_shrink(&mut self) -> Result<()> {
        if self.cache.len() < Self::MAX_SIZE {
            return Ok(());
        }

        for _ in 0..(Self::MAX_SIZE / 2) {
            let (bid, block) = self.cache.pop_lru().unwrap();
            if block.is_dirty() {
                self.fs()
                    .block_device()
                    .write_block(bid as Bid, block.buf.as_slice())?;
            }
        }

        Ok(())
    }

    #[inline]
    fn fs(&self) -> Arc<Ext2> {
        self.fs.upgrade().unwrap()
    }
}

/// Represents a single indirect block buffer cached by the `IndirectCache`.
#[derive(Clone, Debug)]
pub struct IndirectBlock {
    buf: BlockBuf,
    state: State,
}

impl IndirectBlock {
    /// Allocates an uninitialized block whose bytes are to be populated with
    /// data loaded from the disk.
    fn alloc_uninit() -> Self {
        Self {
            buf: BlockBuf::new_uninit(),
            state: State::Uninit,
        }
    }

    /// Allocates a new block with its bytes initialized to zero.
    pub fn alloc() -> Result<Self> {
        let buf = BlockBuf::new_zeroed();
        Ok(Self {
            buf,
            state: State::Dirty,
        })
    }

    /// Returns `true` if it is in dirty state.
    pub fn is_dirty(&self) -> bool {
        self.state == State::Dirty
    }

    /// Reads a bid at a specified `idx`.
    pub fn read_bid(&self, idx: usize) -> Result<u32> {
        assert!(self.state != State::Uninit);
        let bid: u32 = self.buf.read_val(idx * BID_SIZE)?;
        Ok(bid)
    }

    /// Writes a value of bid at a specified `idx`.
    ///
    /// After a successful write operation, the block's state will be marked as dirty.
    pub fn write_bid(&mut self, idx: usize, bid: &u32) -> Result<()> {
        assert!(self.state != State::Uninit);
        self.buf.write_val(idx * BID_SIZE, bid)?;
        self.state = State::Dirty;
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
enum State {
    /// Indicates a new allocated block which content has not been initialized.
    Uninit,
    /// Indicates a block which content is consistent with corresponding disk content.
    UpToDate,
    /// indicates a block which content has been updated and not written back to underlying disk.
    Dirty,
}
