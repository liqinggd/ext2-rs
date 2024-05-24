//! A cache layer for a block device.
use crate::prelude::*;

use core::{num::NonZeroUsize, ops::Range};
use lru::LruCache;

const CACHE_CAP: usize = 65536; // 256MB

/// LRU cache upon a block device.
pub struct BlockCache {
    disk: Arc<dyn BlockDevice>,
    lru: Mutex<LruCache<Bid, BlockBuf>>,
}

impl BlockCache {
    pub fn new(disk: Arc<dyn BlockDevice>) -> Arc<dyn BlockDevice> {
        Arc::new(Self {
            disk,
            lru: Mutex::new(LruCache::new(NonZeroUsize::new(CACHE_CAP).unwrap())),
        })
    }
}

impl BlockDevice for BlockCache {
    fn total_blocks(&self) -> usize {
        self.disk.total_blocks()
    }

    fn read_blocks(&self, mut bid: Bid, blocks: &mut [&mut [u8]]) -> Result<()> {
        if bid as usize + blocks.len() > self.total_blocks() {
            return Err(FsError::InvalidParam);
        }

        // Read from LRU cache first and collect missed blocks in batches
        let mut missed_batches: Vec<(Bid, Range<usize>)> = Vec::new();
        let mut lru = self.lru.lock().unwrap();
        for (nth, block) in blocks.iter_mut().enumerate() {
            debug_assert_eq!(block.len(), BLOCK_SIZE);

            if let Some(cached_block) = lru.get(&bid) {
                block.copy_from_slice(cached_block.as_slice());
            } else {
                if let Some((last_bid, range)) = missed_batches.last_mut() {
                    if *last_bid + range.len() as Bid == bid {
                        range.end = nth + 1;
                    } else {
                        missed_batches.push((bid, nth..nth + 1));
                    }
                } else {
                    missed_batches.push((bid, nth..nth + 1));
                }
            }

            bid += 1;
        }

        // Read missed block batches then update the LRU cache
        for (mut start_bid, range) in missed_batches {
            self.disk
                .read_blocks(start_bid, &mut blocks[range.clone()])?;

            for nth in range {
                let _ = lru.put(start_bid, {
                    let mut cached_block = BlockBuf::new_uninit();
                    cached_block.write_bytes(0, &blocks[nth])?;
                    cached_block
                });
                start_bid += 1;
            }
        }
        Ok(())
    }

    fn write_blocks(&self, mut bid: Bid, blocks: &[&[u8]]) -> Result<()> {
        if bid as usize + blocks.len() > self.total_blocks() {
            return Err(FsError::InvalidParam);
        }

        // Write to LRU cache if present then write to disk
        let start_bid = bid;
        let mut lru = self.lru.lock().unwrap();
        for block in blocks {
            debug_assert_eq!(block.len(), BLOCK_SIZE);

            if let Some(cached_block) = lru.peek_mut(&bid) {
                cached_block.write_bytes(0, block)?;
            }

            bid += 1;
        }
        drop(lru);

        self.disk.write_blocks(start_bid, blocks)
    }

    fn sync(&self) -> Result<()> {
        self.disk.sync()
    }
}
