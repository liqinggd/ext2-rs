// SPDX-License-Identifier: MPL-2.0

use core::{fmt::Debug, ops::Range};

use bitvec::prelude::BitVec;

/// An id allocator implemented by the bitmap.
/// The true bit implies that the id is allocated, and vice versa.
#[derive(Clone)]
pub struct IdAlloc {
    bitset: BitVec<u8>,
    first_available_id: usize,
}

impl IdAlloc {
    /// Constructs a new id allocator with a maximum capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut bitset = BitVec::with_capacity(capacity);
        bitset.resize(capacity, false);
        Self {
            bitset,
            first_available_id: 0,
        }
    }

    /// Constructs a new id allocator from a slice of `u8` bytes and a maximum capacity.
    ///
    /// The slice of `u8` bytes is the raw data of a bitmap.
    pub fn from_bytes_with_capacity(slice: &[u8], capacity: usize) -> Self {
        let bitset = if capacity > slice.len() * 8 {
            let mut bitset = BitVec::from_slice(slice);
            bitset.resize(capacity, false);
            bitset
        } else {
            let mut bitset = BitVec::from_slice(&slice[..capacity.div_ceil(8)]);
            bitset.truncate(capacity);
            bitset
        };

        let first_available_id = (0..bitset.len())
            .find(|&i| !bitset[i])
            .map_or(bitset.len(), |i| i);

        Self {
            bitset,
            first_available_id,
        }
    }

    /// Allocates and returns a new `id`.
    ///
    /// If allocation is not possible, it returns `None`.
    pub fn alloc(&mut self) -> Option<usize> {
        if self.first_available_id < self.bitset.len() {
            let id = self.first_available_id;
            self.bitset.set(id, true);
            self.first_available_id = (id + 1..self.bitset.len())
                .find(|&i| !self.bitset[i])
                .map_or(self.bitset.len(), |i| i);
            Some(id)
        } else {
            None
        }
    }

    /// Allocates a consecutive range of new `id`s.
    ///
    /// The `count` is the number of consecutive `id`s to allocate. If it is 0, return `None`.
    ///
    /// If allocation is not possible, it returns `None`.
    pub fn alloc_range(&mut self, count: usize) -> Option<Range<usize>> {
        if count == 0 {
            return None;
        }

        let mut allocated_range: Option<Range<usize>> = None;
        for id in self.first_available_id..self.bitset.len() {
            // Not enough space left to allocate the range
            let allocated_count = allocated_range.as_ref().map_or(0, |range| range.len());
            if count - allocated_count > self.bitset.len() - id {
                return None;
            }

            // Reset the range
            if self.is_allocated(id) {
                allocated_range = None;
                continue;
            }

            match allocated_range {
                Some(ref mut range) => {
                    range.end += 1;
                }
                None => {
                    allocated_range = Some(id..id + 1);
                }
            }

            let range = allocated_range.as_ref().unwrap();
            if range.len() == count {
                for id in range.clone() {
                    self.bitset.set(id, true);
                }

                // Update the first available id if it is allocated.
                if self.is_allocated(self.first_available_id) {
                    self.first_available_id = (range.end..self.bitset.len())
                        .find(|&i| !self.bitset[i])
                        .map_or(self.bitset.len(), |i| i);
                }
                break;
            }
        }

        allocated_range
    }

    /// Releases the consecutive range of allocated `id`s.
    ///
    /// # Panic
    ///
    /// If the `range` is out of bounds, this method will panic.
    pub fn free_range(&mut self, range: Range<usize>) {
        if range.is_empty() {
            return;
        }

        for id in range.clone() {
            debug_assert!(self.is_allocated(id));
            self.bitset.set(id, false);
        }

        if range.start < self.first_available_id {
            self.first_available_id = range.start
        }
    }

    /// Releases the allocated `id`.
    ///
    /// # Panic
    ///
    /// If the `id` is out of bounds, this method will panic.
    pub fn free(&mut self, id: usize) {
        debug_assert!(self.is_allocated(id));

        self.bitset.set(id, false);
        if id < self.first_available_id {
            self.first_available_id = id;
        }
    }

    /// Returns true if the `id` is allocated.
    ///
    /// # Panic
    ///
    /// If the `id` is out of bounds, this method will panic.
    pub fn is_allocated(&self, id: usize) -> bool {
        self.bitset[id]
    }

    /// Views the id allocator as a slice of `u8` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bitset.as_raw_slice()
    }
}

impl Debug for IdAlloc {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("IdAlloc")
            .field("len", &self.bitset.len())
            .field("first_available_id", &self.first_available_id)
            .finish()
    }
}
