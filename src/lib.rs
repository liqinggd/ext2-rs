// SPDX-License-Identifier: MPL-2.0

//! A Rust Ext2 filesystem.
//!
//! The Second Extended File System(Ext2) is a major rewrite of the Ext filesystem.
//! It is the predominant filesystem in use by Linux from the early 1990s to the early 2000s.
//! The structures of Ext3 and Ext4 are based on Ext2 and add some additional options
//! such as journaling.
//!
//! # Example
//!
//! ```no_run
//! // Opens an Ext2 from the block device.
//! let ext2 = Ext2::open(block_device)?;
//! // Lookup the root inode.
//! let root = ext2.root_inode()?;
//! // Create a file inside root directory.
//! let file = root.create("file", FileType::File, FilePerm::from_bits_truncate(0o666))?;
//! // Write data into the file.
//! const WRITE_DATA: &[u8] = b"Hello, World";
//! let len = file.write_at(0, WRITE_DATA)?;
//! assert!(len == WRITE_DATA.len());
//! ```

#![cfg_attr(not(test), no_std)]
#![feature(int_roundings)]
#![feature(new_uninit)]
#![feature(btree_drain_filter)]
#![allow(dead_code)]

#[cfg(feature = "sgx")]
extern crate sgx_types;
#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;
#[cfg(feature = "sgx")]
extern crate sgx_libc as libc;

#[macro_use]
extern crate log;

extern crate alloc;
extern crate lru;

pub use fs::Ext2;
pub use inode::{FilePerm, FileType, Inode};
pub use super_block::{SuperBlock, MAGIC_NUM};

mod bio;
mod block_group;
mod block_ptr;
mod blocks_hole;
mod dir;
mod fs;
mod impl_for_vfs;
mod indirect_cache;
mod inode;
mod prelude;
mod super_block;
mod utils;

// #[cfg(test)]
// mod test;
