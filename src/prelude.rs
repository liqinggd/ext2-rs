// SPDX-License-Identifier: MPL-2.0

pub(crate) use bitflags::bitflags;
pub(crate) use pod::Pod;
pub(crate) use rcore_fs::vfs::{self, DirentVisitor, FsError, Result};
pub(crate) use static_assertions::const_assert;

pub(crate) use crate::bio::{
    Bid, BlockBuf, BlockDevice, BlockDeviceExt, BLOCK_SIZE, BLOCK_SIZE_LOG2,
};

pub(crate) use core::{fmt::Debug, mem::size_of, ops::Range, time::Duration};

cfg_if::cfg_if! {
    if #[cfg(feature = "sgx")] {
        pub(crate) use std::prelude::v1::*;
        pub(crate) use std::sync::{Arc, Weak, SgxMutex as Mutex};
        pub(crate) use std::collections::BTreeMap;
        pub(crate) use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};
    } else {
        pub(crate) use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};
        pub(crate) use alloc::{boxed::Box, collections::BTreeMap, string::{ToString, String}, vec, vec::Vec, sync::{Arc, Weak}};
    }
}
