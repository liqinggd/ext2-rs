// SPDX-License-Identifier: MPL-2.0

use core::ops::Deref;

use rcore_fs::vfs;

use crate::{
    inode::MAX_FNAME_LEN, prelude::*, utils::Dirty, Ext2, SuperBlock as Ext2SuperBlock,
    MAGIC_NUM as EXT2_MAGIC,
};

impl vfs::FileSystem for Ext2 {
    fn sync(&self) -> vfs::Result<()> {
        self.sync_all_inodes()?;
        self.sync_metadata()?;
        Ok(())
    }

    fn root_inode(&self) -> Arc<dyn vfs::INode> {
        self.root_inode().unwrap()
    }

    fn info(&self) -> vfs::FsInfo {
        vfs::FsInfo::from(self.super_block().deref())
    }
}

impl From<&Dirty<Ext2SuperBlock>> for vfs::FsInfo {
    fn from(ext2_sb: &Dirty<Ext2SuperBlock>) -> Self {
        Self {
            magic: EXT2_MAGIC as _,
            bsize: ext2_sb.block_size() as _,
            frsize: ext2_sb.fragment_size() as _,
            blocks: ext2_sb.total_blocks() as _,
            bfree: ext2_sb.free_blocks_count() as _,
            bavail: ext2_sb.free_blocks_count() as _,
            files: ext2_sb.total_inodes() as _,
            ffree: ext2_sb.free_inodes_count() as _,
            namemax: MAX_FNAME_LEN as _,
        }
    }
}
