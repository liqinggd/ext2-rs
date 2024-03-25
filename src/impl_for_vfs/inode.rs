// SPDX-License-Identifier: MPL-2.0

use core::any::Any;

use rcore_fs::vfs;

use crate::{
    inode::{FilePerm, FileType, Inode as Ext2Inode},
    prelude::*,
    utils::UnixTime,
};

impl vfs::INode for Ext2Inode {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> vfs::Result<usize> {
        if self.file_type() == FileType::Symlink {
            debug_assert!(offset == 0);

            let symlink = self.read_link()?;
            let len = symlink.len().min(buf.len());
            buf[0..len].copy_from_slice(&symlink.as_bytes()[0..len]);
            return Ok(len);
        }

        Ok(self.read_at(offset, buf)?)
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> vfs::Result<usize> {
        if self.file_type() == FileType::Symlink {
            debug_assert!(offset == 0);

            self.write_link(&String::from_utf8(buf.to_vec()).map_err(|_| FsError::InvalidParam)?)?;
            return Ok(buf.len());
        }

        Ok(self.write_at(offset, buf)?)
    }

    fn metadata(&self) -> vfs::Result<vfs::Metadata> {
        Ok(vfs::Metadata {
            dev: 0,
            inode: self.ino() as _,
            size: self.file_size() as _,
            blk_size: self.fs().super_block().block_size(),
            blocks: self.blocks_count() as _,
            atime: vfs::Timespec::from(self.atime()),
            mtime: vfs::Timespec::from(self.mtime()),
            ctime: vfs::Timespec::from(self.ctime()),
            type_: vfs::FileType::from(self.file_type()),
            mode: self.file_perm().bits(),
            nlinks: self.hard_links() as _,
            uid: self.uid() as _,
            gid: self.gid() as _,
            rdev: self.device_id().unwrap_or(0) as _,
        })
    }

    fn set_metadata(&self, metadata: &vfs::Metadata) -> vfs::Result<()> {
        self.set_file_perm(FilePerm::from_bits_truncate(metadata.mode));
        self.set_uid(metadata.uid as u32);
        self.set_gid(metadata.gid as u32);
        self.set_atime(UnixTime::from(metadata.atime));
        self.set_mtime(UnixTime::from(metadata.mtime));
        Ok(())
    }

    fn sync_all(&self) -> vfs::Result<()> {
        Ok(self.sync_all()?)
    }

    fn sync_data(&self) -> vfs::Result<()> {
        Ok(self.sync_data()?)
    }

    fn resize(&self, new_size: usize) -> vfs::Result<()> {
        Ok(self.resize(new_size)?)
    }

    fn create(
        &self,
        name: &str,
        type_: vfs::FileType,
        mode: u16,
    ) -> vfs::Result<Arc<dyn vfs::INode>> {
        Ok(self.create(name, type_.into(), FilePerm::from_bits_truncate(mode))?)
    }

    fn link(&self, name: &str, other: &Arc<dyn vfs::INode>) -> vfs::Result<()> {
        let other = other
            .downcast_ref::<Ext2Inode>()
            .ok_or_else(|| vfs::FsError::NotSameFs)?;
        Ok(self.link(other, name)?)
    }

    fn unlink(&self, name: &str) -> Result<()> {
        let target = self.lookup(name)?;
        if target.file_type() == FileType::Dir {
            self.rmdir(name)?;
        } else {
            self.unlink(name)?;
        }
        Ok(())
    }

    fn move_(
        &self,
        old_name: &str,
        target: &Arc<dyn vfs::INode>,
        new_name: &str,
    ) -> vfs::Result<()> {
        let target = target
            .downcast_ref::<Ext2Inode>()
            .ok_or_else(|| vfs::FsError::NotSameFs)?;
        Ok(self.rename(old_name, target, new_name)?)
    }

    fn find(&self, name: &str) -> vfs::Result<Arc<dyn vfs::INode>> {
        Ok(self.lookup(name)?)
    }

    fn iterate_entries(&self, offset: usize, visitor: &mut dyn DirentVisitor) -> Result<usize> {
        Ok(self.readdir_at(offset, visitor)?)
    }

    fn list(&self) -> vfs::Result<Vec<String>> {
        let mut entries: Vec<String> = Vec::new();
        let _ = self.readdir_at(0, &mut entries)?;
        Ok(entries)
    }

    fn get_entry(&self, id: usize) -> vfs::Result<String> {
        let mut entries: Vec<String> = Vec::new();
        let _ = self.readdir_at(0, &mut entries)?;
        if id < entries.len() {
            Ok(entries.remove(id))
        } else {
            Err(vfs::FsError::EntryNotFound)
        }
    }

    fn fs(&self) -> Arc<dyn vfs::FileSystem> {
        self.fs()
    }

    fn as_any_ref(&self) -> &dyn Any {
        self
    }
}

impl From<FileType> for vfs::FileType {
    fn from(type_: FileType) -> Self {
        match type_ {
            FileType::Fifo => Self::NamedPipe,
            FileType::Char => Self::CharDevice,
            FileType::Dir => Self::Dir,
            FileType::Block => Self::BlockDevice,
            FileType::File => Self::File,
            FileType::Symlink => Self::SymLink,
            FileType::Socket => Self::Socket,
        }
    }
}

impl From<vfs::FileType> for FileType {
    fn from(type_: vfs::FileType) -> Self {
        Self::try_from(type_ as u16).unwrap()
    }
}

impl From<UnixTime> for vfs::Timespec {
    fn from(time: UnixTime) -> Self {
        Self {
            sec: time.sec as i64,
            nsec: 0,
        }
    }
}

impl From<vfs::Timespec> for UnixTime {
    fn from(time: vfs::Timespec) -> Self {
        Self {
            sec: time.sec as u32,
        }
    }
}
