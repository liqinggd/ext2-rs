// SPDX-License-Identifier: MPL-2.0

use inherit_methods_macro::inherit_methods;
use rcore_fs::util::BlockIter;

use crate::{
    block_ptr::{BidPath, BlockPtrs, BID_SIZE, BLOCK_PTR_CNT},
    blocks_hole::BlocksHoleDesc,
    dir::{DirEntry, DirEntryReader, DirEntryWriter},
    fs::Ext2,
    indirect_cache::{IndirectBlock, IndirectCache},
    prelude::*,
    utils::{Dirty, UnixTime},
};

/// Max length of file name.
pub const MAX_FNAME_LEN: usize = 255;

/// Max path length of the fast symlink.
pub const FAST_SYMLINK_MAX_LEN: usize = BLOCK_PTR_CNT * BID_SIZE;

/// The Ext2 inode.
pub struct Inode {
    ino: u32,
    block_group_idx: usize,
    pub(super) inner: RwLock<InodeInner>,
    fs: Weak<Ext2>,
    lookup_cache: RwLock<HashMap<String, Arc<Inode>>>,
}

impl Inode {
    pub(super) fn new(
        ino: u32,
        block_group_idx: usize,
        desc: Dirty<InodeDesc>,
        fs: Weak<Ext2>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|weak_self| Self {
            ino,
            block_group_idx,
            inner: RwLock::new(InodeInner::new(desc, weak_self.clone(), fs.clone())),
            fs,
            lookup_cache: RwLock::new(HashMap::new()),
        })
    }

    pub fn ino(&self) -> u32 {
        self.ino
    }

    pub(super) fn block_group_idx(&self) -> usize {
        self.block_group_idx
    }

    pub fn fs(&self) -> Arc<Ext2> {
        self.fs.upgrade().unwrap()
    }

    pub fn resize(&self, new_size: usize) -> Result<()> {
        let mut inner = self.inner.upgradeable_read().upgrade();
        if inner.file_type() != FileType::File {
            return Err(FsError::NotFile);
        }
        if new_size == inner.file_size() {
            return Ok(());
        }

        inner.resize(new_size)?;
        Ok(())
    }

    pub fn create(
        &self,
        name: &str,
        file_type: FileType,
        file_perm: FilePerm,
    ) -> Result<Arc<Self>> {
        if name.len() > MAX_FNAME_LEN {
            return Err(FsError::NameTooLong);
        }

        let inner = self.inner.read();
        if inner.file_type() != FileType::Dir {
            return Err(FsError::NotDir);
        }
        if inner.hard_links() == 0 {
            return Err(FsError::DirRemoved);
        }
        if inner.get_entry(name, 0).is_some() {
            return Err(FsError::EntryExist);
        }
        drop(inner);

        let inode = self
            .fs()
            .create_inode(self.block_group_idx, file_type, file_perm)?;
        let is_dir = file_type == FileType::Dir;
        if let Err(e) = inode.init(self.ino) {
            self.fs().free_inode(inode.ino, is_dir).unwrap();
            return Err(e);
        }
        let new_entry = DirEntry::new(inode.ino, name, file_type);

        if let Err(e) = self
            .inner
            .upgradeable_read()
            .upgrade()
            .append_entry(new_entry, 0)
        {
            self.fs().free_inode(inode.ino, is_dir).unwrap();
            return Err(e);
        }
        Ok(inode)
    }

    pub fn lookup(&self, name: &str) -> Result<Arc<Self>> {
        if name.len() > MAX_FNAME_LEN {
            return Err(FsError::NameTooLong);
        }

        if let Some(inode) = self.lookup_cache.read().get(name) {
            return Ok(inode.clone());
        }

        let ino = {
            let inner = self.inner.read();
            if inner.file_type() != FileType::Dir {
                return Err(FsError::NotDir);
            }
            if inner.hard_links() == 0 {
                return Err(FsError::DirRemoved);
            }
            let ino = inner.get_entry_ino(name, 0).ok_or(FsError::EntryNotFound)?;
            ino
        };

        let inode = self.fs().lookup_inode(ino)?;

        self.lookup_cache
            .upgradeable_read()
            .upgrade()
            .insert(name.to_string(), inode.clone());
        Ok(inode)
    }

    pub fn link(&self, inode: &Inode, name: &str) -> Result<()> {
        if name.len() > MAX_FNAME_LEN {
            return Err(FsError::NameTooLong);
        }

        let mut inner = self.inner.upgradeable_read().upgrade();
        if inner.file_type() != FileType::Dir {
            return Err(FsError::NotDir);
        }
        if inner.hard_links() == 0 {
            return Err(FsError::DirRemoved);
        }
        let inode_type = inode.file_type();
        if inode_type == FileType::Dir {
            return Err(FsError::PermError);
        }

        if inner.get_entry(name, 0).is_some() {
            return Err(FsError::EntryExist);
        }

        let new_entry = DirEntry::new(inode.ino, name, inode_type);
        inner.append_entry(new_entry, 0)?;
        drop(inner);

        inode.inner.upgradeable_read().upgrade().inc_hard_links();
        Ok(())
    }

    pub fn unlink(&self, name: &str) -> Result<()> {
        if name.len() > MAX_FNAME_LEN {
            return Err(FsError::NameTooLong);
        }
        if name == "." || name == ".." {
            return Err(FsError::IsDir);
        }

        let inode = {
            let mut inner = self.inner.upgradeable_read().upgrade();
            if inner.file_type() != FileType::Dir {
                return Err(FsError::NotDir);
            }
            if inner.hard_links() == 0 {
                return Err(FsError::DirRemoved);
            }

            let (offset, entry) = inner.get_entry(name, 0).ok_or(FsError::EntryNotFound)?;
            let inode = self.fs().lookup_inode(entry.ino())?;
            if inode.file_type() == FileType::Dir {
                return Err(FsError::IsDir);
            }
            inner.remove_entry(name, offset)?;
            inode
        };

        inode.inner.upgradeable_read().upgrade().dec_hard_links();
        Ok(())
    }

    pub fn rmdir(&self, name: &str) -> Result<()> {
        if name.len() > MAX_FNAME_LEN {
            return Err(FsError::NameTooLong);
        }
        if name == "." {
            return Err(FsError::InvalidParam);
        }
        if name == ".." {
            return Err(FsError::DirNotEmpty);
        }

        let dir_inode = {
            let inner = self.inner.read();
            if inner.file_type() != FileType::Dir {
                return Err(FsError::NotDir);
            }
            if inner.hard_links() == 0 {
                return Err(FsError::DirRemoved);
            }

            let ino = inner.get_entry_ino(name, 0).ok_or(FsError::EntryNotFound)?;
            let dir_inode = self.fs().lookup_inode(ino)?;
            let dir_inner = dir_inode.inner.read();
            if dir_inner.file_type() != FileType::Dir {
                return Err(FsError::NotDir);
            }
            if dir_inner.entry_count() > 2 {
                return Err(FsError::DirNotEmpty);
            }
            drop(dir_inner);
            dir_inode
        };

        let (mut self_inner, mut dir_inner) = write_lock_two_inodes(self, &dir_inode);
        if self_inner.hard_links() == 0 {
            return Err(FsError::DirRemoved);
        }
        if dir_inner.entry_count() > 2 {
            return Err(FsError::DirNotEmpty);
        }
        self_inner.remove_entry(name, 0)?;
        dir_inner.dec_hard_links();
        dir_inner.dec_hard_links(); // For "."
        Ok(())
    }

    /// Rename within its own directory.
    fn rename_within(&self, old_name: &str, new_name: &str) -> Result<()> {
        let mut self_inner = self.inner.upgradeable_read().upgrade();
        if self_inner.file_type() != FileType::Dir {
            return Err(FsError::NotDir);
        }
        if self_inner.hard_links() == 0 {
            return Err(FsError::DirRemoved);
        }

        let (src_offset, src_entry) = self_inner
            .get_entry(old_name, 0)
            .ok_or(FsError::EntryNotFound)?;

        let Some((_, dst_entry)) = self_inner.get_entry(new_name, 0) else {
            self_inner.rename_entry(old_name, new_name, src_offset)?;
            return Ok(());
        };

        drop(self_inner);
        if src_entry.ino() == dst_entry.ino() {
            // Same inode, do nothing
            return Ok(());
        }

        let dst_inode = self.fs().lookup_inode(dst_entry.ino())?;
        let (mut self_inner, mut dst_inner) = write_lock_two_inodes(self, &dst_inode);
        if self_inner.hard_links() == 0 {
            return Err(FsError::DirRemoved);
        }
        match (src_entry.type_(), dst_entry.type_()) {
            (FileType::Dir, FileType::Dir) => {
                if dst_inner.entry_count() > 2 {
                    return Err(FsError::DirNotEmpty);
                }
            }
            (FileType::Dir, _) => {
                return Err(FsError::NotDir);
            }
            (_, FileType::Dir) => {
                return Err(FsError::NotFile);
            }
            _ => {}
        }

        self_inner.remove_entry(new_name, 0)?;
        self_inner.rename_entry(old_name, new_name, 0)?;
        dst_inner.dec_hard_links();
        if dst_inner.file_type() == FileType::Dir {
            dst_inner.dec_hard_links(); // For "."
        }

        Ok(())
    }

    pub fn rename(&self, old_name: &str, target: &Inode, new_name: &str) -> Result<()> {
        if old_name == "." || old_name == ".." || new_name == "." || new_name == ".." {
            return Err(FsError::NotFile);
        }
        if new_name.len() > MAX_FNAME_LEN || new_name.len() > MAX_FNAME_LEN {
            return Err(FsError::NameTooLong);
        }

        // Rename inside the inode
        if self.ino == target.ino {
            return self.rename_within(old_name, new_name);
        }

        let (mut self_inner, mut target_inner) = write_lock_two_inodes(self, target);
        if self_inner.file_type() != FileType::Dir || target_inner.file_type() != FileType::Dir {
            return Err(FsError::NotDir);
        }
        if self_inner.hard_links() == 0 || target_inner.hard_links() == 0 {
            return Err(FsError::DirRemoved);
        }

        let (src_offset, src_entry) = self_inner
            .get_entry(old_name, 0)
            .ok_or(FsError::EntryNotFound)?;
        // Avoid renaming a directory to a subdirectory of itself
        if src_entry.ino() == target.ino {
            return Err(FsError::InvalidParam);
        }

        let Some((_, dst_entry)) = target_inner.get_entry(new_name, 0) else {
            self_inner.remove_entry(old_name, src_offset)?;
            let new_entry = DirEntry::new(src_entry.ino(), new_name, src_entry.type_());
            target_inner.append_entry(new_entry, 0)?;

            if src_entry.type_() == FileType::Dir {
                drop(self_inner);
                drop(target_inner);
                let src_inode = self.fs().lookup_inode(src_entry.ino())?;
                src_inode.inner.upgradeable_read().upgrade().set_parent_ino(target.ino)?;
            }
            return Ok(());
        };

        drop(self_inner);
        drop(target_inner);
        if src_entry.ino() == dst_entry.ino() {
            // Same inode, do nothing
            return Ok(());
        }

        // Avoid renaming a subdirectory to a directory.
        if self.ino == dst_entry.ino() {
            return Err(FsError::DirNotEmpty);
        }

        let dst_inode = self.fs().lookup_inode(dst_entry.ino())?;
        let mut write_guards = write_lock_multiple_inodes(vec![self, target, &dst_inode]);
        let mut dst_inner = write_guards.pop().unwrap();
        match (src_entry.type_(), dst_entry.type_()) {
            (FileType::Dir, FileType::Dir) => {
                if dst_inner.entry_count() > 2 {
                    return Err(FsError::DirNotEmpty);
                }
            }
            (FileType::Dir, _) => {
                return Err(FsError::NotDir);
            }
            (_, FileType::Dir) => {
                return Err(FsError::NotFile);
            }
            _ => {}
        }

        let mut target_inner = write_guards.pop().unwrap();
        let mut self_inner = write_guards.pop().unwrap();

        self_inner.remove_entry(old_name, 0)?;
        target_inner.remove_entry(new_name, 0)?;
        let new_entry = DirEntry::new(src_entry.ino(), new_name, src_entry.type_());
        target_inner.append_entry(new_entry, 0)?;

        dst_inner.dec_hard_links();
        if dst_inner.file_type() == FileType::Dir {
            dst_inner.dec_hard_links(); // For "."
        }

        if src_entry.type_() == FileType::Dir {
            drop(write_guards);
            let src_inode = self.fs().lookup_inode(src_entry.ino())?;
            src_inode
                .inner
                .upgradeable_read()
                .upgrade()
                .set_parent_ino(target.ino)?;
        }

        Ok(())
    }

    pub fn readdir_at(&self, offset: usize, visitor: &mut dyn DirentVisitor) -> Result<usize> {
        let inner = self.inner.read();
        if inner.file_type() != FileType::Dir {
            return Err(FsError::NotDir);
        }
        if inner.hard_links() == 0 {
            return Err(FsError::DirRemoved);
        }

        let try_readdir = |offset: &mut usize, visitor: &mut dyn DirentVisitor| -> Result<()> {
            let dir_entry_reader = DirEntryReader::new(&inner, *offset);
            for (_, dir_entry) in dir_entry_reader {
                visitor.visit_entry(
                    dir_entry.name(),
                    dir_entry.ino() as u64,
                    vfs::FileType::from(dir_entry.type_()),
                    dir_entry.record_len(),
                )?;
                *offset += dir_entry.record_len();
            }

            Ok(())
        };

        let mut iterate_offset = offset;
        match try_readdir(&mut iterate_offset, visitor) {
            Err(e) if iterate_offset == offset => Err(e),
            _ => Ok(iterate_offset - offset),
        }
    }

    pub fn write_link(&self, target: &str) -> Result<()> {
        let mut inner = self.inner.upgradeable_read().upgrade();
        if inner.file_type() != FileType::Symlink {
            return Err(FsError::IsDir);
        }

        inner.write_link(target)?;
        Ok(())
    }

    pub fn read_link(&self) -> Result<String> {
        let inner = self.inner.read();
        if inner.file_type() != FileType::Symlink {
            return Err(FsError::IsDir);
        }

        inner.read_link()
    }

    pub fn set_device_id(&self, device_id: u64) -> Result<()> {
        let mut inner = self.inner.upgradeable_read().upgrade();
        let file_type = inner.file_type();
        if file_type != FileType::Block && file_type != FileType::Char {
            return Err(FsError::IsDir);
        }

        inner.set_device_id(device_id);
        Ok(())
    }

    pub fn device_id(&self) -> Result<u64> {
        let inner = self.inner.read();
        let file_type = inner.file_type();
        if file_type != FileType::Block && file_type != FileType::Char {
            return Err(FsError::IsDir);
        }

        Ok(inner.device_id())
    }

    pub fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let inner = self.inner.read();
        if inner.file_type() != FileType::File {
            return Err(FsError::NotFile);
        }

        let (offset, read_len) = {
            let file_size = self.file_size();
            let start = file_size.min(offset);
            let end = file_size.min(offset + buf.len());
            (start, end - start)
        };

        inner.read_bytes(offset, &mut buf[..read_len])?;
        Ok(read_len)
    }

    // The offset and the length of buffer must be multiples of the block size.
    pub fn read_direct_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        if !is_block_aligned(offset) || !is_block_aligned(buf.len()) {
            return Err(FsError::InvalidParam);
        }

        self.read_at(offset, buf)
    }

    pub fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        let new_size = offset + buf.len();

        let mut inner = self.inner.upgradeable_read().upgrade();
        if inner.file_type() != FileType::File {
            return Err(FsError::NotFile);
        }

        if new_size > inner.file_size() {
            inner.resize(new_size)?;
        }
        drop(inner);

        self.inner.read().write_bytes(offset, buf)?;

        Ok(buf.len())
    }

    // The offset and the length of buffer must be multiples of the block size.
    pub fn write_direct_at(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        if !is_block_aligned(offset) || !is_block_aligned(buf.len()) {
            return Err(FsError::InvalidParam);
        }

        self.write_at(offset, buf)
    }

    fn init(&self, dir_ino: u32) -> Result<()> {
        let mut inner = self.inner.upgradeable_read().upgrade();
        match inner.file_type() {
            FileType::Dir => {
                inner.init_dir(self.ino, dir_ino)?;
            }
            _ => {
                // TODO: Reserve serval blocks for regular file ?
            }
        }
        Ok(())
    }

    pub fn sync_metadata(&self) -> Result<()> {
        if !self.inner.read().desc.is_dirty() {
            return Ok(());
        }

        let mut inner = self.inner.upgradeable_read().upgrade();
        if !inner.desc.is_dirty() {
            return Ok(());
        }

        if inner.hard_links() == 0 {
            inner.resize(0)?;
            // Adds the check here to prevent double-free.
            if !inner.is_freed {
                self.fs()
                    .free_inode(self.ino, inner.file_type() == FileType::Dir)?;
                inner.is_freed = true;
            }
        }

        inner
            .indirect_blocks
            .upgradeable_read()
            .upgrade()
            .evict_all()?;
        self.fs().sync_inode(self.ino, &inner.desc)?;
        inner.desc.clear_dirty();
        Ok(())
    }

    pub fn sync_all(&self) -> Result<()> {
        self.inner.read().sync_data_holes()?;
        self.sync_metadata()?;

        // XXX: Should we sync the disk here?
        // self.fs().block_device().sync()?;
        Ok(())
    }

    pub fn sync_data(&self) -> Result<()> {
        self.inner.read().sync_data_holes()?;

        // XXX: Should we sync the disk here?
        // self.fs().block_device().sync()?;
        Ok(())
    }
}

#[inherit_methods(from = "self.inner.read()")]
impl Inode {
    pub fn file_size(&self) -> usize;
    pub fn file_type(&self) -> FileType;
    pub fn file_perm(&self) -> FilePerm;
    pub fn uid(&self) -> u32;
    pub fn gid(&self) -> u32;
    pub fn file_flags(&self) -> FileFlags;
    pub fn hard_links(&self) -> u16;
    pub fn blocks_count(&self) -> u32;
    pub fn acl(&self) -> Option<u32>;
    pub fn atime(&self) -> UnixTime;
    pub fn mtime(&self) -> UnixTime;
    pub fn ctime(&self) -> UnixTime;
}

#[inherit_methods(from = "self.inner.upgradeable_read().upgrade()")]
impl Inode {
    pub fn set_file_perm(&self, perm: FilePerm);
    pub fn set_uid(&self, uid: u32);
    pub fn set_gid(&self, gid: u32);
    pub fn set_atime(&self, time: UnixTime);
    pub fn set_mtime(&self, time: UnixTime);
}

impl Debug for Inode {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Inode")
            .field("ino", &self.ino)
            .field("block_group_idx", &self.block_group_idx)
            .finish()
    }
}

pub(crate) struct InodeInner {
    desc: Dirty<InodeDesc>,
    blocks_hole_desc: RwLock<BlocksHoleDesc>,
    indirect_blocks: RwLock<IndirectCache>,
    is_freed: bool,
    last_alloc_device_bid: Option<u32>,
    weak_self: Weak<Inode>,
    pub(super) dentry_cache: RwLock<BTreeMap<usize, DirEntry>>,
}

impl InodeInner {
    pub fn new(desc: Dirty<InodeDesc>, weak_self: Weak<Inode>, fs: Weak<Ext2>) -> Self {
        Self {
            blocks_hole_desc: RwLock::new(BlocksHoleDesc::new(desc.blocks_count() as usize)),
            desc,
            indirect_blocks: RwLock::new(IndirectCache::new(fs)),
            is_freed: false,
            last_alloc_device_bid: None,
            weak_self,
            dentry_cache: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn inode(&self) -> Arc<Inode> {
        self.weak_self.upgrade().unwrap()
    }

    pub fn fs(&self) -> Arc<Ext2> {
        self.inode().fs()
    }

    pub fn file_size(&self) -> usize {
        self.desc.size
    }

    pub fn resize(&mut self, new_size: usize) -> Result<()> {
        let old_size = self.desc.size;
        if new_size > old_size {
            self.expand(new_size)?;
        } else {
            self.shrink(new_size);
        }
        Ok(())
    }

    pub fn file_type(&self) -> FileType {
        self.desc.type_
    }

    pub fn file_perm(&self) -> FilePerm {
        self.desc.perm
    }

    pub fn set_file_perm(&mut self, perm: FilePerm) {
        self.desc.perm = perm;
    }

    pub fn uid(&self) -> u32 {
        self.desc.uid
    }

    pub fn set_uid(&mut self, uid: u32) {
        self.desc.uid = uid;
    }

    pub fn gid(&self) -> u32 {
        self.desc.gid
    }

    pub fn set_gid(&mut self, gid: u32) {
        self.desc.gid = gid;
    }

    pub fn file_flags(&self) -> FileFlags {
        self.desc.flags
    }

    pub fn hard_links(&self) -> u16 {
        self.desc.hard_links
    }

    pub fn inc_hard_links(&mut self) {
        self.desc.hard_links += 1;
    }

    pub fn dec_hard_links(&mut self) {
        debug_assert!(self.desc.hard_links > 0);
        self.desc.hard_links -= 1;
    }

    pub fn blocks_count(&self) -> u32 {
        self.desc.blocks_count()
    }

    pub fn acl(&self) -> Option<u32> {
        self.desc.acl
    }

    pub fn atime(&self) -> UnixTime {
        self.desc.atime
    }

    pub fn set_atime(&mut self, time: UnixTime) {
        self.desc.atime = time;
    }

    pub fn mtime(&self) -> UnixTime {
        self.desc.mtime
    }

    pub fn set_mtime(&mut self, time: UnixTime) {
        self.desc.mtime = time;
    }

    pub fn ctime(&self) -> UnixTime {
        self.desc.ctime
    }

    pub fn set_device_id(&mut self, device_id: u64) {
        self.desc.block_ptrs.as_bytes_mut()[..size_of::<u64>()]
            .copy_from_slice(device_id.as_bytes());
    }

    pub fn device_id(&self) -> u64 {
        let mut device_id: u64 = 0;
        device_id
            .as_bytes_mut()
            .copy_from_slice(&self.desc.block_ptrs.as_bytes()[..size_of::<u64>()]);
        device_id
    }

    pub fn read_block(&self, bid: u32, block: &mut [u8]) -> Result<()> {
        if bid >= self.desc.blocks_count() {
            return Err(FsError::InvalidParam);
        }

        if self.blocks_hole_desc.read().is_hole(bid as usize) {
            block.fill(0);
            return Ok(());
        }

        let device_bid = DeviceRangeReader::new(self, bid..bid + 1)?.read()?.start;
        self.fs()
            .block_device()
            .read_block(device_bid as Bid, block)?;
        Ok(())
    }

    pub fn write_block(&self, bid: u32, block: &[u8]) -> Result<()> {
        if bid >= self.desc.blocks_count() {
            return Err(FsError::InvalidParam);
        }

        let device_bid = DeviceRangeReader::new(self, bid..bid + 1)?.read()?.start;
        self.fs()
            .block_device()
            .write_block(device_bid as Bid, block)?;
        self.blocks_hole_desc
            .upgradeable_read()
            .upgrade()
            .unset(bid as usize);

        Ok(())
    }

    pub fn read_bytes(&self, offset: usize, buf: &mut [u8]) -> Result<()> {
        let max_offset = offset.checked_add(buf.len()).ok_or(FsError::InvalidParam)?;
        if max_offset > self.file_size() {
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
                    range.block as u32,
                    &mut buf[buf_offset..buf_offset + BLOCK_SIZE],
                )?;
            } else {
                let mut block_buf = BlockBuf::new_uninit();
                self.read_block(range.block as u32, block_buf.as_mut_slice())?;
                block_buf
                    .read_bytes(range.begin, &mut buf[buf_offset..buf_offset + range.len()])?;
            }
            buf_offset += range.len();
        }

        Ok(())
    }

    pub fn write_bytes(&self, offset: usize, buf: &[u8]) -> Result<()> {
        let max_offset = offset.checked_add(buf.len()).ok_or(FsError::InvalidParam)?;
        if max_offset > self.file_size() {
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
                    range.block as u32,
                    &buf[buf_offset..buf_offset + BLOCK_SIZE],
                )?;
            } else {
                let mut block_buf = BlockBuf::new_uninit();
                self.read_block(range.block as u32, block_buf.as_mut_slice())?;
                block_buf.write_bytes(range.begin, &buf[buf_offset..buf_offset + range.len()])?;
                self.write_block(range.block as u32, block_buf.as_slice())?;
            }
            buf_offset += range.len();
        }

        Ok(())
    }

    pub fn read_val<T: Pod>(&self, offset: usize) -> Result<T> {
        let mut val = T::new_uninit();
        self.read_bytes(offset, val.as_bytes_mut())?;
        Ok(val)
    }

    pub fn write_val<T: Pod>(&self, offset: usize, new_val: &T) -> Result<()> {
        self.write_bytes(offset, new_val.as_bytes())
    }

    pub fn write_link(&mut self, target: &str) -> Result<()> {
        if target.len() <= FAST_SYMLINK_MAX_LEN {
            if self.file_size() != target.len() {
                self.resize(target.len())?;
            }
            self.desc.block_ptrs.as_bytes_mut()[..target.len()].copy_from_slice(target.as_bytes());
            return Ok(());
        }

        if self.file_size() != target.len() {
            self.resize(target.len())?;
        }
        self.write_bytes(0, target.as_bytes())?;
        Ok(())
    }

    pub fn read_link(&self) -> Result<String> {
        let file_size = self.file_size();
        let mut symlink = vec![0u8; file_size];

        if file_size <= FAST_SYMLINK_MAX_LEN {
            symlink.copy_from_slice(&self.desc.block_ptrs.as_bytes()[..file_size]);
            return String::from_utf8(symlink).map_err(|_| FsError::InvalidParam);
        }

        self.read_bytes(0, symlink.as_mut_slice())?;
        String::from_utf8(symlink).map_err(|_| FsError::InvalidParam)
    }

    fn init_dir(&mut self, self_ino: u32, parent_ino: u32) -> Result<()> {
        self.append_entry(DirEntry::self_entry(self_ino), 0)?;
        self.append_entry(DirEntry::parent_entry(parent_ino), 0)?;
        Ok(())
    }

    pub fn get_entry_ino(&self, name: &str, offset: usize) -> Option<u32> {
        self.get_entry(name, offset).map(|(_, entry)| entry.ino())
    }

    pub fn get_entry(&self, name: &str, offset: usize) -> Option<(usize, DirEntry)> {
        DirEntryReader::new(self, offset).find(|(_, entry)| entry.name() == name)
    }

    pub fn entry_count(&self) -> usize {
        DirEntryReader::new(&self, 0).count()
    }

    pub fn append_entry(&mut self, entry: DirEntry, offset: usize) -> Result<()> {
        let is_dir = entry.type_() == FileType::Dir;
        let is_parent = entry.name() == "..";

        DirEntryWriter::new(self, offset).append_entry(entry)?;
        if is_dir && !is_parent {
            self.inc_hard_links(); // for ".."
        }
        Ok(())
    }

    pub fn remove_entry(&mut self, name: &str, offset: usize) -> Result<()> {
        let entry = DirEntryWriter::new(self, offset).remove_entry(name)?;
        let is_dir = entry.type_() == FileType::Dir;
        if is_dir {
            self.dec_hard_links(); // for ".."
        }
        Ok(())
    }

    pub fn rename_entry(&mut self, old_name: &str, new_name: &str, offset: usize) -> Result<()> {
        DirEntryWriter::new(self, offset).rename_entry(old_name, new_name)?;
        Ok(())
    }

    pub fn set_parent_ino(&mut self, parent_ino: u32) -> Result<()> {
        let (offset, mut entry) = self.get_entry("..", 0).unwrap();
        entry.set_ino(parent_ino);
        DirEntryWriter::new(self, offset).write_entry(&entry)?;
        Ok(())
    }

    pub fn sync_data_holes(&self) -> Result<()> {
        let zero_block = unsafe { Box::<[u8]>::new_zeroed_slice(BLOCK_SIZE).assume_init() };
        for bid in 0..self.desc.blocks_count() {
            let is_data_hole = self.blocks_hole_desc.read().is_hole(bid as usize);
            if is_data_hole {
                self.write_block(bid, &zero_block)?;
            }
        }
        Ok(())
    }

    /// Expands inode size.
    ///
    /// After a successful expansion, the size will be enlarged to `new_size`,
    /// which may result in an increased block count.
    fn expand(&mut self, new_size: usize) -> Result<()> {
        let new_blocks = self.desc.size_to_blocks(new_size);
        let old_blocks = self.desc.blocks_count();

        // Expands block count if necessary
        if new_blocks > old_blocks {
            if new_blocks - old_blocks > self.fs().super_block().free_blocks_count() {
                return Err(FsError::NoDeviceSpace);
            }
            self.expand_blocks(old_blocks..new_blocks)?;
            self.blocks_hole_desc
                .upgradeable_read()
                .upgrade()
                .resize(new_blocks as usize);
        }

        // Expands the size
        self.desc.size = new_size;
        Ok(())
    }

    /// Expands inode blocks.
    ///
    /// After a successful expansion, the block count will be enlarged to `range.end`.
    fn expand_blocks(&mut self, range: Range<u32>) -> Result<()> {
        let mut current_range = range.clone();
        while !current_range.is_empty() {
            let Ok(expand_cnt) = self.try_expand_blocks(current_range.clone()) else {
                self.shrink_blocks(range.start..current_range.start);
                return Err(FsError::NoDeviceSpace);
            };
            current_range.start += expand_cnt;
        }

        Ok(())
    }

    /// Attempts to expand a range of blocks and returns the number of consecutive
    /// blocks successfully allocated.
    ///
    /// Note that the returned number may be less than the requested range if there
    /// isn't enough consecutive space available or if there is a necessity to allocate
    /// indirect blocks.
    fn try_expand_blocks(&mut self, range: Range<u32>) -> Result<u32> {
        // Calculates the maximum number of consecutive blocks that can be allocated in
        // this round, as well as the number of additional indirect blocks required for
        // the allocation.
        let (max_cnt, indirect_cnt) = {
            let bid_path = BidPath::from(range.start);
            let max_cnt = (range.len() as u32).min(bid_path.cnt_to_next_indirect());
            let indirect_cnt = match bid_path {
                BidPath::Direct(_) => 0,
                BidPath::Indirect(0) => 1,
                BidPath::Indirect(_) => 0,
                BidPath::DbIndirect(0, 0) => 2,
                BidPath::DbIndirect(_, 0) => 1,
                BidPath::DbIndirect(_, _) => 0,
                BidPath::TbIndirect(0, 0, 0) => 3,
                BidPath::TbIndirect(_, 0, 0) => 2,
                BidPath::TbIndirect(_, _, 0) => 1,
                BidPath::TbIndirect(_, _, _) => 0,
            };
            (max_cnt, indirect_cnt)
        };

        // Calculates the block_group_idx to advise the filesystem on which group
        // to prioritize for allocation.
        let block_group_idx = self
            .last_alloc_device_bid
            .map_or(self.inode().block_group_idx, |id| {
                ((id + 1) / self.fs().blocks_per_group()) as usize
            });

        // Allocates the blocks only, no indirect blocks are required.
        if indirect_cnt == 0 {
            let device_range = self
                .fs()
                .alloc_blocks(block_group_idx, max_cnt)
                .ok_or_else(|| FsError::NoDeviceSpace)?;
            if let Err(e) = self.set_device_range(range.start, device_range.clone()) {
                self.fs().free_blocks(device_range).unwrap();
                return Err(e);
            }
            self.desc.blocks_count = range.start + device_range.len() as u32;
            self.last_alloc_device_bid = Some(device_range.end - 1);
            return Ok(device_range.len() as u32);
        }

        // Allocates the required additional indirect blocks and at least one block.
        let (indirect_bids, device_range) = {
            let mut indirect_bids: Vec<u32> = Vec::with_capacity(indirect_cnt as usize);
            let mut total_cnt = max_cnt + indirect_cnt;
            let mut device_range: Option<Range<u32>> = None;
            while device_range.is_none() {
                let Some(mut range) = self.fs().alloc_blocks(block_group_idx, total_cnt) else {
                    for indirect_bid in indirect_bids.iter() {
                        self.fs()
                            .free_blocks(*indirect_bid..*indirect_bid + 1)
                            .unwrap();
                    }
                    return Err(FsError::NoDeviceSpace);
                };
                total_cnt -= range.len() as u32;

                // Stores the bids for indirect blocks.
                while (indirect_bids.len() as u32) < indirect_cnt && !range.is_empty() {
                    indirect_bids.push(range.start);
                    range.start += 1;
                }

                if !range.is_empty() {
                    device_range = Some(range);
                }
            }

            (indirect_bids, device_range.unwrap())
        };

        if let Err(e) = self.set_indirect_bids(range.start, &indirect_bids) {
            self.free_indirect_blocks_required_by(range.start).unwrap();
            return Err(e);
        }

        if let Err(e) = self.set_device_range(range.start, device_range.clone()) {
            self.fs().free_blocks(device_range).unwrap();
            self.free_indirect_blocks_required_by(range.start).unwrap();
            return Err(e);
        }

        self.desc.blocks_count = range.start + device_range.len() as u32;
        self.last_alloc_device_bid = Some(device_range.end - 1);
        Ok(device_range.len() as u32)
    }

    /// Sets the device block IDs for a specified range.
    ///
    /// It updates the mapping between the file's block IDs and the device's block IDs
    /// starting from `start_bid`. It maps each block ID in the file to the corresponding
    /// block ID on the device based on the provided `device_range`.
    fn set_device_range(&mut self, start_bid: u32, device_range: Range<u32>) -> Result<()> {
        match BidPath::from(start_bid) {
            BidPath::Direct(idx) => {
                for (i, bid) in device_range.enumerate() {
                    self.desc.block_ptrs.set_direct(idx + i, bid);
                }
            }
            BidPath::Indirect(idx) => {
                let indirect_bid = self.desc.block_ptrs.indirect();
                assert!(indirect_bid != 0);
                let mut indirect_blocks = self.indirect_blocks.upgradeable_read().upgrade();
                let indirect_block = indirect_blocks.find_mut(indirect_bid)?;
                for (i, bid) in device_range.enumerate() {
                    indirect_block.write_bid(idx + i, &bid)?;
                }
            }
            BidPath::DbIndirect(lvl1_idx, lvl2_idx) => {
                let mut indirect_blocks = self.indirect_blocks.upgradeable_read().upgrade();
                let lvl1_indirect_bid = {
                    let db_indirect_bid = self.desc.block_ptrs.db_indirect();
                    assert!(db_indirect_bid != 0);
                    let db_indirect_block = indirect_blocks.find(db_indirect_bid)?;
                    db_indirect_block.read_bid(lvl1_idx)?
                };
                assert!(lvl1_indirect_bid != 0);

                let lvl1_indirect_block = indirect_blocks.find_mut(lvl1_indirect_bid)?;
                for (i, bid) in device_range.enumerate() {
                    lvl1_indirect_block.write_bid(lvl2_idx + i, &bid)?;
                }
            }
            BidPath::TbIndirect(lvl1_idx, lvl2_idx, lvl3_idx) => {
                let mut indirect_blocks = self.indirect_blocks.upgradeable_read().upgrade();
                let lvl2_indirect_bid = {
                    let lvl1_indirect_bid = {
                        let tb_indirect_bid = self.desc.block_ptrs.tb_indirect();
                        assert!(tb_indirect_bid != 0);
                        let tb_indirect_block = indirect_blocks.find(tb_indirect_bid)?;
                        tb_indirect_block.read_bid(lvl1_idx)?
                    };
                    assert!(lvl1_indirect_bid != 0);
                    let lvl1_indirect_block = indirect_blocks.find(lvl1_indirect_bid)?;
                    lvl1_indirect_block.read_bid(lvl2_idx)?
                };
                assert!(lvl2_indirect_bid != 0);

                let lvl2_indirect_block = indirect_blocks.find_mut(lvl2_indirect_bid)?;
                for (i, bid) in device_range.enumerate() {
                    lvl2_indirect_block.write_bid(lvl3_idx + i, &bid)?;
                }
            }
        }
        Ok(())
    }

    /// Sets the device block IDs for indirect blocks required by a specific block ID.
    ///
    /// It assigns a sequence of block IDs (`indirect_bids`) on the device to be used
    /// as indirect blocks for a given file block ID (`bid`).
    fn set_indirect_bids(&mut self, bid: u32, indirect_bids: &[u32]) -> Result<()> {
        assert!((1..=3).contains(&indirect_bids.len()));

        let mut indirect_blocks = self.indirect_blocks.upgradeable_read().upgrade();
        let bid_path = BidPath::from(bid);
        for indirect_bid in indirect_bids.iter() {
            let indirect_block = IndirectBlock::alloc()?;
            indirect_blocks.insert(*indirect_bid, indirect_block)?;

            match bid_path {
                BidPath::Indirect(idx) => {
                    assert_eq!(idx, 0);
                    self.desc.block_ptrs.set_indirect(*indirect_bid);
                }
                BidPath::DbIndirect(lvl1_idx, lvl2_idx) => {
                    assert_eq!(lvl2_idx, 0);
                    if self.desc.block_ptrs.db_indirect() == 0 {
                        self.desc.block_ptrs.set_db_indirect(*indirect_bid);
                    } else {
                        let db_indirect_block =
                            indirect_blocks.find_mut(self.desc.block_ptrs.db_indirect())?;
                        db_indirect_block.write_bid(lvl1_idx, indirect_bid)?;
                    }
                }
                BidPath::TbIndirect(lvl1_idx, lvl2_idx, lvl3_idx) => {
                    assert_eq!(lvl3_idx, 0);
                    if self.desc.block_ptrs.tb_indirect() == 0 {
                        self.desc.block_ptrs.set_tb_indirect(*indirect_bid);
                    } else {
                        let lvl1_indirect_bid = {
                            let tb_indirect_block =
                                indirect_blocks.find(self.desc.block_ptrs.tb_indirect())?;
                            tb_indirect_block.read_bid(lvl1_idx)?
                        };

                        if lvl1_indirect_bid == 0 {
                            let tb_indirect_block =
                                indirect_blocks.find_mut(self.desc.block_ptrs.tb_indirect())?;
                            tb_indirect_block.write_bid(lvl1_idx, indirect_bid)?;
                        } else {
                            let lvl1_indirect_block =
                                indirect_blocks.find_mut(lvl1_indirect_bid)?;
                            lvl1_indirect_block.write_bid(lvl2_idx, indirect_bid)?;
                        }
                    }
                }
                BidPath::Direct(_) => panic!(),
            }
        }

        Ok(())
    }

    /// Shrinks inode size.
    ///
    /// After the reduction, the size will be shrinked to `new_size`,
    /// which may result in an decreased block count.
    fn shrink(&mut self, new_size: usize) {
        let new_blocks = self.desc.size_to_blocks(new_size);
        let old_blocks = self.desc.blocks_count();

        // Shrinks block count if necessary
        if new_blocks < old_blocks {
            self.shrink_blocks(new_blocks..old_blocks);
            self.blocks_hole_desc
                .upgradeable_read()
                .upgrade()
                .resize(new_blocks as usize);
        }

        // Shrinks the size
        self.desc.size = new_size;
    }

    /// Shrinks inode blocks.
    ///
    /// After the reduction, the block count will be decreased to `range.start`.
    fn shrink_blocks(&mut self, range: Range<u32>) {
        let mut current_range = range.clone();
        while !current_range.is_empty() {
            let free_cnt = self.try_shrink_blocks(current_range.clone());
            current_range.end -= free_cnt;
        }

        self.desc.blocks_count = range.start;
        self.last_alloc_device_bid = if range.start == 0 {
            None
        } else {
            Some(
                DeviceRangeReader::new(self, (range.start - 1)..range.start)
                    .unwrap()
                    .read()
                    .unwrap()
                    .start,
            )
        };
    }

    /// Attempts to shrink a range of blocks and returns the number of blocks
    /// successfully freed.
    ///
    /// Note that the returned number may be less than the requested range if needs
    /// to free the indirect blocks that are no longer required.
    fn try_shrink_blocks(&mut self, range: Range<u32>) -> u32 {
        // Calculates the maximum range of blocks that can be freed in this round.
        let range = {
            let max_cnt =
                (range.len() as u32).min(BidPath::from(range.end - 1).last_lvl_idx() as u32 + 1);
            (range.end - max_cnt)..range.end
        };

        let fs = self.fs();
        let device_range_reader = DeviceRangeReader::new(self, range.clone()).unwrap();
        for device_range in device_range_reader {
            fs.free_blocks(device_range.clone()).unwrap();
        }

        self.free_indirect_blocks_required_by(range.start).unwrap();
        range.len() as u32
    }

    /// Frees the indirect blocks required by the specified block ID.
    ///
    /// It ensures that the indirect blocks that are required by the block ID
    /// are properly released.
    fn free_indirect_blocks_required_by(&mut self, bid: u32) -> Result<()> {
        let bid_path = BidPath::from(bid);
        if bid_path.last_lvl_idx() != 0 {
            return Ok(());
        }
        if bid == 0 {
            return Ok(());
        }

        match bid_path {
            BidPath::Indirect(_) => {
                let indirect_bid = self.desc.block_ptrs.indirect();
                if indirect_bid == 0 {
                    return Ok(());
                }

                self.desc.block_ptrs.set_indirect(0);
                self.indirect_blocks
                    .upgradeable_read()
                    .upgrade()
                    .remove(indirect_bid);
                self.fs()
                    .free_blocks(indirect_bid..indirect_bid + 1)
                    .unwrap();
            }
            BidPath::DbIndirect(lvl1_idx, _) => {
                let db_indirect_bid = self.desc.block_ptrs.db_indirect();
                if db_indirect_bid == 0 {
                    return Ok(());
                }

                let mut indirect_blocks = self.indirect_blocks.upgradeable_read().upgrade();
                let lvl1_indirect_bid = {
                    let db_indirect_block = indirect_blocks.find(db_indirect_bid)?;
                    db_indirect_block.read_bid(lvl1_idx)?
                };
                if lvl1_indirect_bid != 0 {
                    indirect_blocks.remove(lvl1_indirect_bid);
                    self.fs()
                        .free_blocks(lvl1_indirect_bid..lvl1_indirect_bid + 1)
                        .unwrap();
                }
                if lvl1_idx == 0 {
                    self.desc.block_ptrs.set_db_indirect(0);
                    indirect_blocks.remove(db_indirect_bid);
                    self.fs()
                        .free_blocks(db_indirect_bid..db_indirect_bid + 1)
                        .unwrap();
                }
            }
            BidPath::TbIndirect(lvl1_idx, lvl2_idx, _) => {
                let tb_indirect_bid = self.desc.block_ptrs.tb_indirect();
                if tb_indirect_bid == 0 {
                    return Ok(());
                }

                let mut indirect_blocks = self.indirect_blocks.upgradeable_read().upgrade();
                let lvl1_indirect_bid = {
                    let tb_indirect_block = indirect_blocks.find(tb_indirect_bid)?;
                    tb_indirect_block.read_bid(lvl1_idx)?
                };
                if lvl1_indirect_bid != 0 {
                    let lvl2_indirect_bid = {
                        let lvl1_indirect_block = indirect_blocks.find(lvl1_indirect_bid)?;
                        lvl1_indirect_block.read_bid(lvl2_idx)?
                    };
                    if lvl2_indirect_bid != 0 {
                        indirect_blocks.remove(lvl2_indirect_bid);
                        self.fs()
                            .free_blocks(lvl2_indirect_bid..lvl2_indirect_bid + 1)
                            .unwrap();
                    }
                    if lvl2_idx == 0 {
                        indirect_blocks.remove(lvl1_indirect_bid);
                        self.fs()
                            .free_blocks(lvl1_indirect_bid..lvl1_indirect_bid + 1)
                            .unwrap();
                    }
                }

                if lvl2_idx == 0 && lvl1_idx == 0 {
                    self.desc.block_ptrs.set_tb_indirect(0);
                    indirect_blocks.remove(tb_indirect_bid);
                    self.fs()
                        .free_blocks(tb_indirect_bid..tb_indirect_bid + 1)
                        .unwrap();
                }
            }
            BidPath::Direct(_) => panic!(),
        }

        Ok(())
    }
}

/// A reader to get the corresponding device block IDs for a specified range.
///
/// It calculates and returns the range of block IDs on the device that would map to
/// the file's block range. This is useful for translating file-level block addresses
/// to their locations on the physical storage device.
struct DeviceRangeReader<'a> {
    inode: &'a InodeInner,
    indirect_blocks: RwLockWriteGuard<'a, IndirectCache>,
    range: Range<u32>,
    indirect_block: Option<IndirectBlock>,
}

impl<'a> DeviceRangeReader<'a> {
    /// Creates a new reader.
    ///
    /// # Panic
    ///
    /// If the 'range' is empty, this method will panic.
    pub fn new(inode: &'a InodeInner, range: Range<u32>) -> Result<Self> {
        assert!(!range.is_empty());

        let mut reader = Self {
            indirect_blocks: inode.indirect_blocks.upgradeable_read().upgrade(),
            inode,
            range,
            indirect_block: None,
        };

        reader.update_indirect_block()?;
        Ok(reader)
    }

    /// Reads the corresponding device block IDs for a specified range.
    ///
    /// Note that the returned device range size may be smaller than the requested range
    /// due to possible inconsecutive block allocation.
    pub fn read(&mut self) -> Result<Range<u32>> {
        let bid_path = BidPath::from(self.range.start);
        let max_cnt = self
            .range
            .len()
            .min(bid_path.cnt_to_next_indirect() as usize);
        let start_idx = bid_path.last_lvl_idx();

        // Reads the device block ID range
        let mut device_range: Option<Range<u32>> = None;
        for i in start_idx..start_idx + max_cnt {
            let device_bid = match &self.indirect_block {
                None => self.inode.desc.block_ptrs.direct(i),
                Some(indirect_block) => indirect_block.read_bid(i)?,
            };
            match device_range {
                Some(ref mut range) => {
                    if device_bid == range.end {
                        range.end += 1;
                    } else {
                        break;
                    }
                }
                None => {
                    device_range = Some(device_bid..device_bid + 1);
                }
            }
        }
        let device_range = device_range.unwrap();

        // Updates the range
        self.range.start += device_range.len() as u32;
        if device_range.len() == bid_path.cnt_to_next_indirect() as usize {
            // Updates the indirect block
            self.update_indirect_block()?;
        }

        Ok(device_range)
    }

    fn update_indirect_block(&mut self) -> Result<()> {
        let bid_path = BidPath::from(self.range.start);
        match bid_path {
            BidPath::Direct(_) => {
                self.indirect_block = None;
            }
            BidPath::Indirect(_) => {
                let indirect_bid = self.inode.desc.block_ptrs.indirect();
                let indirect_block = self.indirect_blocks.find(indirect_bid)?;
                self.indirect_block = Some(indirect_block.clone());
            }
            BidPath::DbIndirect(lvl1_idx, _) => {
                let lvl1_indirect_bid = {
                    let db_indirect_block = self
                        .indirect_blocks
                        .find(self.inode.desc.block_ptrs.db_indirect())?;
                    db_indirect_block.read_bid(lvl1_idx)?
                };
                let lvl1_indirect_block = self.indirect_blocks.find(lvl1_indirect_bid)?;
                self.indirect_block = Some(lvl1_indirect_block.clone());
            }
            BidPath::TbIndirect(lvl1_idx, lvl2_idx, _) => {
                let lvl2_indirect_bid = {
                    let lvl1_indirect_bid = {
                        let tb_indirect_block = self
                            .indirect_blocks
                            .find(self.inode.desc.block_ptrs.tb_indirect())?;
                        tb_indirect_block.read_bid(lvl1_idx)?
                    };
                    let lvl1_indirect_block = self.indirect_blocks.find(lvl1_indirect_bid)?;
                    lvl1_indirect_block.read_bid(lvl2_idx)?
                };
                let lvl2_indirect_block = self.indirect_blocks.find(lvl2_indirect_bid)?;
                self.indirect_block = Some(lvl2_indirect_block.clone());
            }
        }

        Ok(())
    }
}

impl<'a> Iterator for DeviceRangeReader<'a> {
    type Item = Range<u32>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.range.is_empty() {
            return None;
        }

        let range = self.read().unwrap();
        Some(range)
    }
}

/// The in-memory rust inode descriptor.
///
/// It represents a file, directory, symbolic link, etc.
/// It contains pointers to the filesystem blocks which contain the data held in the
/// object and all of the metadata about an object except its name.
///
/// Each block group has an inode table it is responsible for.
#[derive(Clone, Copy, Debug)]
pub(super) struct InodeDesc {
    /// Type.
    type_: FileType,
    /// Permission.
    perm: FilePerm,
    /// User Id.
    uid: u32,
    /// Group Id.
    gid: u32,
    /// Size in bytes.
    size: usize,
    /// Access time.
    atime: UnixTime,
    /// Creation time.
    ctime: UnixTime,
    /// Modification time.
    mtime: UnixTime,
    /// Deletion time.
    dtime: UnixTime,
    /// Hard links count.
    hard_links: u16,
    /// Number of blocks.
    blocks_count: u32,
    /// File flags.
    flags: FileFlags,
    /// Pointers to blocks.
    block_ptrs: BlockPtrs,
    /// File or directory acl block.
    acl: Option<u32>,
}

impl TryFrom<RawInode> for InodeDesc {
    type Error = FsError;

    fn try_from(inode: RawInode) -> Result<Self> {
        let file_type = FileType::from_raw_mode(inode.mode)?;
        Ok(Self {
            type_: file_type,
            perm: FilePerm::from_raw_mode(inode.mode)?,
            uid: (inode.os_dependent_2.uid_high as u32) << 16 | inode.uid as u32,
            gid: (inode.os_dependent_2.gid_high as u32) << 16 | inode.gid as u32,
            size: if file_type == FileType::File {
                (inode.size_high as usize) << 32 | inode.size_low as usize
            } else {
                inode.size_low as usize
            },
            atime: inode.atime,
            ctime: inode.ctime,
            mtime: inode.mtime,
            dtime: inode.dtime,
            hard_links: inode.hard_links,
            blocks_count: inode.blocks_count,
            flags: FileFlags::from_bits(inode.flags).ok_or(FsError::InvalidParam)?,
            block_ptrs: inode.block_ptrs,
            acl: match file_type {
                FileType::File => Some(inode.file_acl),
                FileType::Dir => Some(inode.size_high),
                _ => None,
            },
        })
    }
}

impl InodeDesc {
    pub fn new(type_: FileType, perm: FilePerm, time: UnixTime) -> Dirty<Self> {
        Dirty::new_dirty(Self {
            type_,
            perm,
            uid: 0,
            gid: 0,
            size: 0,
            atime: time,
            ctime: time,
            mtime: time,
            dtime: UnixTime::ZERO,
            hard_links: 1,
            blocks_count: 0,
            flags: FileFlags::empty(),
            block_ptrs: BlockPtrs::default(),
            acl: match type_ {
                FileType::File | FileType::Dir => Some(0),
                _ => None,
            },
        })
    }

    pub fn num_page_bytes(&self) -> usize {
        (self.blocks_count() as usize) * BLOCK_SIZE
    }

    /// Returns the actual number of blocks utilized.
    ///
    /// Ext2 allows the `block_count` to exceed the actual number of blocks utilized.
    pub fn blocks_count(&self) -> u32 {
        let blocks = self.size_to_blocks(self.size);
        assert!(blocks <= self.blocks_count);
        blocks
    }

    #[inline]
    fn size_to_blocks(&self, size: usize) -> u32 {
        if self.type_ == FileType::Symlink && size <= FAST_SYMLINK_MAX_LEN {
            return 0;
        }
        size.div_ceil(BLOCK_SIZE) as u32
    }
}

#[repr(u16)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileType {
    /// FIFO special file
    Fifo = 0o010000,
    /// Character device
    Char = 0o020000,
    /// Directory
    Dir = 0o040000,
    /// Block device
    Block = 0o060000,
    /// Regular file
    File = 0o100000,
    /// Symbolic link
    Symlink = 0o120000,
    /// Socket
    Socket = 0o140000,
}

impl TryFrom<u16> for FileType {
    type Error = FsError;

    fn try_from(val: u16) -> Result<Self> {
        match val {
            val if val == Self::Fifo as u16 => Ok(Self::Fifo),
            val if val == Self::Char as u16 => Ok(Self::Char),
            val if val == Self::Dir as u16 => Ok(Self::Dir),
            val if val == Self::Block as u16 => Ok(Self::Block),
            val if val == Self::File as u16 => Ok(Self::File),
            val if val == Self::Symlink as u16 => Ok(Self::Symlink),
            val if val == Self::Socket as u16 => Ok(Self::Socket),
            _ => Err(FsError::InvalidParam),
        }
    }
}

impl FileType {
    pub fn from_raw_mode(mode: u16) -> Result<Self> {
        const TYPE_MASK: u16 = 0o170000;
        Self::try_from(mode & TYPE_MASK)
    }
}

bitflags! {
    pub struct FilePerm: u16 {
        /// set-user-ID
        const S_ISUID = 0o4000;
        /// set-group-ID
        const S_ISGID = 0o2000;
        /// sticky bit
        const S_ISVTX = 0o1000;
        /// read by owner
        const S_IRUSR = 0o0400;
        /// write by owner
        const S_IWUSR = 0o0200;
        /// execute/search by owner
        const S_IXUSR = 0o0100;
        /// read by group
        const S_IRGRP = 0o0040;
        /// write by group
        const S_IWGRP = 0o0020;
        /// execute/search by group
        const S_IXGRP = 0o0010;
        /// read by others
        const S_IROTH = 0o0004;
        /// write by others
        const S_IWOTH = 0o0002;
        /// execute/search by others
        const S_IXOTH = 0o0001;
    }
}

impl FilePerm {
    pub fn from_raw_mode(mode: u16) -> Result<Self> {
        const PERM_MASK: u16 = 0o7777;
        Self::from_bits(mode & PERM_MASK).ok_or(FsError::InvalidParam)
    }
}

bitflags! {
    pub struct FileFlags: u32 {
        /// Secure deletion.
        const SECURE_DEL = 1 << 0;
        /// Undelete.
        const UNDELETE = 1 << 1;
        /// Compress file.
        const COMPRESS = 1 << 2;
        /// Synchronous updates.
        const SYNC_UPDATE = 1 << 3;
        /// Immutable file.
        const IMMUTABLE = 1 << 4;
        /// Append only.
        const APPEND_ONLY = 1 << 5;
        /// Do not dump file.
        const NO_DUMP = 1 << 6;
        /// Do not update atime.
        const NO_ATIME = 1 << 7;
        /// Dirty.
        const DIRTY = 1 << 8;
        /// One or more compressed clusters.
        const COMPRESS_BLK = 1 << 9;
        /// Do not compress.
        const NO_COMPRESS = 1 << 10;
        /// Encrypted file.
        const ENCRYPT = 1 << 11;
        /// Hash-indexed directory.
        const INDEX_DIR = 1 << 12;
        /// AFS directory.
        const IMAGIC = 1 << 13;
        /// Journal file data.
        const JOURNAL_DATA = 1 << 14;
        /// File tail should not be merged.
        const NO_TAIL = 1 << 15;
        /// Dirsync behaviour (directories only).
        const DIR_SYNC = 1 << 16;
        /// Top of directory hierarchies.
        const TOP_DIR = 1 << 17;
        /// Reserved for ext2 lib.
        const RESERVED = 1 << 31;
    }
}

const_assert!(core::mem::size_of::<RawInode>() == 128);

/// The raw inode on device.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Pod)]
pub(super) struct RawInode {
    /// File mode (type and permissions).
    pub mode: u16,
    /// Low 16 bits of User Id.
    pub uid: u16,
    /// Lower 32 bits of size in bytes.
    pub size_low: u32,
    /// Access time.
    pub atime: UnixTime,
    /// Creation time.
    pub ctime: UnixTime,
    /// Modification time.
    pub mtime: UnixTime,
    /// Deletion time.
    pub dtime: UnixTime,
    /// Low 16 bits of Group Id.
    pub gid: u16,
    pub hard_links: u16,
    pub blocks_count: u32,
    /// File flags.
    pub flags: u32,
    /// OS dependent Value 1.
    reserved1: u32,
    /// Pointers to blocks.
    pub block_ptrs: BlockPtrs,
    /// File version (for NFS).
    pub generation: u32,
    /// In revision 0, this field is reserved.
    /// In revision 1, File ACL.
    pub file_acl: u32,
    /// In revision 0, this field is reserved.
    /// In revision 1, Upper 32 bits of file size (if feature bit set)
    /// if it's a file, Directory ACL if it's a directory.
    pub size_high: u32,
    /// Fragment address.
    pub frag_addr: u32,
    /// OS dependent 2.
    pub os_dependent_2: Osd2,
}

impl From<&InodeDesc> for RawInode {
    fn from(inode: &InodeDesc) -> Self {
        Self {
            mode: inode.type_ as u16 | inode.perm.bits(),
            uid: inode.uid as u16,
            size_low: inode.size as u32,
            atime: inode.atime,
            ctime: inode.ctime,
            mtime: inode.mtime,
            dtime: inode.dtime,
            gid: inode.gid as u16,
            hard_links: inode.hard_links,
            blocks_count: inode.blocks_count,
            flags: inode.flags.bits(),
            block_ptrs: inode.block_ptrs,
            file_acl: match inode.acl {
                Some(acl) if inode.type_ == FileType::File => acl,
                _ => Default::default(),
            },
            size_high: match inode.acl {
                Some(acl) if inode.type_ == FileType::Dir => acl,
                _ => Default::default(),
            },
            os_dependent_2: Osd2 {
                uid_high: (inode.uid >> 16) as u16,
                gid_high: (inode.gid >> 16) as u16,
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

/// OS dependent Value 2
#[repr(C)]
#[derive(Clone, Copy, Default, Debug, Pod)]
pub(super) struct Osd2 {
    /// Fragment number.
    pub frag_num: u8,
    /// Fragment size.
    pub frag_size: u8,
    pad1: u16,
    /// High 16 bits of User Id.
    pub uid_high: u16,
    /// High 16 bits of Group Id.
    pub gid_high: u16,
    reserved2: u32,
}

fn is_block_aligned(offset: usize) -> bool {
    offset % BLOCK_SIZE == 0
}

fn write_lock_two_inodes<'a>(
    this: &'a Inode,
    other: &'a Inode,
) -> (
    RwLockWriteGuard<'a, InodeInner>,
    RwLockWriteGuard<'a, InodeInner>,
) {
    let mut write_guards = write_lock_multiple_inodes(vec![this, other]);
    let other_guard = write_guards.pop().unwrap();
    let this_guard = write_guards.pop().unwrap();
    (this_guard, other_guard)
}

fn write_lock_multiple_inodes<'a>(inodes: Vec<&'a Inode>) -> Vec<RwLockWriteGuard<'a, InodeInner>> {
    // Record the index information of the input.
    let mut inodes: Vec<(usize, &'a Inode)> = inodes
        .into_iter()
        .enumerate()
        .map(|(idx, inode)| (idx, inode))
        .collect();
    // Sort in ascending order of ino, then upgrade the guards in order.
    inodes.sort_by(|a, b| a.1.ino.cmp(&b.1.ino));
    let mut guards: Vec<(usize, RwLockWriteGuard<'a, InodeInner>)> = inodes
        .into_iter()
        .map(|(idx, inode)| (idx, inode.inner.upgradeable_read().upgrade()))
        .collect();

    // Resort the guards by the input index.
    // This ensures that the output order is consistent with the input.
    guards.sort_by(|a, b| a.0.cmp(&b.0));
    guards.into_iter().map(|(_, guard)| guard).collect()
}
