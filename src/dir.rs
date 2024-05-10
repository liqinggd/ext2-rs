// SPDX-License-Identifier: MPL-2.0

use crate::{
    inode::{FileType, InodeInner, MAX_FNAME_LEN},
    prelude::*,
    utils::{AlignExt, FixedCStr},
};

pub type CStr256 = FixedCStr<256>;

/// The data structure in a directory's data block. It is stored in a linked list.
///
/// Each entry contains the name of the entry, the inode number, the file type,
/// and the distance within the directory file to the next entry.
#[derive(Clone, Debug)]
pub struct DirEntry {
    /// The header part.
    header: DirEntryHeader,
    /// Name of the entry, up to 255 bytes (excluding the null terminator).
    name: CStr256,
}

impl DirEntry {
    /// Constructs a new `DirEntry` object with the specified inode (`ino`),
    /// name (`name`), and file type (`file_type`).
    pub(super) fn new(ino: u32, name: &str, file_type: FileType) -> Self {
        debug_assert!(name.len() <= MAX_FNAME_LEN);

        let record_len = (Self::header_len() + name.len()).align_up(4) as u16;
        Self {
            header: DirEntryHeader {
                ino,
                record_len,
                name_len: name.len() as u8,
                file_type: DirEntryFileType::from(file_type) as _,
            },
            name: CStr256::from(name),
        }
    }

    /// Constructs a `DirEntry` with the name "." and `self_ino` as its inode.
    pub(super) fn self_entry(self_ino: u32) -> Self {
        Self::new(self_ino, ".", FileType::Dir)
    }

    /// Constructs a `DirEntry` with the name ".." and `parent_ino` as its inode.
    pub(super) fn parent_entry(parent_ino: u32) -> Self {
        Self::new(parent_ino, "..", FileType::Dir)
    }

    /// Returns a reference to the header.
    fn header(&self) -> &DirEntryHeader {
        &self.header
    }

    /// Returns the length of the header.
    fn header_len() -> usize {
        size_of::<DirEntryHeader>()
    }

    /// Returns the inode number.
    pub fn ino(&self) -> u32 {
        self.header.ino
    }

    /// Modifies the inode number.
    pub fn set_ino(&mut self, ino: u32) {
        self.header.ino = ino;
    }

    /// Returns the name.
    pub fn name(&self) -> &str {
        self.name.as_str().unwrap()
    }

    /// Returns the type.
    pub fn type_(&self) -> FileType {
        FileType::from(DirEntryFileType::try_from(self.header.file_type).unwrap())
    }

    /// Returns the distance to the next entry.
    pub fn record_len(&self) -> usize {
        self.header.record_len as _
    }

    /// Modifies the distance to the next entry.
    pub(super) fn set_record_len(&mut self, record_len: usize) {
        debug_assert!(record_len >= self.actual_len());
        self.header.record_len = record_len as _;
    }

    /// Returns the actual length of the current entry.
    pub(super) fn actual_len(&self) -> usize {
        (Self::header_len() + self.name.len()).align_up(4)
    }

    /// Returns the length of the gap between the current entry and the next entry.
    pub(super) fn gap_len(&self) -> usize {
        self.record_len() - self.actual_len()
    }
}

/// The header of `DirEntry`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct DirEntryHeader {
    /// Inode number
    ino: u32,
    /// Directory entry length
    record_len: u16,
    /// Name Length
    name_len: u8,
    /// Type indicator
    file_type: u8,
}

/// The type indicator in the `DirEntry`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum DirEntryFileType {
    Unknown = 0,
    File = 1,
    Dir = 2,
    Char = 3,
    Block = 4,
    Fifo = 5,
    Socket = 6,
    Symlink = 7,
}

impl TryFrom<u8> for DirEntryFileType {
    type Error = FsError;

    fn try_from(val: u8) -> Result<Self> {
        match val {
            val if val == Self::Unknown as u8 => Ok(Self::Unknown),
            val if val == Self::File as u8 => Ok(Self::File),
            val if val == Self::Dir as u8 => Ok(Self::Dir),
            val if val == Self::Char as u8 => Ok(Self::Char),
            val if val == Self::Block as u8 => Ok(Self::Block),
            val if val == Self::Fifo as u8 => Ok(Self::Fifo),
            val if val == Self::Socket as u8 => Ok(Self::Socket),
            val if val == Self::Symlink as u8 => Ok(Self::Symlink),
            _ => Err(FsError::InvalidParam),
        }
    }
}

impl From<FileType> for DirEntryFileType {
    fn from(file_type: FileType) -> Self {
        match file_type {
            FileType::Fifo => Self::Fifo,
            FileType::Char => Self::Char,
            FileType::Dir => Self::Dir,
            FileType::Block => Self::Block,
            FileType::File => Self::File,
            FileType::Symlink => Self::Symlink,
            FileType::Socket => Self::Socket,
        }
    }
}

impl From<DirEntryFileType> for FileType {
    fn from(file_type: DirEntryFileType) -> Self {
        match file_type {
            DirEntryFileType::Fifo => Self::Fifo,
            DirEntryFileType::Char => Self::Char,
            DirEntryFileType::Dir => Self::Dir,
            DirEntryFileType::Block => Self::Block,
            DirEntryFileType::File => Self::File,
            DirEntryFileType::Symlink => Self::Symlink,
            DirEntryFileType::Socket => Self::Socket,
            DirEntryFileType::Unknown => panic!("unknown file type"),
        }
    }
}

/// A reader for reading `DirEntry`.
pub struct DirEntryReader<'a> {
    inode: &'a InodeInner,
    offset: usize,
}

impl<'a> DirEntryReader<'a> {
    /// Constructs a reader with the given inode and offset.
    pub(super) fn new(inode: &'a InodeInner, from_offset: usize) -> Self {
        Self {
            inode,
            offset: from_offset,
        }
    }

    /// Reads one `DirEntry` from the current offset.
    pub fn read_entry(&mut self) -> Result<DirEntry> {
        if let Some(entry) = self.inode.dentry_cache.read().get(&self.offset) {
            self.offset += entry.record_len();
            return Ok(entry.clone());
        }

        let header = self.inode.read_val::<DirEntryHeader>(self.offset)?;
        if header.ino == 0 {
            return Err(FsError::EntryNotFound);
        }

        let mut name = vec![0u8; header.name_len as _];
        self.inode
            .read_bytes(self.offset + DirEntry::header_len(), &mut name)?;
        let entry = DirEntry {
            header,
            name: CStr256::from(name.as_slice()),
        };

        self.inode
            .dentry_cache
            .upgradeable_read()
            .upgrade()
            .insert(self.offset, entry.clone());

        self.offset += entry.record_len();

        Ok(entry)
    }
}

impl<'a> Iterator for DirEntryReader<'a> {
    type Item = (usize, DirEntry);

    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.offset;
        let entry = match self.read_entry() {
            Ok(entry) => entry,
            Err(_) => {
                return None;
            }
        };

        Some((offset, entry))
    }
}

/// A writer for modifying `DirEntry`.
pub struct DirEntryWriter<'a> {
    inode: &'a mut InodeInner,
    offset: usize,
}

impl<'a> DirEntryWriter<'a> {
    /// Constructs a writer with the given inode and offset.
    pub(super) fn new(inode: &'a mut InodeInner, from_offset: usize) -> Self {
        Self {
            inode,
            offset: from_offset,
        }
    }

    /// Writes a `DirEntry` at the current offset.
    pub fn write_entry(&mut self, entry: &DirEntry) -> Result<()> {
        self.inode.write_val(self.offset, entry.header())?;
        self.inode.write_bytes(
            self.offset + DirEntry::header_len(),
            entry.name().as_bytes(),
        )?;

        self.inode
            .dentry_cache
            .upgradeable_read()
            .upgrade()
            .insert(self.offset, entry.clone());

        self.offset += entry.record_len();
        Ok(())
    }

    /// Appends a new `DirEntry` starting from the current offset.
    ///
    /// If there is a gap between existing entries, inserts the new entry into the gap；
    /// If there is no available space, expands the size and appends the new entry at the end.
    pub fn append_entry(&mut self, mut new_entry: DirEntry) -> Result<()> {
        let Some((offset, mut entry)) = DirEntryReader::new(self.inode, self.offset)
            .find(|(_, entry)| entry.gap_len() >= new_entry.record_len())
        else {
            // Resize and append it at the new block.
            let old_size = self.inode.file_size();
            let new_size = old_size + BLOCK_SIZE;
            self.inode.resize(new_size)?;
            new_entry.set_record_len(BLOCK_SIZE);
            self.offset = old_size;
            self.write_entry(&new_entry)?;
            return Ok(());
        };

        // Write in the gap between existing entries.
        new_entry.set_record_len(entry.gap_len());
        entry.set_record_len(entry.actual_len());
        self.offset = offset;
        self.write_entry(&entry)?;
        self.write_entry(&new_entry)?;
        Ok(())
    }

    /// Removes and returns an existing `DirEntry` indicated by `name`.
    pub fn remove_entry(&mut self, name: &str) -> Result<DirEntry> {
        let self_entry_record_len = DirEntry::self_entry(0).record_len();
        let reader = DirEntryReader::new(self.inode, 0);
        let next_reader = DirEntryReader::new(self.inode, self_entry_record_len);
        let Some(((pre_offset, mut pre_entry), (offset, entry))) = reader
            .zip(next_reader)
            .find(|((_, _), (_, dir_entry))| dir_entry.name() == name)
        else {
            return Err(FsError::EntryNotFound);
        };

        if DirEntryReader::new(self.inode, offset).next().is_none()
            && (pre_offset / BLOCK_SIZE) != (offset / BLOCK_SIZE)
        {
            // Shrink the size.
            let new_size = pre_offset.align_up(BLOCK_SIZE);
            self.inode.resize(new_size)?;
            pre_entry.set_record_len(new_size - pre_offset);
            self.offset = pre_offset;
            self.write_entry(&pre_entry)?;
        } else {
            // Update the previous entry.
            pre_entry.set_record_len(pre_entry.record_len() + entry.record_len());
            self.offset = pre_offset;
            self.write_entry(&pre_entry)?;
        }

        Ok(entry)
    }

    /// Renames the `DirEntry` from `old_name` to the `new_name` from the current offset.
    ///
    /// It will moves the `DirEntry` to another position,
    /// if the record length is not big enough.
    pub fn rename_entry(&mut self, old_name: &str, new_name: &str) -> Result<()> {
        let (offset, entry) = DirEntryReader::new(self.inode, self.offset)
            .find(|(_, entry)| entry.name() == old_name)
            .ok_or(FsError::EntryNotFound)?;

        let mut new_entry = DirEntry::new(entry.ino(), new_name, entry.type_());
        if new_entry.record_len() <= entry.record_len() {
            // Just rename the entry.
            new_entry.set_record_len(entry.record_len());
            self.offset = offset;
            self.write_entry(&new_entry)?;
        } else {
            // Move to another position.
            self.remove_entry(old_name)?;
            self.offset = 0;
            self.append_entry(new_entry)?;
        }
        Ok(())
    }
}
