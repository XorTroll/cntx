use std::{cell::RefCell, io::{Error, Result, ErrorKind, SeekFrom}, rc::Rc};

use crate::util::{ReadSeek, reader_read_val};

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct Header {
    header_size: usize,
    dir_hash_table_offset: u64,
    dir_hash_table_size: usize,
    dir_table_offset: u64,
    dir_table_size: usize,
    file_hash_table_offset: u64,
    file_hash_table_size: usize,
    file_table_offset: u64,
    file_table_size: usize,
    file_data_offset: u64
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct DirectoryInfo {
    parent_dir_offset: u32,
    sibling_dir_offset: u32,
    first_child_dir_offset: u32,
    first_child_file_offset: u32,
    next_dir_hash: u32,
    name_len: u32
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct FileInfo {
    parent_dir_offset: u32,
    sibling_file_offset: u32,
    data_offset: u64,
    data_size: usize,
    next_file_hash: u32,
    name_len: u32
}

pub struct RomFs {
    reader: Rc<RefCell<dyn ReadSeek>>,
    header: Header
}

impl RomFs {
    const INVALID_INFO_OFFSET: u32 = u32::MAX;
    const ROOT_DIR_OFFSET: u32 = 0;

    fn compute_hash(parent_offset: u32, name: &[u8], hash_table_count: usize) -> u32 {
        let mut hash = parent_offset ^ 123456789;
        for name_chr in name {
            hash = (hash >> 5) | (hash << 27);
            hash ^= *name_chr as u32;
        }

        hash % hash_table_count as u32
    }

    fn read_dir_offset(&mut self, hash: u32) -> Result<u32> {
        self.reader.borrow_mut().seek(SeekFrom::Start(self.header.dir_hash_table_offset + hash as u64 * std::mem::size_of::<u32>() as u64))?;
        reader_read_val(&self.reader)
    }

    fn read_file_offset(&mut self, hash: u32) -> Result<u32> {
        self.reader.borrow_mut().seek(SeekFrom::Start(self.header.file_hash_table_offset + hash as u64 * std::mem::size_of::<u32>() as u64))?;
        reader_read_val(&self.reader)
    }

    fn read_dir_info(&mut self, offset: u32) -> Result<(DirectoryInfo, String)> {
        self.reader.borrow_mut().seek(SeekFrom::Start(self.header.dir_table_offset + offset as u64))?;
        let dir_info: DirectoryInfo = reader_read_val(&self.reader)?;

        let mut name_data = vec![0u8; dir_info.name_len as usize]; 
        self.reader.borrow_mut().read_exact(&mut name_data)?;
        let name = String::from_utf8(name_data).unwrap();
        Ok((dir_info, name))
    }

    fn read_file_info(&mut self, offset: u32) -> Result<(FileInfo, String)> {
        self.reader.borrow_mut().seek(SeekFrom::Start(self.header.file_table_offset + offset as u64))?;
        let file_info: FileInfo = reader_read_val(&self.reader)?;

        let mut name_data = vec![0u8; file_info.name_len as usize]; 
        self.reader.borrow_mut().read_exact(&mut name_data)?;
        let name = String::from_utf8(name_data).unwrap();
        Ok((file_info, name))
    }

    fn find_dir_offset(&mut self, parent_dir_offset: u32, name: String) -> Result<u32> {
        let hash = Self::compute_hash(parent_dir_offset, name.as_bytes(), self.header.dir_hash_table_size / std::mem::size_of::<u32>());
        let first_dir_offset = self.read_dir_offset(hash)?;

        let mut cur_dir_offset = first_dir_offset;
        while cur_dir_offset != Self::INVALID_INFO_OFFSET {
            let (dir, dir_name) = self.read_dir_info(cur_dir_offset)?;
            if dir.parent_dir_offset == parent_dir_offset && dir_name == name {
                return Ok(cur_dir_offset);
            }

            cur_dir_offset = dir.next_dir_hash;
        }

        Err(Error::new(ErrorKind::NotFound, "Directory not found"))
    }

    fn find_file_info(&mut self, parent_dir_offset: u32, name: String) -> Result<FileInfo> {
        let hash = Self::compute_hash(parent_dir_offset, name.as_bytes(), self.header.file_hash_table_size / std::mem::size_of::<u32>());
        let first_dir_offset = self.read_file_offset(hash)?;

        let mut cur_file_offset = first_dir_offset;
        while cur_file_offset != Self::INVALID_INFO_OFFSET {
            let (file, file_name) = self.read_file_info(cur_file_offset)?;
            if file.parent_dir_offset == parent_dir_offset && file_name == name {
                return Ok(file);
            }

            cur_file_offset = file.next_file_hash;
        }

        Err(Error::new(ErrorKind::NotFound, "File not found"))
    }

    fn find_file(&mut self, path: String) -> Result<FileInfo> {
        let mut path_items: Vec<_> = path.split("/").collect();
        let file_item = path_items.pop().unwrap();

        let mut cur_dir_offset = Self::ROOT_DIR_OFFSET;
        for dir_item in path_items {
            cur_dir_offset = self.find_dir_offset(cur_dir_offset, String::from(dir_item))?;
        }

        self.find_file_info(cur_dir_offset, String::from(file_item))
    }

    pub fn exists_file(&mut self, path: String) -> bool {
        self.find_file(path).is_ok()
    }

    pub fn get_file_size(&mut self, path: String) -> Result<usize> {
        let file_info = self.find_file(path)?;
        Ok(file_info.data_size)
    }

    pub fn read_file(&mut self, path: String, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let file_info = self.find_file(path)?;
        if (offset as usize + buf.len()) > file_info.data_size {
            return Err(Error::new(ErrorKind::UnexpectedEof, "EOF reached"));
        }

        let file_data_offset = self.header.file_data_offset + file_info.data_offset;
        let read_offset = file_data_offset + offset;
        self.reader.borrow_mut().seek(SeekFrom::Start(read_offset))?;
        self.reader.borrow_mut().read(buf)
    }

    pub fn new(reader: Rc<RefCell<dyn ReadSeek>>) -> Result<Self> {
        let header: Header = reader_read_val(&reader)?;

        Ok(Self {
            reader: reader,
            header: header
        })
    }
}