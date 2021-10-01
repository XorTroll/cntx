use std::io::{Error, Result, ErrorKind, SeekFrom};

use crate::util::{ReadSeek, Shared, reader_read_val};

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

fn read_dir_info(reader: &Shared<dyn ReadSeek>, dir_table_offset: u64, offset: u32, read_str: bool) -> Result<(DirectoryInfo, String)> {
    reader.lock().unwrap().seek(SeekFrom::Start(dir_table_offset + offset as u64))?;
    let dir_info: DirectoryInfo = reader_read_val(&reader)?;

    let name = match read_str {
        true => {
            let mut name_data = vec![0u8; dir_info.name_len as usize]; 
            reader.lock().unwrap().read_exact(&mut name_data)?;
            String::from_utf8(name_data).unwrap()
        },
        false => String::new()
    };
    Ok((dir_info, name))
}

fn read_file_info(reader: &Shared<dyn ReadSeek>, file_table_offset: u64, offset: u32, read_str: bool) -> Result<(FileInfo, String)> {
    reader.lock().unwrap().seek(SeekFrom::Start(file_table_offset + offset as u64))?;
    let file_info: FileInfo = reader_read_val(&reader)?;

    let name = match read_str {
        true => {
            let mut name_data = vec![0u8; file_info.name_len as usize]; 
            reader.lock().unwrap().read_exact(&mut name_data)?;
            String::from_utf8(name_data).unwrap()
        },
        false => String::new()
    };
    Ok((file_info, name))
}

pub struct RomFsDirectoryIterator {
    reader: Shared<dyn ReadSeek>,
    dir_table_offset: u64,
    file_table_offset: u64,
    dir_offsets: Vec<u32>,
    file_offsets: Vec<u32>,
    cur_dir_idx: usize,
    cur_file_idx: usize
}

impl RomFsDirectoryIterator {
    pub fn new(reader: Shared<dyn ReadSeek>, dir_table_offset: u64, file_table_offset: u64, dir_offsets: Vec<u32>, file_offsets: Vec<u32>) -> Self {
        Self {
            reader,
            dir_table_offset,
            file_table_offset,
            dir_offsets,
            file_offsets,
            cur_dir_idx: 0,
            cur_file_idx: 0
        }
    }

    pub fn next_dir(&mut self) -> Result<String> {
        if self.cur_dir_idx == self.dir_offsets.len() {
            Err(Error::new(ErrorKind::UnexpectedEof, "No more directories"))
        }
        else {
            let (_, dir_name) = read_dir_info(&self.reader, self.dir_table_offset, self.dir_offsets[self.cur_dir_idx], true)?;
            self.cur_dir_idx += 1;
            Ok(dir_name)
        }
    }

    pub fn get_dir_count(&self) -> usize {
        self.dir_offsets.len()
    }

    pub fn rewind_dirs(&mut self) {
        self.cur_dir_idx = 0;
    }

    pub fn next_file(&mut self) -> Result<(String, usize)> {
        if self.cur_file_idx == self.file_offsets.len() {
            Err(Error::new(ErrorKind::UnexpectedEof, "No more files"))
        }
        else {
            let (file, file_name) = read_file_info(&self.reader, self.file_table_offset, self.file_offsets[self.cur_file_idx], true)?;
            self.cur_file_idx += 1;
            Ok((file_name, file.data_size))
        }
    }

    pub fn get_file_count(&self) -> usize {
        self.file_offsets.len()
    }

    pub fn rewind_files(&mut self) {
        self.cur_file_idx = 0;
    }
}

pub struct RomFs {
    reader: Shared<dyn ReadSeek>,
    header: Header
}

impl RomFs {
    pub const INVALID_INFO_OFFSET: u32 = u32::MAX;
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
        self.reader.lock().unwrap().seek(SeekFrom::Start(self.header.dir_hash_table_offset + hash as u64 * std::mem::size_of::<u32>() as u64))?;
        reader_read_val(&self.reader)
    }

    fn read_file_offset(&mut self, hash: u32) -> Result<u32> {
        self.reader.lock().unwrap().seek(SeekFrom::Start(self.header.file_hash_table_offset + hash as u64 * std::mem::size_of::<u32>() as u64))?;
        reader_read_val(&self.reader)
    }

    fn find_dir_offset(&mut self, parent_dir_offset: u32, name: String) -> Result<u32> {
        let hash = Self::compute_hash(parent_dir_offset, name.as_bytes(), self.header.dir_hash_table_size / std::mem::size_of::<u32>());
        let first_dir_offset = self.read_dir_offset(hash)?;

        let mut cur_dir_offset = first_dir_offset;
        while cur_dir_offset != Self::INVALID_INFO_OFFSET {
            let (dir, dir_name) = read_dir_info(&self.reader, self.header.dir_table_offset, cur_dir_offset, true)?;
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
            let (file, file_name) = read_file_info(&self.reader, self.header.file_table_offset, cur_file_offset, true)?;
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

    fn find_dir(&mut self, path: String) -> Result<DirectoryInfo> {
        let path_items: Vec<_> = path.split("/").collect();

        let mut cur_dir_offset = Self::ROOT_DIR_OFFSET;
        for dir_item in path_items {
            cur_dir_offset = self.find_dir_offset(cur_dir_offset, String::from(dir_item))?;
        }

        let (dir, _) = read_dir_info(&self.reader, self.header.dir_table_offset, cur_dir_offset, false)?;
        Ok(dir)
    }

    pub fn exists_file(&mut self, path: String) -> bool {
        self.find_file(path).is_ok()
    }

    pub fn exists_dir(&mut self, path: String) -> bool {
        self.find_dir(path).is_ok()
    }

    pub fn get_file_size(&mut self, path: String) -> Result<usize> {
        let file_info = self.find_file(path)?;
        Ok(file_info.data_size)
    }

    pub fn get_file_offset(&mut self, path: String) -> Result<u64> {
        let file_info = self.find_file(path)?;
        Ok(file_info.data_offset)
    }

    pub fn read_file_by_offset(&mut self, file_offset: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let file_data_offset = self.header.file_data_offset + file_offset;
        let read_offset = file_data_offset + offset;
        self.reader.lock().unwrap().seek(SeekFrom::Start(read_offset))?;
        self.reader.lock().unwrap().read(buf)
    }
    
    #[inline]
    pub fn read_file(&mut self, path: String, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let file_offset = self.get_file_offset(path)?;
        self.read_file_by_offset(file_offset, offset, buf)
    }

    pub fn open_dir_iterator(&mut self, path: String) -> Result<RomFsDirectoryIterator> {
        let dir = self.find_dir(path)?;

        let mut child_dir_offsets: Vec<u32> = Vec::new();
        let mut cur_child_dir_offset = dir.first_child_dir_offset;
        while cur_child_dir_offset != Self::INVALID_INFO_OFFSET {
            child_dir_offsets.push(cur_child_dir_offset);

            let (child_dir, _) = read_dir_info(&self.reader, self.header.dir_table_offset, cur_child_dir_offset, false)?;
            cur_child_dir_offset = child_dir.sibling_dir_offset;
        }

        let mut child_file_offsets: Vec<u32> = Vec::new();
        let mut cur_child_file_offset = dir.first_child_file_offset;
        while cur_child_file_offset != Self::INVALID_INFO_OFFSET {
            child_file_offsets.push(cur_child_file_offset);

            let (child_file, _) = read_file_info(&self.reader, self.header.file_table_offset, cur_child_file_offset, false)?;
            cur_child_file_offset = child_file.sibling_file_offset;
        }

        Ok(RomFsDirectoryIterator::new(self.reader.clone(), self.header.dir_table_offset, self.header.file_table_offset, child_dir_offsets, child_file_offsets))
    }

    pub fn new(reader: Shared<dyn ReadSeek>) -> Result<Self> {
        let header: Header = reader_read_val(&reader)?;

        Ok(Self {
            reader: reader,
            header: header
        })
    }
}