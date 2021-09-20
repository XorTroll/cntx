use std::cell::RefCell;
use std::io::{Read, Result, Seek, SeekFrom};
use std::rc::Rc;
use aes::Aes128;
use ctr::Ctr128;
use ctr::cipher::NewStreamCipher;
use ctr::cipher::StreamCipher;

pub trait ReadSeek: Read + Seek {
}

pub fn reader_read_val<T>(reader: &Rc<RefCell<dyn ReadSeek>>) -> Result<T> {
    let mut t: T = unsafe {
        std::mem::zeroed()
    };

    let t_buf = unsafe {
        std::slice::from_raw_parts_mut(&mut t as *mut _ as *mut u8, std::mem::size_of::<T>())
    };
    reader.borrow_mut().read_exact(t_buf)?;

    Ok(t)
}

impl<R: Read + Seek> ReadSeek for R {}

pub struct DataReader {
    offset: usize,
    data: Vec<u8>
}

impl DataReader {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            offset: 0,
            data: data
        }
    }
}

impl Read for DataReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let end = std::cmp::min(self.data.len(), self.offset + buf.len());
        let size = end - self.offset;
        buf.copy_from_slice(&self.data[self.offset..end]);
        self.offset = end;
        Ok(size)
    }
}

impl Seek for DataReader {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        match pos {
            SeekFrom::Current(pos_val) => {
                let new_offset = self.offset as i64 + pos_val;
                self.offset = new_offset as usize;
            },
            SeekFrom::Start(pos_val) => self.offset = pos_val as usize,
            SeekFrom::End(pos_val) => {
                let new_offset = self.data.len() as i64 + pos_val;
                self.offset = new_offset as usize;
            }
        };

        Ok(self.offset as u64)
    }
}

pub fn get_nintendo_tweak(sector_index: u128) -> [u8; 0x10] {
    sector_index.to_be_bytes()
}

pub struct Aes128CtrReader {
    base_offset: u64,
    offset: u64,
    base_reader: Rc<RefCell<dyn ReadSeek>>,
    ctr: u64,
    key: Vec<u8>
}

impl Aes128CtrReader {
    pub fn new(base_reader: Rc<RefCell<dyn ReadSeek>>, base_offset: u64, ctr: u64, key: Vec<u8>) -> Self {
        base_reader.borrow_mut().seek(SeekFrom::Start(base_offset)).unwrap();
        Self {
            base_offset: base_offset,
            offset: base_offset,
            base_reader: base_reader,
            ctr: ctr,
            key: key
        }
    }
}

pub const fn align_down(value: u64, align: u64) -> u64 {
    let inv_mask = align - 1;
    value & !inv_mask
}

pub const fn align_up(value: usize, align: usize) -> usize {
    let inv_mask = align - 1;
    (value + inv_mask) & !inv_mask
}

impl Read for Aes128CtrReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let offset = self.base_reader.borrow_mut().stream_position()?;
        let aligned_offset = align_down(offset, 0x10);
        let diff = (offset - aligned_offset) as i64;

        let read_buf_size_raw = buf.len() + diff as usize;
        let read_buf_size = align_up(read_buf_size_raw, 0x10);
        let read_buf_size_diff = (read_buf_size - read_buf_size_raw) as i64;
        let mut read_buf = vec![0u8; read_buf_size];
        self.seek(SeekFrom::Current(-diff))?;
        let read_size = self.base_reader.borrow_mut().read(&mut read_buf)? as i64;
        self.seek(SeekFrom::Current(read_size - read_buf_size_diff))?;

        let iv = get_nintendo_tweak(((aligned_offset as u128) >> 4) | ((self.ctr as u128) << 64));
        let mut ctr = Ctr128::<Aes128>::new_var(&self.key, &iv).unwrap();
        ctr.decrypt(&mut read_buf);

        let read_buf_start = diff as usize;
        let read_buf_end = read_buf_start + buf.len();
        buf.copy_from_slice(&read_buf[read_buf_start..read_buf_end]);

        Ok(buf.len())
    }
}

impl Seek for Aes128CtrReader {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        match pos {
            SeekFrom::Current(cur_pos) => {
                let new_offset = self.offset as i64 + cur_pos;
                self.offset = new_offset as u64;
            },
            SeekFrom::Start(start_pos) => self.offset = self.base_offset + start_pos,
            SeekFrom::End(end_pos) => {
                let new_offset = self.offset as i64 + end_pos;
                self.offset = new_offset as u64;
            }
        }

        self.base_reader.borrow_mut().seek(SeekFrom::Start(self.offset))
    }
}

#[inline]
pub fn new_shared<T>(t: T) -> Rc<RefCell<T>> {
    Rc::new(RefCell::new(t))
}