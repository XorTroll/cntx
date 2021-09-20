use std::cell::RefCell;
use std::io::{Error, ErrorKind, Result};
use std::rc::Rc;
use aes::Aes128;
use aes::NewBlockCipher;
use block_modes::Ecb;
use block_modes::BlockMode;
use block_modes::block_padding::NoPadding;
use xts_mode::Xts128;
use crate::key::Keyset;
use crate::pfs0::PFS0;
use crate::romfs::RomFs;
use crate::util::{Aes128CtrReader, ReadSeek, get_nintendo_tweak, new_shared};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum DistributionType {
    System,
    Gamecard
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ContentType {
    Program,
    Meta,
    Control,
    Manual,
    Data,
    PublicData
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct RSASignature {
    part_1: [u8; 0x20],
    part_2: [u8; 0x20],
    part_3: [u8; 0x20],
    part_4: [u8; 0x20],
    part_5: [u8; 0x20],
    part_6: [u8; 0x20],
    part_7: [u8; 0x20],
    part_8: [u8; 0x20]
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct SdkAddonVersion {
    unk: u8,
    micro: u8,
    minor: u8,
    major: u8
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct FileSystemEntry {
    start_offset: u32,
    end_offset: u32,
    reserved: [u8; 0x8]
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct Sha256Hash {
    hash: [u8; 0x20]
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum KeyAreaEncryptionKeyIndex {
    Application,
    Ocean,
    System
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
#[repr(C)]
pub struct KeyArea {
    aes_xts_key: [u8; 0x20],
    aes_ctr_key: [u8; 0x10],
    unk_key: [u8; 0x10]
}

impl KeyArea {
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            aes_xts_key: slice[0..0x20].try_into().unwrap(),
            aes_ctr_key: slice[0x20..0x30].try_into().unwrap(),
            unk_key: slice[0x30..0x40].try_into().unwrap()
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<Self>())
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self as *mut _ as *mut u8, std::mem::size_of::<Self>())
        }
    }
}

pub const MAX_FILESYSTEM_COUNT: usize = 4;
pub const SECTOR_SIZE: usize = 0x200;
pub const MEDIA_UNIT_SIZE: usize = 0x200;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct Header {
    pub header_rsa_sig_1: RSASignature,
    pub header_rsa_sig_2: RSASignature,
    pub magic: u32,
    pub dist_type: DistributionType,
    pub cnt_type: ContentType,
    pub key_generation_old: u8,
    pub key_area_encryption_key_index: KeyAreaEncryptionKeyIndex,
    pub cnt_size: usize,
    pub program_id: u64,
    pub cnt_idx: u32,
    pub sdk_addon_ver: SdkAddonVersion,
    pub key_generation: u8,
    pub header_1_signature_key_generation: u8,
    pub reserved: [u8; 0xE],
    pub rights_id: [u8; 0x10],
    pub fs_entries: [FileSystemEntry; MAX_FILESYSTEM_COUNT],
    pub fs_header_hashes: [Sha256Hash; MAX_FILESYSTEM_COUNT],
    pub encrypted_key_area: KeyArea,
    pub reserved_1: [u8; 0x20],
    pub reserved_2: [u8; 0x20],
    pub reserved_3: [u8; 0x20],
    pub reserved_4: [u8; 0x20],
    pub reserved_5: [u8; 0x20],
    pub reserved_6: [u8; 0x20]
}

impl Header {
    pub const MAGIC: u32 = u32::from_le_bytes(*b"NCA3");

    #[inline]
    pub fn get_key_generation(self) -> u8 {
        let base_key_gen = {
            if self.key_generation_old < self.key_generation {
                self.key_generation
            }
            else {
                self.key_generation_old
            }
        };

        if base_key_gen > 0 {
            // Both 0 and 1 are master key 0...
            base_key_gen - 1
        }
        else {
            base_key_gen
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FileSystemType {
    RomFs,
    PartitionFs
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum HashType {
    Auto = 0,
    HierarchicalSha256 = 2,
    HierarchicalIntegrity = 3
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EncryptionType {
    Auto,
    None,
    AesCtrOld,
    AesCtr,
    AesCtrEx
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct HierarchicalSha256 {
    hash_table_hash: Sha256Hash,
    block_size: u32,
    unk_2: u32,
    hash_table_offset: u64,
    hash_table_size: usize,
    pfs0_offset: u64,
    pfs0_size: usize,
    reserved_1: [u8; 0x20],
    reserved_2: [u8; 0x20],
    reserved_3: [u8; 0x20],
    reserved_4: [u8; 0x20],
    reserved_5: [u8; 0x20],
    reserved_6: [u8; 0x10]
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct HierarchicalIntegrityLevelInfo {
    offset: u64,
    size: usize,
    block_size_log2: u32,
    reserved: [u8; 0x4]
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct HierarchicalIntegrity {
    magic: u32,
    magic_num: u32,
    maybe_master_hash_size: u32,
    unk_7: u32,
    levels: [HierarchicalIntegrityLevelInfo; 6],
    reserved: [u8; 0x20],
    hash: Sha256Hash
}

impl HierarchicalIntegrity {
    pub const MAGIC: u32 = u32::from_le_bytes(*b"IVFC");
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union HashInfo {
    hierarchical_sha256: HierarchicalSha256,
    hierarchical_integrity: HierarchicalIntegrity
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct BucketRelocationInfo {
    offset: u64,
    size: usize,
    magic: u32,
    unk_1: u32,
    unk_2: i32,
    unk_3: u32
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct PatchInfo {
    info: BucketRelocationInfo,
    info_2: BucketRelocationInfo
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct SparseInfo {
    data_1: [u8; 0x20],
    data_2: [u8; 0x10]
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct FileSystemHeader {
    version: u16,
    fs_type: FileSystemType,
    hash_type: HashType,
    encryption_type: EncryptionType,
    pad: [u8; 0x3],
    hash_info: HashInfo,
    patch_info: PatchInfo,
    ctr: u64,
    sparse_info: SparseInfo,
    reserved_1: [u8; 0x20],
    reserved_2: [u8; 0x20],
    reserved_3: [u8; 0x20],
    reserved_4: [u8; 0x20],
    reserved_5: [u8; 0x8]
}

pub struct NCA {
    reader: Rc<RefCell<dyn ReadSeek>>,
    keyset: Keyset,
    dec_key_area: KeyArea,
    pub header: Header,
    pub fs_headers: Vec<FileSystemHeader>
}

impl NCA {
    pub fn new(reader: Rc<RefCell<dyn ReadSeek>>, keyset: Keyset) -> Result<Self> {
        let cipher_1 = Aes128::new_varkey(&keyset.header_key[..0x10]).unwrap();
        let cipher_2 = Aes128::new_varkey(&keyset.header_key[0x10..]).unwrap();
        let xts = Xts128::new(cipher_1, cipher_2);

        let mut header: Header = unsafe {
            std::mem::zeroed()
        };
        let header_buf = unsafe {
            std::slice::from_raw_parts_mut(&mut header as *mut _ as *mut u8, std::mem::size_of::<Header>())
        };
        reader.borrow_mut().read_exact(header_buf)?;
        xts.decrypt_area(header_buf, SECTOR_SIZE, 0, get_nintendo_tweak);
    
        let mut fs_headers: [FileSystemHeader; MAX_FILESYSTEM_COUNT] = [unsafe { std::mem::zeroed() }; MAX_FILESYSTEM_COUNT];
        let fs_headers_buf = unsafe {
            std::slice::from_raw_parts_mut(fs_headers.as_mut_ptr() as *mut u8, std::mem::size_of::<FileSystemHeader>() * fs_headers.len())
        };
        reader.borrow_mut().read_exact(fs_headers_buf)?;
        xts.decrypt_area(fs_headers_buf, SECTOR_SIZE, 2, get_nintendo_tweak);

        let key_gen = header.get_key_generation();
        let key_area_key = match header.key_area_encryption_key_index {
            KeyAreaEncryptionKeyIndex::Application => &keyset.key_area_keys_application[key_gen as usize],
            KeyAreaEncryptionKeyIndex::Ocean => &keyset.key_area_keys_ocean[key_gen as usize],
            KeyAreaEncryptionKeyIndex::System => &keyset.key_area_keys_system[key_gen as usize]
        };

        let ecb_iv = get_nintendo_tweak(0);
        let ecb = Ecb::<Aes128, NoPadding>::new_var(key_area_key, &ecb_iv).unwrap();
        let dec_key_area = KeyArea::from_slice(ecb.decrypt(header.encrypted_key_area.as_mut_slice()).unwrap());

        let mut actual_fs_headers: Vec<FileSystemHeader> = Vec::new();
        for i in 0..MAX_FILESYSTEM_COUNT {
            let fs_entry = header.fs_entries[i];
            let fs_header = fs_headers[i];

            let fs_start_offset = fs_entry.start_offset as u64 * MEDIA_UNIT_SIZE as u64;
            if fs_start_offset > 0 {
                // Only save non-empty/present filesystem headers
                actual_fs_headers.push(fs_header);
            }
        }

        Ok(Self {
            reader: reader,
            keyset: keyset,
            dec_key_area: dec_key_area,
            header: header,
            fs_headers: actual_fs_headers
        })
    }

    #[inline]
    pub fn get_filesystem_count(&self) -> usize {
        self.fs_headers.len()
    }

    pub fn open_pfs0_filesystem(&mut self, idx: usize) -> Result<PFS0> {
        if idx >= self.fs_headers.len() {
            return Err(Error::new(ErrorKind::InvalidInput, "Invalid filesystem index"));
        }
        
        let fs_header = &self.fs_headers[idx];
        let fs_entry = &self.header.fs_entries[idx];
        if fs_header.fs_type != FileSystemType::PartitionFs {
            return Err(Error::new(ErrorKind::InvalidInput, format!("Invalid filesystem type (actual type: {:?})", fs_header.fs_type)));
        }

        let fs_start_offset = fs_entry.start_offset as u64 * MEDIA_UNIT_SIZE as u64;

        match fs_header.encryption_type {
            EncryptionType::AesCtr => {
                let pfs0_abs_offset = fs_start_offset + unsafe { fs_header.hash_info.hierarchical_sha256.pfs0_offset };
                let pfs0_reader = new_shared(Aes128CtrReader::new(self.reader.clone(), pfs0_abs_offset, fs_header.ctr, self.dec_key_area.aes_ctr_key.to_vec()));

                PFS0::new(pfs0_reader)
            },
            enc_type => todo!("Unsupported crypto type: {:?}", enc_type)
        }
    }

    pub fn open_romfs_filesystem(&mut self, idx: usize) -> Result<RomFs> {
        if idx >= self.fs_headers.len() {
            return Err(Error::new(ErrorKind::InvalidInput, "Invalid filesystem index"));
        }
        
        let fs_header = &self.fs_headers[idx];
        let fs_entry = &self.header.fs_entries[idx];
        if fs_header.fs_type != FileSystemType::RomFs {
            return Err(Error::new(ErrorKind::InvalidInput, format!("Invalid filesystem type (actual type: {:?})", fs_header.fs_type)));
        }

        let fs_start_offset = fs_entry.start_offset as u64 * MEDIA_UNIT_SIZE as u64;

        match fs_header.encryption_type {
            EncryptionType::AesCtr => {
                let romfs_offset = fs_start_offset + unsafe { fs_header.hash_info.hierarchical_integrity.levels.last().as_ref().unwrap().offset };
                let romfs_reader = new_shared(Aes128CtrReader::new(self.reader.clone(), romfs_offset, fs_header.ctr, self.dec_key_area.aes_ctr_key.to_vec()));

                RomFs::new(romfs_reader)
            },
            enc_type => todo!("Unsupported crypto type: {:?}", enc_type)
        }
    }
}