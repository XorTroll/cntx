use std::cell::RefCell;
use std::io::Result;
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
    major: u8,
    minor: u8,
    micro: u8
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
    header_rsa_sig_1: RSASignature,
    header_rsa_sig_2: RSASignature,
    magic: u32,
    dist_type: DistributionType,
    cnt_type: ContentType,
    key_generation_old: u8,
    key_area_encryption_key_index: KeyAreaEncryptionKeyIndex,
    cnt_size: usize,
    program_id: u64,
    cnt_idx: u32,
    sdk_addon_ver: SdkAddonVersion,
    key_generation: u8,
    header_1_signature_key_generation: u8,
    reserved: [u8; 0xE],
    rights_id: [u8; 0x10],
    fs_entries: [FileSystemEntry; MAX_FILESYSTEM_COUNT],
    fs_header_hashes: [Sha256Hash; MAX_FILESYSTEM_COUNT],
    encrypted_key_area: KeyArea,
    reserved_1: [u8; 0x20],
    reserved_2: [u8; 0x20],
    reserved_3: [u8; 0x20],
    reserved_4: [u8; 0x20],
    reserved_5: [u8; 0x20],
    reserved_6: [u8; 0x20]
}

impl Header {
    pub const MAGIC: u32 = u32::from_le_bytes(*b"NCA3");

    #[inline]
    pub fn get_key_generation(self) -> u8 {
        if self.key_generation_old < self.key_generation {
            self.key_generation
        }
        else {
            self.key_generation_old
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

pub struct FileSystem {
    pub header: FileSystemHeader,
    pub pfs0: Option<PFS0>,
    pub romfs: Option<RomFs>
}

pub struct NCA {
    reader: Rc<RefCell<dyn ReadSeek>>,
    header: Header,
    pub filesystems: Vec<FileSystem>
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

        let ecb = Ecb::<Aes128, NoPadding>::new_var(key_area_key, &get_nintendo_tweak(0)).unwrap();
        let dec_key_area = KeyArea::from_slice(ecb.decrypt(header.encrypted_key_area.as_mut_slice()).unwrap());

        let mut filesystems: Vec<FileSystem> = Vec::new();
        for i in 0..MAX_FILESYSTEM_COUNT {
            let fs_entry = &header.fs_entries[i];
            let fs_header = &fs_headers[i];

            let start = fs_entry.start_offset as u64 * MEDIA_UNIT_SIZE as u64;
            let end = fs_entry.end_offset as u64 * MEDIA_UNIT_SIZE as u64;
            let size = (end - start) as usize;

            if size > 0 {
                let mut fs = FileSystem {
                    header: *fs_header,
                    pfs0: None,
                    romfs: None
                };

                match fs_header.fs_type {
                    FileSystemType::PartitionFs => {
                        let pfs0_abs_offset = start + unsafe { fs_header.hash_info.hierarchical_sha256.pfs0_offset };
                        let pfs0_reader = new_shared(Aes128CtrReader::new(reader.clone(), pfs0_abs_offset, dec_key_area.aes_ctr_key.to_vec()));

                        fs.pfs0 = Some(PFS0::new(pfs0_reader)?);
                    },
                    FileSystemType::RomFs => {
                        let romfs_abs_offset = start + unsafe { fs_header.hash_info.hierarchical_integrity.levels.last().unwrap().offset };
                        let romfs_reader = new_shared(Aes128CtrReader::new(reader.clone(), romfs_abs_offset, dec_key_area.aes_ctr_key.to_vec()));

                        fs.romfs = Some(RomFs::new(romfs_reader)?);
                    }
                };

                filesystems.push(fs);
            }
        }

        Ok(Self {
            reader: reader,
            header: header,
            filesystems: filesystems
        })
    }
}