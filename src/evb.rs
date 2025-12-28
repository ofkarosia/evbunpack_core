use deku::DekuRead;

// NOTE: Maybe use another int type
pub(crate) const EVB_MAGIC: &[u8; 4] = b"EVB\0";
pub(crate) const VFS_PADDING: usize = 4;
pub(crate) const DEFAULT_FOLDER_LEN: usize = 32;
pub(crate) const DEFAULT_FOLDER_BYTES: &[u8; DEFAULT_FOLDER_LEN] = &[
    b'%', 0, b'D', 0, b'E', 0, b'F', 0, b'A', 0, b'U', 0, b'L', 0, b'T', 0,
    b' ', 0, b'F', 0, b'O', 0, b'L', 0, b'D', 0, b'E', 0, b'R', 0, b'%', 0
];
pub(crate) const EVB_PACK_HEADER_SIZE: usize = 64;
pub(crate) const VFS_HEADER_SIZE: usize = 16;
pub(crate) const VFS_NODE_TYPE_FILE: u8 = 2;
pub(crate) const VFS_NODE_TYPE_FOLDER: u8 = 3;
pub(crate) const VFS_CHUNK_HEADER_SIZE: u32 = 8;

#[derive(DekuRead)]
#[deku(endian = "little")]
pub(crate) struct VfsHeader {
    pub size: u32,
    #[deku(pad_bytes_before = "8")]
    pub objects_count: u32,
}

#[derive(DekuRead, Debug)]
#[deku(endian = "little")]
pub(crate) struct ModernFileNode {
    #[deku(pad_bytes_before = "2")]
    pub original_size: u32,
    #[deku(pad_bytes_before = "43")]
    pub stored_size: u32,
}

#[derive(DekuRead, Debug)]
#[deku(endian = "little")]
pub(crate) struct LegacyFileNode {
    #[deku(pad_bytes_before = "2")]
    pub original_size: u32,
    #[deku(pad_bytes_before = "35", pad_bytes_after = "4")]
    pub stored_size: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct FileNode {
    pub(crate) original_size: u32,
    pub(crate) stored_size: u32,
    pub(crate) offset: u64
}

impl FileNode {
    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn is_compressed(&self) -> bool {
        self.stored_size != self.original_size
    }
}

/// Header + NamedNode + FileNode
#[derive(Debug)]
pub struct VfsNode {
    pub name: String,
    pub size: u32,
    pub objects_count: u32,
    pub is_folder: bool,
    pub file: Option<FileNode>
}

impl VfsNode {
    pub fn is_compressed(&self) -> bool {
        self.file.as_ref().map(|f| f.original_size != f.stored_size).unwrap_or_default()
    }
}

#[derive(DekuRead)]
#[deku(endian = "little")]
pub(crate) struct ChunkHeader {
    #[deku(pad_bytes_after = "4")]
    pub(crate) size: u32
}
