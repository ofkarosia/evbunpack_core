use cfg_if::cfg_if;
use deku::{DekuContainerRead, DekuError};
use encoding_rs::UTF_16LE;
use indexmap::IndexMap;
use log::debug;
use thiserror::Error;
use std::{io::{self, Cursor, Seek}, path::{Path, PathBuf}, result};

cfg_if! {
    if #[cfg(feature = "aplib")] {
        mod aplib;
        use ::aplib::AplibError;
    }
}

use crate::{evb::{DEFAULT_FOLDER_BYTES, DEFAULT_FOLDER_LEN, EVB_MAGIC, EVB_PACK_HEADER_SIZE, FileNode, LegacyFileNode, ModernFileNode, VFS_HEADER_SIZE, VFS_NODE_TYPE_FILE, VFS_NODE_TYPE_FOLDER, VFS_PADDING, VfsHeader, VfsNode}, extensions::ReadBytesExt};

#[derive(Debug, Error)]
pub enum UnpackerError {
    #[error("Serialize error")]
    Serialize(#[from] DekuError),
    #[error("No null terminator found")]
    NullTerminatorNotFound,
    #[error("IO error")]
    Io(#[from] io::Error),
    #[error("Unknown node type")]
    UnknownNodeType,
    #[error("No EVB Magic found")]
    MagicNotFound,
    #[error("Unsupported root folder")]
    RootFolderNotSupported,
    #[error("Invalid VFS")]
    InvalidVfs,
    #[error("Invalid character")]
    InvalidCharacter,
    #[error("node name cannot be either . or ..")]
    RelativePath,
    #[error("Multiple root folders are not supported")]
    MultipleRootFolders,
    #[cfg(feature = "aplib")]
    #[error("Decompress error")]
    Decompress(#[from] AplibError),
    #[error("Size mismatch: {0}")]
    SizeMismatch(&'static str)
}

pub struct Unpacker<'r> {
    slice: &'r [u8],
    reader: Cursor<&'r [u8]>,
    entries: IndexMap<PathBuf, VfsNode>,
    data_abs_offset: u64,
    legacy_next_available_offset: u64, // Header or file data
    is_legacy: bool
}

struct VfsPreAnalysis {
    is_legacy: bool,
    data_abs_offset: u64,
    next_header_offset: usize
}

type Result<T> = result::Result<T, UnpackerError>;

impl<'r> Unpacker<'r> {
    pub fn new(data: &'r [u8]) -> Result<Self> {
        let mut unpacker = Self {
            slice: data,
            reader: Cursor::new(data),
            entries: IndexMap::new(),
            data_abs_offset: 0,
            legacy_next_available_offset: 0,
            is_legacy: false,
        };

        unpacker.build_entries()?;
        Ok(unpacker)
    }

    fn read_header(&mut self) -> Result<VfsHeader> {
        let (_, node) = VfsHeader::from_reader((&mut self.reader, 0))?;
        Ok(node)
    }

    fn read_node(&mut self) -> Result<VfsNode> {
        let header = self.read_header()?;
        let start = self.reader.position() as usize;
        let offset = self.slice[start..]
            .chunks_exact(2)
            .position(|chunk| chunk[0] == 0 && chunk[1] == 0)
            .ok_or(UnpackerError::NullTerminatorNotFound)? * 2;

        let final_offset = offset + 2;
        let (s, ..) = UTF_16LE.decode(&self.slice[start..start + offset]);
        self.reader.seek_relative(final_offset as i64)?;

        let is_folder = match self.reader.read_u8()? {
            VFS_NODE_TYPE_FILE => false,
            VFS_NODE_TYPE_FOLDER => true,
            _ => return Err(UnpackerError::UnknownNodeType)
        };

        if self.is_legacy {
            self.legacy_next_available_offset = (header.size as usize + VFS_PADDING - VFS_HEADER_SIZE - final_offset - 1) as u64;
        }

        let name = self.process_file_name(s.to_string())?;

        Ok(VfsNode {
            name,
            size: header.size,
            objects_count: header.objects_count,
            is_folder,
            file: None,
        })
    }

    fn read_file_node(&mut self) -> Result<ModernFileNode> {
        let (_, file_node) = ModernFileNode::from_reader((&mut self.reader, 0))?;
        Ok(file_node)
    }

    fn read_file_node_legacy(&mut self) -> Result<LegacyFileNode> {
        let (_, file_node) = LegacyFileNode::from_reader((&mut self.reader, 0))?;
        Ok(file_node)
    }

    fn find_magic(&self) -> Result<usize> {
        // The executable may contain embedded data that coincidentally matches the
        // EVB magic. Validate each candidate by probing its VFS header instead of
        // blindly trusting the first match.
        let mut last_error = None;

        for (pos, window) in self.slice.windows(EVB_MAGIC.len()).enumerate() {
            if window != EVB_MAGIC {
                continue;
            }

            let main_header_pos = pos + EVB_PACK_HEADER_SIZE;
            match self.get_pre_analysis(main_header_pos) {
                Ok(_) => return Ok(pos),
                Err(error) => last_error = Some(error)
            }
        }

        Err(last_error.unwrap_or(UnpackerError::MagicNotFound))
    }

    fn process_file_name(&self, name: String) -> Result<String> {
        if name == "%DEFAULT FOLDER%" {
            return Ok(String::new());
        }

        if name.contains(r"\") || name.contains("/") || name.contains(":") {
            return Err(UnpackerError::InvalidCharacter)
        }

        if name == ".." || name == "." {
            return Err(UnpackerError::RelativePath)
        }

        Ok(name)
    }

    fn process_node(&mut self, node: &mut VfsNode) -> Result<()> {
        if node.is_folder {
            self.reader.seek_relative(25)?;
            return Ok(());
        }

        let file_node = self.read_file_node()?;
        let offset = self.data_abs_offset;
        self.data_abs_offset += file_node.stored_size as u64;

        node.file = Some(FileNode {
            original_size: file_node.original_size,
            stored_size: file_node.stored_size,
            offset,
        });

        Ok(())
    }

    fn process_node_legacy(&mut self, node: &mut VfsNode) -> Result<()> {
        if node.is_folder {
            self.reader.seek_relative(self.legacy_next_available_offset as i64)?;
            return Ok(());
        }

        // Alternative way (from python implementation): legacy_next_available_offset - VFS_LEGACY_FILE_NODE_SIZE (49)
        // Currently just assume file node is right after the header
        let file_node = self.read_file_node_legacy()?;
        let offset = self.reader.position();
        self.reader.seek_relative(file_node.stored_size as i64)?;

        node.file = Some(FileNode {
            original_size: file_node.original_size,
            stored_size: file_node.stored_size,
            offset,
        });

        Ok(())
    }

    fn slice_at(&self, start: usize, len: usize) -> Option<&'r [u8]> {
        self.slice.get(start..start.checked_add(len)?)
    }

    fn get_pre_analysis(&self, main_header_pos: usize) -> Result<VfsPreAnalysis> {
        let header = self.slice_at(main_header_pos, VFS_HEADER_SIZE).ok_or(UnpackerError::InvalidVfs)?;
        let (_, main_node) = VfsHeader::from_bytes((header, 0))?;
        if main_node.objects_count != 1 {
            return Err(UnpackerError::MultipleRootFolders);
        }

        debug!("Main node size: {}, objects_count: {}", main_node.size, main_node.objects_count);

        // NOTE: There is an edge case when the actual type is modern and the first file is a UTF-16LE encoded text
        // Not going to handle it for now
        let next_header_offset = main_node.size as usize + VFS_PADDING;
        let legacy_start = main_header_pos + next_header_offset + VFS_HEADER_SIZE;

        if self.slice_at(legacy_start, DEFAULT_FOLDER_LEN) == Some(DEFAULT_FOLDER_BYTES.as_slice()) {
            debug!("Found legacy VFS");
            return Ok(VfsPreAnalysis {
                is_legacy: true,
                data_abs_offset: 0,
                next_header_offset
            });
        }

        let data_abs_offset = (main_header_pos + next_header_offset) as u64;
        let next_header_offset = VFS_HEADER_SIZE - 1;
        let modern_start = main_header_pos + next_header_offset + VFS_HEADER_SIZE;

        if self.slice_at(modern_start, DEFAULT_FOLDER_LEN) == Some(DEFAULT_FOLDER_BYTES.as_slice()) {
            debug!("Found modern VFS");
            return Ok(VfsPreAnalysis {
                is_legacy: false,
                data_abs_offset,
                next_header_offset
            });
        }

        let is_unsupported_root = |start: usize| self.slice_at(start, 2) == Some(b"%\0".as_slice());
        if is_unsupported_root(legacy_start) || is_unsupported_root(modern_start) {
            return Err(UnpackerError::RootFolderNotSupported)
        }

        Err(UnpackerError::InvalidVfs)
    }

    fn build_entries(&mut self) -> Result<()> {
        let magic_pos = self.find_magic()?;
        debug!("Found magic at: 0x{:x}", magic_pos);
        let main_header_pos = magic_pos + EVB_PACK_HEADER_SIZE;
        self.reader.set_position(main_header_pos as u64);

        let VfsPreAnalysis { is_legacy, data_abs_offset, next_header_offset } = self.get_pre_analysis(main_header_pos)?;
        debug!("Next header offset: {}", next_header_offset);

        self.data_abs_offset = data_abs_offset;
        self.reader.seek_relative(next_header_offset as i64)?;
        self.is_legacy = is_legacy;

        let mut stack: Vec<(PathBuf, u32)> = vec![(PathBuf::from(""), 1)];

        while let Some((current_base, remaining_objects)) = stack.last_mut() {
            if *remaining_objects == 0 {
                stack.pop();
                continue;
            }

            let mut node = self.read_node()?;

            if self.is_legacy {
                self.process_node_legacy(&mut node)?;
            } else {
                self.process_node(&mut node)?;
            }

            let full_path = current_base.join(&node.name);
            *remaining_objects -= 1;

            if node.is_folder {
                stack.push((full_path.clone(), node.objects_count));
            }

            self.entries.insert(full_path, node);
        }

        Ok(())
    }

    pub fn files(&self) -> &IndexMap<PathBuf, VfsNode> {
        &self.entries
    }

    pub fn get_node(&self, path: &Path) -> Option<&VfsNode> {
        self.entries.get(path)
    }

    pub fn get_raw_file_data(&self, node: &VfsNode) -> Option<&[u8]> {
        if node.is_folder {
            return None;
        }

        let file_node = node.file.as_ref().unwrap();
        let offset = file_node.offset as usize;
        let size = file_node.stored_size as usize;

        debug!("File: {}, offset: 0x{:x}, size: {}", node.name, offset, size);

        Some(&self.slice[offset..offset + size])
    }
}
