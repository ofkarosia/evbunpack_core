use std::{borrow::Cow, io::{Cursor, Seek}};
use aplib::decompress_to;
use deku::DekuContainerRead;

use crate::{evb::{ChunkHeader, FileNode, VFS_CHUNK_HEADER_SIZE, VfsNode}, vfs::{Result, Unpacker, UnpackerError}};

const DEFAULT_CHUNK_SIZE: usize = 65536;

impl<'r> Unpacker<'r> {
    pub fn get_decompressed_file_data(&self, node: &VfsNode) -> Result<Option<Vec<u8>>> {
        // This method has already checked whether node is folder
        if !node.is_compressed() {
            return Ok(None)
        }

        let FileNode { original_size, offset, stored_size } = node.file.unwrap();
        let mut decompressed = Vec::with_capacity(original_size as usize);
        let mut reader = Cursor::new(self.slice);
        reader.set_position(offset);

        let (_, chunk_header) = ChunkHeader::from_reader((&mut reader, 0))?;
        let chunk_data_start = reader.position() as usize;
        let chunk_data_size = (chunk_header.size - VFS_CHUNK_HEADER_SIZE) as usize;
        let chunk_data = &self.slice[chunk_data_start..chunk_data_start + chunk_data_size];
        reader.seek_relative(chunk_data_size as i64)?;

        let expected_total_chunk_size = stored_size - chunk_header.size;
        let mut total_chunk_size = 0;

        if chunk_data.len() == 4 {
            let start = reader.position() as usize;
            let size = u32::from_le_bytes(chunk_data.try_into().unwrap());
            decompress_to(&self.slice[start..start + size as usize], &mut decompressed)?;
            return Ok(Some(decompressed))
        }

        let mut decompressed_buf = Vec::with_capacity(DEFAULT_CHUNK_SIZE);

        for chunk_size in chunk_data.chunks_exact(4).step_by(3).map(|e| u32::from_le_bytes(e.try_into().unwrap())) {
            let start = reader.position() as usize;
            reader.seek_relative(chunk_size as i64)?;
            
            let data = &self.slice[start..start + chunk_size as usize];
            decompress_to(data, &mut decompressed_buf)?;
            decompressed.append(&mut decompressed_buf);
            total_chunk_size += chunk_size;
        }

        if total_chunk_size != expected_total_chunk_size {
            return Err(UnpackerError::SizeMismatch("total chunk size"))
        }

        if decompressed.len() != original_size as usize {
            return Err(UnpackerError::SizeMismatch("decompressed size"))
        }

        Ok(Some(decompressed))
    }

    pub fn get_file_data(&self, node: &VfsNode) -> Result<Option<Cow<'_, [u8]>>> {
        if node.is_compressed() {
            Ok(self.get_decompressed_file_data(node)?.map(Cow::Owned))
        } else {
            Ok(self.get_raw_file_data(node).map(Cow::Borrowed))
        }
    }
}
