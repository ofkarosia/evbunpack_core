use std::io;
use pelite::{PeFile, image::IMAGE_DATA_DIRECTORY, pe::Pe, pe32::Pe as Pe32};

pub(crate) trait PeFileExt {
    fn rva_to_file_offset(&self, rva: u32) -> pelite::Result<usize>;
    fn is_x64(&self) -> bool;
}

impl<'a> PeFileExt for PeFile<'a> {
    fn rva_to_file_offset(&self, rva: u32) -> pelite::Result<usize> {
        match self {
            Self::T64(pe) => pe.rva_to_file_offset(rva),
            Self::T32(pe) => pe.rva_to_file_offset(rva)
        }
    }

    fn is_x64(&self) -> bool {
        matches!(self, PeFile::T64(_))
    }
}

pub(crate) trait DataDirExt {
    fn set(&mut self, addr: u32, size: u32);
}

impl DataDirExt for IMAGE_DATA_DIRECTORY {
    fn set(&mut self, addr: u32, size: u32) {
        self.VirtualAddress = addr;
        self.Size = size;
    }
}

pub(crate) trait ReadBytesExt: io::Read {
    #[inline]
    fn read_u8(&mut self) -> io::Result<u8> {
        let mut buf = [0; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

impl<T: io::Read> ReadBytesExt for T {}
