use deku::{DekuContainerRead, DekuError, DekuRead};
use log::debug;
use pelite::{
    PeFile,
    image::{
        IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXCEPTION,
        IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DOS_HEADER,
        IMAGE_FILE_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64,
        IMAGE_SECTION_HEADER, IMAGE_TLS_DIRECTORY32, IMAGE_TLS_DIRECTORY64,
    },
    pe::Rva,
};
use thiserror::Error;
use std::{cmp::{max, min}, result};

use crate::extensions::{DataDirExt, PeFileExt};

const ENIGMA1_HEADER_SIZE: usize = 16;
const TLS_DATA_64: usize = 32;
const TLS_DATA_32: usize = 16;
const UNK_1_SIZE: usize = 8;
const UNK_2_SIZE: usize = 8;
const UNK_3_SIZE: usize = 4;

#[derive(DekuRead)]
#[deku(endian = "little")]
pub struct Enigma1Header {
    #[deku(skip)]
    tls_data: [u8; 12],
    import_address: u32,
    import_size: u32,
    reloc_address: u32,
    reloc_size: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum PeVariant {
    V10_70,
    V9_70,
    V7_80,
}

impl PeVariant {
    fn get_header_start_offset_64(&self) -> usize {
        match self {
            Self::V10_70 => TLS_DATA_64 + 7 * 8 + UNK_1_SIZE + 3 * 8,
            Self::V9_70 => TLS_DATA_64 + 7 * 8 + 4 + UNK_1_SIZE + 8,
            Self::V7_80 => TLS_DATA_64 + 7 * 8 + UNK_1_SIZE + 8,
        }
    }

    fn get_header_start_offset_32(&self) -> usize {
        match self {
            Self::V10_70 => TLS_DATA_32 + 6 * 8 + UNK_1_SIZE + UNK_2_SIZE + UNK_3_SIZE,
            Self::V9_70 => TLS_DATA_32 + 6 * 8 + UNK_1_SIZE + UNK_2_SIZE,
            Self::V7_80 => TLS_DATA_32 + 6 * 8 + UNK_1_SIZE + UNK_3_SIZE,
        }
    }

    pub fn header_start_offset(&self, is_x64: bool) -> usize {
        if is_x64 {
            self.get_header_start_offset_64()
        } else {
            self.get_header_start_offset_32()
        }
    }
}

pub struct EmptyHeader;

#[derive(Debug, Error)]
pub enum RestorePeError {
    #[error("No .enigma1 section found")]
    Enigma1NotFound,
    #[error("Serialize error")]
    Serialize(#[from] DekuError),
    #[error("PE header parsing error")]
    Pe(#[from] pelite::Error)
}

pub struct RestorePeContext<'r, H> {
    slice: &'r mut [u8],
    is_x64: bool,
    header: H,
}

impl<'r> RestorePeContext<'r, EmptyHeader> {
    pub fn new(input: &'r mut [u8]) -> Self {
        Self {
            slice: input,
            is_x64: false,
            header: EmptyHeader,
        }
    }
}

pub type Result<T> = result::Result<T, RestorePeError>;

impl<'r> RestorePeContext<'r, EmptyHeader> {
    fn parse_enigma_header(&self, pe: &PeFile, variant: PeVariant) -> Result<Enigma1Header> {
        let enigma1 = pe
            .section_headers()
            .by_name(".enigma1")
            .ok_or(RestorePeError::Enigma1NotFound)?;
        let raw_data = &self.slice[enigma1.PointerToRawData as usize..];
        let header_start = variant.header_start_offset(pe.is_x64());
        let (_, mut enigma_header) = Enigma1Header::from_bytes((
            &raw_data[header_start..header_start + ENIGMA1_HEADER_SIZE],
            0,
        ))?;

        enigma_header.tls_data = raw_data[..12].try_into().unwrap();

        Ok(enigma_header)
    }

    fn parse_enigma_header_auto(&self, pe: &PeFile) -> Option<Enigma1Header> {
        let candidates = [PeVariant::V10_70, PeVariant::V9_70, PeVariant::V7_80];

        for variant in candidates {
            let Ok(enigma_header) = self.parse_enigma_header(pe, variant) else {
                debug!("Skip variant (header parse): {:?}", variant);
                continue;
            };
            let Ok(import_descriptor) =
                pe.derva::<IMAGE_IMPORT_DESCRIPTOR>(enigma_header.import_address)
            else {
                debug!("Skip variant (import desc): {:?}", variant);
                continue;
            };
            let Ok(name) = pe.derva_c_str(import_descriptor.Name) else {
                debug!("Skip variant (import name): {:?}", variant);
                continue;
            };

            let len = name.len();
            if len <= 4 {
                debug!("Skip variant (name len): {:?}", variant);
                continue;
            }

            let suffix = &name[len - 4..];
            if suffix.eq_ignore_ascii_case(b".dll") {
                debug!("Found valid variant: {:?}", variant);
                return Some(enigma_header);
            }
        }

        None
    }

    fn get_pe(&self) -> Result<(PeFile<'_>, bool)> {
        let pe = PeFile::from_bytes(self.slice)?;
        let is_x64 = pe.is_x64();
        debug!("Executable arch: {}", if is_x64 { "x64" } else { "x86" });

        Ok((pe, is_x64))
    }

    pub fn with_variant(self, variant: PeVariant) -> Result<RestorePeContext<'r, Enigma1Header>> {
        let (pe, is_x64) = self.get_pe()?;
        let header = self.parse_enigma_header(&pe, variant)?;

        Ok(RestorePeContext {
            slice: self.slice,
            is_x64,
            header,
        })
    }

    pub fn with_variant_auto(self) -> Option<RestorePeContext<'r, Enigma1Header>> {
        let (pe, is_x64) = self.get_pe().ok()?;
        let header = self.parse_enigma_header_auto(&pe)?;

        Some(RestorePeContext {
            slice: self.slice,
            is_x64,
            header,
        })
    }
}

#[derive(Debug, Default)]
struct ExceptionPatch {
    exception_start: usize,
    new_exception_size: usize,
    exception_dest_rva: Option<Rva>,
    exception_dest: Option<usize>,
    section_index: Option<usize>,
}

enum NtHeaders<'a> {
    T32(&'a mut IMAGE_NT_HEADERS32),
    T64(&'a mut IMAGE_NT_HEADERS64),
}

impl<'a> NtHeaders<'a> {
    fn file_header_mut(&mut self) -> &mut IMAGE_FILE_HEADER {
        match self {
            Self::T64(headers) => &mut headers.FileHeader,
            Self::T32(headers) => &mut headers.FileHeader,
        }
    }

    fn update_checksum(&mut self, checksum: u32) {
        match self {
            Self::T64(headers) => headers.OptionalHeader.CheckSum = checksum,
            Self::T32(headers) => headers.OptionalHeader.CheckSum = checksum,
        }
    }

    fn update_image_size(&mut self, size: u32) {
        match self {
            Self::T64(headers) => headers.OptionalHeader.SizeOfImage = size,
            Self::T32(headers) => headers.OptionalHeader.SizeOfImage = size
        }
    }
}

type MutableHeaders<'a> = (
    &'a mut IMAGE_DOS_HEADER,
    NtHeaders<'a>,
    &'a mut [IMAGE_DATA_DIRECTORY],
    &'a mut [IMAGE_SECTION_HEADER],
);

fn get_headers_mut(input: &mut [u8], is_x64: bool) -> MutableHeaders<'_> {
    // SAFETY:
    // The byte slice is checked when parsing enigma header
    if is_x64 {
        let (dos_headers, nt_headers, data_directories, section_headers) =
            unsafe { pelite::pe64::headers_mut(input) };
        return (
            dos_headers,
            NtHeaders::T64(nt_headers),
            data_directories,
            section_headers,
        );
    }

    let (dos_headers, nt_headers, data_directories, section_headers) =
        unsafe { pelite::pe32::headers_mut(input) };
    (
        dos_headers,
        NtHeaders::T32(nt_headers),
        data_directories,
        section_headers,
    )
}

#[derive(Debug, Clone, Copy)]
struct EnigmaMask(u128);

impl EnigmaMask {
    fn is_enigma_section(&self, section_index: usize) -> bool {
        (self.0 >> section_index) & 1 == 1
    }
}

struct PeAnalysis {
    exception_patch: Option<ExceptionPatch>,
    tls_rva: Option<Rva>,
    enigma_mask: EnigmaMask,
    final_physical_end: usize,
    max_enigma_end: usize
}

impl<'r> RestorePeContext<'r, Enigma1Header> {
    fn find_zero_hole(&self, pe: &PeFile, enigma_mask: EnigmaMask, size: usize) -> Option<(Rva, usize)> {
        for (index, header) in pe.section_headers().iter().enumerate() {
            if enigma_mask.is_enigma_section(index) {
                continue;
            }

            let raw_offset = header.PointerToRawData as usize;
            let raw_size = header.SizeOfRawData as usize;
            let raw_data = &self.slice[raw_offset..raw_offset + raw_size];

            let Some(pos) = raw_data
                .windows(size)
                .position(|w| w.iter().all(|b| *b == 0))
            else {
                continue;
            };

            debug!("Found section to place new exception data: {:?}", header.Name);
            return Some((header.VirtualAddress + pos as u32, index));
        }

        None
    }

    fn analyze_exception_table(
        &self,
        pe: &PeFile,
        enigma_mask: EnigmaMask,
    ) -> Result<Option<ExceptionPatch>> {
        let stride: usize = if self.is_x64 { 12 } else { 20 };
        let exception_dir = &pe.data_directory()[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

        if exception_dir.VirtualAddress == 0 || exception_dir.Size < stride as u32 {
            debug!("No valid exception directory found");
            return Ok(None);
        }

        let exception_start = pe.rva_to_file_offset(exception_dir.VirtualAddress)?;
        let exception_data =
            &self.slice[exception_start..exception_start + exception_dir.Size as usize];
        debug!("Exception start: 0x{:x}", exception_start);

        let section_headers = pe.section_headers();
        let valid_count = exception_data
            .chunks_exact(stride)
            .enumerate()
            .find_map(|(index, chunk)| {
                let begin_addr = u32::from_le_bytes(chunk[0..4].try_into().unwrap());
                let header_index = section_headers.iter().position(|h| {
                    h.VirtualAddress <= begin_addr
                        && begin_addr < h.VirtualAddress.wrapping_add(h.VirtualSize)
                })?;

                if enigma_mask.is_enigma_section(header_index) {
                    Some(index)
                } else {
                    None
                }
            })
            .unwrap_or(exception_dir.Size as usize / stride);
        debug!("Valid exception count: {}", valid_count);

        let new_exception_size = valid_count * stride;

        if new_exception_size == 0 {
            debug!("No exception to preserve");
            return Ok(Some(ExceptionPatch {
                exception_start,
                new_exception_size,
                ..Default::default()
            }));
        }

        let (exception_dest_rva, section_index) = self
            .find_zero_hole(pe, enigma_mask, new_exception_size)
            .unzip();
        let exception_dest = exception_dest_rva.map(|r| pe.rva_to_file_offset(r).unwrap());

        Ok(Some(ExceptionPatch {
            exception_start,
            new_exception_size,
            exception_dest_rva,
            exception_dest,
            section_index,
        }))
    }

    fn analyze_tls(&self, pe: &PeFile, enigma_mask: EnigmaMask) -> Option<Rva> {
        let tls_pattern = &self.header.tls_data;

        for (index, section) in pe.section_headers().iter().enumerate() {
            if enigma_mask.is_enigma_section(index) {
                continue;
            }

            let raw_offset = section.PointerToRawData as usize;
            let raw_size = section.SizeOfRawData as usize;
            let raw_data = &self.slice[raw_offset..raw_offset + raw_size];

            let Some(pos) = raw_data.windows(12).position(|w| w == tls_pattern) else {
                continue;
            };
            debug!("Found tls data in section: {:?}", section.Name);
            return Some(section.VirtualAddress + pos as u32);
        }

        None
    }

    fn analyze_pe(&self) -> Result<PeAnalysis> {
        let pe = PeFile::from_bytes(self.slice).unwrap();

        let mut enigma_mask: u128 = 0;
        let mut final_physical_end = self.slice.len();
        let mut max_enigma_end = 0;

        for (index, header) in pe.section_headers().iter().enumerate() {
            if !header.Name.starts_with(b".enigma") {
                continue;
            }

            enigma_mask |= 1 << index;
            let start = header.PointerToRawData as usize;
            let end = start + header.SizeOfRawData as usize;

            final_physical_end = min(final_physical_end, start);
            max_enigma_end = max(max_enigma_end, end)
        }

        let enigma_mask = EnigmaMask(enigma_mask);
        let exception_patch = self.analyze_exception_table(&pe, enigma_mask)?;
        let tls_rva = self.analyze_tls(&pe, enigma_mask);

        Ok(PeAnalysis {
            exception_patch,
            tls_rva,
            enigma_mask,
            final_physical_end,
            max_enigma_end
        })
    }

    pub fn restore_pe(self) -> Result<usize> {
        let PeAnalysis { exception_patch, tls_rva, enigma_mask, final_physical_end, max_enigma_end } =
            self.analyze_pe()?;
        debug!("Exception patch: {:?}", exception_patch);
        debug!("TLS rva: {:?}", tls_rva);
        debug!("Enigma mask: {:?}, physical end: 0x{:x}, max enigma end: 0x{:x}", enigma_mask, final_physical_end, max_enigma_end);

        let overlay_size = self.slice.len() - max_enigma_end;
        debug!("Overlay size: {}", overlay_size);

        if overlay_size > 0 {
            self.slice.copy_within(max_enigma_end.., final_physical_end);
        }

        if let Some(ExceptionPatch {
            exception_dest,
            exception_start,
            new_exception_size,
            ..
        }) = exception_patch
            && let Some(dest) = exception_dest
        {
            self.slice
                .copy_within(exception_start..exception_start + new_exception_size, dest);
        }

        let Enigma1Header {
            import_address,
            import_size,
            reloc_address,
            reloc_size,
            ..
        } = self.header;

        debug!("Import addr: 0x{:x}, size: {}", import_address, import_size);
        debug!("Reloc addr: 0x{:x}, size: {}", reloc_address, reloc_size);

        let (_, mut nt_headers, data_directories, section_headers) =
            get_headers_mut(self.slice, self.is_x64);

        data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT].set(import_address, import_size);
        data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].set(reloc_address, reloc_size);

        if let Some(ExceptionPatch {
            exception_dest_rva,
            new_exception_size,
            section_index,
            ..
        }) = exception_patch
            && let Some(rva) = exception_dest_rva
        {
            data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].set(rva, new_exception_size as u32);
            let header = &mut section_headers[section_index.unwrap()];
            let size = rva - header.VirtualAddress + new_exception_size as u32;
            header.SizeOfRawData = size;
        } else {
            data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].set(0, 0);
        }

        if let Some(rva) = tls_rva {
            let tls_size = if self.is_x64 {
                std::mem::size_of::<IMAGE_TLS_DIRECTORY64>() as u32
            } else {
                std::mem::size_of::<IMAGE_TLS_DIRECTORY32>() as u32
            };

            data_directories[IMAGE_DIRECTORY_ENTRY_TLS].set(rva, tls_size);
        } else {
            data_directories[IMAGE_DIRECTORY_ENTRY_TLS].set(0, 0);
        }

        let mut removed = 0;
        let mut last_section_index = 0;
        for (index, header) in section_headers.iter_mut().enumerate() {
            if !enigma_mask.is_enigma_section(index) {
                last_section_index = index;
                continue;
            }

            header.VirtualSize = 0;
            header.SizeOfRawData = 0;
            header.PointerToRawData = 0;
            header.VirtualAddress = 0;
            removed += 1;
        }

        debug!("Removed sections: {}, last section index: {}", removed, last_section_index);

        let last_section_header = &section_headers[last_section_index];
        nt_headers.file_header_mut().NumberOfSections -= removed;
        nt_headers.update_checksum(0);
        nt_headers.update_image_size(last_section_header.VirtualAddress + last_section_header.VirtualSize);

        Ok(final_physical_end + overlay_size)
    }
}
