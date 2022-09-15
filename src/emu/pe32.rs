/*
 * PE32 Structures and loader
*/

use std::str;
use crate::emu;
use std::fs::File;
use std::io::Read;

macro_rules! read_u8 {
    ($raw:expr, $off:expr) => {
        $raw[$off]
    }
}

macro_rules! read_u16_le {
    ($raw:expr, $off:expr) => {
        (($raw[$off+1] as u16) << 8) | ($raw[$off] as u16)
    }
}

macro_rules! read_u32_le {
    ($raw:expr, $off:expr) => {
          (($raw[$off+3] as u32) << 24) | (($raw[$off+2] as u32) << 16) | (($raw[$off+1] as u32) << 8) | ($raw[$off] as u32)
    }
}

macro_rules! write_u32_le {
    ($raw:expr, $off:expr, $val:expr) => {
      $raw[$off+0]  = ($val & 0x000000ff) as u8;
      $raw[$off+1] = (($val & 0x0000ff00) >> 8) as u8;
      $raw[$off+2] = (($val & 0x00ff0000) >> 16) as u8;
      $raw[$off+3] = (($val & 0xff000000) >> 24) as u8;
    }   
} 


pub const IMAGE_DOS_SIGNATURE:u16 = 0x5A4D;
pub const IMAGE_OS2_SIGNATURE:u16 = 0x544E;
pub const IMAGE_OS2_SIGNATURE_LE:u16 = 0x45AC;
pub const IMAGE_NT_SIGNATURE:u32 = 0x00004550;
pub const IMAGE_SIZEOF_FILE_HEADER:u8 = 20;
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES:usize = 16;
pub const SECTION_HEADER_SZ:usize = 40;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT:usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT:usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE:usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION:usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY:usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC:usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG:usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_COPYRIGHT:usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR:usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS:usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT:usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_LOAD:usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_DOTNET_HDR:usize = 14;


pub const IMAGE_SIZEOF_SHORT_NAME:usize = 8;
pub const IMAGE_DEBUG_TYPE_UNKNOWN:u8 = 0;
pub const IMAGE_DEBUG_TYPE_COFF:u8 = 1;
pub const IMAGE_DEBUG_TYPE_CODEVIEW:u8 = 2;
pub const IMAGE_DEBUG_TYPE_FPO:u8 = 3;
pub const IMAGE_DEBUG_TYPE_MISC:u8 = 4;


#[derive(Debug)]
pub struct ImageDosHeader {
    pub e_magic: u16,		// Magic number
	pub e_cblp: u16, 		// Bytes on last page of file
	pub e_cp: u16,		    // Pages in file
 	pub e_crlc: u16, 		// Relocations
 	pub e_cparhdr: u16,	    // Size of header in paragraphs
 	pub e_minalloc: u16,    // Minimum extra paragraphs needed
 	pub e_maxalloc: u16,    // Maximum extra paragraphs needed
  	pub e_ss: u16,		    // Initial (relative) SS value
  	pub e_sp: u16,		    // Initial SP value
 	pub e_csum: u16,	    // Checksum
 	pub e_ip: u16,		    // Initial IP value
 	pub e_cs: u16,		    // Initial (relative) CS value
	pub e_lfarlc: u16,	    // File address of relocation table
	pub e_ovno: u16,	    // Overlay number
	pub e_res: [u16;4],	    // Reserved words
	pub e_oemid: u16,		// OEM identifier (for e_oeminfo)
	pub e_oeminfo: u16,	    // OEM information; e_oemid specific
	pub e_res2:	[u16;10],	// Reserved words
	pub e_lfanew: u32,	    // File address of new exe header
}

impl ImageDosHeader {

    pub fn size() -> usize {
        return 64;
    }

    pub fn load(raw: &Vec<u8>, off: usize) -> ImageDosHeader {
        ImageDosHeader {
            e_magic: read_u16_le!(raw, off),
            e_cblp: read_u16_le!(raw, off+2),
            e_cp: read_u16_le!(raw, off+4),
            e_crlc: read_u16_le!(raw, off+6),
            e_cparhdr: read_u16_le!(raw, off+8),
            e_minalloc: read_u16_le!(raw, off+10),
            e_maxalloc: read_u16_le!(raw, off+12),
            e_ss: read_u16_le!(raw, off+14),
            e_sp: read_u16_le!(raw, off+16),
            e_csum: read_u16_le!(raw, off+18),
            e_ip: read_u16_le!(raw, off+20),  
            e_cs: read_u16_le!(raw, off+22),
            e_lfarlc: read_u16_le!(raw, off+24),
            e_ovno: read_u16_le!(raw, off+26),
            e_res: [read_u16_le!(raw, off+28), read_u16_le!(raw, off+30), read_u16_le!(raw, off+32), read_u16_le!(raw, off+34)], 
            e_oemid: read_u16_le!(raw, off+36),
            e_oeminfo: read_u16_le!(raw, off+38),
            e_res2: [0,0,0,0,0,0,0,0,0,0],
            e_lfanew: read_u32_le!(raw, off+60),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageNtHeaders {
    pub signature: u32,
}

impl ImageNtHeaders {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageNtHeaders {
        ImageNtHeaders {
            signature: read_u32_le!(raw, off),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

impl ImageFileHeader {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageFileHeader {
        ImageFileHeader {
            machine: read_u16_le!(raw, off),
            number_of_sections: read_u16_le!(raw, off+2),
            time_date_stamp: read_u32_le!(raw, off+4),
            pointer_to_symbol_table: read_u32_le!(raw, off+8),
            number_of_symbols: read_u32_le!(raw, off+12),
            size_of_optional_header: read_u16_le!(raw, off+16),
            characteristics: read_u16_le!(raw, off+18),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl ImageDataDirectory {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageDataDirectory {
        ImageDataDirectory {
            virtual_address: read_u32_le!(raw, off),
            size: read_u32_le!(raw, off+4),
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageOptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub reserved1: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: Vec<ImageDataDirectory> //  IMAGE_NUMBEROF_DIRECTORY_ENTRIES
}

impl ImageOptionalHeader {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageOptionalHeader {
        let mut dd: Vec<ImageDataDirectory> = Vec::new();
        let mut pos = 96;
        for i in 0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
              dd.push( ImageDataDirectory::load(raw, off+pos) );
              pos += 8;
        }

        ImageOptionalHeader {
            magic: read_u16_le!(raw, off),
            major_linker_version: read_u8!(raw, off+2),
            minor_linker_version: read_u8!(raw, off+3),
            size_of_code: read_u32_le!(raw, off+4),
            size_of_initialized_data: read_u32_le!(raw, off+8),
            size_of_uninitialized_data: read_u32_le!(raw, off+12),
            address_of_entry_point: read_u32_le!(raw, off+16),
            base_of_code: read_u32_le!(raw, off+20),
            base_of_data: read_u32_le!(raw, off+24),
            image_base: read_u32_le!(raw, off+28),
            section_alignment: read_u32_le!(raw, off+32),
            file_alignment: read_u32_le!(raw, off+36),
            major_operating_system_version: read_u16_le!(raw, off+40),
            minor_operating_system_version: read_u16_le!(raw, off+42),
            major_image_version: read_u16_le!(raw, off+44),
            minor_image_version: read_u16_le!(raw, off+46),
            major_subsystem_version: read_u16_le!(raw, off+48),
            minor_subsystem_version: read_u16_le!(raw, off+50),
            reserved1: read_u32_le!(raw, off+52),
            size_of_image: read_u32_le!(raw, off+56),
            size_of_headers: read_u32_le!(raw, off+60),
            checksum: read_u32_le!(raw, off+64),
            subsystem: read_u16_le!(raw, off+68),
            dll_characteristics: read_u16_le!(raw, off+70),
            size_of_stack_reserve: read_u32_le!(raw, off+72),
            size_of_stack_commit: read_u32_le!(raw, off+76),
            size_of_heap_reserve: read_u32_le!(raw, off+80),
            size_of_heap_commit: read_u32_le!(raw, off+84),
            loader_flags: read_u32_le!(raw, off+88),
            number_of_rva_and_sizes: read_u32_le!(raw, off+92),
            data_directory: dd,
        }
    }

    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageSectionHeader {
    pub name: [u8;IMAGE_SIZEOF_SHORT_NAME],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

impl ImageSectionHeader {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageSectionHeader {
        let mut name:[u8;IMAGE_SIZEOF_SHORT_NAME] = [0;IMAGE_SIZEOF_SHORT_NAME];
        for i in off..off+IMAGE_SIZEOF_SHORT_NAME {
            name[i-off] = raw[i];
        }

        let off2 = off + IMAGE_SIZEOF_SHORT_NAME;

        ImageSectionHeader {
            name: name,
            virtual_size: read_u32_le!(raw, off2),
            virtual_address: read_u32_le!(raw, off2+4),
            size_of_raw_data: read_u32_le!(raw, off2+8),
            pointer_to_raw_data: read_u32_le!(raw, off2+12),
            pointer_to_relocations: read_u32_le!(raw, off2+16),
            pointer_to_linenumbers: read_u32_le!(raw, off2+20),
            number_of_relocations: read_u16_le!(raw, off2+24),
            number_of_linenumbers: read_u16_le!(raw, off2+26),
            characteristics: read_u32_le!(raw, off2+28),
        }
    }

    pub fn get_name(&self) -> String {

        let s = match str::from_utf8(&self.name) {
            Ok(v) => v,
            Err(_) => "err",
        };

        s.to_string().replace("\x00","")
    }
    
    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageResourceDirectoryEntry {
    pub name: u32,
    pub offset_to_data: u32,
}

impl ImageResourceDirectoryEntry {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageResourceDirectoryEntry {
        ImageResourceDirectoryEntry {
            name: read_u32_le!(raw, off),
            offset_to_data: read_u32_le!(raw, off+4),
        }
    }
    
    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageResourceDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub number_of_named_entries: u16,
    pub number_of_id_entries: u16,
}

impl ImageResourceDirectory {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageResourceDirectory {
        ImageResourceDirectory {
            characteristics: read_u32_le!(raw, off),
            time_date_stamp: read_u32_le!(raw, off+4),
            major_version: read_u16_le!(raw, off+8),
            minor_version: read_u16_le!(raw, off+10),
            number_of_named_entries: read_u16_le!(raw, off+12),
            number_of_id_entries: read_u16_le!(raw, off+14),
        }
    }
    
    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageResourceDataEntry {
    pub offset_to_data: u32,
    pub size: u32,
    pub code_page: u32,
    pub reserved: u32,
}

impl ImageResourceDataEntry {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageResourceDataEntry {
        ImageResourceDataEntry {
            offset_to_data: read_u32_le!(raw, off),
            size: read_u32_le!(raw, off+4),
            code_page: read_u32_le!(raw, off+8),
            reserved: read_u32_le!(raw, off+12),
        }
    }
    
    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageResourceDirStringU {
    pub length: u16,
    pub name_string: u8
}

impl ImageResourceDirStringU {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageResourceDirStringU {
        ImageResourceDirStringU {
            length: read_u16_le!(raw, off),
            name_string: read_u8!(raw, off+2),
        }
    }
    
    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

impl ImageExportDirectory {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageExportDirectory {
        ImageExportDirectory {
            characteristics: read_u32_le!(raw, off),
            time_date_stamp: read_u32_le!(raw, off+4),
            major_version: read_u16_le!(raw, off+8),
            minor_version: read_u16_le!(raw, off+10),
            name: read_u32_le!(raw, off+12),
            base: read_u32_le!(raw, off+16),
            number_of_functions: read_u32_le!(raw, off+20),
            number_of_names: read_u32_le!(raw, off+24),
            address_of_functions: read_u32_le!(raw, off+28),
            address_of_names: read_u32_le!(raw, off+22),
            address_of_name_ordinals: read_u32_le!(raw, off+26),
        }
    }
    
    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

//
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table
//

#[derive(Debug)]
pub struct ImageImportDirectory {
    pub address_of_import_lookup_table: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub address_of_names: u32,
    pub address_of_import_table: u32,
}

impl ImageImportDirectory {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageImportDirectory {
        ImageImportDirectory {
            address_of_import_lookup_table: read_u32_le!(raw, off),
            time_date_stamp: read_u32_le!(raw, off+4),
            forwarder_chain: read_u32_le!(raw, off+8),
            address_of_names: read_u32_le!(raw, off+12),
            address_of_import_table: read_u32_le!(raw, off+16),
        }
    }
    
    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageImportDescriptor {  // one per imported dll
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_ptr: u32,
    pub first_thunk: u32,
    pub name: String,
}

impl ImageImportDescriptor {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageImportDescriptor {
        ImageImportDescriptor {
            original_first_thunk: read_u32_le!(raw, off),
            time_date_stamp: read_u32_le!(raw, off+4),
            forwarder_chain: read_u32_le!(raw, off+8),
            name_ptr: read_u32_le!(raw, off+12),
            first_thunk: read_u32_le!(raw, off+16),
            name: String::new(),
        }
    }

    pub fn size() -> usize {
        20
    }
}

// https://docs.microsof[t.com/en-us/windows/win32/debug/pe-format#import-lookup-table

#[derive(Debug)]
pub struct ImportLookupTable {
    pub bits: Vec<u32>,
}

#[derive(Debug)]
pub struct HintNameItem {
    pub is_ordinal: bool,
    pub func_name_addr: u32,
}

impl HintNameItem {
    pub fn load(raw: &Vec<u8>, off: usize) -> HintNameItem {

        let func_name_addr = read_u32_le!(raw, off); // & 0b01111111_11111111_11111111_11111111;

        HintNameItem {
            is_ordinal: raw[off] & 0b10000000 == 0b10000000,
            func_name_addr: func_name_addr
        }
    }

    pub fn size() -> usize {
        4
    }
}   


#[derive(Debug)]
pub struct ImportAddressTable {

}

impl ImportLookupTable {
    pub fn load(raw: &Vec<u8>, off: usize, nitems: usize) -> ImportLookupTable {
        let bits: Vec<u32> = Vec::new();
        /*
        for i in 0..nitems {
            raw + off + i*32
        }*/

        ImportLookupTable {
            bits: bits
        }
    }
}


#[derive(Debug)]
pub struct TagImportDirectory {
    pub dw_rva_function_name_list: u32,
    pub dw_useless1: u32,
    pub dw_useless2: u32,
    pub dw_rva_module_name: u32,
    pub dw_rva_function_address_list: u32,
}

impl TagImportDirectory {
    pub fn load(raw: &Vec<u8>, off: usize) -> TagImportDirectory {
        TagImportDirectory {
            dw_rva_function_name_list: read_u32_le!(raw, off),
            dw_useless1: read_u32_le!(raw, off+4),
            dw_useless2: read_u32_le!(raw, off+8),
            dw_rva_module_name: read_u32_le!(raw, off+12),
            dw_rva_function_address_list: read_u32_le!(raw, off+16),
        }
    }
    
    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageDebugDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16, 
    pub minor_version: u16,
    pub types: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

impl ImageDebugDirectory {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageDebugDirectory {
        ImageDebugDirectory {
            characteristics: read_u32_le!(raw, off),
            time_date_stamp: read_u32_le!(raw, off+4),
            major_version: read_u16_le!(raw, off+8),
            minor_version: read_u16_le!(raw, off+10),
            types: read_u32_le!(raw, off+12),
            size_of_data: read_u32_le!(raw, off+16),
            address_of_raw_data: read_u32_le!(raw, off+20),
            pointer_to_raw_data: read_u32_le!(raw, off+24),
        }
    }
    
    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}


#[derive(Debug)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

impl ImageBaseRelocation {
    pub fn load(raw: &Vec<u8>, off: usize) -> ImageBaseRelocation {
        ImageBaseRelocation {
            virtual_address: read_u32_le!(raw, off),
            size_of_block: read_u32_le!(raw, off+4),
        }
    }
    
    pub fn print(&self) {
        println!("{:#x?}", self);
    }
}

pub struct Section {
    pub name: String,
    pub off: usize,
    pub sz: usize,
}

impl Section {
    pub fn new(off: usize, sz: usize) -> Section {
        Section {
            name: String::new(),
            off: off,
            sz: sz,
        }
    }
}


pub struct PE32 {
    raw: Vec<u8>,
    pub dos: ImageDosHeader,
    pub nt: ImageNtHeaders,
    pub fh: ImageFileHeader,
    pub opt: ImageOptionalHeader,
    sect_hdr: Vec<ImageSectionHeader>,
    //import_dir: ImageImportDirectory,
    pub image_import_descriptor: Vec<ImageImportDescriptor>,
    //export_dir: Option<ImageExportDirectory>,
}

impl PE32 {

    pub fn is_pe32(filename: &str) -> bool {
        let mut fd = File::open(filename).expect("file not found");
        let mut raw = vec![0u8; ImageDosHeader::size()];
        fd.read_exact(&mut raw).expect("couldnt read the file");
        let dos = ImageDosHeader::load(&raw, 0);

        if dos.e_magic != 0x5a4d {
            return false;
        }

        if dos.e_lfanew >= fd.metadata().unwrap().len() as u32 {
            return false;
        }

        return true;
    }

    pub fn read_string(raw:&[u8], off: usize) -> String { 
        let mut last = 0;

        for i in off..off+200 {
            if raw[i] == 0 {
                last = i;
                break;
            }
        }

        if last == 0 {
            panic!("cannot found end of string");
        }

        let s = str::from_utf8(raw.get(off..last).unwrap()).expect("utf8 error");
        s.to_string()
    }

    pub fn load(filename: &str) -> PE32 {   
        let mut fd = File::open(filename).expect("pe32 binary not found");
        let mut raw: Vec<u8> = Vec::new();
        fd.read_to_end(&mut raw).expect("couldnt read the pe32 binary");

        let dos = ImageDosHeader::load(&raw, 0);
        let nt = ImageNtHeaders::load(&raw, dos.e_lfanew as usize);
        let fh = ImageFileHeader::load(&raw, dos.e_lfanew as usize +4); 
        let opt = ImageOptionalHeader::load(&raw, dos.e_lfanew as usize +24);
        let mut sect: Vec<ImageSectionHeader> = Vec::new();

        let mut off = dos.e_lfanew as usize +248; 
        for i in 0..fh.number_of_sections {
            let s = ImageSectionHeader::load(&raw, off);
            sect.push(s);
            off += SECTION_HEADER_SZ;
        }

        let importd: ImageImportDirectory;
        let exportd: ImageExportDirectory;
        let import_va = opt.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address;
        let export_va = opt.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].virtual_address;
        let mut import_off: usize;

        let mut image_import_descriptor: Vec<ImageImportDescriptor> = Vec::new();

        if import_va > 0 {
            import_off = PE32::vaddr_to_off(&sect, import_va) as usize;
            if import_off > 0 {

                loop {
                    let mut iid = ImageImportDescriptor::load(&raw, import_off);
                    if iid.name_ptr == 0 {
                        break;
                    }
                    let off = PE32::vaddr_to_off(&sect, iid.name_ptr) as usize;
                    if off > raw.len() {
                        panic!("the name of pe32 iid is out of buffer");
                    }
                    

                    let libname = PE32::read_string(&raw, off);
                    iid.name = libname.to_string();

                    image_import_descriptor.push(iid);
                    import_off += ImageImportDescriptor::size();
                }

            } else {
                //println!("no import directory at va 0x{:x}.", import_va);
            }
        } else {
            //println!("no import directory at va 0x{:x}", import_va);
        }

        PE32 {
            raw: raw,
            dos: dos,
            fh: fh,
            nt: nt,
            opt: opt,
            sect_hdr: sect,
            image_import_descriptor: image_import_descriptor
            //import_dir: importd,
            //export_dir: exportd,
        }
    }

    pub fn get_raw(&self) -> &[u8] {
           return  &self.raw[0..self.raw.len()];
    }

    pub fn get_headers(&self) -> &[u8] {
        return  &self.raw[0..self.opt.size_of_headers as usize];
    }

    pub fn clear(&mut self) {
        self.raw.clear();
        self.sect_hdr.clear();
    }

    pub fn vaddr_to_off(sections: &Vec<ImageSectionHeader>, vaddr: u32) -> u32 {
        for sect in sections {
            if vaddr >= sect.virtual_address &&
                vaddr < sect.virtual_address + sect.virtual_size {
                    return vaddr - sect.virtual_address + sect.pointer_to_raw_data; 
            }
        }
        
        return 0;
    }

    pub fn num_of_sections(&self) -> usize {
        return self.sect_hdr.len();
    }

    pub fn get_section_ptr_by_name(&self, name: &str) -> &[u8] {
        for i in 0..self.sect_hdr.len() {
            if self.sect_hdr[i].get_name() == name {
                let off = self.sect_hdr[i].pointer_to_raw_data as usize;
                let sz = self.sect_hdr[i].virtual_size as usize;
                let section_ptr = &self.raw[off..off+sz];
                return section_ptr;
            }
        }
        panic!("section name {} not found", name);
        //return &[];
    }

    pub fn get_section(&self, id: usize) -> &ImageSectionHeader {
        return &self.sect_hdr[id];
    }

    pub fn get_section_ptr(&self, id: usize) -> &[u8] {
        let off = self.sect_hdr[id].pointer_to_raw_data as usize;
        let mut sz = self.sect_hdr[id].size_of_raw_data as usize; //TODO: coger sz en disk no en va
        if off+sz >= self.raw.len() {
            //println!("/!\\ warning: raw sz:{} off:{} sz:{}  off+sz:{}", self.raw.len(), off, sz, off+sz);
            sz = self.raw.len() - off - 1;
        }
        let section_ptr = &self.raw[off..off+sz];
        return section_ptr;
    }

    pub fn get_section_vaddr(&self, id: usize) -> u32 {
        return self.sect_hdr[id].virtual_address;
    }

    pub fn iat_binding(&mut self, emu:&mut emu::Emu) {
        let dbg = false;
        // https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2#Binding

        println!("IAT binding started ...");
        for i in 0..self.image_import_descriptor.len() {
            let iim = &self.image_import_descriptor[i];
            if dbg { println!("import: {}", iim.name); }

            if emu::winapi32::kernel32::load_library(emu, &iim.name) == 0 {
                panic!("cannot found the library {} on maps32/", &iim.name);
            }
            
            // Walking function names.
            let mut off_name = PE32::vaddr_to_off(&self.sect_hdr, iim.original_first_thunk) as usize;
            let mut off_addr = PE32::vaddr_to_off(&self.sect_hdr, iim.first_thunk) as usize;

            loop {
                let hint = HintNameItem::load(&self.raw, off_name);
                if hint.func_name_addr == 0 {
                    break;
                }
                let addr = read_u32_le!(self.raw, off_addr); // & 0b01111111_11111111_11111111_11111111;
                let off2 = PE32::vaddr_to_off(&self.sect_hdr, hint.func_name_addr) as usize;
                if off2 == 0 { //|| addr < 0x100 {
                    off_name += HintNameItem::size();
                    off_addr += 4;
                    continue;
                }
                let func_name = PE32::read_string(&self.raw, off2+2);
                if dbg { println!("0x{:x} {}!{}", addr, iim.name, func_name); }

                let real_addr = emu::winapi32::kernel32::resolve_api_name(emu, &func_name);
                if dbg { println!("real addr: 0x{:x}", real_addr); }

                write_u32_le!(self.raw, off_addr, real_addr);

                off_name += HintNameItem::size();
                off_addr += 4;
            }

        }
        println!("IAT Bound.");
    }
}

