use super::err::ScemuError;
use super::maps::mem64::Mem64;

macro_rules! read_u8 {
    ($raw:expr, $off:expr) => {
        $raw[$off]
    };
}

macro_rules! read_u16_le {
    ($raw:expr, $off:expr) => {
        (($raw[$off + 1] as u16) << 8) | ($raw[$off] as u16)
    };
}

macro_rules! read_u32_le {
    ($raw:expr, $off:expr) => {
        (($raw[$off + 3] as u32) << 24)
            | (($raw[$off + 2] as u32) << 16)
            | (($raw[$off + 1] as u32) << 8)
            | ($raw[$off] as u32)
    };
}



pub const EI_NIDENT:usize = 16;

pub struct Elf32 {
    pub bin: Vec<u8>,
    pub elf_hdr: Elf32Ehdr,
    pub elf_phdr: Elf32Phdr,
    pub elf_shdr: Elf32Shdr,
}

impl Elf32 {
    pub fn parse(filename: &str) -> Result<Elf32, ScemuError> {
        let mut mem: Mem64 = Mem64::new();
        if !mem.load(&filename) {
            return Err(ScemuError::new("cannot open elf binary"));
        }
        let bin = mem.get_mem();

        let ehdr:Elf32Ehdr = Elf32Ehdr::parse(&bin);
        let phdr:Elf32Phdr = Elf32Phdr::parse(&bin, ehdr.e_phoff as usize);
        let shdr:Elf32Shdr = Elf32Shdr::parse(&bin, ehdr.e_shoff as usize);


        Ok(Elf32 {
            bin: bin,
            elf_hdr: ehdr,
            elf_phdr: phdr,
            elf_shdr: shdr,
        })
    }

    pub fn is_elf(&self) -> bool {
        if self.elf_hdr.e_ident[0] == 0x7f &&
            self.elf_hdr.e_ident[1] == b'E' &&
            self.elf_hdr.e_ident[2] == b'L' && 
            self.elf_hdr.e_ident[3] == b'F' {
                return true;
        }
        false 
    }
}

#[derive(Debug)]
pub struct Elf32Ehdr {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl Elf32Ehdr {
    pub fn new() -> Elf32Ehdr { 
        Elf32Ehdr {
            e_ident: [0; EI_NIDENT],
            e_type: 0,
            e_machine: 0,
            e_version: 0,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 0,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }

    pub fn parse(bin: &[u8]) -> Elf32Ehdr { 
        let off = EI_NIDENT as u64;
        Elf32Ehdr {
            e_ident: [
                read_u8!(bin, 0),
                read_u8!(bin, 1),
                read_u8!(bin, 2),
                read_u8!(bin, 3),
                read_u8!(bin, 4),
                read_u8!(bin, 5),
                read_u8!(bin, 6),
                read_u8!(bin, 7),
                read_u8!(bin, 8),
                read_u8!(bin, 9),
                read_u8!(bin, 10),
                read_u8!(bin, 11),
                read_u8!(bin, 12),
                read_u8!(bin, 13),
                read_u8!(bin, 14),
                read_u8!(bin, 15),
            ],
            e_type: read_u16_le!(bin, 16),
            e_machine: read_u16_le!(bin, 18),
            e_version: read_u32_le!(bin, 20),
            e_entry: read_u32_le!(bin, 24),
            e_phoff: read_u32_le!(bin, 28),
            e_shoff: read_u32_le!(bin, 32),
            e_flags: read_u32_le!(bin, 36),
            e_ehsize: read_u16_le!(bin, 40),
            e_phentsize: read_u16_le!(bin, 42),
            e_phnum: read_u16_le!(bin, 44),
            e_shentsize: read_u16_le!(bin, 46),
            e_shnum: read_u16_le!(bin, 48),
            e_shstrndx: read_u16_le!(bin, 50),
        }
    }
}

pub struct Elf32Phdr {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_paddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

impl Elf32Phdr {
    pub fn parse(bin: &[u8], phoff: usize) -> Elf32Phdr {
        Elf32Phdr {
            p_type: read_u32_le!(bin, phoff),
            p_offset: read_u32_le!(bin, phoff+4),
            p_vaddr: read_u32_le!(bin, phoff+8),
            p_paddr: read_u32_le!(bin, phoff+12),
            p_filesz: read_u32_le!(bin, phoff+16),
            p_memsz: read_u32_le!(bin, phoff+20),
            p_flags: read_u32_le!(bin, phoff+24),
            p_align: read_u32_le!(bin, phoff+28),
        }
    }
}

pub struct Elf32Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u32,
    pub sh_addr: u32,
    pub sh_offset: u32,
    pub sh_size: u32,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u32,
    pub sh_entsize: u32,
}

impl Elf32Shdr {
    pub fn parse(bin: &[u8], shoff: usize) -> Elf32Shdr {
        Elf32Shdr {
            sh_name: read_u32_le!(bin, shoff),
            sh_type: read_u32_le!(bin, shoff+4),
            sh_flags: read_u32_le!(bin, shoff+8),
            sh_addr: read_u32_le!(bin, shoff+12),
            sh_offset: read_u32_le!(bin, shoff+16),
            sh_size: read_u32_le!(bin, shoff+20),
            sh_link: read_u32_le!(bin, shoff+24),
            sh_info: read_u32_le!(bin, shoff+28),
            sh_addralign: read_u32_le!(bin, shoff+32),
            sh_entsize: read_u32_le!(bin, 36),
        }
    }
}


