use super::err::ScemuError;
use super::maps::mem64::Mem64;

pub const EI_NIDENT:usize = 16;

pub struct Elf32 {
    pub bin: Mem64,
    pub elf_hdr: Elf32Ehdr,
}

impl Elf32 {
    pub fn parse(filename: &str) -> Result<Elf32, ScemuError> {
        let mut bin: Mem64 = Mem64::new();
        if !bin.load(&filename) {
            return Err(ScemuError::new("cannot open elf binary"));
        }

        let ehdr:Elf32Ehdr = Elf32Ehdr::parse(&bin);

        Ok(Elf32 {
            bin: bin,
            elf_hdr: ehdr,
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

    pub fn parse(bin: &Mem64) -> Elf32Ehdr { 
        let off = EI_NIDENT as u64;
        Elf32Ehdr {
            e_ident: [
                bin.read_byte(0),
                bin.read_byte(1),
                bin.read_byte(2),
                bin.read_byte(3),
                bin.read_byte(4),
                bin.read_byte(5),
                bin.read_byte(6),
                bin.read_byte(7),
                bin.read_byte(8),
                bin.read_byte(9),
                bin.read_byte(10),
                bin.read_byte(11),
                bin.read_byte(12),
                bin.read_byte(13),
                bin.read_byte(14),
                bin.read_byte(15),
            ],
            e_type: bin.read_word(off),
            e_machine: bin.read_word(off+2),
            e_version: bin.read_dword(off+4),
            e_entry: bin.read_dword(off+8),
            e_phoff: bin.read_dword(off+12),
            e_shoff: bin.read_dword(off+16),
            e_flags: bin.read_dword(off+20),
            e_ehsize: bin.read_word(off+24),
            e_phentsize: bin.read_word(off+26),
            e_phnum: bin.read_word(off+28),
            e_shentsize: bin.read_word(off+30),
            e_shnum: bin.read_word(off+32),
            e_shstrndx: bin.read_word(off+34),
        }
    }
}


