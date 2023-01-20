use crate::emu;
use crate::emu::winapi32::kernel32;
//use crate::emu::winapi32::helper;
//use crate::emu::endpoint;


pub fn gateway(addr:u32, emu:&mut emu::Emu) -> String {
    match addr {
        0x761f1d9d => _initterm_e(emu),
        0x761ec151 => _initterm(emu),
        0x7670d2ac => StrCmpCA(emu),
        _ => {
            let apiname = kernel32::guess_api_name(emu, addr);
            println!("calling unimplemented msvcrt API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }

    return String::new();
}

fn _initterm_e(emu:&mut emu::Emu) {
    let start_ptr = emu.maps.read_dword(emu.regs.get_esp())
        .expect("msvcrt!_initterm_e: error reading start pointer") as u64;
    let end_ptr = emu.maps.read_dword(emu.regs.get_esp()+4)
        .expect("msvcrt!_initterm_e: error reading en pointer") as u64;


    println!("{}** {} msvcrt!_initterm_e 0x{:x} - 0x{:x} {}", 
             emu.colors.light_red, emu.pos, start_ptr, end_ptr, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 0;
}


fn _initterm(emu:&mut emu::Emu) {
    let start_ptr = emu.maps.read_dword(emu.regs.get_esp())
        .expect("msvcrt!_initterm_e: error reading start pointer") as u64;
    let end_ptr = emu.maps.read_dword(emu.regs.get_esp()+4)
        .expect("msvcrt!_initterm_e: error reading end pointer") as u64;

    println!("{}** {} msvcrt!_initterm 0x{:x} - 0x{:x} {}", 
             emu.colors.light_red, emu.pos, start_ptr, end_ptr, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 0;
}

fn StrCmpCA(emu:&mut emu::Emu) {
    let str1_ptr = emu.maps.read_dword(emu.regs.get_esp())
        .expect("msvcrt!StrCmpA: error reading str1 pointer") as u64;
    let str2_ptr = emu.maps.read_dword(emu.regs.get_esp()+4)
        .expect("msvcrt!StrCmpA: error reading str2 pointer") as u64;

    let str1 = emu.maps.read_string(str1_ptr);
    let str2 = emu.maps.read_string(str2_ptr);

    println!("{}** {} msvcrt!StrCmpA {} == {} {}", 
             emu.colors.light_red, emu.pos, str1, str2, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);

    if str1 == str2 {
        emu.regs.rax = 0;
    } else {
        emu.regs.rax = 0xffffffff;
    }
}


