use crate::emu;
use crate::emu::winapi32::kernel32;
//use crate::emu::winapi32::helper;
//use crate::emu::endpoint;


pub fn gateway(addr:u32, emu:&mut emu::Emu) -> String {
    match addr {
        0x761f1d9d => _initterm_e(emu),
        0x761ec151 => _initterm(emu),
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
        .expect("msvcrt!_initterm_e: error reading en pointer") as u64;

    println!("{}** {} msvcrt!_initterm 0x{:x} - 0x{:x} {}", 
             emu.colors.light_red, emu.pos, start_ptr, end_ptr, emu.colors.nc);

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 0;
}



