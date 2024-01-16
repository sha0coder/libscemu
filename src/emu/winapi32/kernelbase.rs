use crate::emu;
//use crate::emu::console;
//use crate::emu::constants;
//use crate::emu::context32;
//use crate::emu::peb32;
//use crate::emu::structures;
//use crate::emu::winapi32::helper;
use crate::emu::winapi32::kernel32;

use lazy_static::lazy_static;
use std::sync::Mutex;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    match addr {
        0x7594eca1 => LoadStringW(emu),

        _ => {
            let apiname = kernel32::guess_api_name(emu, addr);
            println!(
                "calling unimplemented kernelbase API 0x{:x} {}",
                addr, apiname
            );
            return apiname;
        }
    }

    return String::new();
}

lazy_static! {
    static ref COUNT_READ: Mutex<u32> = Mutex::new(0);
    static ref COUNT_WRITE: Mutex<u32> = Mutex::new(0);
    pub static ref TICK: Mutex<u32> = Mutex::new(0);
    static ref LAST_ERROR: Mutex<u32> = Mutex::new(0);
}

//// kernelbase API ////

fn LoadStringW(emu: &mut emu::Emu) {
    let hndl = emu.maps.read_dword(emu.regs.rsp)
        .expect("kernelbase!LoadStringW error reading param");
    let id = emu.maps.read_dword(emu.regs.rsp+4)
        .expect("kernelbase!LoadStringW error reading param");
    let buff = emu.maps.read_dword(emu.regs.rsp+8)
        .expect("kernelbase!LoadStringW error reading param");
    let len = emu.maps.read_dword(emu.regs.rsp+12)
        .expect("kernelbase!LoadStringW error reading param");

    println!(
        "{}** {} kernelbase!LoadStringW {} 0x{} {}",
        emu.colors.light_red, emu.pos, id, buff, emu.colors.nc,
    );

    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.stack_pop32(false);
    emu.regs.rax = 1;
}




