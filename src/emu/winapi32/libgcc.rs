use crate::emu;
//use crate::emu::constants::*;
//use crate::emu::winapi32::helper;
use crate::emu::winapi32::kernel32;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    match addr {
        0x6e955da8 => __register_frame_info(emu),
        0x6e9565c0 => __deregister_frame_info(emu),


        _ => {
            let apiname = kernel32::guess_api_name(emu, addr);
            println!(
                "calling unimplemented libgcc API 0x{:x} {}",
                addr, apiname
            );
            return apiname;
        }
    }

    return String::new();
}


fn __register_frame_info(emu: &mut emu::Emu) {
    let p1 =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("advapi32!__register_frame_info error reading param");
    let p2 =
        emu.maps
            .read_dword(emu.regs.get_esp()+4)
            .expect("advapi32!__register_frame_info error reading param");

    println!(
        "{}** {} libgcc!__register_frame_info {:x} {:x} {}",
        emu.colors.light_red, emu.pos, p1, p2, emu.colors.nc
    );

    let mem = match emu.maps.get_mem_by_addr(0x40E198) {
        Some(m) => m,
        None => {
            let m = emu.maps.create_map("glob1");
            m.set_base(0x40E198);
            m.set_size(100);
            m
        }
    };

    mem.write_dword(0x40E198, 0x6e940000);
            

    for _ in 0..2 {
        emu.stack_pop32(false);
    }
    emu.regs.rax = 1;
}


fn __deregister_frame_info(emu: &mut emu::Emu) {
    let p1 =
        emu.maps
            .read_dword(emu.regs.get_esp())
            .expect("advapi32!__deregister_frame_info error reading param");

    println!(
        "{}** {} libgcc!__deregister_frame_info {:x} {}",
        emu.colors.light_red, emu.pos, p1, emu.colors.nc
    );

    emu.stack_pop32(false);
    emu.regs.rax = 1;
}
