use crate::emu;
use crate::emu::winapi32::kernel32;

pub fn gateway(addr: u32, emu: &mut emu::Emu) -> String {
    match addr {
        0x7740ea11 => MessageBoxA(emu),
        0x7740ea5f => MessageBoxW(emu),
        0x773c01a9 => GetDesktopWindow(emu),
        0x773d426d => wsprintfW(emu),
        0x773bdfdc => GetProcessWindowStation(emu),
        0x773be355 => GetUserObjectInformationW(emu),
        0x773bba8a => CharLowerW(emu),
        _ => {
            let apiname = kernel32::guess_api_name(emu, addr);
            println!("calling unimplemented user32 API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }

    return String::new();
}

fn MessageBoxA(emu: &mut emu::Emu) {
    let titleptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("user32_MessageBoxA: error reading title") as u64;
    let msgptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("user32_MessageBoxA: error reading message") as u64;
    let msg = emu.maps.read_string(msgptr);
    let title = emu.maps.read_string(titleptr);

    println!(
        "{}** {} user32!MessageBoxA {} {} {}",
        emu.colors.light_red, emu.pos, title, msg, emu.colors.nc
    );

    emu.regs.rax = 0;
    for _ in 0..4 {
        emu.stack_pop32(false);
    }
}

fn MessageBoxW(emu: &mut emu::Emu) {
    let titleptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 8)
        .expect("user32_MessageBoxA: error reading title") as u64;
    let msgptr = emu
        .maps
        .read_dword(emu.regs.get_esp() + 4)
        .expect("user32_MessageBoxA: error reading message") as u64;
    let msg = emu.maps.read_wide_string(msgptr);
    let title = emu.maps.read_wide_string(titleptr);

    println!(
        "{}** {} user32!MessageBoxW {} {} {}",
        emu.colors.light_red, emu.pos, title, msg, emu.colors.nc
    );

    emu.regs.rax = 0;
    for _ in 0..4 {
        emu.stack_pop32(false);
    }
}

fn GetDesktopWindow(emu: &mut emu::Emu) {
    println!(
        "{}** {} user32!GetDesktopWindow {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );
    //emu.regs.rax = 0x11223344; // current window handle
    emu.regs.rax = 0; // no windows handler is more stealthy
}

fn wsprintfW(emu: &mut emu::Emu) {}

fn GetProcessWindowStation(emu: &mut emu::Emu) {
    println!(
        "{}** {} user32!GetProcessWindowStation {}",
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    emu.regs.rax = 0x1337;  // get handler
}

fn GetUserObjectInformationW(emu: &mut emu::Emu) {
    let hndl = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!GetUserObjectInformationW: error reading title") as u64;
    let nidx = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!GetUserObjectInformationW: error reading title") as u64;
    let out_vinfo = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!GetUserObjectInformationW: error reading title") as u64;
    let nlen = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!GetUserObjectInformationW: error reading title") as u64;
    let out_len = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!GetUserObjectInformationW: error reading title") as u64;



    println!(                                         
        "{}** {} user32!GetUserObjectInformationW {}",  
        emu.colors.light_red, emu.pos, emu.colors.nc
    );

    for _ in 0..5 {
        emu.stack_pop32(false);
    }
        
    emu.regs.rax = 1;  // get handler
}

fn CharLowerW(emu: &mut emu::Emu) {
    let ptr_str = emu
        .maps
        .read_dword(emu.regs.get_esp())
        .expect("user32!CharLowerW: error reading param") as u64;

    let s = emu.maps.read_wide_string(ptr_str);

    println!(                                         
        "{}** {} user32!CharLowerW(`{}`) {}",  
        emu.colors.light_red, emu.pos, s, emu.colors.nc
    );
    
    emu.maps.write_wide_string(ptr_str, &s.to_lowercase());

    emu.stack_pop32(false);
    emu.regs.rax = ptr_str;
}


