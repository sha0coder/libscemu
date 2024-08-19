mod advapi32;
mod comctl64;
mod dnsapi;
pub mod kernel32;
mod ntdll;
mod shell32;
mod user32;
mod winhttp;
mod wininet;
mod ws2_32;

use crate::emu;

pub fn gateway(addr: u64, name: String, emu: &mut emu::Emu) {
    let unimplemented_api = match name.as_str() {
        "kernel32_text" => kernel32::gateway(addr, emu),
        "kernel32_rdata" => kernel32::gateway(addr, emu),
        "ntdll_text" => ntdll::gateway(addr, emu),
        "user32_text" => user32::gateway(addr, emu),
        "ws2_32_text" => ws2_32::gateway(addr, emu),
        "wininet_text" => wininet::gateway(addr, emu),
        "advapi32_text" => advapi32::gateway(addr, emu),
        "winhttp_text" => winhttp::gateway(addr, emu),
        "dnsapi_text" => dnsapi::gateway(addr, emu),
        "comctl32.text" => comctl64::gateway(addr, emu),
        "shell32.text" => shell32::gateway(addr, emu),
        _ => panic!("/!\\ trying to execute on {} at 0x{:x}", name, addr),
    };

    if unimplemented_api.len() > 0 {
        println!(
            "{}({}, {}, {}, {}) (unimplemented)",
            unimplemented_api, emu.regs.rcx, emu.regs.rdx, emu.regs.r8, emu.regs.r9
        );

        emu.regs.rax = 1;
    }
}
