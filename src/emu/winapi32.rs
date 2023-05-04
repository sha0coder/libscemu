pub mod kernel32;
mod ntdll;
mod user32;
mod wininet;
mod ws2_32;
mod advapi32;
mod crypt32;
mod dnsapi;
mod mscoree;
mod msvcrt;
mod shlwapi;
mod oleaut32;
pub mod helper;

use crate::emu;


pub fn gateway(addr:u32, name:String, emu:&mut emu::Emu) { 
    emu.regs.sanitize32();
    let unimplemented_api = match name.as_str() {
        "kernel32_text" => kernel32::gateway(addr, emu),
        "ntdll_text" => ntdll::gateway(addr, emu),
        "user32_text" => user32::gateway(addr, emu),
        "ws2_32_text" => ws2_32::gateway(addr, emu),
        "wininet_text" => wininet::gateway(addr, emu),
        "advapi32_text" => advapi32::gateway(addr, emu),
        "crypt32.text" => crypt32::gateway(addr, emu),
        "crypt32_text" => crypt32::gateway(addr, emu),
        "dnsapi.text" => dnsapi::gateway(addr, emu),
        "mscoree.text" => mscoree::gateway(addr, emu),
        "msvcrt_text" => msvcrt::gateway(addr, emu),
        "shlwapi_text" => msvcrt::gateway(addr, emu),
        "oleaut32_text" => oleaut32::gateway(addr, emu),
        _ => panic!("/!\\ trying to execute on {} at 0x{:x}", name, addr),
    };


    if unimplemented_api.len() > 0 {

        if emu.cfg.skip_unimplemented {
            let params = emu.banzai.get_params(&unimplemented_api);
            println!("{} {} parameters", unimplemented_api, params);

            for _ in 0..params {
                emu.stack_pop32(false);
            }
            emu.regs.rax = 1;

        } else {
            panic!("function is not in emulation list.");
        }
    }

}
