mod advapi32;
mod crypt32;
mod dnsapi;
pub mod helper;
pub mod kernel32;
mod kernelbase;
mod mscoree;
mod msvcrt;
mod ntdll;
mod oleaut32;
mod shlwapi;
mod user32;
mod wininet;
mod ws2_32;
mod libgcc;

use crate::emu;

pub fn gateway(addr: u32, name: String, emu: &mut emu::Emu) {
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
        "kernelbase_text" => kernelbase::gateway(addr, emu),
        "libgcc_s_dw2-1.text" => libgcc::gateway(addr, emu),
        _ => {
            println!("/!\\ trying to execute on {} at 0x{:x}", name, addr);
            name
        }
    };

    if unimplemented_api.len() > 0 {
        let params = emu.banzai.get_params(&unimplemented_api);
        println!("{} {} parameters", unimplemented_api, params);

        for _ in 0..params {
            emu.stack_pop32(false);
        }
        emu.regs.rax = 1;
    }
}
