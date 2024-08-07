use crate::emu;

pub fn gateway(addr: u64, emu: &mut emu::Emu) -> String {
    match addr {

        _ => {
            let apiname = emu::winapi64::kernel32::guess_api_name(emu, addr);
            println!("calling unimplemented comctl32 API 0x{:x} {}", addr, apiname);
            return apiname;
        }
    }

    // return String::new();
}
