use crate::emu;
/*
use crate::emu::console;
use crate::emu::constants;
use crate::emu::context32;
use crate::emu::peb32;
use crate::emu::structures;
use lazy_static::lazy_static;
use std::sync::Mutex;
*/

pub fn gateway(syscall: u64, argv: u64, emu: &mut emu::Emu) {
    match syscall {
        0xdc => {
            log::info!("/!\\ direct syscall: NtAlpcSendWaitReceivePort");
            emu.regs.rax = 0;
        }

        0x10f => {
            log::info!("/!\\ direct syscall: NtOpenFile {:x}", argv);
            emu.regs.rax = 0;
        }

        _ => {
            log::info!(
                "{}{} 0x{:x}: {}{}",
                emu.colors.red,
                emu.pos,
                emu.regs.rip,
                emu.out,
                emu.colors.nc
            );
            unimplemented!();
        }
    }
}

