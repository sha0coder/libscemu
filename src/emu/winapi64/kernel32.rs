use crate::emu;
use crate::emu::winapi32::helper;
use crate::emu::constants;
use crate::emu::console;
use crate::emu::peb64;

use crate::emu::context64;
use lazy_static::lazy_static; 
use std::sync::Mutex;

// a in RCX, b in RDX, c in R8, d in R9, f then e pushed on stack

pub fn gateway(addr:u64, emu:&mut emu::Emu) {
    match addr {
        0x76dc7070 => LoadLibraryA(emu),
        0x76dc6f80 => LoadLibraryW(emu),
        0x76dbe3b0 => LoadLibraryExA(emu),
        0x76dc6640 => LoadLibraryExW(emu),
        0x76dd3690 => GetProcAddress(emu),
        0x76e48d80 => WinExec(emu),
        0x76ff9380 => GetVersion(emu),
        0x76dc70c0 => GetVersionExA(emu),
        0x76dbd910 => GetVersionExW(emu),
        0x76e48840 => CreateProcessA(emu),
        0x76dd1bb0 => CreateProcessW(emu),
        0x76db21e0 => CreateToolhelp32Snapshot(emu),
        0x76e0fdb0 => Process32First(emu),
        0x76e0fcc0 => Process32Next(emu),
        0x76db40a0 => LStrCmpI(emu),
        0x76dfc5d0 => AreFileApiIsAnsi(emu),
        0x76e3e420 => BeginUpdateResourceA(emu),
        0x76dccad0 => OpenProcess(emu),
        0x76dc67a0 => VirtualAlloc(emu),
        0x76dfbbd0 => VirtualAllocEx(emu),
        0x76dfaa70 => Thread32First(emu),
        0x76dfa980 => Thread32Next(emu),
        0x76dcc560 => OpenThread(emu),
        0x76dc3f40 => GetSystemTimeAsFileTime(emu),
        0x76dc3ee0 => GetCurrentThreadId(emu),
        0x76dc5a50 => GetCurrentProcessId(emu),
        0x76dc6500 => QueryPerformanceCounter(emu),
        0x76dd3050 => GetProcessHeap(emu),
        0x76e5a504 => HeapAlloc(emu),
        0x76dc1120 => CreateEventA(emu),
        0x76dc6580 => CreateThread(emu),
        0x76dd2b70 => Sleep(emu),
        0x76dc47c0 => LocalAlloc(emu),
        0x76dfbad0 => WriteProcessMemory(emu),
        0x76dfc4f0 => CreateRemoteThread(emu),
        0x76e12ba0 => CreateNamedPipeA(emu),
        0x76db2540 => CreateNamedPipeW(emu),
        0x76db20d0 => ConnectNamedPipe(emu),
        0x76dfc460 => DisconnectNamedPipe(emu),
        0x76dc1500 => ReadFile(emu),
        0x76dd35a0 => WriteFile(emu),
        0x76e4d350 => CloseHandle(emu),
        0x76e5a404 => ExitProcess(emu),
        0x76dfbca0 => TerminateProcess(emu),
        0x76dd2b20 => WaitForSingleObject(emu),
        0x76db2f40 => GetThreadContext(emu),
        0x76dfbdc0 => ReadProcessMemory(emu),
        0x76dbec50 => GetCurrentDirectoryA(emu),
        0x76dcc580 => GetCurrentDirectoryW(emu),
        0x76db2ef0 => VirtualProtect(emu),
        0x76dfbb70 => VirtualProtectEx(emu),
        0x76dc13a0 => ResumeThread(emu),
        0x76dd3670 => GetFullPathNameA(emu),
        0x76dc76e0 => GetFullPathNameW(emu),
        0x76dfbcb0 => SystemTimeToTzSpecificLocalTime(emu),
        0x76dbb930 => GetLogicalDrives(emu),
        0x76db80a0 => ExpandEnvironmentStringsA(emu),
        0x76dc71b0 => ExpandEnvironmentStringsW(emu),
        0x76dc13e0 => GetFileAttributesA(emu),
        0x76dcbdd0 => GetFileAttributesW(emu),
        0x76dbaf20 => FileTimeToSystemTime(emu),
        0x76dfc380 => FindFirstFileA(emu),
        0x76dcbd80 => FindFirstFileW(emu),
        0x76dfc320 => FindNextFileA(emu),
        0x76dc1910 => FindNextFileW(emu),
        0x76e45620 => CopyFileA(emu),
        0x76db92d0 => CopyFileW(emu),


        _ => panic!("calling unimplemented kernel32 64bits API 0x{:x} {}", addr, guess_api_name(emu, addr)),
    }
}

lazy_static! {                                                            
    static ref COUNT_READ:Mutex<u32> = Mutex::new(0);                                                               
    static ref COUNT_WRITE:Mutex<u32> = Mutex::new(0);
    pub static ref TICK:Mutex<u32> = Mutex::new(0);
} 


pub fn dump_module_iat(emu:&mut emu::Emu, module: &str) {
    let mut flink = peb64::Flink::new(emu);
    flink.load(emu);
    let first_ptr = flink.get_ptr();
    
    loop {
        if flink.mod_name.to_lowercase().contains(module) {  
            if flink.export_table_rva > 0 {
                for i in 0..flink.num_of_funcs {
                    if flink.pe_hdr == 0 {
                        continue
                    }

                    let ordinal = flink.get_function_ordinal(emu, i);
                    println!("0x{:x} {}!{}", ordinal.func_va, &flink.mod_name, 
                             &ordinal.func_name);
                }
            }
        }
        flink.next(emu);
    
        if flink.get_ptr() == first_ptr {  
            break;  
        }
    }
}

pub fn resolve_api_name(emu:&mut emu::Emu, name: &str) -> u64 {
    let mut flink = peb64::Flink::new(emu);
    flink.load(emu);
    let first_ptr = flink.get_ptr();
                    
    loop {
        if flink.export_table_rva > 0 {
            for i in 0..flink.num_of_funcs {
                if flink.pe_hdr == 0 {
                    continue
                }

                let ordinal = flink.get_function_ordinal(emu, i);
                if ordinal.func_name.contains(name) {
                    return ordinal.func_va;
                }
            }
        }
        flink.next(emu);

        if flink.get_ptr() == first_ptr {  
            break;  
        }
    }


    return 0; //TODO: use Option<>
}

pub fn search_api_name(emu:&mut emu::Emu, name: &str) -> (u64, String, String) {
    let mut flink = peb64::Flink::new(emu);
    flink.load(emu);
    let first_ptr = flink.get_ptr();

    loop {
        if flink.export_table_rva > 0 {
            for i in 0..flink.num_of_funcs {
                if flink.pe_hdr == 0 {
                    continue
                }

                let ordinal = flink.get_function_ordinal(emu, i);
                if ordinal.func_name.contains(name) {
                    return (ordinal.func_va, flink.mod_name.clone(), ordinal.func_name.clone());
                }
            }
        }
        flink.next(emu);

        if flink.get_ptr() == first_ptr {  
            break;  
        }
    }


    return (0,String::new(), String::new()); //TODO: use Option<>
}

pub fn guess_api_name(emu:&mut emu::Emu, addr: u64) -> String {
    let mut flink = peb64::Flink::new(emu);
    flink.load(emu);
    let first_ptr = flink.get_ptr();

    loop {
        //let mod_name = flink.mod_name.clone();
        
        if flink.export_table_rva > 0 {
            for i in 0..flink.num_of_funcs {
                if flink.pe_hdr == 0 {
                    continue;
                }

                let ordinal = flink.get_function_ordinal(emu, i);

                if ordinal.func_va == addr.into() {
                    return ordinal.func_name.clone();
                }
            }
        }

        flink.next(emu);

        if flink.get_ptr() == first_ptr {
            break;
        }
    }

    return "function not found".to_string();

}

pub fn load_library(emu:&mut emu::Emu, libname: &str) -> u64 {
    let mut dll = libname.to_string().to_lowercase();

    if dll.len() == 0 {
        emu.regs.rax = 0;
        return 0;
    }

    if !dll.ends_with(".dll") {
        dll.push_str(".dll");
    }

    let mut dll_path = emu.cfg.maps_folder.clone();
    dll_path.push_str(&dll);

    match peb64::get_module_base(&dll, emu) {
        Some(base) => {
            // already linked
            if emu.cfg.verbose > 0 {
                println!("dll {} already linked.", dll);
            }
            return base;
        },
        None => {
            // do link
            if std::path::Path::new(&dll_path).exists() {
                let (base, pe_off) = emu.load_pe64(&dll_path, false, 0);
                peb64::dynamic_link_module(base as u64, pe_off,  &dll, emu);
                return base as u64;
            } else {
                if emu.cfg.verbose > 0 {
                    println!("dll {} not found.", dll_path);
                }
                return 0;
            }
        }                                                                                         
    };
}


fn LoadLibraryA(emu:&mut emu::Emu) {
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);

    println!("{}** {} kernel32!LoadLibraryA  '{}' =0x{:x} {}", emu.colors.light_red, 
             emu.pos, dll, emu.regs.rax, emu.colors.nc);
}

fn LoadLibraryW(emu:&mut emu::Emu) {
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_wide_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);

    println!("{}** {} kernel32!LoadLibraryA  '{}' =0x{:x} {}", emu.colors.light_red, 
             emu.pos, dll, emu.regs.rax, emu.colors.nc);
}

fn LoadLibraryExA(emu:&mut emu::Emu) {
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);


    println!("{}** {} kernel32!LoadLibraryExA  '{}' =0x{:x} {}", emu.colors.light_red, 
             emu.pos, dll, emu.regs.rax, emu.colors.nc);
}

fn LoadLibraryExW(emu:&mut emu::Emu) {
    let dllptr = emu.regs.rcx;
    let dll = emu.maps.read_wide_string(dllptr);

    emu.regs.rax = load_library(emu, &dll);


    println!("{}** {} kernel32!LoadLibraryExW '{}' =0x{:x} {}", emu.colors.light_red, 
             emu.pos, dll, emu.regs.rax, emu.colors.nc);
}

fn GetProcAddress(emu:&mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let func_ptr = emu.regs.rdx;

    let func = emu.maps.read_string(func_ptr).to_lowercase();

    let mut flink = peb64::Flink::new(emu);
    flink.load(emu);
    let first_flink = flink.get_ptr();

    loop {
        if flink.export_table_rva > 0 {
            for i in 0..flink.num_of_funcs {
                if flink.pe_hdr == 0 {
                    continue;
                }
                let ordinal = flink.get_function_ordinal(emu, i);
                
               // println!("func name {}!{}", flink.mod_name, ordinal.func_name);
                
                if ordinal.func_name.to_lowercase() == func {
                    emu.regs.rax = ordinal.func_va;
                    println!("{}** {} kernel32!GetProcAddress  `{}!{}` =0x{:x} {}", 
                             emu.colors.light_red, emu.pos, flink.mod_name, ordinal.func_name,
                             emu.regs.rax, emu.colors.nc);
                    return;
                }
            }
        }

        flink.next(emu);
        if flink.get_ptr() == first_flink {
            break;
        }
    }
    emu.regs.rax = 0;
    if emu.cfg.verbose >= 1 {
        println!("kernel32!GetProcAddress error searching {}", func);
    }

}

fn WinExec(emu:&mut emu::Emu) {
    let cmdline_ptr = emu.regs.rcx;
    let cmdline = emu.maps.read_string(cmdline_ptr);

    println!("{}** {} kernel32!WinExec  '{}'  {}", emu.colors.light_red, emu.pos, cmdline, emu.colors.nc);

    emu.regs.rax = 32;
}

fn GetVersion(emu:&mut emu::Emu) {
    emu.regs.rax = emu::constants::VERSION;
    println!("{}** {} kernel32!GetVersion   =0x{:x}  {}", emu.colors.light_red, emu.pos, emu.regs.rax, emu.colors.nc);
}

fn GetVersionExW(emu:&mut emu::Emu) {
    let version_info_ptr = emu.regs.rcx;
                                                       
    println!("{}** {} kernel32!GetVersionExW 0x{:x} {}", emu.colors.light_red, emu.pos, version_info_ptr, emu.colors.nc);                              
   
    let os_version_info = emu::structures::OsVersionInfo::new(); 
    os_version_info.save(version_info_ptr, &mut emu.maps);
      
    emu.regs.rax = 1;
}

fn GetVersionExA(emu:&mut emu::Emu) {
    let version_info_ptr = emu.regs.rcx;
                                                       
    println!("{}** {} kernel32!GetVersionExA 0x{:x} {}", emu.colors.light_red, emu.pos, version_info_ptr, emu.colors.nc);                              
   
    let os_version_info = emu::structures::OsVersionInfo::new(); 
    os_version_info.save(version_info_ptr, &mut emu.maps);
      
    emu.regs.rax = 1;
}


fn CreateToolhelp32Snapshot(emu:&mut emu::Emu) {
    let flags = emu.regs.rcx;
    let pid = emu.regs.rdx;

    println!("{}** {} kernel32!CreateToolhelp32Snapshot flags: {:x} pid: {} {}", 
             emu.colors.light_red, emu.pos, flags, pid, emu.colors.nc);

    let uri = format!("CreateToolhelp32Snapshot://{}", pid);
    emu.regs.rax = helper::handler_create(&uri);
}

fn Process32First(emu:&mut emu::Emu) {
    let handle = emu.regs.rcx;
    let lppe = emu.regs.rdx;

    println!("{}** {} kernel32!Process32First hndl: {:x} lppe: 0x{:x} {}", 
             emu.colors.light_red, emu.pos, handle, lppe, emu.colors.nc);

    if !helper::handler_exist(handle) {
        emu.regs.rax = 0;
        return;
    }

    emu.maps.write_string(lppe +  44, "smss.exe\x00");

/*

            typedef struct tagPROCESSENTRY32 {
            DWORD     dwSize;                +0
            DWORD     cntUsage;              +4
            DWORD     th32ProcessID;         +8
            ULONG_PTR th32DefaultHeapID;    +12
            DWORD     th32ModuleID;         +16
            DWORD     cntThreads;           +20
            DWORD     th32ParentProcessID;  +24
            LONG      pcPriClassBase;       +28
            DWORD     dwFlags;              +32
            CHAR      szExeFile[MAX_PATH];  +36
            } PROCESSENTRY32;
*/

    emu.regs.rax = 1;
}

fn Process32Next(emu:&mut emu::Emu) {
    let handle = emu.regs.rcx;
    let lppe = emu.regs.rdx;

    println!("{}** {} kernel32!Process32Next hndl: {:x} lppe: 0x{:x} {}", 
             emu.colors.light_red, emu.pos, handle, lppe, emu.colors.nc);

    emu.maps.write_string(lppe +  44, "explorer.exe\x00");

    if !helper::handler_exist(handle) {
        emu.regs.rax = 0;
        return;
    }

    emu.regs.rax = 0; // trigger exit loop
}

fn LStrCmpI(emu:&mut emu::Emu) {
    let sptr1 = emu.regs.rcx;
    let sptr2 = emu.regs.rdx;

    let s1 = emu.maps.read_string(sptr1);
    let s2 = emu.maps.read_string(sptr2);

    if s1 == s2 {
        println!("{}** {} kernel32!lstrcmpi `{}` == `{}` {}", emu.colors.light_red, emu.pos, 
                 s1, s2, emu.colors.nc);
        emu.regs.rax = 0;

    } else {
        println!("{}** {} kernel32!lstrcmpi `{}` != `{}` {}", emu.colors.light_red, emu.pos, 
                 s1, s2, emu.colors.nc);
        emu.regs.rax = 1;
    }
}

fn AreFileApiIsAnsi(emu:&mut emu::Emu) {
    println!("{}** {} kernel32!AreFileApiIsAnsi {}", emu.colors.light_red, emu.pos, 
             emu.colors.nc);
    emu.regs.rax = 1;
}

fn BeginUpdateResourceA(emu:&mut emu::Emu) {
    let pFileName = emu.regs.rcx;
    let bDeleteExistingResources = emu.regs.rdx;
 
    let filename = emu.maps.read_string(pFileName);

    println!("{}** {} kernel32!BeginUpdateResourceA `{}` {} {}", emu.colors.light_red, 
             emu.pos, filename, bDeleteExistingResources, emu.colors.nc);

    emu.regs.rax = helper::handler_create(&filename);
}

fn OpenProcess(emu:&mut emu::Emu) {
    let access = emu.regs.rcx;
    let inherit = emu.regs.rdx;
    let pid = emu.regs.r8;

    println!("{}** {} kernel32!OpenProcess pid: {} {}", emu.colors.light_red, emu.pos, 
             pid, emu.colors.nc);

    let uri = format!("pid://{}", pid);
    emu.regs.rax = helper::handler_create(&uri);
}

fn VirtualAlloc(emu:&mut emu::Emu) {
    let addr = emu.regs.rcx;
    let size = emu.regs.rdx;
    let typ = emu.regs.r8;
    let prot = emu.regs.r9;

    let base = emu.maps.alloc(size).expect("kernel32!VirtualAlloc out of memory");

    println!("{}** {} kernel32!VirtualAlloc addr: 0x{:x} sz: {} = 0x{:x} {}", 
             emu.colors.light_red, emu.pos, addr, size, base, emu.colors.nc);

    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(size);
    
    emu.regs.rax = base;
}

fn VirtualAllocEx(emu:&mut emu::Emu) {
    let proc_hndl = emu.regs.rcx;
    let addr = emu.regs.rdx;
    let size = emu.regs.r8;
    let alloc_type = emu.regs.r9;
    let protect = emu.maps.read_qword(emu.regs.rsp).expect("kernel32!VirtualAllocEx cannot read_qword protect");

    let base = emu.maps.alloc(size).expect("kernel32!VirtualAllocEx out of memory");

    println!("{}** {} kernel32!VirtualAllocEx hproc: 0x{:x} addr: 0x{:x} sz: {} = 0x{:x} {}", emu.colors.light_red, emu.pos, proc_hndl, addr, size, base, emu.colors.nc);

    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(size);
    
    emu.regs.rax = base;
    emu.stack_pop64(false);
}

fn WriteProcessMemory(emu:&mut emu::Emu) {
    let proc_hndl = emu.regs.rcx;
    let addr = emu.regs.rdx;
    let buff = emu.regs.r8;
    let size = emu.regs.r9;
    let written_ptr = emu.maps.read_qword(emu.regs.rsp).expect("kernel32!WriteProcessMemory cannot read written_ptr");

    println!("{}** {} kernel32!WriteProcessMemory hproc: 0x{:x} from: 0x{:x } to: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, proc_hndl, buff, addr, size, emu.colors.nc);


    if emu.maps.memcpy(buff, addr, size as usize) {
        emu.regs.rax = 1;
        println!("{}\twritten succesfully{}", emu.colors.light_red, emu.colors.nc);
        if written_ptr != 0 && !emu.maps.write_qword(written_ptr, size) {
            println!("kernel32!WriteProcessMemory cannot write on written_ptr");
        }
    } else {
        emu.regs.rax = 0;
        println!("{}\tcouldnt write all the bytes{}", emu.colors.light_red, emu.colors.nc);
        if written_ptr != 0 && !emu.maps.write_qword(written_ptr,  0) {
            println!("kernel32!WriteProcessMemory cannot write on written_ptr");
        }
    }

    emu.stack_pop64(false);
}

fn Thread32First(emu:&mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let entry = emu.regs.rdx;
  
    println!("{}** {} kernel32!Thread32First {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 1;
    //emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn Thread32Next(emu:&mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let entry = emu.regs.rdx;
  
    println!("{}** {} kernel32!Thread32Next {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn OpenThread(emu:&mut emu::Emu) {
    let access = emu.regs.rcx;
    let inherit = emu.regs.rdx;
    let tid = emu.regs.r8;

    println!("{}** {} kernel32!OpenThread tid: {} {}", emu.colors.light_red, emu.pos, tid, emu.colors.nc);

    let uri = format!("tid://{}", tid);
    emu.regs.rax = helper::handler_create(&uri);
}

fn GetSystemTimeAsFileTime(emu:&mut emu::Emu) {
    let sys_time_ptr = emu.regs.rcx;

    println!("{}** {} kernel32!GetSystemTimeAsFileTime {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 1;
}

fn GetCurrentThreadId(emu:&mut emu::Emu) {
    println!("{}** {} kernel32!GetCurrentThreadId {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 0x111; //TODO: track pids and tids
}

fn GetCurrentProcessId(emu:&mut emu::Emu) {
    println!("{}** {} kernel32!GetCurrentProcessId {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 0x123; 
}

fn QueryPerformanceCounter(emu:&mut emu::Emu) {
    let counter_ptr = emu.regs.rcx;

    emu.maps.write_dword(counter_ptr, 0x1);

    println!("{}** {} kernel32!QueryPerformanceCounter {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 1;
}

fn GetProcessHeap(emu:&mut emu::Emu) {
    emu.regs.rax = helper::handler_create("heap");

    println!("{}** {} kernel32!GetProcessHeap ={} {}", emu.colors.light_red, emu.pos, emu.regs.rax, emu.colors.nc);
}

fn HeapAlloc(emu:&mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let flags = emu.regs.rdx;
    let size = emu.regs.r8;

    emu.regs.rax = match emu.maps.alloc(size) {
        Some(sz) => sz,
        None => 0,
    };

    let mem = emu.maps.create_map(format!("alloc_{:x}", emu.regs.rax).as_str());
    mem.set_base(emu.regs.rax);
    mem.set_size(size);
    
    println!("{}** {} kernel32!HeapAlloc flags: 0x{:x} size: {} =0x{:x} {}", emu.colors.light_red, 
        emu.pos, flags, size, emu.regs.rax, emu.colors.nc);
}

fn CreateEventA(emu:&mut emu::Emu) {
    let attributes = emu.regs.rcx;
    let bManualReset = emu.regs.rdx;
    let bInitialState = emu.regs.r8;
    let name_ptr = emu.regs.r9;

    let mut name = String::new();
    if name_ptr > 0 {
        name = emu.maps.read_string(name_ptr);
    }

    println!("{}** {} kernel32!CreateEventA attr: 0x{:x} manual_reset: {} init_state: {} name: {} {}", 
        emu.colors.light_red, emu.pos, attributes, bManualReset, bInitialState, name, emu.colors.nc);
   
    let uri = format!("event://{}", name);
    emu.regs.rax = helper::handler_create(&uri);
}

fn CreateThread(emu:&mut emu::Emu) {
    let sec_attr = emu.regs.rcx;
    let stack_sz = emu.regs.rdx;
    let code = emu.regs.r8;
    let param = emu.regs.r9;
    let flags = emu.maps.read_qword(emu.regs.rsp).expect("kernel32!CreateThread cannot read flags") as u64;
    let tid_ptr = emu.maps.read_qword(emu.regs.rsp+8).expect("kernel32!CreateThread cannot read tid_ptr") as u64;

    emu.maps.write_dword(tid_ptr, 0x123);

    println!("{}** {} kernel32!CreateThread code: 0x{:x} param: 0x{:x} {}", emu.colors.light_red, emu.pos, code, param, emu.colors.nc);

    for _ in 0..2 {
        emu.stack_pop64(false);
    }

    if flags == constants::CREATE_SUSPENDED {
        println!("\tcreated suspended!");
    }

    let con = console::Console::new();
    con.print("Continue emulating the created thread (y/n)? ");
    let line = con.cmd();

    if line == "y" || line == "yes" {
        if emu.maps.is_mapped(code) {
            emu.regs.rip = code;
            emu.regs.rax = 0;
            emu.regs.rcx = param;
            emu.main_thread_cont = emu.gateway_return;
            emu.stack_push64(param);
            emu.stack_push64(constants::RETURN_THREAD.into());

            // alloc a stack vs reusing stack.
            return;
        } else {
            println!("cannot emulate the thread, the function pointer is not mapped.");
        }
    } 

    emu.regs.rax = helper::handler_create("tid://0x123");
}

fn Sleep(emu:&mut emu::Emu) {
    let millis = emu.regs.rcx;

    println!("{}** {} kernel32!Sleep millis: {} {}", emu.colors.light_red, emu.pos, millis, emu.colors.nc);

}

fn LocalAlloc(emu:&mut emu::Emu) {
    let flags = emu.regs.rcx;
    let bytes = emu.regs.rdx;

    println!("{}** {} kernel32!LocalAlloc flags: {:x} sz: {} {}", emu.colors.light_red, emu.pos, flags, bytes, emu.colors.nc);

    let base = emu.maps.alloc(bytes).expect("kernel32!LocalAlloc out of memory");                          
    let alloc = emu.maps.create_map(format!("alloc_{:x}", base).as_str());
    alloc.set_base(base);
    alloc.set_size(bytes);           
    
    emu.regs.rax = base;
}

fn CreateProcessA(emu:&mut emu::Emu) {
    let appname_ptr = emu.regs.rcx;
    let cmdline_ptr = emu.regs.rdx;
    let appname = emu.maps.read_string(appname_ptr);
    let cmdline = emu.maps.read_string(cmdline_ptr);

     println!("{}** {} kernel32!CreateProcessA  {} {} {}", emu.colors.light_red, emu.pos, appname, cmdline, emu.colors.nc);

     emu.regs.rax = 1;
}


fn CreateProcessW(emu:&mut emu::Emu) {
    let appname_ptr = emu.regs.rcx;
    let cmdline_ptr = emu.regs.rdx;
    let appname = emu.maps.read_wide_string(appname_ptr);
    let cmdline = emu.maps.read_wide_string(cmdline_ptr);

     println!("{}** {} kernel32!CreateProcessW  {} {} {}", emu.colors.light_red, emu.pos, appname, cmdline, emu.colors.nc);

     emu.regs.rax = 1;
}

fn CreateRemoteThread(emu:&mut emu::Emu) {
    let proc_hndl = emu.regs.rcx;
    let sec = emu.regs.rdx;
    let stack_size = emu.regs.r8;
    let addr = emu.regs.r9;
    let param = emu.maps.read_qword(emu.regs.rsp).expect("krenel32!CreateRemoteThread cannot read the param");
    let flags = emu.maps.read_qword(emu.regs.rsp+8).expect("kernel32!CreateRemoteThread cannot read the flags");
    let out_tid = emu.maps.read_qword(emu.regs.rsp+16).expect("kernel32!CreateRemoteThread cannot read the tid");

    println!("{}** {} kernel32!CreateRemoteThread hproc: 0x{:x} addr: 0x{:x} {}", emu.colors.light_red, emu.pos, proc_hndl, addr, emu.colors.nc);
    
    emu.maps.write_dword(out_tid, 0x123);
    emu.regs.rax = helper::handler_create("tid://0x123");

    emu.stack_pop64(false);
    emu.stack_pop64(false);
    emu.stack_pop64(false);
}

fn CreateNamedPipeA(emu: &mut emu::Emu) {
    let name_ptr = emu.regs.rcx;
    let open_mode = emu.regs.rcx;
    let pipe_mode = emu.regs.r8;
    let instances = emu.regs.r9;
    let out_buff_sz = emu.maps.read_qword(emu.regs.rsp).expect("kernel32!CreateNamedPipeA cannot read the to_buff_sz");
    let in_buff_sz = emu.maps.read_qword(emu.regs.rsp+8).expect("kernel32!CreateNamedPipeA cannot read the in_buff_sz");
    let timeout = emu.maps.read_qword(emu.regs.rsp+16).expect("kernel32!CreateNamedPipeA cannot read the timeout");
    let security = emu.maps.read_qword(emu.regs.rsp+24).expect("kernel32!CreateNamedPipeA cannot read the security");

    let name = emu.maps.read_string(name_ptr);

    println!("{}** {} kernel32!CreateNamedPipeA  name:{} in: 0x{:x} out: 0x{:x} {}", emu.colors.light_red, emu.pos, name, 
        in_buff_sz, out_buff_sz, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop64(false);
    }

    emu.regs.rax = helper::handler_create(&name);
}


fn CreateNamedPipeW(emu: &mut emu::Emu) {
    let name_ptr = emu.regs.rcx;
    let open_mode = emu.regs.rcx;
    let pipe_mode = emu.regs.r8;
    let instances = emu.regs.r9;
    let out_buff_sz = emu.maps.read_qword(emu.regs.rsp).expect("kernel32!CreateNamedPipeA cannot read the to_buff_sz");
    let in_buff_sz = emu.maps.read_qword(emu.regs.rsp+8).expect("kernel32!CreateNamedPipeA cannot read the in_buff_sz");
    let timeout = emu.maps.read_qword(emu.regs.rsp+16).expect("kernel32!CreateNamedPipeA cannot read the timeout");
    let security = emu.maps.read_qword(emu.regs.rsp+24).expect("kernel32!CreateNamedPipeA cannot read the security");

    let name = emu.maps.read_wide_string(name_ptr);

    println!("{}** {} kernel32!CreateNamedPipeA  name:{} in: 0x{:x} out: 0x{:x} {}", emu.colors.light_red, emu.pos, name, 
        in_buff_sz, out_buff_sz, emu.colors.nc);

    for _ in 0..4 {
        emu.stack_pop64(false);
    }

    emu.regs.rax = helper::handler_create(&name);
}

fn ConnectNamedPipe(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;
    let overlapped = emu.regs.rdx;

    println!("{}** {} kernel32!ConnectNamedPipe hndl: 0x{:x} {}", emu.colors.light_red, emu.pos, handle, emu.colors.nc);

    if !helper::handler_exist(handle) {
        println!("\tinvalid handle.");
    }
    
    emu.regs.rax = 1;
}


fn DisconnectNamedPipe(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;

    println!("{}** {} kernel32!DisconnectNamedPipe hndl: 0x{:x} {}", emu.colors.light_red, emu.pos, handle, emu.colors.nc);

    emu.regs.rax = 1;
}

fn ReadFile(emu: &mut emu::Emu) {
    let file_hndl = emu.regs.rcx;
    let buff = emu.regs.rdx;
    let size = emu.regs.r8;
    let bytes_read = emu.regs.r9;
    let overlapped = emu.maps.read_qword(emu.regs.rsp).expect("kernel32!ReadFile cannot read the overlapped");

    let mut count = COUNT_READ.lock().unwrap();
    *count += 1;  
  
    if size == 4 && *count == 1 {  
        // probably reading the size  
        emu.maps.write_dword(buff, 0x10); 
    }  
  
    if *count < 3 {  
        // keep reading bytes  
        emu.maps.write_qword(bytes_read, size);
        emu.maps.memset(buff, 0x90, size as usize);
        emu.regs.rax = 1;  
    } else {  
        // try to force finishing reading and continue the malware logic  
        emu.maps.write_qword(bytes_read, 0);
        emu.regs.rax = 0;  
    }  
  
    //TODO: write some random bytes to the buffer  
    //emu.maps.write_spaced_bytes(buff, "00 00 00 01".to_string());  
    
    println!("{}** {} kernel32!ReadFile hndl: 0x{:x} buff: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, 
        file_hndl, buff, size, emu.colors.nc);  
  
    if !helper::handler_exist(file_hndl) {  
        println!("\tinvalid handle.")  
    }  
  
    emu.stack_pop64(false);
}

fn WriteFile(emu: &mut emu::Emu) {
    let file_hndl = emu.regs.rcx;
    let buff = emu.regs.rdx;
    let size = emu.regs.r8;
    let bytes_written = emu.regs.r9;
    let overlapped = emu.maps.read_qword(emu.regs.rsp).expect("kernel32!WriteFile cannot read the overlapped");

    let mut count = COUNT_WRITE.lock().unwrap();
    *count += 1;

    emu.maps.write_qword(bytes_written, size);

    println!("{}** {} kernel32!WriteFile hndl: 0x{:x} buff: 0x{:x} sz: {} {}", emu.colors.light_red, emu.pos, 
        file_hndl, buff, size, emu.colors.nc);

    if !helper::handler_exist(file_hndl) {
        println!("\tinvalid handle.")
    }

    emu.stack_pop64(false);
    emu.regs.rax = 1;
}


fn CloseHandle(emu: &mut emu::Emu) {
    let handle = emu.regs.rcx;

    println!("{}** {} kernel32!CloseHandle 0x{:X} {}", emu.colors.light_red, emu.pos, handle, emu.colors.nc);

    if !helper::handler_close(handle) {
        println!("\tinvalid handle.")
    }
    emu.regs.rax = 1;
}

fn ExitProcess(emu: &mut emu::Emu) {
    let code = emu.regs.rcx;

    println!("{}** {} kernel32!ExitProcess code: {} {}", emu.colors.light_red, emu.pos, code, emu.colors.nc);
    std::process::exit(1);
}

fn TerminateProcess(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let code = emu.regs.rdx;

    println!("{}** {} kernel32!TerminateProcess hndl: {} code: {} {}", emu.colors.light_red, emu.pos, hndl, code, emu.colors.nc);
    emu.regs.rax = 1;
}


fn WaitForSingleObject(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let millis = emu.regs.rdx;

    println!("{}** {} kernel32!WaitForSingleObject  hndl: {} millis: {} {}", emu.colors.light_red, emu.pos, hndl, millis, emu.colors.nc);

    emu.regs.rax = emu::constants::WAIT_TIMEOUT;
}

fn GetThreadContext(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let ctx_ptr = emu.regs.rdx;

    let ctx = context64::Context64::new(&emu.regs);
    ctx.save(ctx_ptr, &mut emu.maps);

    println!("{}** {} kernel32!GetThreadContext  {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 1;
}

fn ReadProcessMemory(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let addr = emu.regs.rdx;
    let buff = emu.regs.r8;
    let size = emu.regs.r9;
    let bytes = emu.maps.read_qword(emu.regs.rsp).expect("kernel32!ReadProcessMemory cannot read bytes");

    println!("{}** {} kernel32!ReadProcessMemory hndl: {} from: 0x{:x} to: 0x{:x} sz: {} {}", emu.colors.light_red, 
        emu.pos, hndl, addr, buff, size, emu.colors.nc);

    emu.maps.write_qword(bytes, size);
    emu.maps.memset(buff, 0x90, size as usize);

    emu.stack_pop64(false);
    emu.regs.rax = 1;
}

fn GetCurrentDirectoryA(emu: &mut emu::Emu) {
    let buff_len = emu.regs.rcx;
    let buff_ptr = emu.regs.rdx;

    emu.maps.write_string(buff_ptr, "c:\\\x00");
    println!("{}** {} kernel32!GetCurrentDirectoryA {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 3;
}

fn GetCurrentDirectoryW(emu: &mut emu::Emu) {
    let buff_len = emu.regs.rcx;
    let buff_ptr = emu.regs.rdx;

    emu.maps.write_string(buff_ptr, "c\x00:\x00\\\x00\x00\x00\x00\x00");
    println!("{}** {} kernel32!GetCurrentDirectoryW {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 6;
}

fn VirtualProtect(emu: &mut emu::Emu) {
    let addr = emu.regs.rcx;
    let size = emu.regs.rdx;
    let new_prot = emu.regs.r8;
    let old_prot_ptr = emu.regs.r9;

    emu.maps.write_qword(old_prot_ptr, new_prot);

    println!("{}** {} kernel32!VirtualProtect addr: 0x{:x} sz: {} prot: {} {}", emu.colors.light_red, emu.pos,
        addr, size, new_prot, emu.colors.nc);

    emu.regs.rax = 1;
}

fn VirtualProtectEx(emu: &mut emu::Emu) {
    let hproc = emu.regs.rcx;
    let addr = emu.regs.rdx;
    let size = emu.regs.r8;
    let new_prot = emu.regs.r9;
    let oldld_prot_ptr = emu.maps.read_qword(emu.regs.rsp)
        .expect("kernel32!VirtualProtectEx cannot read old_prot");

    println!("{}** {} kernel32!VirtualProtectEx hproc: {} addr: 0x{:x} sz: {} prot: {} {}", emu.colors.light_red, 
        emu.pos, hproc, addr, size, new_prot, emu.colors.nc);

    emu.stack_pop64(false);
    emu.regs.rax = 1;
}

fn ResumeThread(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;

    println!("{}** {} kernel32!ResumeThread hndl: {} {}", emu.colors.light_red, emu.pos, hndl, emu.colors.nc);

    emu.regs.rax = 1; // previous suspend count
}

fn GetFullPathNameA(emu: &mut emu::Emu) {
    let file_ptr = emu.regs.rcx;
    let size = emu.regs.rdx;
    let buff = emu.regs.r8;
    let path = emu.regs.r9;

    let filename = emu.maps.read_string(file_ptr);
    println!("{}** {} kernel32!GetFullPathNameA file: {}  {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);
    // TODO: save the path to buff.
    emu.regs.rax = 10;
}

fn GetFullPathNameW(emu: &mut emu::Emu) {
    let file_ptr = emu.regs.rcx;
    let size = emu.regs.rdx;
    let buff = emu.regs.r8;
    let path = emu.regs.r9;

    let filename = emu.maps.read_wide_string(file_ptr);
    println!("{}** {} kernel32!GetFullPathNameW file: {}  {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);
    // TODO: save the path to buff.
    emu.regs.rax = 10;
}

fn SystemTimeToTzSpecificLocalTime(emu: &mut emu::Emu) {
    let tz_ptr = emu.regs.rcx;
    let ut_ptr = emu.regs.rcx;
    let lt_ptr = emu.regs.r8;

    println!("{}** {} kernel32!SystemTimeToTzSpecificLocalTime {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = 1;
}

fn GetLogicalDrives(emu: &mut emu::Emu) {
    println!("{}** {} kernel32!GetLogicalDrives {}", emu.colors.light_red, emu.pos, emu.colors.nc);
    emu.regs.rax = 0xc;
}

fn ExpandEnvironmentStringsA(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;
    let size = emu.regs.r8;

    let src = emu.maps.read_string(src_ptr);

    println!("{}** {} kernel32!ExpandEnvironmentStringsA `{}` {}", emu.colors.light_red, emu.pos, src, emu.colors.nc);
    // TODO: expand typical environment varsl.
    emu.regs.rax = 1;
}

fn ExpandEnvironmentStringsW(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;
    let size = emu.regs.r8;

    let src = emu.maps.read_wide_string(src_ptr);

    println!("{}** {} kernel32!ExpandEnvironmentStringsW `{}` {}", emu.colors.light_red, emu.pos, src, emu.colors.nc);
    // TODO: expand typical environment varsl.
    emu.regs.rax = 1;
}

fn GetFileAttributesA(emu: &mut emu::Emu) {
    let filename_ptr = emu.regs.rcx;
    let filename = emu.maps.read_string(filename_ptr);

    println!("{}** {} kernel32!GetFileAttributesA file: {} {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);
    emu.regs.rax = 0x123;
}

fn GetFileAttributesW(emu: &mut emu::Emu) {
    let filename_ptr = emu.regs.rcx;
    let filename = emu.maps.read_wide_string(filename_ptr);

    println!("{}** {} kernel32!GetFileAttributesW file: {} {}", emu.colors.light_red, emu.pos, filename, emu.colors.nc);
    emu.regs.rax = 0x123;
}

fn FileTimeToSystemTime(emu: &mut emu::Emu) {
    let file_time = emu.regs.rcx;
    let sys_time_ptr = emu.regs.rdx;

    println!("{}** {} kernel32!FileTimeToSystemTime {} ", emu.colors.light_red, emu.pos, emu.colors.nc);
    emu.regs.rax = 1;
}

fn FindFirstFileA(emu: &mut emu::Emu) {
    let file_ptr = emu.regs.rcx;
    let find_data = emu.regs.rdx;
    
    let file = emu.maps.read_string(file_ptr);
    println!("{}** {} kernel32!FindFirstFileA file: {} {}", emu.colors.light_red, emu.pos, file, emu.colors.nc);
    emu.regs.rax = 1;
}

fn FindFirstFileW(emu: &mut emu::Emu) {
    let file_ptr = emu.regs.rcx;
    let find_data = emu.regs.rdx;
    
    let file = emu.maps.read_wide_string(file_ptr);
    println!("{}** {} kernel32!FindFirstFileW file: {} {}", emu.colors.light_red, emu.pos, file, emu.colors.nc);
    emu.regs.rax = 1;
}

fn FindNextFileA(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let find_data = emu.regs.rdx;

    println!("{}** {} kernel32!FindNextFileA {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn FindNextFileW(emu: &mut emu::Emu) {
    let hndl = emu.regs.rcx;
    let find_data = emu.regs.rdx;

    println!("{}** {} kernel32!FindNextFileW {}", emu.colors.light_red, emu.pos, emu.colors.nc);

    emu.regs.rax = constants::ERROR_NO_MORE_FILES;
}

fn CopyFileA(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;
    let do_fail = emu.regs.r8;

    let src = emu.maps.read_string(src_ptr);
    let dst = emu.maps.read_string(dst_ptr);

    println!("{}** {} kernel32!CopyFileA `{}` to `{}` {}", emu.colors.light_red, emu.pos, src, dst, emu.colors.nc);

    emu.regs.rax = 1;
}

fn CopyFileW(emu: &mut emu::Emu) {
    let src_ptr = emu.regs.rcx;
    let dst_ptr = emu.regs.rdx;
    let do_fail = emu.regs.r8;

    let src = emu.maps.read_wide_string(src_ptr);
    let dst = emu.maps.read_wide_string(dst_ptr);

    println!("{}** {} kernel32!CopyFileW `{}` to `{}` {}", emu.colors.light_red, emu.pos, src, dst, emu.colors.nc);

    emu.regs.rax = 1;
}



