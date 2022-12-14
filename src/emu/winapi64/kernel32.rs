use crate::emu;
use crate::emu::winapi32::helper;
use crate::emu::constants;
use crate::emu::console;
use crate::emu::peb64;


/*
use crate::emu::context32;
use lazy_static::lazy_static; 
use std::sync::Mutex;*/

// a in RCX, b in RDX, c in R8, d in R9, f then e pushed on stack

pub fn gateway(addr:u64, emu:&mut emu::Emu) {
    match addr {
        0x76dc7070 => LoadLibraryA(emu),
        0x76dd3690 => GetProcAddress(emu),
        0x76db21e0 => CreateToolhelp32Snapshot(emu),
        0x76e0fdb0 => Process32First(emu),
        0x76e0fcc0 => Process32Next(emu),
        0x76db40a0 => LStrCmpI(emu),
        0x76dfc5d0 => AreFileApiIsAnsi(emu),
        0x76e3e420 => BeginUpdateResourceA(emu),
        0x76dccad0 => OpenProcess(emu),
        0x76dc67a0 => VirtualAlloc(emu),
        0x76dfbbd0 => VirtualAllocEx(emu),
        0x76dfbad0 => WriteProcessMemory(emu),
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
        _ => panic!("calling unimplemented kernel32 64bits API 0x{:x} {}", addr, guess_api_name(emu, addr)),
    }
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

    /*
    let mut dll_path = emu.cfg.maps_folder.clone();
    dll_path.push_str(&dll);

    println!("dll path: {}", dll_path);

    match dll.to_lowercase().as_str() {
        "ntdll"|"ntdll.dll" => emu.regs.rax = emu.maps.get_mem("ntdll_pe").get_base(),
        "ws2_32"|"ws2_32.dll" => emu.regs.rax = emu.maps.get_mem("ws2_32_pe").get_base(),
        "wininet"|"wininet.dll" => emu.regs.rax = emu.maps.get_mem("wininet_pe").get_base(),
        "advapi32"|"advapi32.dll" => emu.regs.rax = emu.maps.get_mem("advapi32_pe").get_base(),
        "kernel32"|"kernel32.dll" => emu.regs.rax = emu.maps.get_mem("kernel32_pe").get_base(),
        "winhttp"|"winhttp.dll" => emu.regs.rax = emu.maps.get_mem("winhttp_pe").get_base(),
        "dnsapi"|"dnsapi.dll" => emu.regs.rax = emu.maps.get_mem("dnsapi_pe").get_base(),
        "iphlpapi"|"iphlpapi.dll" => emu.regs.rax = emu.maps.get_mem("iphlpapi_pe").get_base(),
        "user32"|"user32.dll" => emu.regs.rax = emu.maps.get_mem("user32_pe").get_base(),
        
        _ => {
            unimplemented!("/!\\ kernel32!LoadLibraryA: lib not found {}", dll);
        }
    }
    */

    emu.regs.rax = load_library(emu, &dll);

    println!("{}** {} kernel32!LoadLibraryA  '{}' =0x{:x} {}", emu.colors.light_red, 
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




    /*
    let peb = emu.maps.get_mem("peb");
    let peb_base = peb.get_base();
    let ldr = peb.read_qword(peb_base + 0x18);
    if dbg {
        println!("ldr: 0x{:x}", ldr);
    }
    let mut flink = emu.maps.read_qword(ldr + 0x10).expect("kernel32!GetProcAddress error reading flink");
    if dbg {
        println!("flink: 0x{:x}", flink);
    }

    loop { // walk modules

        let mod_name_ptr = emu.maps.read_qword(flink + 0x60).expect("kernel32!GetProcAddress error reading mod_name_ptr");
        let mod_path_ptr = emu.maps.read_qword(flink + 0x50).expect("kernel32!GetProcAddress error reading mod_name_ptr");
        if dbg {
            println!("mod_name_ptr: 0x{:x}", mod_name_ptr);
        }

        let mod_base = emu.maps.read_qword(flink + 0x30).expect("kernel32!GetProcAddress error reading mod_addr");
        if dbg {
            println!("mod_base: 0x{:x}", mod_base);
        }

        let mod_name = emu.maps.read_wide_string(mod_name_ptr);
        if dbg {
            println!("mod_name: {}", mod_name);
        }
    

        let pe_hdr_off = match emu.maps.read_dword(mod_base + 0x3c) { 
            Some(hdr) => hdr as u64,
            None => { emu.regs.rax = 0; return; }
        };

        if dbg {
            println!("pe_hdr_off: 0x{:x}", pe_hdr_off);
        }

        // pe_hdr correct

        
        let export_table_rva = emu.maps.read_dword(mod_base + pe_hdr_off + 0x88).expect("kernel32!GetProcAddress error reading export_table_rva") as u64;
        if dbg {
            println!("({:x}) {:x} =  {:x} + pehdr:{:x} + {:x}", export_table_rva, mod_base + pe_hdr_off + 0x78, mod_base, pe_hdr_off, 0x78);
        }

        if export_table_rva == 0 {
            flink = emu.maps.read_qword(flink).expect("kernel32!GetProcAddress error reading next flink") as u64;
            if dbg {
                println!("getting new flink: 0x{:x}", flink);
            }
            continue;
        }

        let export_table = export_table_rva + mod_base;
        if dbg {
            println!("export_table: 0x{:x}", export_table);
        }

       

        if !emu.maps.is_mapped(export_table) {
            flink = emu.maps.read_qword(flink).expect("kernel32!GetProcAddress error reading next flink") as u64;
            if dbg {
                println!("getting new flink: 0x{:x}", flink);
            }
            continue;
        }


        let mut num_of_funcs = emu.maps.read_dword(export_table + 0x18).expect("kernel32!GetProcAddress error reading the num_of_funcs") as u64;

        if dbg {
            println!("num_of_funcs:  0x{:x} -> 0x{:x}", export_table + 0x18, num_of_funcs);
        }


        if num_of_funcs == 0 {
            flink = emu.maps.read_qword(flink).expect("kernel32!GetProcAddress error reading next flink") as u64;
            println!("getting new flink: 0x{:x}", flink);
            continue;
        }
        

        let func_name_tbl_rva = emu.maps.read_dword(export_table + 0x20).expect("kernel32!GetProcAddress  error reading func_name_tbl_rva") as u64;
        let func_name_tbl = func_name_tbl_rva + mod_base;

        if num_of_funcs == 0 {
            flink = emu.maps.read_dword(flink).expect("kernel32!GetProcAddress error reading next flink") as u64;
            continue;
        }

        loop { // walk functions
                
            num_of_funcs -= 1;
            let func_name_rva = emu.maps.read_dword(func_name_tbl + num_of_funcs * 4).expect("kernel32!GetProcAddress error reading func_rva") as u64;
            let func_name_va = func_name_rva + mod_base;
            let func_name = emu.maps.read_string(func_name_va).to_lowercase();

            //println!("func_name: {}", func_name);
            
            if func_name == func { 
                let ordinal_tbl_rva = emu.maps.read_dword(export_table + 0x24).expect("kernel32!GetProcAddress error reading ordinal_tbl_rva") as u64; // Ok address_of_ordinals
                let ordinal_tbl = ordinal_tbl_rva + mod_base;
                let ordinal = emu.maps.read_word(ordinal_tbl + 2 * num_of_funcs).expect("kernel32!GetProcAddress error reading ordinal") as u64;
                let func_addr_tbl_rva = emu.maps.read_dword(export_table + 0x1c).expect("kernel32!GetProcAddress  error reading func_addr_tbl_rva") as u64; //Ok address_of_functions
                let func_addr_tbl = func_addr_tbl_rva + mod_base;
                
                let func_rva = emu.maps.read_dword(func_addr_tbl + 4 * ordinal).expect("kernel32!GetProcAddress error reading func_rva") as u64;
                let func_va = func_rva + mod_base;

                emu.regs.rax = func_va;

                println!("{}** {} kernel32!GetProcAddress  `{}!{}` =0x{:x} {}", emu.colors.light_red, emu.pos, mod_name, func_name, emu.regs.get_eax() as u32, emu.colors.nc);
                return;
            }

            if num_of_funcs == 0 {
                break;
            }
        }

        flink = emu.maps.read_qword(flink).expect("kernel32!GetProcAddress error reading next flink") as u64;
    } 
    */
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




