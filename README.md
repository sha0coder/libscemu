
# SCEMU the lib


## Usage

Download the maps32.zip or maps64.zip from:
https://github.com/sha0coder/scemu/releases/download/maps/maps32.zip
https://github.com/sha0coder/scemu/releases/download/maps/maps64.zip

Uncompress it somewhere, in the example it's on /tmp/ but dont use tmp.

Create an emu32 or emu64 and it's important to set the maps folder.

```rust
    use libscemu::emu32;


    let mut emu = emu32();
    emu.set_maps_folder("/tmp/maps32/");
    emu.init();

```

Load your shellcode or PE binary and run the emulator.
Zero parameter means emulate for-ever.

```rust
    emu.load_code("shellcodes32/shikata.bin");
    emu.set_verbose(2);
    emu.run(0); 
```

Or if you prefer call specific function.

```rust
    emu.load_code("samples/malware.exe");

    let crypto_key_gen = 0x40112233;
    let ret_addr = 0x40110000; // any place safe to return.

    let param1 = 0x33;
    let param2_out_buff = emu.alloc("buffer", 1024);

    emu.maps.memset(param2_out_buff, 0, 1024); // non necesary, by default alloc create zeros.
    emu.maps.write_spaced_bytes(param2_out_buff, 
            "DE CC 6C 83 CC F3 66 85 34"); // example of initialization.

    // call function
    emu.regs.set_eip(crypto_key_gen);
    emu.stack_push32(param2_out_buff);
    emu.stack_push32(param1);
    emu.stack_push32(ret_addr);
    emu.run(ret_addr);

    emu.step();

    // check result
    println!("return value: 0x{:x}", emu.regs.get_eax());
    emu.maps.dump(param2_out_buff);

```

