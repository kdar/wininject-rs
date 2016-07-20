#![feature(asm)]

extern crate winapi;
extern crate kernel32;
extern crate win32_error;
extern crate pe;
#[macro_use(defer)]
extern crate scopeguard;

use std::ffi::{CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use winapi::{BOOL, TRUE, FALSE, LPCSTR};
use win32_error::Win32Error;
use std::fs::{self, File};
use std::io::Read;
use scopeguard::guard;

#[derive(Debug, PartialEq)]
enum Bitness {
  MACHINE64,
  MACHINE32,
}

fn to_wstring(s: &str) -> Vec<u16> {
  let v: Vec<u16> = OsStr::new(s).encode_wide().chain(Some(0).into_iter()).collect();
  v
}

fn get_proc_bits(pid: u32) -> Bitness {
  let h = unsafe { kernel32::OpenProcess(winapi::PROCESS_QUERY_INFORMATION, FALSE, pid) };

  let mut b: BOOL = FALSE;
  let ret = unsafe { kernel32::IsWow64Process(h, &mut b) };
  if ret == FALSE {
    let err = Win32Error::new();
    println!("{}", err);
    return Bitness::MACHINE64;
  }

  unsafe { kernel32::CloseHandle(h) };

  if b == TRUE {
    Bitness::MACHINE32
  } else {
    Bitness::MACHINE64
  }
}

fn get_pe_bits(p: &str) -> Bitness {
  let mut file = File::open(p).unwrap();
  let mut buf = vec![];
  file.read_to_end(&mut buf).unwrap();
  let exe = pe::Pe::new(&buf).unwrap();
  let header = exe.get_header();

  if header.machine == pe::types::Machine::AMD64 || header.machine == pe::types::Machine::IA64 {
    Bitness::MACHINE64
  } else {
    Bitness::MACHINE32
  }
}

// #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn inject(dll: &str, pid: u32) -> Result<(), String> {
  let pebits = get_pe_bits(dll);
  let procbits = get_proc_bits(pid);

  if pebits != procbits {
    return Err(format!("Machine bits missmatch. Target: {:?}, DLL: {:?}",
                       procbits,
                       pebits)
      .to_owned());
  }

  let k32_handle = unsafe { kernel32::LoadLibraryW(to_wstring("kernel32.dll").as_ptr()) };
  let loadlibrary =
    unsafe { kernel32::GetProcAddress(k32_handle, "LoadLibraryA".as_ptr() as *const i8) };

  let full_path = match fs::canonicalize(dll) {
    Ok(p) => p.to_str().unwrap().replace("\\\\?\\", ""),
    Err(e) => return Err(e.to_string()),
  };

  let h = unsafe {
    kernel32::OpenProcess(winapi::PROCESS_CREATE_THREAD | winapi::PROCESS_VM_WRITE |
                          winapi::PROCESS_VM_OPERATION,
                          FALSE,
                          pid)
  };
  let h = guard(h, |h| {
    unsafe { kernel32::CloseHandle(*h) };
  });

  let path_size = full_path.len() as u64 + 1;

  let addr = unsafe {
    kernel32::VirtualAllocEx(*h,
                             0 as *mut std::os::raw::c_void,
                             path_size,
                             winapi::MEM_COMMIT,
                             winapi::PAGE_READWRITE)
  };
  if addr.is_null() {
    let err = Win32Error::new();
    return Err(err.to_string());
  }
  let addr = guard(addr, |addr| {
    unsafe { kernel32::VirtualFreeEx(*h, *addr, path_size, winapi::MEM_DECOMMIT) };
  });

  let mut n = 0;
  let ret = unsafe {
    kernel32::WriteProcessMemory(*h,
                                 *addr,
                                 CString::new(full_path).unwrap().as_ptr() as *const std::os::raw::c_void,
                                 path_size,
                                 &mut n)
  };
  if ret == 0 || n == 0 {
    let err = Win32Error::new();
    return Err(err.to_string());
  }

  let thread = unsafe {
    kernel32::CreateRemoteThread(*h,
                                 0 as *mut winapi::SECURITY_ATTRIBUTES,
                                 0,
                                 Some(std::mem::transmute(loadlibrary)),
                                 *addr,
                                 0,
                                 0 as *mut u32)
  };
  if thread.is_null() {
    let err = Win32Error::new();
    return Err(err.to_string());
  }

  let thread = guard(thread, |thread| {
    unsafe { kernel32::CloseHandle(*thread) };
  });

  unsafe { kernel32::WaitForSingleObject(*thread, winapi::INFINITE) };

  Ok(())
}

fn main() {
  // println!("{:?}", getProcessBits(5332));
  // println!("{:?}", getPEBits("hook64.dll"));
  match inject("hook64.dll", 10368) {
    Err(e) => println!("{}", e),
    Ok(()) => (),
  }
}
