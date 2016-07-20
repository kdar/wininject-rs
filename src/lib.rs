#![feature(asm)]

extern crate winapi;
extern crate kernel32;
extern crate pe;
#[macro_use(defer)]
extern crate scopeguard;

use std::ffi::{CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use winapi::{BOOL, TRUE, FALSE};
use std::fs::{self, File};
use std::io::Read;
use scopeguard::guard;
use std::ptr;

#[derive(Debug, PartialEq)]
enum Bitness {
  MACHINE64,
  MACHINE32,
}

fn to_wstring(s: &str) -> Vec<u16> {
  let v: Vec<u16> = OsStr::new(s).encode_wide().chain(Some(0).into_iter()).collect();
  v
}

fn get_last_error_string() -> String {
  unsafe {
    let mut buf = [0u16; 256];
    let buf_size = 256;

    let mut n = kernel32::FormatMessageW(winapi::FORMAT_MESSAGE_IGNORE_INSERTS |
                                         winapi::FORMAT_MESSAGE_FROM_SYSTEM |
                                         winapi::FORMAT_MESSAGE_ARGUMENT_ARRAY,
                                         ptr::null(),
                                         kernel32::GetLastError(),
                                         0,
                                         buf.as_mut_ptr(),
                                         (buf_size + 1) as u32,
                                         ptr::null_mut());

    let mut msg = String::from_utf16(&buf).unwrap();
    msg.truncate(n as usize);

    for c in msg.chars().rev() {
      if c == ' ' || c == '\r' || c == '\n' {
        n -= 1;
      } else {
        break;
      }
    }

    msg.truncate(n as usize);
    msg
  }
}

fn get_proc_bits(pid: u32) -> Result<Bitness, String> {
  unsafe {
    let h = kernel32::OpenProcess(winapi::PROCESS_QUERY_INFORMATION, FALSE, pid);

    let mut b: BOOL = FALSE;
    let ret = kernel32::IsWow64Process(h, &mut b);
    if ret == FALSE {
      return Err(get_last_error_string());
    }

    kernel32::CloseHandle(h);

    if b == TRUE {
      Ok(Bitness::MACHINE32)
    } else {
      Ok(Bitness::MACHINE64)
    }
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
pub fn inject(dll: &str, pid: u32) -> Result<(), String> {
  unsafe {

    let pebits = get_pe_bits(dll);
    let procbits = match get_proc_bits(pid) {
      Ok(b) => b,
      Err(e) => return Err(e),
    };

    if pebits != procbits {
      return Err(format!("Machine bits missmatch. Target: {:?}, DLL: {:?}",
                         procbits,
                         pebits)
        .to_owned());
    }

    let k32_handle = kernel32::LoadLibraryW(to_wstring("kernel32.dll").as_ptr());
    let loadlibrary = kernel32::GetProcAddress(k32_handle, "LoadLibraryA".as_ptr() as *const i8);

    let full_path = match fs::canonicalize(dll) {
      Ok(p) => p.to_str().unwrap().replace("\\\\?\\", ""),
      Err(e) => return Err(e.to_string()),
    };

    let h = kernel32::OpenProcess(winapi::PROCESS_CREATE_THREAD | winapi::PROCESS_VM_WRITE |
                                  winapi::PROCESS_VM_OPERATION,
                                  FALSE,
                                  pid);
    let h = guard(h, |h| {
      kernel32::CloseHandle(*h);
    });

    let path_size = full_path.len() as u64 + 1;

    let addr = kernel32::VirtualAllocEx(*h,
                                        ptr::null_mut(),
                                        path_size,
                                        winapi::MEM_COMMIT,
                                        winapi::PAGE_READWRITE);
    if addr.is_null() {
      return Err(get_last_error_string());
    }
    let addr = guard(addr, |addr| {
      kernel32::VirtualFreeEx(*h, *addr, path_size, winapi::MEM_DECOMMIT);
    });

    let mut n = 0;
    let ret =
    kernel32::WriteProcessMemory(*h,
                                 *addr,
                                 CString::new(full_path).unwrap().as_ptr() as *const std::os::raw::c_void,
                                 path_size,
                                 &mut n)
  ;
    if ret == 0 || n == 0 {
      return Err(get_last_error_string());
    }

    let thread = kernel32::CreateRemoteThread(*h,
                                              ptr::null_mut(),
                                              0,
                                              Some(std::mem::transmute(loadlibrary)),
                                              *addr,
                                              0,
                                              ptr::null_mut());
    if thread.is_null() {
      return Err(get_last_error_string());
    }

    let thread = guard(thread, |thread| {
      kernel32::CloseHandle(*thread);
    });

    kernel32::WaitForSingleObject(*thread, winapi::INFINITE);

    Ok(())
  }
}
