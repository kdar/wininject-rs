extern crate sharedlib;
extern crate winapi;
extern crate libc;
extern crate kernel32;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use sharedlib::{Lib, Func, Symbol};
use winapi::{HWND, LPCWSTR, UINT, HINSTANCE, DWORD, LPVOID, BOOL, TRUE};
use libc::c_int;

const DLL_PROCESS_DETACH: DWORD = 0;
const DLL_PROCESS_ATTACH: DWORD = 1;
const DLL_THREAD_ATTACH: DWORD = 2;
const DLL_THREAD_DETACH: DWORD = 3;

fn to_wstring(str: &str) -> Vec<u16> {
  let v: Vec<u16> = OsStr::new(str).encode_wide().chain(Some(0).into_iter()).collect();
  v
}

fn message_box(title: &str, message: &str) {
  unsafe {
    let path_to_lib = "user32.dll";
    let lib = Lib::new(path_to_lib).unwrap();
    let symbol: Func<extern "C" fn(hWnd: HWND, lpText: LPCWSTR, lpCaption: LPCWSTR, uType: UINT)
                                   -> c_int> = lib.find_func("MessageBoxW").unwrap();
    let mbw = symbol.get();
    mbw(0 as HWND,
        to_wstring(message).as_ptr(),
        to_wstring(title).as_ptr(),
        0);
  }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn DllMain(hinst: HINSTANCE, reason: DWORD, reserved: LPVOID) -> BOOL {
  match reason {
    DLL_PROCESS_DETACH => {}
    DLL_PROCESS_ATTACH => unsafe {
      message_box("Title", "Process attached");
      kernel32::DisableThreadLibraryCalls(hinst);
    },
    DLL_THREAD_ATTACH => {}
    DLL_THREAD_DETACH => {}
    _ => {}
  };

  return TRUE;
}

pub extern "C" fn initialize() {
  message_box("Title", "Process attached");
}
