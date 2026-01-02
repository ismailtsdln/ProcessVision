use crate::core::errors::{ProcessVisionError, Result};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::*;

pub struct ProcessHandle {
    handle: HANDLE,
    pid: u32,
}

impl ProcessHandle {
    pub fn open(pid: u32, access: u32) -> Result<Self> {
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle == 0 {
            return Err(ProcessVisionError::ProcessOpenError(pid, unsafe {
                GetLastError()
            }));
        }
        Ok(Self { handle, pid })
    }

    pub fn read_memory(&self, address: usize, buffer: &mut [u8]) -> Result<usize> {
        let mut bytes_read = 0;
        let success = unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                &mut bytes_read,
            )
        };

        if success != 0 {
            Ok(bytes_read)
        } else {
            Err(ProcessVisionError::MemoryReadError(
                self.pid,
                address,
                unsafe { GetLastError() },
            ))
        }
    }

    pub fn raw_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe { CloseHandle(self.handle) };
        }
    }
}
