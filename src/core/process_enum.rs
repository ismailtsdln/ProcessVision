use crate::core::errors::{ProcessVisionError, Result};
use crate::core::findings::ProcessMetadata;
use std::mem::size_of;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
// use windows_sys::Win32::System::ProcessStatus::*;

pub fn enumerate_processes() -> Result<Vec<ProcessMetadata>> {
    let mut processes = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(ProcessVisionError::ProcessEnumerationError(GetLastError()));
        }

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                let name = String::from_utf8_lossy(&entry.szExeFile)
                    .trim_matches(char::from(0))
                    .to_string();

                processes.push(ProcessMetadata {
                    pid: entry.th32ProcessID,
                    name,
                    path: None, // Will be populated if needed
                });

                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }

    Ok(processes)
}
