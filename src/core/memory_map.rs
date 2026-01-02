use crate::core::errors::{ProcessVisionError, Result};
use crate::core::findings::MemoryRegionInfo;
use std::mem::size_of;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

pub fn get_process_memory_map(pid: u32) -> Result<Vec<MemoryRegionInfo>> {
    let mut regions = Vec::new();

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle == 0 {
            return Err(ProcessVisionError::ProcessOpenError(pid, GetLastError()));
        }

        let mut address: usize = 0;
        let mut mem_info: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

        while VirtualQueryEx(
            handle,
            address as *const _,
            &mut mem_info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0
        {
            regions.push(MemoryRegionInfo {
                base_address: mem_info.BaseAddress as usize,
                allocation_base: mem_info.AllocationBase as usize,
                size: mem_info.RegionSize,
                protection: mem_info.Protect,
                state: mem_info.State,
                region_type: mem_info.Type,
            });

            // Move to the next region
            let next_address = (mem_info.BaseAddress as usize).checked_add(mem_info.RegionSize);
            if let Some(next) = next_address {
                address = next;
            } else {
                break;
            }
        }

        CloseHandle(handle);
    }

    Ok(regions)
}
