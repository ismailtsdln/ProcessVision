use crate::core::errors::Result;
use crate::core::findings::{DetectionTechnique, Finding, MemoryRegionInfo, ProcessMetadata};
use entropy::shannon_entropy;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::*;

pub struct ShellcodeEngine;

impl ShellcodeEngine {
    pub fn analyze(process: &ProcessMetadata, regions: &[MemoryRegionInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for region in regions {
            // Only scan executable regions
            if (region.protection & 0xF0) != 0 {
                // Simple check for execute bits (PAGE_EXECUTE_*)
                if region.size < 512 {
                    continue;
                }

                let mut buffer = vec![0u8; region.size.min(4096)];
                if Self::read_process_memory(process.pid, region.base_address, &mut buffer).is_ok()
                {
                    let ent = shannon_entropy(&buffer);

                    // High entropy in executable memory is very suspicious (packed/encrypted shellcode)
                    if ent > 6.5 {
                        findings.push(Finding {
                            process: process.clone(),
                            region: Some(region.clone()),
                            engine_name: "ShellcodeEngine".to_string(),
                            technique: DetectionTechnique::ShellcodeInjection,
                            confidence: 75,
                            explanation: format!(
                                "High entropy ({:.2}) detected in executable region at 0x{:X}. This suggests packed or encrypted shellcode.",
                                ent, region.base_address
                            ),
                            recommended_action: "Examine the region for common shellcode stubs (e.g., egg hunters or decoders).".to_string(),
                        });
                    }
                }
            }
        }

        findings
    }

    fn read_process_memory(pid: u32, address: usize, buffer: &mut [u8]) -> Result<()> {
        unsafe {
            let handle = OpenProcess(PROCESS_VM_READ, 0, pid);
            if handle == 0 {
                return Err(crate::core::errors::ProcessVisionError::ProcessOpenError(
                    pid,
                    windows_sys::Win32::Foundation::GetLastError(),
                ));
            }

            let mut bytes_read = 0;
            let success = ReadProcessMemory(
                handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                &mut bytes_read,
            );

            windows_sys::Win32::Foundation::CloseHandle(handle);

            if success != 0 {
                Ok(())
            } else {
                Err(crate::core::errors::ProcessVisionError::MemoryReadError(
                    pid,
                    address,
                    windows_sys::Win32::Foundation::GetLastError(),
                ))
            }
        }
    }
}
