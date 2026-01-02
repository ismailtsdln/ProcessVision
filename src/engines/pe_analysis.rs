use crate::core::errors::Result;
use crate::core::findings::{DetectionTechnique, Finding, MemoryRegionInfo, ProcessMetadata};
use goblin::pe::PE;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Threading::*;

pub struct PeAnalysisEngine;

impl PeAnalysisEngine {
    pub fn analyze(process: &ProcessMetadata, regions: &[MemoryRegionInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1. Look for PE headers in memory regions that are PRIVATE or unusual
        for region in regions {
            if region.size < 1024 {
                continue;
            } // Too small for PE header

            // Read first 1024 bytes to check for PE header
            let mut buffer = vec![0u8; 1024];
            if Self::read_process_memory(process.pid, region.base_address, &mut buffer).is_ok() {
                if buffer.starts_with(b"MZ") {
                    // Possible PE header
                    if let Ok(_pe) = PE::parse(&buffer) {
                        // If it's MEM_PRIVATE, it's highly suspicious (Manual Mapping / Reflective Injection)
                        if region.region_type == windows_sys::Win32::System::Memory::MEM_PRIVATE {
                            findings.push(Finding {
                                process: process.clone(),
                                region: Some(region.clone()),
                                engine_name: "PeAnalysisEngine".to_string(),
                                technique: DetectionTechnique::ManualMapping,
                                confidence: 95,
                                explanation: format!(
                                    "Manually mapped PE detected in private memory at 0x{:X}. Valid MZ/PE headers found in a region not backed by a disk image.",
                                    region.base_address
                                ),
                                recommended_action: "Examine the exports and strings of this in-memory DLL to determine its purpose.".to_string(),
                            });
                        }
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
