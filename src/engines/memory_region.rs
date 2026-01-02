use crate::core::findings::{DetectionTechnique, Finding, MemoryRegionInfo, ProcessMetadata};
use windows_sys::Win32::System::Memory::*;

pub struct MemoryRegionEngine;

impl MemoryRegionEngine {
    pub fn analyze(process: &ProcessMetadata, regions: &[MemoryRegionInfo]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for region in regions {
            // 1. Detect RWX memory regions
            if (region.protection & PAGE_EXECUTE_READWRITE) != 0 {
                findings.push(Finding {
                    process: process.clone(),
                    region: Some(region.clone()),
                    engine_name: "MemoryRegionEngine".to_string(),
                    technique: DetectionTechnique::UnbackedExecutableMemory,
                    confidence: 85,
                    explanation: format!(
                        "RWX region detected at 0x{:X}. This violates W^X principles and is often used for staging shellcode.",
                        region.base_address
                    ),
                    recommended_action: "Analyze memory content for executable code.".to_string(),
                });
            }

            // 2. Executable memory in Private/Typical Heap/Stack regions
            if (region.protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
                != 0
                && region.region_type == MEM_PRIVATE
            {
                findings.push(Finding {
                        process: process.clone(),
                        region: Some(region.clone()),
                        engine_name: "MemoryRegionEngine".to_string(),
                        technique: DetectionTechnique::UnbackedExecutableMemory,
                        confidence: 75,
                        explanation: format!(
                            "File-unbacked executable memory (MEM_PRIVATE) detected at 0x{:X}. Potential manual mapping or reflective injection.",
                            region.base_address
                        ),
                        recommended_action: "Check for PE headers or shellcode stubs in this region.".to_string(),
                    });
            }

            // 3. Detect "Executable WriteCopy" - unusual for legitimate code
            if (region.protection & PAGE_EXECUTE_WRITECOPY) != 0 {
                findings.push(Finding {
                    process: process.clone(),
                    region: Some(region.clone()),
                    engine_name: "MemoryRegionEngine".to_string(),
                    technique: DetectionTechnique::UnbackedExecutableMemory,
                    confidence: 60,
                    explanation: format!(
                        "PAGE_EXECUTE_WRITECOPY protection at 0x{:X}. Often used during the final stages of reflective loading.",
                        region.base_address
                    ),
                    recommended_action: "Monitor this region for further protection changes.".to_string(),
                });
            }

            // 4. Executable memory with Guard pages - suspicious behavior
            if (region.protection & PAGE_GUARD) != 0 && (region.protection & 0xF0) != 0 {
                findings.push(Finding {
                    process: process.clone(),
                    region: Some(region.clone()),
                    engine_name: "MemoryRegionEngine".to_string(),
                    technique: DetectionTechnique::UnbackedExecutableMemory,
                    confidence: 90,
                    explanation: format!(
                        "Executable memory with PAGE_GUARD detected at 0x{:X}. This is a classic anti-debugging or anti-dumping technique.",
                        region.base_address
                    ),
                    recommended_action: "Attempt memory dump with care, as it may trigger debugger traps.".to_string(),
                });
            }
        }

        findings
    }
}
