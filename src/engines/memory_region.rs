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
                    confidence: 80,
                    explanation: format!(
                        "RWX (Read-Write-Execute) memory region detected at 0x{:X}. This is a common indicator of shellcode or self-modifying code.",
                        region.base_address
                    ),
                    recommended_action: "Inspect the memory content for shellcode or injected PE files.".to_string(),
                });
            }

            // 2. Detect executable memory that is PRIVATE (not mapped from file)
            // Note: In Windows, Type MEM_PRIVATE usually indicates it's not a mapped file.
            if (region.protection
                & (PAGE_EXECUTE
                    | PAGE_EXECUTE_READ
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY))
                != 0
                && region.region_type == MEM_PRIVATE
            {
                findings.push(Finding {
                    process: process.clone(),
                    region: Some(region.clone()),
                    engine_name: "MemoryRegionEngine".to_string(),
                    technique: DetectionTechnique::UnbackedExecutableMemory,
                    confidence: 70,
                    explanation: format!(
                        "Executable memory at 0x{:X} is not backed by a file (MEM_PRIVATE). This often indicates manual mapping or reflective injection.",
                        region.base_address
                    ),
                    recommended_action: "Correlate with PE analysis to see if a valid PE structure exists in this region.".to_string(),
                });
            }
        }

        findings
    }
}
