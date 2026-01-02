use crate::core::findings::{DetectionTechnique, Finding, MemoryRegionInfo, ProcessMetadata};
use crate::core::process_handle::ProcessHandle;
use goblin::pe::PE;

pub struct PeAnalysisEngine;

impl PeAnalysisEngine {
    pub fn analyze(
        process: &ProcessMetadata,
        handle: &ProcessHandle,
        regions: &[MemoryRegionInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for region in regions {
            if region.size < 4096 {
                continue;
            }

            let mut buffer = vec![0u8; 4096];
            if handle.read_memory(region.base_address, &mut buffer).is_ok()
                && buffer.starts_with(b"MZ")
            {
                if let Ok(pe) = PE::parse(&buffer) {
                    // 1. Detect manual mapping in private memory
                    if region.region_type == windows_sys::Win32::System::Memory::MEM_PRIVATE {
                        findings.push(Finding {
                            process: process.clone(),
                            region: Some(region.clone()),
                            engine_name: "PeAnalysisEngine".to_string(),
                            technique: DetectionTechnique::ManualMapping,
                            confidence: 95,
                            explanation: format!(
                                "Manually mapped PE detected in private memory at 0x{:X}.",
                                region.base_address
                            ),
                            recommended_action: "Inspect the PE exports and strings.".to_string(),
                        });
                    }

                    // 2. Detect Suspicious Section Names (e.g., UPX, .text1, etc.)
                    for section in &pe.sections {
                        let name = String::from_utf8_lossy(&section.name)
                            .trim_matches(char::from(0))
                            .to_string();
                        if ["upx", "pack", ".text1", ".pdata"]
                            .iter()
                            .any(|&s| name.to_lowercase().contains(s))
                        {
                            findings.push(Finding {
                                process: process.clone(),
                                region: Some(region.clone()),
                                engine_name: "PeAnalysisEngine".to_string(),
                                technique: DetectionTechnique::CodeIntegrityMismatch,
                                confidence: 50,
                                explanation: format!(
                                    "Suspicious section name '{}' detected in PE at 0x{:X}.",
                                    name, region.base_address
                                ),
                                recommended_action:
                                    "Verify if the file on disk uses the same packer.".to_string(),
                            });
                        }
                    }

                    // 3. Detect Section Overlap or Discrepancy
                    // If VirtualSize is much larger than SizeOfRawData in memory, it might be unpacked.
                } else {
                    // 4. MZ present but PE header invalid/malformed (Anti-forensics)
                    findings.push(Finding {
                            process: process.clone(),
                            region: Some(region.clone()),
                            engine_name: "PeAnalysisEngine".to_string(),
                            technique: DetectionTechnique::ProcessHollowing,
                            confidence: 40,
                            explanation: format!(
                                "MZ header found at 0x{:X} but subsequent PE header is malformed or wiped. Common anti-analysis technique.",
                                region.base_address
                            ),
                            recommended_action: "Examine the region for shellcode that may have overwritten the header.".to_string(),
                        });
                }
            }
        }

        findings
    }
}
