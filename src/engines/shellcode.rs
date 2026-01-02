use crate::core::findings::{DetectionTechnique, Finding, MemoryRegionInfo, ProcessMetadata};
use crate::core::process_handle::ProcessHandle;
use entropy::shannon_entropy;

pub struct ShellcodeEngine;

impl ShellcodeEngine {
    pub fn analyze(
        process: &ProcessMetadata,
        handle: &ProcessHandle,
        regions: &[MemoryRegionInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Common shellcode/malware byte patterns
        let patterns = [
            (
                &[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00][..],
                "PEB Access (FS:[30h])",
            ), // mov eax, fs:[30h]
            (
                &[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60][..],
                "PEB Access (GS:[60h])",
            ), // mov rax, gs:[60h] (x64)
            (&[0xEB, 0xFE][..], "Infinite Loop / Spinlock Stub"), // jmp $
            (&[0xFF, 0xD0][..], "Indirect Call (Call EAX/RAX)"),
            (&[0x0F, 0x05][..], "Direct Syscall Instruction (x64)"),
        ];

        for region in regions {
            if (region.protection & 0xF0) != 0 {
                let scan_size = region.size.min(16384);
                let mut buffer = vec![0u8; scan_size];

                if handle.read_memory(region.base_address, &mut buffer).is_ok() {
                    // 1. High Entropy Check
                    let ent = shannon_entropy(&buffer);
                    if ent > 6.8 {
                        findings.push(Finding {
                            process: process.clone(),
                            region: Some(region.clone()),
                            engine_name: "ShellcodeEngine".to_string(),
                            technique: DetectionTechnique::ShellcodeInjection,
                            confidence: 80,
                            explanation: format!(
                                "Critical entropy ({:.2}) detected at 0x{:X}. High probability of encrypted payload.",
                                ent, region.base_address
                            ),
                            recommended_action: "Dump region and look for decoders.".to_string(),
                        });
                    }

                    // 2. Pattern Matching (Heuristic Signatures)
                    for (pattern, desc) in &patterns {
                        if let Some(pos) = buffer.windows(pattern.len()).position(|w| w == *pattern)
                        {
                            findings.push(Finding {
                                process: process.clone(),
                                region: Some(region.clone()),
                                engine_name: "ShellcodeEngine".to_string(),
                                technique: DetectionTechnique::ShellcodeInjection,
                                confidence: 70,
                                explanation: format!(
                                    "Suspicious instruction pattern '{}' found at offset 0x{:X} within region 0x{:X}.",
                                    desc, pos, region.base_address
                                ),
                                recommended_action: "Perform behavioral analysis to see if this code resolves system APIs.".to_string(),
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}
