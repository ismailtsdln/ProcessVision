use crate::core::errors::Result;
use crate::core::findings::{Finding, ProcessMetadata};
use crate::core::memory_map::get_process_memory_map;
use crate::core::process_enum::enumerate_processes;

pub struct Scanner {
    // Future: add specific engines here
}

impl Scanner {
    pub fn new() -> Self {
        Self {}
    }

    pub fn scan_all(&self) -> Result<Vec<Finding>> {
        let processes = enumerate_processes()?;
        let mut all_findings = Vec::new();

        for process in processes {
            match self.scan_process(&process) {
                Ok(findings) => all_findings.extend(findings),
                Err(_) => continue, // Skip processes we can't access
            }
        }

        Ok(all_findings)
    }

    pub fn scan_process(&self, process: &ProcessMetadata) -> Result<Vec<Finding>> {
        let regions = get_process_memory_map(process.pid)?;
        let mut findings = Vec::new();

        // 1. Memory Region Analysis
        findings.extend(crate::engines::memory_region::MemoryRegionEngine::analyze(
            process, &regions,
        ));

        // 2. PE Analysis
        findings.extend(crate::engines::pe_analysis::PeAnalysisEngine::analyze(
            process, &regions,
        ));

        // 3. Shellcode Analysis
        findings.extend(crate::engines::shellcode::ShellcodeEngine::analyze(
            process, &regions,
        ));

        // 4. Hook Analysis
        findings.extend(crate::engines::hooks::HookEngine::analyze(
            process, &regions,
        ));

        // 5. Thread Analysis
        findings.extend(crate::engines::threads::ThreadEngine::analyze(
            process, &regions,
        ));

        Ok(findings)
    }
}
