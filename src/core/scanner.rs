use crate::core::errors::Result;
use crate::core::findings::{Finding, ProcessMetadata};
use crate::core::memory_map::get_process_memory_map;
use crate::core::process_enum::enumerate_processes;

pub struct Scanner {
    // Future: add specific engines here
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
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
        let mut raw_findings = Vec::new();

        // 1. Memory Region Analysis
        raw_findings.extend(crate::engines::memory_region::MemoryRegionEngine::analyze(
            process, &regions,
        ));

        // 2. PE Analysis
        raw_findings.extend(crate::engines::pe_analysis::PeAnalysisEngine::analyze(
            process, &regions,
        ));

        // 3. Shellcode Analysis
        raw_findings.extend(crate::engines::shellcode::ShellcodeEngine::analyze(
            process, &regions,
        ));

        // 4. Hook Analysis
        raw_findings.extend(crate::engines::hooks::HookEngine::analyze(
            process, &regions,
        ));

        // 5. Thread Analysis
        raw_findings.extend(crate::engines::threads::ThreadEngine::analyze(
            process, &regions,
        ));

        // Correlation Logic: Group findings by region address
        let mut correlated_findings = Vec::new();
        let mut handled_indices = std::collections::HashSet::new();

        for i in 0..raw_findings.len() {
            if handled_indices.contains(&i) {
                continue;
            }

            let mut base_finding = raw_findings[i].clone();
            handled_indices.insert(i);

            for (j, other_finding) in raw_findings.iter().enumerate().skip(i + 1) {
                if handled_indices.contains(&j) {
                    continue;
                }

                if let (Some(r1), Some(r2)) = (&base_finding.region, &other_finding.region) {
                    if r1.base_address == r2.base_address {
                        // Strengthen confidence score
                        base_finding.confidence =
                            base_finding.confidence.saturating_add(15).min(100);
                        base_finding.explanation.push_str(&format!(
                            "\n[Correlation] Also flagged by {} as {:?}",
                            raw_findings[j].engine_name, raw_findings[j].technique
                        ));
                        handled_indices.insert(j);
                    }
                }
            }
            correlated_findings.push(base_finding);
        }

        Ok(correlated_findings)
    }
}
