use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMetadata {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionInfo {
    pub base_address: usize,
    pub allocation_base: usize,
    pub size: usize,
    pub protection: u32,
    pub state: u32,
    pub region_type: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionTechnique {
    ProcessHollowing,
    ManualMapping,
    ShellcodeInjection,
    ApiHooking,
    UnbackedExecutableMemory,
    SuspiciousThread,
    CodeIntegrityMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub process: ProcessMetadata,
    pub region: Option<MemoryRegionInfo>,
    pub engine_name: String,
    pub technique: DetectionTechnique,
    pub confidence: u8, // 0-100
    pub explanation: String,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub timestamp: String,
    pub findings: Vec<Finding>,
}
