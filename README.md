# ProcessVision 🛡️

**ProcessVision** is a next-generation, signature-less process memory inspection and threat detection tool written in Rust. It is designed for blue teams, incident responders, and malware analysts to detect sophisticated in-memory threats.

![ProcessVision Banner](https://img.shields.io/badge/Status-Active-brightgreen)
![Rust](https://img.shields.io/badge/Language-Rust-orange)
![License](https://img.shields.io/badge/License-MIT-blue)

## ✨ Features

- **Advanced Memory Analysis**: Detects RWX regions, W^X violations, and executable memory in private/heap regions.
- **PE Integrity Engine**: Scans for manually mapped PEs, suspicious section names (packers), and malformed headers (anti-forensics).
- **Shellcode Heuristics**: Detects high-entropy payloads and common instruction patterns (PEB access, direct syscalls).
- **Hook & Integrity Detection**: Identifies potential API redirections and IAT/EAT hooking via indirect jump patterns.
- **Detection Correlation**: Automatically strengthens confidence scores when multiple engines flag the same region.
- **Modern CLI**: Feature-rich terminal interface with progress indicators, colored finding cards, and filtered scan modes.

## 🚀 Installation

### Prerequisites

- **OS**: Windows (Targeting WinAPI)
- **Rust**: Latest stable toolchain

### Build from source

```powershell
git clone https://github.com/ismailtsdln/ProcessVision.git
cd ProcessVision
cargo build --release
```

The binary will be located at `./target/release/processvision.exe`.

## 🛠️ Usage

### Scan all processes

```powershell
processvision scan-all
```

### Scan with filters (Name & Confidence)

```powershell
processvision scan-all --name chrome --min-confidence 70
```

### Deep scan a specific process

```powershell
processvision scan-pid 1234
```

## 🔍 Detection Engines

| Engine | Technique | Focus |
| :--- | :--- | :--- |
| **MemoryRegion** | Unbacked Executable Memory | RWX, W^X violations, Guard pages |
| **PeAnalysis** | Manual Mapping / Hollowing | Section audit, Header integrity |
| **Shellcode** | Shellcode Heuristics | High entropy, Syscall stubs, PEB access |
| **HookEngine** | API/IAT Hooking | Indirect jumps, inline hooks |
| **ThreadEngine** | Suspicious Execution | Private execution entry points |

## 🛡️ Safety & Reliability

- **Non-Destructive**: ProcessVision never modifies the target process. It only queries and reads memory.
- **Rust Powered**: Leverage's Rust's memory safety to avoid common security pitfalls.
- **Structured Errors**: Robust handling of UAC (Access Denied) and protected process errors.

## 🤝 Contribution

Contributions are welcome! If you have ideas for new detection engines or UI improvements, please open an issue or submit a pull request.

## ⚖️ License

Distributed under the MIT License. See `LICENSE` for more information.

---
**Created by Ismail Tasdelen**
