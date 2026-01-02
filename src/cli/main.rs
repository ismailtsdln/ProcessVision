use clap::{Parser, Subcommand};
use colored::Colorize;
use processvision::core::scanner::Scanner;

#[derive(Parser)]
#[command(name = "processvision")]
#[command(about = "Advanced Process Memory Threat Detection", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan all running processes
    ScanAll,
    /// Scan a specific process by PID
    ScanPid { pid: u32 },
}

fn main() {
    let cli = Cli::parse();
    let scanner = Scanner::new();

    match cli.command {
        Commands::ScanAll => {
            println!("{}", "Starting full system memory scan...".bold().cyan());
            match scanner.scan_all() {
                Ok(findings) => print_findings(findings),
                Err(e) => eprintln!("{}: {}", "Error".red().bold(), e),
            }
        }
        Commands::ScanPid { pid } => {
            println!("{} PID: {}", "Scanning process".bold().cyan(), pid);
            // For now, scan_process needs a ProcessMetadata which requires name, etc.
            // In a real implementation we'd look it up.
            // Let's just wrap it for this demonstration.
            match processvision::core::process_enum::enumerate_processes() {
                Ok(procs) => {
                    if let Some(proc) = procs.iter().find(|p| p.pid == pid) {
                        match scanner.scan_process(proc) {
                            Ok(findings) => print_findings(findings),
                            Err(e) => eprintln!("{}: {}", "Error".red().bold(), e),
                        }
                    } else {
                        eprintln!("{}: PID {} not found", "Error".red().bold(), pid);
                    }
                }
                Err(e) => eprintln!("{}: {}", "Error".red().bold(), e),
            }
        }
    }
}

fn print_findings(findings: Vec<processvision::core::findings::Finding>) {
    if findings.is_empty() {
        println!("{}", "No threats detected.".green().bold());
        return;
    }

    println!(
        "{} {} finding(s) detected!\n",
        "ALERT:".red().bold(),
        findings.len()
    );

    for finding in findings {
        println!("{}", "=".repeat(60).yellow());
        println!(
            "{}: {} (PID: {})",
            "Process".bold(),
            finding.process.name,
            finding.process.pid
        );
        println!("{}: {:?}", "Technique".bold(), finding.technique);
        println!("{}: {}/100", "Confidence".bold(), finding.confidence);
        println!("{}: {}", "Engine".bold(), finding.engine_name);
        if let Some(region) = &finding.region {
            println!(
                "{}: 0x{:X} (Size: {} bytes)",
                "Region".bold(),
                region.base_address,
                region.size
            );
        }
        println!("\n{}:", "Explanation".bold());
        println!("{}", finding.explanation);
        println!("\n{}:", "Action".bold());
        println!("{}", finding.recommended_action);
        println!("{}\n", "=".repeat(60).yellow());
    }
}
