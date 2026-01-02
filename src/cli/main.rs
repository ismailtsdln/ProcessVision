use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
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
    ScanAll {
        /// Filter by process name
        #[arg(short, long)]
        name: Option<String>,
        /// Filter findings by minimum confidence (0-100)
        #[arg(short, long, default_value_t = 0)]
        min_confidence: u8,
    },
    /// Scan a specific process by PID
    ScanPid {
        pid: u32,
        /// Filter findings by minimum confidence (0-100)
        #[arg(short, long, default_value_t = 0)]
        min_confidence: u8,
    },
}

fn main() {
    let cli = Cli::parse();
    let scanner = Scanner::new();

    match cli.command {
        Commands::ScanAll {
            name,
            min_confidence,
        } => {
            println!("{}", "Starting full system memory scan...".bold().cyan());

            match processvision::core::process_enum::enumerate_processes() {
                Ok(mut procs) => {
                    if let Some(n) = name {
                        procs.retain(|p| p.name.to_lowercase().contains(&n.to_lowercase()));
                    }

                    let pb = ProgressBar::new(procs.len() as u64);
                    pb.set_style(ProgressStyle::default_bar()
                        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                        .unwrap()
                        .progress_chars("#>-"));

                    let mut all_findings = Vec::new();
                    for proc in procs {
                        if let Ok(findings) = scanner.scan_process(&proc) {
                            all_findings.extend(
                                findings
                                    .into_iter()
                                    .filter(|f| f.confidence >= min_confidence),
                            );
                        }
                        pb.inc(1);
                    }
                    pb.finish_with_message("Scan complete");
                    println!();
                    print_findings(all_findings);
                }
                Err(e) => eprintln!("{}: {}", "Error".red().bold(), e),
            }
        }
        Commands::ScanPid {
            pid,
            min_confidence,
        } => {
            println!("{} PID: {}", "Scanning process".bold().cyan(), pid);
            match processvision::core::process_enum::enumerate_processes() {
                Ok(procs) => {
                    if let Some(proc) = procs.iter().find(|p| p.pid == pid) {
                        match scanner.scan_process(proc) {
                            Ok(findings) => {
                                let filtered: Vec<_> = findings
                                    .into_iter()
                                    .filter(|f| f.confidence >= min_confidence)
                                    .collect();
                                print_findings(filtered);
                            }
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
        println!(
            "{}",
            "No threats detected matching criteria.".green().bold()
        );
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
