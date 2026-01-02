use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use processvision::core::scanner::Scanner;

#[derive(Parser)]
#[command(name = "processvision")]
#[command(about = "Next-Generation Process Memory Forensic Tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan all running processes with advanced heuristics
    ScanAll {
        /// Filter by process name
        #[arg(short, long)]
        name: Option<String>,
        /// Filter findings by minimum confidence (0-100)
        #[arg(short, long, default_value_t = 0)]
        min_confidence: u8,
    },
    /// Deep scan a specific process by PID
    ScanPid {
        pid: u32,
        /// Filter findings by minimum confidence (0-100)
        #[arg(short, long, default_value_t = 0)]
        min_confidence: u8,
    },
}

fn print_banner() {
    let banner = r#"
    ____                             _     _             
   |  _ \ _ __ ___   ___ ___  ___ ___| |   (_) ___  _ __  
   | |_) | '__/ _ \ / __/ _ \/ __/ __| \   | |/ _ \| '_ \ 
   |  __/| | | (_) | (_|  __/\__ \__ \ |___| | (_) | | | |
   |_|   |_|  \___/ \___\___||___/___/_____|_|\___/|_| |_|
    "#;
    println!("{}", banner.bright_cyan().bold());
    println!(
        "    {} v{} - {} by Ismail Tasdelen",
        "ProcessVision".white().bold(),
        env!("CARGO_PKG_VERSION").green(),
        "Memory Forensic Scanner".yellow().italic()
    );
    println!("{}\n", "=".repeat(70).bright_black());
}

fn main() {
    let cli = Cli::parse();
    let scanner = Scanner::new();

    print_banner();

    match cli.command {
        Commands::ScanAll {
            name,
            min_confidence,
        } => {
            println!(
                " {} {}",
                "▶".bright_blue(),
                "Initializing system-wide memory scan...".bold()
            );

            match processvision::core::process_enum::enumerate_processes() {
                Ok(mut procs) => {
                    if let Some(n) = name {
                        procs.retain(|p| p.name.to_lowercase().contains(&n.to_lowercase()));
                    }

                    let pb = ProgressBar::new(procs.len() as u64);
                    pb.set_style(ProgressStyle::default_bar()
                        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                        .unwrap()
                        .progress_chars("#>-"));

                    let mut all_findings = Vec::new();
                    for proc in procs {
                        pb.set_message(format!("Scanning {} (PID: {})", proc.name, proc.pid));
                        if let Ok(findings) = scanner.scan_process(&proc) {
                            all_findings.extend(
                                findings
                                    .into_iter()
                                    .filter(|f| f.confidence >= min_confidence),
                            );
                        }
                        pb.inc(1);
                    }
                    pb.finish_with_message("Scan Completed");
                    println!("\n{}\n", "=".repeat(70).bright_black());
                    print_findings(all_findings);
                }
                Err(e) => eprintln!("{}: {}", "Error".red().bold(), e),
            }
        }
        Commands::ScanPid {
            pid,
            min_confidence,
        } => {
            println!(
                " {} {} PID: {}",
                "▶".bright_blue(),
                "Deep scanning process".bold(),
                pid.to_string().bright_yellow()
            );
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
            " {} {}",
            "✔".bright_green().bold(),
            "No anomalies detected matching the criteria."
                .green()
                .bold()
        );
        return;
    }

    println!(
        " {} {} suspicious indicator(s) identified!\n",
        "⚠".bright_red().bold(),
        findings.len().to_string().bright_red().bold()
    );

    for finding in findings {
        let confidence_color = if finding.confidence > 80 {
            finding.confidence.to_string().red().bold()
        } else if finding.confidence > 50 {
            finding.confidence.to_string().yellow().bold()
        } else {
            finding.confidence.to_string().cyan()
        };

        println!(
            "┌── {} {}",
            "[FINDING]".bright_red().bold(),
            finding.engine_name.bright_black()
        );
        println!(
            "│  {:<15}: {} (PID: {})",
            "Process".bold(),
            finding.process.name.bright_white(),
            finding.process.pid
        );
        println!("│  {:<15}: {:?}", "Technique".bold(), finding.technique);
        println!("│  {:<15}: {}%", "Confidence".bold(), confidence_color);

        if let Some(region) = &finding.region {
            println!(
                "│  {:<15}: 0x{:X} (Size: {} KB)",
                "Region".bold(),
                region.base_address,
                region.size / 1024
            );
        }

        println!("│");
        println!("│  {}:", "Explanation".bold());
        for line in finding.explanation.lines() {
            println!("│    {}", line.dimmed());
        }

        println!("│");
        println!("│  {}:", "Action".bold());
        println!("│    {}", finding.recommended_action.bright_blue());
        println!("└──{}\n", "─".repeat(57).bright_black());
    }
}
