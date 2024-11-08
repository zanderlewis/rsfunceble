extern crate clap;
extern crate colored;
extern crate futures;
extern crate reqwest;
extern crate tokio;

mod http;

use clap::Parser;
use colored::*;
use std::fs::{remove_file, OpenOptions};
use std::io::Write;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task;

/// CLI Arguments definition using Clap
#[derive(Parser)]
struct Args {
    /// Input file containing the list of domains or URLs to check
    #[arg(short, long)]
    input_file: String,

    /// Output file to write the results
    #[arg(short, long)]
    output_file: String,

    /// Excluded output files [ACTIVE, INACTIVE]
    #[arg(short, long, default_value = "")]
    exclude: String,

    /// Number of concurrent tasks
    #[arg(short, long, default_value_t = 10)]
    concurrency: usize,

    /// Verbose output level (1 or 2)
    #[arg(short, long, default_value_t = 1)]
    verbose_level: u8,
}

/// Main logic for checking a single domain or URL
async fn check_domain_or_url(
    input: String,
    semaphore: Arc<Semaphore>,
    output_file: String,
    exclude: String,
    verbose_level: u8,
) -> Result<(), String> {
    let permit = semaphore.acquire().await.map_err(|e| e.to_string())?;

    if verbose_level > 1 {
        println!("Checking: {}", input);
    }

    let url = if input.starts_with("http://") || input.starts_with("https://") {
        input.clone()
    } else {
        format!("http://{}", input)
    };

    let (http_success, redirected_to_www) = http::check_http(&url, verbose_level > 1)
        .await
        .unwrap_or((false, false));

    let status = if http_success || redirected_to_www {
        "ACTIVE"
    } else {
        "INACTIVE"
    };

    if status != exclude {
        let file_path = format!("{}_{}.txt", output_file, status);
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&file_path)
            .map_err(|e| e.to_string())?;
        writeln!(file, "{}", input).map_err(|e| e.to_string())?;
    }

    if verbose_level > 0 {
        let status_colored = match status {
            "ACTIVE" => status.bold().green(),
            "INACTIVE" => status.bold().red(),
            _ => status.normal(),
        };
        println!("{}: {}", input, status_colored);
    }

    if verbose_level > 1 {
        println!("Finished checking: {}", input);
    }

    drop(permit); // Release semaphore permit
    Ok(())
}

/// Delete output files if they exist
fn delete_output_files(output_file: &str) {
    let active_file = format!("{}_ACTIVE.txt", output_file);
    let inactive_file = format!("{}_INACTIVE.txt", output_file);

    if std::path::Path::new(&active_file).exists() {
        remove_file(&active_file).unwrap();
    }

    if std::path::Path::new(&inactive_file).exists() {
        remove_file(&inactive_file).unwrap();
    }
}

/// Main function
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command-line arguments
    let args = Args::parse();

    // Delete output files if they exist
    delete_output_files(&args.output_file);

    // Read input file
    let contents = std::fs::read_to_string(args.input_file)?;
    let inputs: Vec<String> = contents.lines().map(|s| s.to_string()).collect();

    // Set concurrency limit
    let semaphore = Arc::new(Semaphore::new(args.concurrency));

    // Run checks concurrently
    let mut handles = vec![];

    for input in inputs {
        let sem_clone = semaphore.clone();
        let output_file = args.output_file.clone();
        let exclude = args.exclude.clone();
        let verbose_level = args.verbose_level;
        let handle = task::spawn(async move {
            if let Err(e) =
                check_domain_or_url(input, sem_clone, output_file, exclude, verbose_level).await
            {
                eprintln!("Error checking domain or URL: {}", e);
            }
        });
        handles.push(handle);
    }

    // Await all tasks
    for handle in handles {
        if let Err(e) = handle.await {
            eprintln!("Task failed: {:?}", e);
        }
    }

    if args.verbose_level > 0 {
        println!("All tasks completed.");
    }
    Ok(())
}
