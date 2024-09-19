extern crate clap;
extern crate reqwest;
extern crate tokio;
extern crate trust_dns_resolver;
extern crate whois_rust;
extern crate url;

mod http;
mod dns;
mod whois;

use clap::Parser;
use tokio::task;
use std::sync::Arc;
use tokio::sync::Semaphore;
use std::fs::{OpenOptions, remove_file};
use std::io::Write;
use url::Url;

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

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Perform DNS checks
    #[arg(long)]
    dns: bool,
}

/// Main logic for checking a single domain or URL
async fn check_domain_or_url(input: String, semaphore: Arc<Semaphore>, output_file: String, exclude: String, verbose: bool, dns_check: bool) -> Result<(), String> {
    let permit = semaphore.acquire().await.map_err(|e| e.to_string())?;
    
    if verbose {
        println!("Checking: {}", input);
    }

    let url = if input.starts_with("http://") || input.starts_with("https://") {
        input.clone()
    } else {
        format!("http://{}", input)
    };

    let (http_success, redirected_to_www) = http::check_http(&url, verbose).await.unwrap_or((false, false));

    let status = if http_success || redirected_to_www {
        "ACTIVE"
    } else if dns_check {
        let domain = Url::parse(&url).ok().and_then(|parsed_url| parsed_url.host_str().map(|s| s.to_string()));
        if let Some(domain) = domain {
            let dns_result = dns::check_dns(&domain, verbose).await;
            if dns_result.is_ok() {
                let whois_result = whois::check_whois(&domain, verbose).await;
                if whois_result.is_ok() {
                    "ACTIVE"
                } else {
                    "INACTIVE"
                }
            } else {
                "INACTIVE"
            }
        } else {
            "INACTIVE"
        }
    } else {
        "INACTIVE"
    };

    if status != exclude {
        let file_path = format!("{}_{}.txt", output_file, status);
        let mut file = OpenOptions::new().append(true).create(true).open(&file_path).map_err(|e| e.to_string())?;
        writeln!(file, "{}", input).map_err(|e| e.to_string())?;
    }

    if verbose {
        println!("{}: {}", input, status);
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
        let verbose = args.verbose;
        let dns_check = args.dns;
        let handle = task::spawn(async move {
            if let Err(e) = check_domain_or_url(input, sem_clone, output_file, exclude, verbose, dns_check).await {
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

    if args.verbose {
        println!("All tasks completed.");
    }
    Ok(())
}