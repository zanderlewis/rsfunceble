extern crate clap;
extern crate reqwest;
extern crate tokio;
extern crate trust_dns_resolver;
extern crate whois_rust;

use clap::Parser;
use reqwest::get;
use tokio::task;
use trust_dns_resolver::TokioAsyncResolver;
use whois_rust::{WhoIs, WhoIsLookupOptions};
use std::sync::Arc;
use tokio::sync::Semaphore;
use std::fs::{OpenOptions, remove_file};
use std::io::Write;

/// CLI Arguments definition using Clap
#[derive(Parser)]
struct Args {
    /// Input file containing the list of domains to check
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
}

/// Check DNS resolution
async fn check_dns(domain: &str, verbose: bool) -> Result<(), String> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf().map_err(|e| e.to_string())?;
    let result = resolver.lookup_ip(domain).await.map(|_| ()).map_err(|_| "DNS Lookup Failed".to_string());
    if verbose {
        match &result {
            Ok(_) => println!("DNS Lookup for {} succeeded", domain),
            Err(_) => println!("DNS Lookup for {} failed", domain),
        }
    }
    result
}

/// Check HTTP Status
async fn check_http(domain: &str, verbose: bool) -> Result<(), String> {
    let url = format!("http://{}", domain);
    let result = get(&url).await
        .map_err(|_| "HTTP Status Failed".to_string())
        .and_then(|response| {
            if response.status().is_success() {
                Ok(())
            } else {
                Err("HTTP Status Failed".to_string())
            }
        });
    if verbose {
        match &result {
            Ok(_) => println!("HTTP check for {} succeeded", domain),
            Err(_) => println!("HTTP check for {} failed", domain),
        }
    }
    result
}

/// WHOIS Lookup
async fn check_whois(domain: &str, verbose: bool) -> Result<(), String> {
    let whois_client = WhoIs::from_string(domain).map_err(|e| e.to_string())?;
    let options = WhoIsLookupOptions::from_string(domain).map_err(|e| e.to_string())?;
    let result = whois_client.lookup(options)
        .map_err(|e| e.to_string())
        .and_then(|result| {
            if !result.is_empty() {
                Ok(())
            } else {
                Err("WHOIS Lookup Failed".to_string())
            }
        });
    if verbose {
        match &result {
            Ok(_) => println!("WHOIS Lookup for {} succeeded", domain),
            Err(_) => println!("WHOIS Lookup for {} failed: {}", domain, result.as_ref().err().unwrap()),
        }
    }
    result
}

/// Main logic for checking a single domain
async fn check_domain(domain: String, semaphore: Arc<Semaphore>, output_file: String, exclude: String, verbose: bool) {
    let permit = semaphore.acquire().await.unwrap();
    
    if verbose {
        println!("Checking: {}", domain);
    }
    
    let dns_result = check_dns(&domain, verbose).await;
    let http_result = check_http(&domain, verbose).await;

    let status = if http_result.is_ok() {
        "ACTIVE"
    } else {
        let whois_result = check_whois(&domain, verbose).await;
        if dns_result.is_ok() && whois_result.is_ok() {
            "ACTIVE"
        } else {
            "INACTIVE"
        }
    };

    if status != exclude {
        let file_path = format!("{}_{}.txt", output_file, status);
        let mut file = OpenOptions::new().append(true).create(true).open(&file_path).unwrap();
        writeln!(file, "{}", domain).unwrap();
    }

    if verbose {
        println!("{}: {}", domain, status);
        println!("Finished checking: {}", domain);
    }
    
    drop(permit); // Release semaphore permit
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
    let domains: Vec<String> = contents.lines().map(|s| s.to_string()).collect();
    
    // Set concurrency limit
    let semaphore = Arc::new(Semaphore::new(args.concurrency));
    
    // Run checks concurrently
    let mut handles = vec![];
    
    for domain in domains {
        let sem_clone = semaphore.clone();
        let output_file = args.output_file.clone();
        let exclude = args.exclude.clone();
        let verbose = args.verbose;
        let handle = task::spawn(async move {
            check_domain(domain, sem_clone, output_file, exclude, verbose).await;
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