use whois_rust::{WhoIs, WhoIsLookupOptions};
use futures::future::join_all;
use std::collections::HashMap;
use serde_json::Value;
use url::Url;

/// WHOIS Lookup using multiple servers in parallel
pub async fn check_whois(domain: &str, whois_servers: &HashMap<String, Value>, verbose: bool) -> Result<(), String> {
    // Extract TLD from domain
    let parsed_url = Url::parse(&format!("http://{}", domain)).map_err(|e| e.to_string())?;
    let tld = parsed_url.domain().and_then(|d| d.split('.').last()).ok_or("Invalid domain")?;

    // Determine WHOIS server for the TLD
    let whois_server = whois_servers.get(tld).and_then(|v| v.as_str()).ok_or(format!("No WHOIS server found for TLD: {}", tld))?;

    let mut tasks = vec![];

    let domain = domain.to_string();
    let domain_clone = domain.clone();
    let server = whois_server.to_string();
    let task = tokio::spawn(async move {
        let whois_client = WhoIs::from_string(&server).map_err(|e| e.to_string())?;
        let options = WhoIsLookupOptions::from_string(&domain).map_err(|e| e.to_string())?;
        let result = whois_client.lookup(options)
            .map_err(|e| format!("WHOIS Lookup Failed: {}", e))
            .and_then(|result| {
                if !result.is_empty() {
                    Ok((server.clone(), result))
                } else {
                    Err(format!("WHOIS Lookup Failed: No data found on {}", server))
                }
            });
        result
    });
    tasks.push(task);

    let results = join_all(tasks).await;

    let mut success = false;
    for result in results {
        match result {
            Ok(Ok((server, _))) => {
                success = true;
                println!("WHOIS Lookup for {} succeeded using {}", domain_clone, server);
                break;
            }
            Ok(Err(e)) => {
                if verbose {
                    println!("WHOIS Lookup for {} failed: {}", domain_clone, e);
                }
            }
            Err(e) => {
                if verbose {
                    println!("WHOIS task for {} failed: {:?}", domain_clone, e);
                }
            }
        }
    }

    if success {
        Ok(())
    } else {
        Err(format!("All WHOIS lookups for {} failed", domain_clone))
    }
}