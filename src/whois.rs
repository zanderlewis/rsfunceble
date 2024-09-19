use whois_rust::{WhoIs, WhoIsLookupOptions};

/// WHOIS Lookup
pub async fn check_whois(domain: &str, verbose: bool) -> Result<(), String> {
    let whois_client = WhoIs::from_string(domain).map_err(|e| e.to_string())?;
    let options = WhoIsLookupOptions::from_string(domain).map_err(|e| e.to_string())?;
    let result = whois_client.lookup(options)
        .map_err(|e| format!("WHOIS Lookup Failed: {}", e))
        .and_then(|result| {
            if !result.is_empty() {
                Ok(())
            } else {
                Err("WHOIS Lookup Failed: No data found".to_string())
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