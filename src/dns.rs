use trust_dns_resolver::TokioAsyncResolver;

/// Check DNS resolution
pub async fn check_dns(domain: &str, verbose: bool) -> Result<(), String> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf().map_err(|e| e.to_string())?;
    let result = resolver.lookup_ip(domain).await.map(|_| ()).map_err(|e| format!("DNS Lookup Failed: {}", e));
    if verbose {
        match &result {
            Ok(_) => println!("DNS Lookup for {} succeeded", domain),
            Err(_) => println!("DNS Lookup for {} failed", domain),
        }
    }
    result
}