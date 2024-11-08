use reqwest::Client;
use std::time::Duration;

// HTTP Error Codes that indicate the site exists
const ACTIVE_CODES: [u16; 29] = [
    200, 201, 202, 203, 204, 205, 206, // Successful responses
    300, 301, 302, 303, 304, 307, 308, // Redirection messages
    401, 403, 405, 406, 407, 408, 409, 410, // Client errors that may indicate the site exists
    429, // Too Many Requests (might mean rate-limited but active)
    500, 501, 502, 503, 504, 505, // Server errors
];

// HTTP Error Codes that indicate the site does not exist
const INACTIVE_CODES: [u16; 3] = [
    404, // Not Found
    410, // Gone
    451, // Unavailable For Legal Reasons
];

/// Check HTTP Status with support for redirects
pub async fn check_http(url: &str, verbose: bool) -> Result<(bool, bool), String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5)) // Lower timeout for faster failure
        .pool_max_idle_per_host(100) // Reuse connections
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| format!("HTTP Client Creation Failed: {}", e))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("HTTP Status Failed: {}", e))?;
    let final_url = response.url().clone();
    let status_code = response.status().as_u16();
    let is_active = ACTIVE_CODES.contains(&status_code);
    let is_inactive = INACTIVE_CODES.contains(&status_code);
    let redirected_to_www = final_url
        .host_str()
        .map_or(false, |host| host.starts_with("www."));

    if verbose {
        if is_active {
            println!(
                "HTTP check for {} succeeded with status code {}",
                url, status_code
            );
        } else if is_inactive {
            println!(
                "HTTP check for {} failed with status code {}",
                url, status_code
            );
        } else {
            println!(
                "HTTP check for {} returned status code {}",
                url, status_code
            );
        }
        if redirected_to_www {
            println!("Redirected to www: {}", final_url);
        }
    }

    Ok((is_active, redirected_to_www))
}
