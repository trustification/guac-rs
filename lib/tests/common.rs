const GUAC_URL: &str = "http://localhost:8080/query";

pub fn guac_url() -> String {
    std::env::var("GUAC_URL").unwrap_or_else(|_| GUAC_URL.to_string())
}
