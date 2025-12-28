//! Cloudflare DNS API client for ACME DNS-01 challenges.

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

#[derive(Debug, Error)]
pub enum CloudflareError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("API error: {message}")]
    Api { code: i32, message: String },

    #[error("zone not found for domain: {0}")]
    ZoneNotFound(String),

    #[error("unexpected response format")]
    UnexpectedResponse,
}

/// Cloudflare DNS API client.
pub struct CloudflareClient {
    client: reqwest::Client,
    api_token: String,
}

impl CloudflareClient {
    /// Create a new Cloudflare client with the given API token.
    pub fn new(api_token: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_token,
        }
    }

    /// Get the zone ID for a domain.
    ///
    /// Automatically finds the root zone (e.g., for "api.example.com" finds "example.com").
    pub async fn get_zone_id(&self, domain: &str) -> Result<String, CloudflareError> {
        // Try progressively shorter domain parts
        let parts: Vec<&str> = domain.split('.').collect();

        for i in 0..parts.len().saturating_sub(1) {
            let zone_name = parts[i..].join(".");

            let url = format!("{}/zones?name={}", CF_API_BASE, zone_name);
            let resp: ZoneListResponse = self.get(&url).await?;

            if let Some(zone) = resp.result.first() {
                return Ok(zone.id.clone());
            }
        }

        Err(CloudflareError::ZoneNotFound(domain.to_string()))
    }

    /// Create a TXT record for ACME DNS-01 challenge.
    ///
    /// Returns the record ID for later deletion.
    pub async fn create_txt_record(
        &self,
        zone_id: &str,
        name: &str,
        content: &str,
    ) -> Result<String, CloudflareError> {
        let url = format!("{}/zones/{}/dns_records", CF_API_BASE, zone_id);

        let body = CreateRecordRequest {
            record_type: "TXT".to_string(),
            name: name.to_string(),
            content: content.to_string(),
            ttl: 60, // Short TTL for challenge records
        };

        let resp: CreateRecordResponse = self.post(&url, &body).await?;

        Ok(resp.result.id)
    }

    /// Delete a DNS record.
    pub async fn delete_txt_record(
        &self,
        zone_id: &str,
        record_id: &str,
    ) -> Result<(), CloudflareError> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            CF_API_BASE, zone_id, record_id
        );
        self.delete(&url).await
    }

    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.api_token)).unwrap(),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T, CloudflareError> {
        let resp = self.client.get(url).headers(self.headers()).send().await?;

        self.handle_response(resp).await
    }

    async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<T, CloudflareError> {
        let resp = self
            .client
            .post(url)
            .headers(self.headers())
            .json(body)
            .send()
            .await?;

        self.handle_response(resp).await
    }

    async fn delete(&self, url: &str) -> Result<(), CloudflareError> {
        let resp = self
            .client
            .delete(url)
            .headers(self.headers())
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let error: ApiErrorResponse = resp.json().await?;
            if let Some(err) = error.errors.first() {
                return Err(CloudflareError::Api {
                    code: err.code,
                    message: err.message.clone(),
                });
            }
        }

        Ok(())
    }

    async fn handle_response<T: for<'de> Deserialize<'de>>(
        &self,
        resp: reqwest::Response,
    ) -> Result<T, CloudflareError> {
        let status = resp.status();
        let text = resp.text().await?;

        if !status.is_success() {
            if let Ok(error) = serde_json::from_str::<ApiErrorResponse>(&text) {
                if let Some(err) = error.errors.first() {
                    return Err(CloudflareError::Api {
                        code: err.code,
                        message: err.message.clone(),
                    });
                }
            }
            return Err(CloudflareError::Api {
                code: status.as_u16() as i32,
                message: text,
            });
        }

        serde_json::from_str(&text).map_err(|_| CloudflareError::UnexpectedResponse)
    }
}

// API Response types

#[derive(Debug, Deserialize)]
struct ZoneListResponse {
    result: Vec<Zone>,
}

#[derive(Debug, Deserialize)]
struct Zone {
    id: String,
}

#[derive(Debug, Serialize)]
struct CreateRecordRequest {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
}

#[derive(Debug, Deserialize)]
struct CreateRecordResponse {
    result: DnsRecord,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
}

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    errors: Vec<ApiError>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: i32,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = CloudflareClient::new("test_token".to_string());
        assert!(!client.api_token.is_empty());
    }

    // Integration tests would require mocking or actual CF credentials
    // Add #[ignore] tests for manual testing with real credentials

    #[tokio::test]
    #[ignore]
    async fn test_get_zone_id() {
        let token = std::env::var("CF_API_TOKEN").expect("CF_API_TOKEN required");
        let client = CloudflareClient::new(token);

        let zone_id = client.get_zone_id("example.com").await.unwrap();
        println!("Zone ID: {}", zone_id);
    }
}
