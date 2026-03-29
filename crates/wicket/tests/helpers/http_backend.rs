//! A minimal HTTP/1.1 mock backend for proxy e2e tests.
//!
//! Binds to `127.0.0.1:0` (free port), accepts connections, parses enough
//! of the HTTP request to log it, and writes back a canned 200 response.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// A captured HTTP request.
#[derive(Debug, Clone)]
pub struct RequestLog {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

/// A lightweight HTTP/1.1 mock backend.
pub struct HttpMockBackend {
    pub addr: SocketAddr,
    requests: Arc<Mutex<Vec<RequestLog>>>,
    response_body: String,
    _handle: tokio::task::JoinHandle<()>,
}

impl HttpMockBackend {
    /// Start a new mock backend that returns `response_body` for every request.
    pub async fn start(response_body: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock backend");
        let addr = listener.local_addr().expect("local addr");
        let requests: Arc<Mutex<Vec<RequestLog>>> = Arc::new(Mutex::new(Vec::new()));
        let requests_clone = Arc::clone(&requests);
        let body = response_body.to_string();

        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };

                let reqs = Arc::clone(&requests_clone);
                let resp_body = body.clone();

                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);

                    // Read request line
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).await.is_err() {
                        return;
                    }
                    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
                    let (method, path) = if parts.len() >= 2 {
                        (parts[0].to_string(), parts[1].to_string())
                    } else {
                        return;
                    };

                    // Read headers until blank line
                    let mut headers = Vec::new();
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).await.is_err() {
                            break;
                        }
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            break;
                        }
                        if let Some((k, v)) = trimmed.split_once(':') {
                            headers.push((k.trim().to_lowercase(), v.trim().to_string()));
                        }
                    }

                    reqs.lock().await.push(RequestLog {
                        method,
                        path,
                        headers,
                    });

                    // Write HTTP response
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = writer.write_all(response.as_bytes()).await;
                    let _ = writer.flush().await;
                });
            }
        });

        HttpMockBackend {
            addr,
            requests,
            response_body: response_body.to_string(),
            _handle: handle,
        }
    }

    /// Get all captured requests.
    pub async fn requests(&self) -> Vec<RequestLog> {
        self.requests.lock().await.clone()
    }

    /// Get the number of captured requests.
    pub async fn request_count(&self) -> usize {
        self.requests.lock().await.len()
    }

    /// Get the last captured request, if any.
    pub async fn last_request(&self) -> Option<RequestLog> {
        self.requests.lock().await.last().cloned()
    }

    /// Clear all captured requests.
    pub async fn clear(&self) {
        self.requests.lock().await.clear();
    }

    /// Get the response body this backend returns.
    pub fn response_body(&self) -> &str {
        &self.response_body
    }
}
