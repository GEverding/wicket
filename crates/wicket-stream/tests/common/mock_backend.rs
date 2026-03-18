//! Mock TCP backend server for testing.
//!
//! Provides a simple TCP server that logs all connections and received data,
//! useful for verifying proxy behavior in integration tests.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::debug;

use super::proxy_protocol::ParsedProxyProtocol;

/// Log of a single connection to the mock backend.
#[derive(Debug, Clone)]
pub struct ConnectionLog {
    /// Address of the client that connected
    pub client_addr: SocketAddr,
    /// Raw bytes received from the client
    pub received_bytes: Vec<u8>,
    /// Parsed PROXY protocol header (if present)
    #[allow(dead_code)]
    pub proxy_protocol: Option<ParsedProxyProtocol>,
}

/// Mock TCP backend server that logs connections.
pub struct MockBackend {
    listener: TcpListener,
    pub addr: SocketAddr,
    connections: Arc<Mutex<Vec<ConnectionLog>>>,
}

impl MockBackend {
    /// Start a mock backend on a random port (127.0.0.1:0).
    pub async fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        debug!("MockBackend listening on {}", addr);

        Ok(Self {
            listener,
            addr,
            connections: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Accept one connection, log its data, and return the log.
    pub async fn accept_one(&self) -> std::io::Result<ConnectionLog> {
        let (mut socket, client_addr) = self.listener.accept().await?;

        debug!("MockBackend accepted connection from {}", client_addr);

        // Read all available data
        let mut received_bytes = Vec::new();

        // Try to read with a timeout to avoid hanging
        match tokio::time::timeout(
            std::time::Duration::from_millis(100),
            socket.read_buf(&mut received_bytes),
        )
        .await
        {
            Ok(Ok(_)) => {
                // Data read successfully
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Connection closed, that's fine
            }
            Err(_) => {
                // Timeout, that's fine - we got what we could
            }
            Ok(Err(e)) => return Err(e),
        }

        // Try to parse PROXY protocol header
        let proxy_protocol = ParsedProxyProtocol::parse(&received_bytes).map(|(pp, _)| pp);

        let log = ConnectionLog {
            client_addr,
            received_bytes,
            proxy_protocol,
        };

        // Store in connections log
        self.connections.lock().await.push(log.clone());

        Ok(log)
    }

    /// Accept connections in the background and store logs.
    ///
    /// Returns a JoinHandle that can be awaited or aborted.
    pub fn accept_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Ok((mut socket, client_addr)) = self.listener.accept().await {
                debug!(
                    "MockBackend (background) accepted connection from {}",
                    client_addr
                );

                let connections = Arc::clone(&self.connections);

                // Increment connection count immediately
                let log = ConnectionLog {
                    client_addr,
                    received_bytes: Vec::new(),
                    proxy_protocol: None,
                };
                connections.lock().await.push(log.clone());

                // Read data in background (don't block counter increment)
                tokio::spawn(async move {
                    let mut received_bytes = Vec::new();
                    let _ = socket.read_to_end(&mut received_bytes).await;

                    let _proxy_protocol =
                        ParsedProxyProtocol::parse(&received_bytes).map(|(pp, _)| pp);

                    // Update the log with received data
                    // Note: This is a simplified version - in a real implementation
                    // we'd update the existing log entry, but for these tests
                    // we only care about connection count
                });
            }
        })
    }

    /// Get all logged connections.
    #[allow(dead_code)]
    pub async fn connections(&self) -> Vec<ConnectionLog> {
        self.connections.lock().await.clone()
    }

    /// Get the number of connections received.
    pub async fn connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }

    /// Clear all logged connections.
    pub async fn clear(&self) {
        self.connections.lock().await.clear();
    }

    /// Get the last connection log (if any).
    pub async fn last_connection(&self) -> Option<ConnectionLog> {
        self.connections.lock().await.last().cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_mock_backend_start() {
        let backend = MockBackend::start().await.unwrap();
        assert!(backend.addr.ip().to_string().contains("127.0.0.1"));
        assert!(backend.addr.port() > 0);
    }

    #[tokio::test]
    async fn test_mock_backend_accept_one() {
        let backend = MockBackend::start().await.unwrap();
        let addr = backend.addr;

        // Connect and send data
        let handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(b"test data").await.unwrap();
            stream.flush().await.unwrap();
        });

        let log = backend.accept_one().await.unwrap();
        assert_eq!(log.received_bytes, b"test data");
        assert_eq!(log.client_addr.ip().to_string(), "127.0.0.1");

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_mock_backend_connection_count() {
        let backend = Arc::new(MockBackend::start().await.unwrap());
        let addr = backend.addr;

        let backend_clone = Arc::clone(&backend);
        let handle = tokio::spawn(async move {
            let _ = backend_clone.accept_background().await;
        });

        // Connect multiple times
        for _ in 0..3 {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(b"data").await.unwrap();
        }

        // Give background task time to process
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let count = backend.connection_count().await;
        assert_eq!(count, 3);

        handle.abort();
    }

    #[tokio::test]
    async fn test_mock_backend_clear() {
        let backend = MockBackend::start().await.unwrap();
        let addr = backend.addr;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"data").await.unwrap();

        let _ = backend.accept_one().await;
        assert_eq!(backend.connection_count().await, 1);

        backend.clear().await;
        assert_eq!(backend.connection_count().await, 0);
    }

    #[tokio::test]
    async fn test_mock_backend_last_connection() {
        let backend = MockBackend::start().await.unwrap();
        let addr = backend.addr;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"test").await.unwrap();

        let _ = backend.accept_one().await;
        let last = backend.last_connection().await;

        assert!(last.is_some());
        assert_eq!(last.unwrap().received_bytes, b"test");
    }
}
