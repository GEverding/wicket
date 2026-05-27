//! Stream backend endpoint parsing.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::StreamError;

/// Backend endpoint for stream upstreams.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StreamBackendAddr {
    /// TCP backend address.
    Tcp(SocketAddr),
    /// Unix domain socket backend path.
    Unix(PathBuf),
}

impl StreamBackendAddr {
    /// Parse a backend endpoint from config.
    pub fn parse(input: &str) -> Result<Self, StreamError> {
        input.parse()
    }

    /// Return the TCP address if this endpoint is TCP.
    #[must_use]
    pub fn as_tcp(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp(addr) => Some(*addr),
            Self::Unix(_) => None,
        }
    }

    /// Return the Unix socket path if this endpoint is Unix.
    #[must_use]
    pub fn as_unix_path(&self) -> Option<&Path> {
        match self {
            Self::Tcp(_) => None,
            Self::Unix(path) => Some(path),
        }
    }

    /// Return the backend transport name for diagnostics.
    #[must_use]
    pub fn transport(&self) -> &'static str {
        match self {
            Self::Tcp(_) => "TCP",
            Self::Unix(_) => "Unix",
        }
    }
}

impl FromStr for StreamBackendAddr {
    type Err = StreamError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.is_empty() {
            return Err(StreamError::ConfigError(
                "stream backend endpoint must not be empty".to_string(),
            ));
        }

        if let Some(path) = input.strip_prefix("unix:") {
            return parse_unix_endpoint(input, path);
        }

        let addr = input.parse::<SocketAddr>().map_err(|e| {
            StreamError::ConfigError(format!(
                "invalid TCP stream backend endpoint '{input}': {e}"
            ))
        })?;
        Ok(Self::Tcp(addr))
    }
}

impl fmt::Display for StreamBackendAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "{addr}"),
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

fn parse_unix_endpoint(input: &str, path: &str) -> Result<StreamBackendAddr, StreamError> {
    if path.is_empty() {
        return Err(StreamError::ConfigError(
            "unix stream backend endpoint must include an absolute path".to_string(),
        ));
    }
    if path.starts_with("//") {
        return Err(StreamError::ConfigError(format!(
            "invalid Unix stream backend endpoint '{input}': use unix:/absolute/path, not unix://"
        )));
    }

    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(StreamError::ConfigError(format!(
            "invalid Unix stream backend endpoint '{input}': path must be absolute"
        )));
    }

    Ok(StreamBackendAddr::Unix(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp_endpoint() {
        let endpoint = StreamBackendAddr::parse("127.0.0.1:8080").unwrap();
        assert_eq!(
            endpoint,
            StreamBackendAddr::Tcp("127.0.0.1:8080".parse().unwrap())
        );
        assert_eq!(endpoint.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn parses_ipv6_tcp_endpoint() {
        let endpoint = StreamBackendAddr::parse("[::1]:8080").unwrap();
        assert_eq!(
            endpoint,
            StreamBackendAddr::Tcp("[::1]:8080".parse().unwrap())
        );
        assert_eq!(endpoint.to_string(), "[::1]:8080");
    }

    #[test]
    fn parses_unix_endpoint() {
        let endpoint = StreamBackendAddr::parse("unix:/run/wicket/backend.sock").unwrap();
        assert_eq!(
            endpoint,
            StreamBackendAddr::Unix(PathBuf::from("/run/wicket/backend.sock"))
        );
        assert_eq!(endpoint.to_string(), "unix:/run/wicket/backend.sock");
    }

    #[test]
    fn rejects_empty_endpoint() {
        let err = StreamBackendAddr::parse("").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn rejects_empty_unix_path() {
        let err = StreamBackendAddr::parse("unix:").unwrap_err();
        assert!(err.to_string().contains("absolute path"));
    }

    #[test]
    fn rejects_relative_unix_path() {
        let err = StreamBackendAddr::parse("unix:run/backend.sock").unwrap_err();
        assert!(err.to_string().contains("path must be absolute"));
    }

    #[test]
    fn rejects_unix_url_form_for_now() {
        let err = StreamBackendAddr::parse("unix:///run/backend.sock").unwrap_err();
        assert!(err.to_string().contains("not unix://"));
    }

    #[test]
    fn rejects_unknown_endpoint_format() {
        let err = StreamBackendAddr::parse("http://127.0.0.1:8080").unwrap_err();
        assert!(err
            .to_string()
            .contains("invalid TCP stream backend endpoint"));
    }
}
