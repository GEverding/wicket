//! Structured logging configuration for Wicket.
//!
//! This module sets up tracing with optional JSON output for structured logs.

use anyhow::Result;
use tracing::Level;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    prelude::*,
    EnvFilter,
};

/// Initialize the logging system.
///
/// # Arguments
/// * `json_output` - If true, logs will be formatted as JSON
/// * `log_level` - The minimum log level to output (trace, debug, info, warn, error)
pub fn init(json_output: bool, log_level: &str) -> Result<()> {
    // Create filter from log level, allowing override via RUST_LOG env var
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Default filter: our crate at specified level, dependencies at warn
        EnvFilter::new(format!(
            "wicket={level},pingora={level},tower={warn},hyper={warn}",
            level = log_level,
            warn = "warn"
        ))
    });

    if json_output {
        // JSON formatted output for production
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .json()
                    .with_target(true)
                    .with_current_span(true)
                    .with_span_events(FmtSpan::CLOSE)
                    .with_file(false)
                    .with_line_number(false),
            );
        tracing::subscriber::set_global_default(subscriber)?;
    } else {
        // Pretty formatted output for development
        let subscriber = tracing_subscriber::registry().with(filter).with(
            fmt::layer()
                .with_target(true)
                .with_level(true)
                .with_ansi(true),
        );
        tracing::subscriber::set_global_default(subscriber)?;
    }

    Ok(())
}

/// Parse a log level string into a tracing Level.
#[allow(dead_code)]
fn parse_level(level: &str) -> Level {
    match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" | "warning" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_level() {
        assert_eq!(parse_level("trace"), Level::TRACE);
        assert_eq!(parse_level("DEBUG"), Level::DEBUG);
        assert_eq!(parse_level("Info"), Level::INFO);
        assert_eq!(parse_level("WARN"), Level::WARN);
        assert_eq!(parse_level("warning"), Level::WARN);
        assert_eq!(parse_level("error"), Level::ERROR);
        assert_eq!(parse_level("invalid"), Level::INFO);
    }
}
