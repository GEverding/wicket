# Builder stage
FROM rust:1.85-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates

# Build release binary
RUN cargo build --release -p wicket

# Final stage
FROM debian:bookworm-slim

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 wicket

# Create config directory
RUN mkdir -p /etc/wicket && chown -R wicket:wicket /etc/wicket

# Copy binary from builder
COPY --from=builder /build/target/release/wicket /usr/local/bin/wicket

# Set permissions
RUN chmod +x /usr/local/bin/wicket

# Switch to non-root user
USER wicket

# Expose port
EXPOSE 8080

# Default config path
ENV WICKET_CONFIG=/etc/wicket/wicket.toml

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wicket --validate || exit 1

# Run wicket
ENTRYPOINT ["wicket"]
CMD ["-c", "/etc/wicket/wicket.toml"]
