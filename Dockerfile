# Builder stage
FROM rust:1.85-bookworm AS builder

# Build argument to enable eBPF sockmap support (Linux x86_64 only)
ARG ENABLE_EBPF=false

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install eBPF build dependencies if enabled
RUN if [ "$ENABLE_EBPF" = "true" ]; then \
    apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libelf-dev \
        && rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates

# Copy volt submodule for eBPF support
COPY volt ./volt

# Build BPF bytecode if eBPF is enabled
RUN if [ "$ENABLE_EBPF" = "true" ] && [ -f "volt/Makefile" ]; then \
    cd volt && make bpf; \
    fi

# Build release binary (with or without eBPF feature)
RUN if [ "$ENABLE_EBPF" = "true" ]; then \
    cargo build --release -p wicket --features ebpf; \
    else \
    cargo build --release -p wicket; \
    fi

# Final stage
FROM debian:bookworm-slim

# Inherit build arg for conditional runtime deps
ARG ENABLE_EBPF=false

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Install libelf for eBPF runtime if enabled (needed for BPF loading)
RUN if [ "$ENABLE_EBPF" = "true" ]; then \
    apt-get update && apt-get install -y --no-install-recommends \
        libelf1 \
        && rm -rf /var/lib/apt/lists/*; \
    fi

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
