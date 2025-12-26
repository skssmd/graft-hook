# --- Stage 1: Build ---
FROM rust:1.83-slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev gcc
WORKDIR /app
COPY . .
RUN cargo build --release

# --- Stage 2: Runtime (Support for Docker + Compose) ---
FROM debian:bookworm-slim

# 1. Install Git and SSL (Required for your Rust app and Git tasks)
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Static Docker CLI
RUN curl -L https://download.docker.com/linux/static/stable/x86_64/docker-24.0.7.tgz | \
    tar -xz -C /usr/local/bin --strip-components=1 docker/docker

# 3. Install Docker Compose Plugin (The "Missing Piece")
# This puts the plugin where the 'docker' command can find it
RUN mkdir -p /usr/local/lib/docker/cli-plugins/ && \
    curl -SL https://github.com/docker/compose/releases/download/v2.24.5/docker-compose-linux-x86_64 \
    -o /usr/local/lib/docker/cli-plugins/docker-compose && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

WORKDIR /app
COPY --from=builder /app/target/release/graft-hook .

EXPOSE 3000
CMD ["./graft-hook"]