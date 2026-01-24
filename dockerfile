# --- Stage 1: Build ---
FROM rust:1.83-slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev gcc
WORKDIR /app
COPY . .
RUN cargo build --release

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim

# 1. Install Git, SSL, and Curl
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 1.1 Configure Git
RUN git config --global --add safe.directory '*' 

# 2. Install Static Docker CLI (v29.0.0)
# This perfectly matches your host's v29 engine
RUN curl -L https://download.docker.com/linux/static/stable/x86_64/docker-29.0.0.tgz | \
    tar -xz -C /usr/local/bin --strip-components=1 docker/docker

# 3. Install Docker Compose Plugin (v2.32.4)
RUN mkdir -p /usr/local/lib/docker/cli-plugins/ && \
    curl -SL https://github.com/docker/compose/releases/download/v2.32.4/docker-compose-linux-x86_64 \
    -o /usr/local/lib/docker/cli-plugins/docker-compose && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

WORKDIR /app
COPY --from=builder /app/target/release/graft-hook .

# No need to manually set DOCKER_API_VERSION anymore as they match
EXPOSE 3000
CMD ["./graft-hook"]
