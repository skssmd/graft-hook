# --- Stage 1: Build ---
FROM rust:1.83-slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev libgit2-dev cmake gcc
WORKDIR /app
COPY . .
# Ensure edition is set to 2021 in Cargo.toml
RUN cargo build --release

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim

# 1. Install Runtime Libs + Docker CLI tools
RUN apt-get update && apt-get install -y \
    libssl3 \
    libgit2-1.5 \
    ca-certificates \
    curl \
    gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && apt-get install -y docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/graft-hook .

EXPOSE 3000
CMD ["./graft-hook"]