# --- Stage 1: Build ---
FROM rust:1.83-slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev gcc
WORKDIR /app
COPY . .
RUN cargo build --release

# --- Stage 2: Runtime ---
FROM debian:bookworm-slim

# 1. Install Dependencies, Git, and Docker (Official Repo)
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    curl \
    git \
    gnupg \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && apt-get install -y \
    docker-ce-cli \
    docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

# 1.1 Configure Git
RUN git config --global --add safe.directory '*'

WORKDIR /app
COPY --from=builder /app/target/release/graft-hook .

EXPOSE 3000
CMD ["./graft-hook"]
