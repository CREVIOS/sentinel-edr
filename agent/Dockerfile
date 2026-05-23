# Build the Rust agent and ship on a slim Debian with the tools enforcement needs.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY agent/Cargo.toml agent/Cargo.lock* ./
COPY agent/src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates nftables iproute2 procps usbutils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/sentinel-agent /usr/local/bin/sentinel-agent
ENV SENTINEL_STATE=/var/lib/sentinel/agent.json
ENTRYPOINT ["sentinel-agent"]
