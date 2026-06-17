# Build the Rust agent and ship on a slim Debian with the tools enforcement needs.
#
# NOTE: this demo image is built WITHOUT `--features ebpf` and runs on the userspace polling
# tier. Kernel tamper-protection (the LSM kill/ptrace/file hooks) requires a privileged host
# with `lsm=bpf` and the sentinel.bpf.o object — neither applies to this unprivileged demo
# container. Production endpoints get the eBPF-enabled binary + BPF object via the host
# installer (deploy/app2/install-agent.sh), which the release pipeline builds with --features ebpf.
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
