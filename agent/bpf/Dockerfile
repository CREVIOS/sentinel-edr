# Builder for the C/libbpf CO-RE BPF object (sentinel.bpf.o).
# Used both to compile the object and as the base for the agent's libbpf-rs build.
#   docker build -t sentinel-bpfcc agent/bpf
#   docker run --rm -v /sys/kernel/btf:/sys/kernel/btf:ro -v "$PWD/agent/bpf":/w -w /w sentinel-bpfcc ./build.sh
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev bpftool libelf1 libelf-dev gcc make ca-certificates \
 && rm -rf /var/lib/apt/lists/*
