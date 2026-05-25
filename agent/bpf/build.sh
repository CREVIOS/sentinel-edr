#!/usr/bin/env bash
# Compile the Sentinel CO-RE BPF object. Run inside the sentinel-bpfcc image with the host
# BTF mounted (-v /sys/kernel/btf:/sys/kernel/btf:ro). Emits vmlinux.h (from the running
# kernel's BTF) + sentinel.bpf.o (portable across kernels via CO-RE).
set -euo pipefail
cd "$(dirname "$0")"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) TARGET_ARCH=x86 ;;
  aarch64) TARGET_ARCH=arm64 ;;
  *) echo "unsupported arch $ARCH"; exit 1 ;;
esac

# vmlinux.h is generated from the BTF of whatever kernel we build against; CO-RE relocations
# make the resulting object run on other kernels regardless.
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clang -O2 -g -Wall -Werror \
  -target bpf -D__TARGET_ARCH_"$TARGET_ARCH" \
  -I. -c sentinel.bpf.c -o sentinel.bpf.o

echo "built sentinel.bpf.o ($(wc -c < sentinel.bpf.o) bytes) for $ARCH"
