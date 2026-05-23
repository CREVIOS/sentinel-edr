#!/usr/bin/env bash
# Generate a dev PKI for TLS + mutual-TLS: a CA, a server cert, and an agent client cert.
# Output → ./certs. Point the server at them with:
#   SENTINEL_TLS_CERT=certs/server.crt SENTINEL_TLS_KEY=certs/server.key \
#   SENTINEL_TLS_CLIENT_CA=certs/ca.crt
set -euo pipefail
mkdir -p certs && cd certs
CN="${1:-localhost}"

openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.crt -days 825 \
  -subj "/CN=Sentinel Dev CA" 2>/dev/null

openssl req -newkey rsa:4096 -nodes -keyout server.key -out server.csr \
  -subj "/CN=$CN" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 \
  -extfile <(printf "subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth" "$CN") 2>/dev/null

openssl req -newkey rsa:4096 -nodes -keyout agent.key -out agent.csr \
  -subj "/CN=sentinel-agent" 2>/dev/null
openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out agent.crt -days 825 \
  -extfile <(printf "extendedKeyUsage=clientAuth") 2>/dev/null

rm -f *.csr
echo "✓ wrote certs/{ca,server,agent}.{crt,key}"
