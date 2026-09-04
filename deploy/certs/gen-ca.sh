#!/usr/bin/env bash
# Generate a throwaway CA + server cert for loopback Vaultwarden TLS.
# Output: ./out/{ca.crt,server.crt,server.key} — add ca.crt to NODE_EXTRA_CA_CERTS.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out

# CA
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout out/ca.key -out out/ca.crt \
  -subj "/CN=Dropvault Dev CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Server key + CSR
openssl req -newkey rsa:4096 -nodes -keyout out/server.key -out out/server.csr \
  -subj "/CN=vaultwarden.local"

# Sign server cert with SANs for 127.0.0.1 and localhost
openssl x509 -req -sha256 -days 825 -in out/server.csr \
  -CA out/ca.crt -CAkey out/ca.key -CAcreateserial \
  -out out/server.crt -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth")

chmod 600 out/server.key out/ca.key
rm -f out/server.csr
echo "OK — out/ca.crt, out/server.crt, out/server.key"
