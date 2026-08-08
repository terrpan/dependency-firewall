#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

cert_dir="certs"
rm -rf "$cert_dir"
mkdir -p "$cert_dir"

openssl genrsa -out "$cert_dir/ca-key.pem" 4096
openssl req -x509 -new -nodes \
  -key "$cert_dir/ca-key.pem" \
  -sha256 -days 30 \
  -subj "/CN=dependency-firewall-test-ca" \
  -out "$cert_dir/ca.pem"

openssl genrsa -out "$cert_dir/control-plane-key.pem" 2048
openssl req -new \
  -key "$cert_dir/control-plane-key.pem" \
  -subj "/CN=control-plane.firewall.local" \
  -out "$cert_dir/control-plane.csr"
cat > "$cert_dir/control-plane.ext" <<'EOF'
subjectAltName=DNS:control-plane.firewall.local,DNS:control-plane,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF
openssl x509 -req \
  -in "$cert_dir/control-plane.csr" \
  -CA "$cert_dir/ca.pem" \
  -CAkey "$cert_dir/ca-key.pem" \
  -CAcreateserial \
  -out "$cert_dir/control-plane.pem" \
  -days 30 -sha256 \
  -extfile "$cert_dir/control-plane.ext"

openssl genrsa -out "$cert_dir/proxy-a-key.pem" 2048
openssl req -new \
  -key "$cert_dir/proxy-a-key.pem" \
  -subj "/CN=proxy-a" \
  -out "$cert_dir/proxy-a.csr"
cat > "$cert_dir/proxy-a.ext" <<'EOF'
subjectAltName=DNS:proxy-a.firewall.local
extendedKeyUsage=clientAuth
EOF
openssl x509 -req \
  -in "$cert_dir/proxy-a.csr" \
  -CA "$cert_dir/ca.pem" \
  -CAkey "$cert_dir/ca-key.pem" \
  -CAcreateserial \
  -out "$cert_dir/proxy-a.pem" \
  -days 30 -sha256 \
  -extfile "$cert_dir/proxy-a.ext"

openssl genrsa -out "$cert_dir/dependency-graph-worker-key.pem" 2048
openssl req -new \
  -key "$cert_dir/dependency-graph-worker-key.pem" \
  -subj "/CN=dependency-graph-worker" \
  -out "$cert_dir/dependency-graph-worker.csr"
cat > "$cert_dir/dependency-graph-worker.ext" <<'EOF'
subjectAltName=DNS:dependency-graph-worker.firewall.local
extendedKeyUsage=clientAuth
EOF
openssl x509 -req \
  -in "$cert_dir/dependency-graph-worker.csr" \
  -CA "$cert_dir/ca.pem" \
  -CAkey "$cert_dir/ca-key.pem" \
  -CAcreateserial \
  -out "$cert_dir/dependency-graph-worker.pem" \
  -days 30 -sha256 \
  -extfile "$cert_dir/dependency-graph-worker.ext"

rm -f "$cert_dir"/*.csr "$cert_dir"/*.ext "$cert_dir"/ca.srl
chmod 0600 "$cert_dir"/*-key.pem

echo "Generated test certificates in examples/mtls/$cert_dir"
echo "Proxy client identity: proxy-a.firewall.local"
echo "Dependency graph worker client identity: dependency-graph-worker.firewall.local"
