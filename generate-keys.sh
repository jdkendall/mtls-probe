#!/bin/bash
set -e

STOREPASS=changeit
RESOURCES_DIR="src/test/resources/certs"
SERVER_DIR="$RESOURCES_DIR/server"
CLIENT_DIR="$RESOURCES_DIR/client"
ALIEN_DIR="$RESOURCES_DIR/alien-client"
BROKEN_DIR="$RESOURCES_DIR/broken-server"
EXPIRED_DIR="$RESOURCES_DIR/expired-server"
SELF_SIGNED_DIR="$RESOURCES_DIR/self-signed-server"

rm -r "$SERVER_DIR" 2>/dev/null || true
rm -r "$CLIENT_DIR" 2>/dev/null || true
rm -r "$ALIEN_DIR" 2>/dev/null || true
rm -r "$BROKEN_DIR" 2>/dev/null || true
rm -r "$EXPIRED_DIR" 2>/dev/null || true
rm -r "$SELF_SIGNED_DIR" 2>/dev/null || true

mkdir -p "$SERVER_DIR" "$CLIENT_DIR" "$ALIEN_DIR" "$BROKEN_DIR" "$EXPIRED_DIR" "$SELF_SIGNED_DIR"

echo "🔨 Generating certificate hierarchies..."

### === FUNCTIONS ===

generate_ca() {
  local prefix=$1
  local subj=$2
  local dir=$3

  # Root CA
  openssl genrsa -out "$dir/${prefix}-root.key" 4096
  openssl req -x509 -new -nodes -key "$dir/${prefix}-root.key" -sha256 -days 3650 \
    -subj "$subj Root CA" \
    -out "$dir/${prefix}-root.crt" \
    -extensions v3_ca \
    -config src/test/resources/certs/openssl-ca.cnf

  # Intermediate CA
  openssl genrsa -out "$dir/${prefix}-intermediate.key" 4096
  openssl req -new -key "$dir/${prefix}-intermediate.key" -subj "$subj Intermediate CA" \
    -out "$dir/${prefix}-intermediate.csr"

  openssl x509 -req -in "$dir/${prefix}-intermediate.csr" \
    -CA "$dir/${prefix}-root.crt" -CAkey "$dir/${prefix}-root.key" -CAcreateserial \
    -out "$dir/${prefix}-intermediate.crt" -days 1825 -sha256 \
    -extensions v3_ca \
    -extfile src/test/resources/certs/openssl-ca.cnf

  cat "$dir/${prefix}-intermediate.crt" "$dir/${prefix}-root.crt" > "$dir/chain.crt"
}

generate_leaf() {
  local prefix=$1
  local common_name=$2
  local dir=$3

  # Leaf key & CSR
  openssl genrsa -out "$dir/${prefix}.key" 2048
  openssl req -new -key "$dir/${prefix}.key" -subj "/CN=${common_name}" -out "$dir/${prefix}.csr"

  # Sign with intermediate
  openssl x509 -req -in "$dir/${prefix}.csr" -CA "$dir/${prefix}-intermediate.crt" -CAkey "$dir/${prefix}-intermediate.key" \
    -CAcreateserial -out "$dir/${prefix}.crt" -days 365 -sha256

  cat "$dir/${prefix}.crt" "$dir/${prefix}-intermediate.crt" > "$dir/fullchain.crt"
}

generate_jks_for_client() {
  echo "📦 Creating Java JKS keystore and truststore for client..."

  # Create PKCS#12 file from client cert
  openssl pkcs12 -export \
    -inkey "$CLIENT_DIR/client.key" \
    -in "$CLIENT_DIR/client.crt" \
    -certfile "$CLIENT_DIR/chain.crt" \
    -out "$CLIENT_DIR/client.p12" \
    -passout pass:$STOREPASS

  # Convert to JKS keystore
  keytool -importkeystore \
    -srckeystore "$CLIENT_DIR/client.p12" \
    -srcstoretype PKCS12 \
    -srcstorepass "$STOREPASS" \
    -destkeystore "$CLIENT_DIR/client-keystore.jks" \
    -deststoretype JKS \
    -deststorepass "$STOREPASS"

  # Trust server root cert
  keytool -importcert -alias server-ca \
    -file "$SERVER_DIR/server-root.crt" \
    -keystore "$CLIENT_DIR/client-truststore.jks" \
    -storepass "$STOREPASS" -noprompt
}

generate_untrusted_client_jks() {
  echo "👽 Creating untrusted (alien) client cert and keystore..."

  # Generate alien root + intermediate CA
  generate_ca alien "/O=Alien/CN=Untrusted Client" "$ALIEN_DIR"

  # Generate alien client cert
  generate_leaf alien "alien-client" "$ALIEN_DIR"

  # Export to PKCS12
  openssl pkcs12 -export \
    -inkey "$ALIEN_DIR/alien.key" \
    -in "$ALIEN_DIR/alien.crt" \
    -certfile "$ALIEN_DIR/chain.crt" \
    -out "$ALIEN_DIR/alien.p12" \
    -passout pass:$STOREPASS

  # Convert to JKS
  keytool -importkeystore \
    -srckeystore "$ALIEN_DIR/alien.p12" \
    -srcstoretype PKCS12 \
    -srcstorepass "$STOREPASS" \
    -destkeystore "$ALIEN_DIR/alien-client-keystore.jks" \
    -deststoretype JKS \
    -deststorepass "$STOREPASS"

  echo "☢️  Untrusted client keystore created at: $ALIEN_DIR/alien-client-keystore.jks"
}

generate_broken_chain_server() {
  echo "💔 Creating broken-chain server cert..."

  # Use same server CA hierarchy as trusted server
  # Reuse: $SERVER_DIR/server-root.crt + server-intermediate.crt + key

  # Generate leaf key + CSR
  openssl genrsa -out "$BROKEN_DIR/server.key" 2048
  openssl req -new -key "$BROKEN_DIR/server.key" -subj "/CN=localhost" -out "$BROKEN_DIR/server.csr"

  # Sign with intermediate as usual
  openssl x509 -req -in "$BROKEN_DIR/server.csr" \
    -CA "$SERVER_DIR/server-intermediate.crt" \
    -CAkey "$SERVER_DIR/server-intermediate.key" \
    -CAcreateserial -out "$BROKEN_DIR/server.crt" \
    -days 365 -sha256

  # ❌ Do NOT create a fullchain or include intermediate
  # This will simulate a broken cert chain
  echo "💣 Broken-chain server cert generated at $BROKEN_DIR (no intermediate included)"
}

generate_expired_server_cert() {
  echo "⌛ Generating expired server certificate..."

  # Generate key + CSR
  openssl genrsa -out "$EXPIRED_DIR/server.key" 2048
  openssl req -new -key "$EXPIRED_DIR/server.key" -subj "/CN=localhost" -out "$EXPIRED_DIR/server.csr"

  # Sign with intermediate but make it expired
  openssl x509 -req -in "$EXPIRED_DIR/server.csr" \
    -CA "$SERVER_DIR/server-intermediate.crt" \
    -CAkey "$SERVER_DIR/server-intermediate.key" \
    -CAcreateserial \
    -out "$EXPIRED_DIR/server.crt" \
    -days -1 -sha256

  # Create fullchain (even though expired)
  cat "$EXPIRED_DIR/server.crt" "$SERVER_DIR/server-intermediate.crt" > "$EXPIRED_DIR/fullchain.crt"

  echo "🧟 Expired server certificate generated at: $EXPIRED_DIR"
}

generate_self_signed_server() {
  echo "🧾 Generating self-signed server certificate..."

  # Generate a self-signed cert
  openssl req -x509 -newkey rsa:2048 \
    -keyout "$SELF_SIGNED_DIR/server.key" \
    -out "$SELF_SIGNED_DIR/server.crt" \
    -days 365 -nodes \
    -subj "/CN=localhost"

  # Optional: create a dummy fullchain file for consistency (just the self-signed cert)
  cp "$SELF_SIGNED_DIR/server.crt" "$SELF_SIGNED_DIR/fullchain.crt"

  echo "🔐 Self-signed server certificate generated at: $SELF_SIGNED_DIR"
}

### === EXECUTION ===

# Generate both hierarchies
generate_ca server "/O=Test/CN=Test Server" "$SERVER_DIR"
generate_ca client "/O=Test/CN=Test Client" "$CLIENT_DIR"

# Generate leaf certs
generate_leaf server "localhost" "$SERVER_DIR"
generate_leaf client "client" "$CLIENT_DIR"

# Generate Java client keystore/truststore
generate_jks_for_client

# Generate alien (untrusted) client keystore
generate_untrusted_client_jks

# Generate broken-chain server cert
generate_broken_chain_server

# Generate expired server cert
generate_expired_server_cert

# Generate self-signed server cert (to trigger untrusted root path)
generate_self_signed_server

set +e

# Cleanup intermediate files
for i in "$SERVER_DIR" "$CLIENT_DIR" "$ALIEN_DIR" "$BROKEN_DIR" "$EXPIRED_DIR" "$SELF_SIGNED_DIR"; do
  echo "🧹 Cleaning up intermediate files in $i..."
  # Remove all intermediate files
  rm "$i"/*.csr 2>/dev/null
  rm "$i"/*.srl 2>/dev/null
  rm "$i"/*.p12 2>/dev/null
done

echo "✅ Certificates and keystores generated."
