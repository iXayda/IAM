#!/usr/bin/env bash
set -euo pipefail
umask 077

export IAM_IMAGE=${1:?Expected the reloaded image tag}
jar=${2:?Expected the matching maintenance JAR}
scratch=$(mktemp -d)
project="iam-smoke-$(openssl rand -hex 6)"
compose=(docker compose --project-name "$project" --env-file /dev/null -f compose.yaml -f .github/packaging/smoke-postgres.yaml)
trap 'rm -rf -- "$scratch"' EXIT

export IAM_SECRETS_DIR="$scratch/secrets"
export IAM_PORT=0 IAM_BIND_ADDRESS=127.0.0.1 IAM_PROFILES=runtime
export IAM_PROTOCOL_ISSUER=https://iam.example.invalid
export IAM_PROTOCOL_IDENTITY_FRONTEND_URI="$IAM_PROTOCOL_ISSUER/identity"
export SERVER_SSL_ENABLED=true CURL_CA_BUNDLE=/run/iam/cert.pem
export SPRING_DATASOURCE_URL=jdbc:postgresql://postgres:5432/iam
export SPRING_DATASOURCE_USERNAME=iam_runtime
export SERVER_SSL_KEY_STORE_PASSWORD SPRING_DATASOURCE_PASSWORD SMOKE_POSTGRES_PASSWORD
SERVER_SSL_KEY_STORE_PASSWORD=$(openssl rand -hex 24)
SPRING_DATASOURCE_PASSWORD=$(openssl rand -hex 24)
SMOKE_POSTGRES_PASSWORD=$(openssl rand -hex 24)
owner_password=$(openssl rand -hex 24)

mkdir "$IAM_SECRETS_DIR"
openssl rand -out "$IAM_SECRETS_DIR/signing.key" 32
openssl rand -out "$IAM_SECRETS_DIR/totp.key" 32
openssl rand -out "$IAM_SECRETS_DIR/authorization.key" 64
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=iam.example.invalid \
  -addext subjectAltName=DNS:iam.example.invalid -keyout "$scratch/tls.key" -out "$IAM_SECRETS_DIR/cert.pem"
openssl pkcs12 -export -in "$IAM_SECRETS_DIR/cert.pem" -inkey "$scratch/tls.key" \
  -out "$IAM_SECRETS_DIR/tls.p12" -passout env:SERVER_SSL_KEY_STORE_PASSWORD
chmod 755 "$IAM_SECRETS_DIR"
chmod 444 "$IAM_SECRETS_DIR"/*

trap 'result=$?; "${compose[@]}" down --volumes --remove-orphans || result=1; rm -rf -- "$scratch"; exit "$result"' EXIT
"${compose[@]}" up -d --wait --wait-timeout 90 postgres
psql=("${compose[@]}" exec -T postgres psql -X -v ON_ERROR_STOP=1)
"${psql[@]}" -U postgres <<SQL
CREATE ROLE iam_owner LOGIN NOINHERIT PASSWORD '$owner_password';
CREATE ROLE iam_runtime LOGIN NOINHERIT PASSWORD '$SPRING_DATASOURCE_PASSWORD';
CREATE DATABASE iam OWNER iam_owner;
SQL
db_address=$("${compose[@]}" port postgres 5432)
for command in migrate initialize-signing-key initialize-authorization-key; do
  SPRING_DATASOURCE_URL="jdbc:postgresql://$db_address/iam" SPRING_DATASOURCE_USERNAME=iam_owner \
    SPRING_DATASOURCE_PASSWORD="$owner_password" IAM_SIGNING_KEYFILE="$IAM_SECRETS_DIR/signing.key" \
    IAM_TOTP_KEYFILE="$IAM_SECRETS_DIR/totp.key" IAM_AUTHORIZATION_KEYFILE="$IAM_SECRETS_DIR/authorization.key" \
    java -jar "$jar" "$command"
done
"${psql[@]}" -U iam_owner -d iam -v runtime_role=iam_runtime -v iam_schema=public < deploy/postgresql/grant-runtime.sql

if ! "${compose[@]}" up -d --no-build --pull never --wait --wait-timeout 120 iam; then
  "${compose[@]}" logs --tail 60 iam
  exit 1
fi
address=$("${compose[@]}" port iam 8080)
probe() {
  local status
  status=$(curl --silent --show-error --max-time 5 --noproxy '*' --cacert "$IAM_SECRETS_DIR/cert.pem" \
    --connect-to "::$address" --output "$scratch/response" --write-out '%{http_code}' "$IAM_PROTOCOL_ISSUER/$1")
  if [[ $status != 200 ]]; then
    printf 'Expected HTTP 200 from /%s, got %s\n' "$1" "$status" >&2
    return 1
  fi
}
probe livez
jq -e '.status == "UP"' "$scratch/response" >/dev/null
probe readyz
jq -e '.status == "UP"' "$scratch/response" >/dev/null
probe .well-known/openid-configuration
jq -e --arg issuer "$IAM_PROTOCOL_ISSUER" '.issuer == $issuer and .jwks_uri == ($issuer + "/oauth2/jwks")' "$scratch/response" >/dev/null
probe oauth2/jwks
jq -e 'any(.keys[]; .kty == "RSA" and (.kid | length > 0))' "$scratch/response" >/dev/null
