#!/usr/bin/env bash
set -euo pipefail

# Resolve repo root (script directory)
BASE_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '%s\n' "$*"; }
err() { printf 'Error: %s\n' "$*" >&2; }

# Dependency checks
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing dependency: $1"; return 1; }
}

say "Preflight: checking dependencies (docker, openssl, keytool, perl, dig, ip)"
need_cmd docker
need_cmd openssl
need_cmd keytool || {
  err "keytool not found. Install a JRE (e.g., openjdk-17-jre)."; exit 1; }
need_cmd perl
need_cmd dig
need_cmd ip

# Docker access check
if ! docker info >/dev/null 2>&1; then
  err "Docker not accessible. Ensure Docker is running and your user is in the 'docker' group (then re-login)."
  exit 1
fi

# Utility: check and create directory
check_and_create_dir() {
  if [ ! -d "$1" ]; then
    say "Directory $1 is missing. Creating it now."
    mkdir -p "$1"
  else
    say "Directory $1 already exists."
  fi
}

check_file_exists() {
  if [ ! -f "$1" ]; then
    err "Required file missing: $1"
    return 1
  else
    say "File $1 exists."
    return 0
  fi
}

CONFIG_CACHE="$BASE_DIR/.runner-config"

load_cached_inputs() {
  if [ -f "$CONFIG_CACHE" ]; then
    say "Loading cached configuration from $CONFIG_CACHE"
    # shellcheck disable=SC1090
    . "$CONFIG_CACHE"
  fi
}

save_cached_inputs() {
  local tmp
  tmp="$(mktemp)"
  {
    printf 'FQDN=%q\n' "${FQDN:-}"
    printf 'CERT_PATH=%q\n' "${CERT_PATH:-}"
    printf 'CERT_FILE=%q\n' "${CERT_FILE:-}"
    printf 'KEY_FILE=%q\n' "${KEY_FILE:-}"
    printf 'CHAIN_FILE=%q\n' "${CHAIN_FILE:-}"
  } >"$tmp"
  mv "$tmp" "$CONFIG_CACHE"
}

prompt_with_default() {
  local var_name=$1
  local prompt_message=$2
  local allow_empty=${3:-false}
  local current="${!var_name:-}"
  local input
  while true; do
    if [ -n "$current" ]; then
      read -r -p "$prompt_message [$current]: " input
    else
      read -r -p "$prompt_message: " input
    fi

    if [ -z "$input" ]; then
      if [ -n "$current" ]; then
        printf -v "$var_name" "%s" "$current"
        break
      elif [ "$allow_empty" = "true" ]; then
        printf -v "$var_name" ""
        break
      else
        err "$prompt_message cannot be empty."
        continue
      fi
    else
      printf -v "$var_name" "%s" "$input"
      break
    fi
  done
}

replace_value_in_file() {
  local file=$1
  local placeholder=$2
  local new_value=$3
  local previous_value=${4:-}
  local placeholder_escaped
  local previous_value_escaped
  local new_value_escaped

  if [ ! -f "$file" ]; then
    return
  fi

  placeholder_escaped=${placeholder//$/\\$}
  placeholder_escaped=${placeholder_escaped//@/\\@}
  previous_value_escaped=${previous_value//$/\\$}
  previous_value_escaped=${previous_value_escaped//@/\\@}
  new_value_escaped=${new_value//\\/\\\\}
  new_value_escaped=${new_value_escaped//$/\\$}
  new_value_escaped=${new_value_escaped//@/\\@}

  if [ -n "$previous_value" ] && [ "$previous_value" != "$new_value" ] && grep -q "$previous_value" "$file"; then
    perl -0pi -e 's/\Q'"$previous_value_escaped"'\E/'"$new_value_escaped"'/g' "$file"
  elif grep -q "$placeholder" "$file"; then
    perl -0pi -e 's/\Q'"$placeholder_escaped"'\E/'"$new_value_escaped"'/g' "$file"
  fi
}

update_env_var() {
  local key=$1
  local value=$2
  local file=$3

  if [ ! -f "$file" ]; then
    return
  fi

  if grep -q "^${key}=" "$file"; then
    perl -0pi -e 's/^'"$key"'=.*/'"$key"'='"$value"'/m' "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

load_cached_inputs

register_client() {
  local name=$1
  local security_profile=$2
  local cert_path=$3

  if [ ! -x "$REGISTER_SCRIPT" ]; then
    err "Registration script $REGISTER_SCRIPT not found or not executable."
    return 1
  fi

  if [ -f "$CLIENTS_FILE" ] && grep -q "client_name: $name" "$CLIENTS_FILE"; then
    say "Registration for $name already present; skipping."
    return 0
  fi

  "$REGISTER_SCRIPT" "$name" "$security_profile" "$cert_path"
}

# Check required directories
check_and_create_dir "$BASE_DIR/cert"
check_and_create_dir "$BASE_DIR/conf"
check_and_create_dir "$BASE_DIR/keys"

# Ensure no directory exists at the location of the keystore file
OUT_FILE="$BASE_DIR/conf/default-connector-keystore.p12"
if [ -d "$OUT_FILE" ]; then
  echo "Removing mistakenly created directory at $OUT_FILE"
  rm -rf "$OUT_FILE"
fi

# Prepare files
NGINX_CONF="$BASE_DIR/nginx.development.conf"
COMPOSE_FILE="$BASE_DIR/docker-compose.yml"
CONNECTORCONF="$BASE_DIR/conf/config.json"
ENV_FILE="$BASE_DIR/.env"
CLIENTS_FILE="$BASE_DIR/config/clients.yml"
REGISTER_SCRIPT="$BASE_DIR/scripts/register.sh"

OLD_FQDN="${FQDN:-}"
prompt_with_default FQDN "Fully Qualified Domain Name (FQDN)" true
if [[ -z "${FQDN:-}" ]]; then
  SERVER_IP=$(ip addr show scope global | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | head -n1)
  if [[ -z "$SERVER_IP" ]]; then
    echo "❌ Could not determine the server's IP address."
    exit 1
  fi

  FQDN=$(dig +short -x "$SERVER_IP" | sed 's/\.$//')

  if [[ -z "$FQDN" ]]; then
    echo "❌ Could not resolve FQDN from IP address ($SERVER_IP)."
    exit 1
  fi

  echo "✅ Auto-detected FQDN: $FQDN"
else
  echo "✅ Using FQDN: $FQDN"
fi

OLD_CERT_PATH="${CERT_PATH:-}"
prompt_with_default CERT_PATH "Path to the SSL certificates directory"
if [[ ! -d "$CERT_PATH" ]]; then
  echo "❌ Directory does not exist: $CERT_PATH"
  exit 1
fi

OLD_CERT_FILE="${CERT_FILE:-}"
prompt_with_default CERT_FILE "Public certificate filename"
if [[ ! -f "$CERT_PATH/$CERT_FILE" ]]; then
  echo "❌ Public certificate file not found: $CERT_PATH/$CERT_FILE"
  exit 1
fi

OLD_KEY_FILE="${KEY_FILE:-}"
prompt_with_default KEY_FILE "Private key filename"
if [[ ! -f "$CERT_PATH/$KEY_FILE" ]]; then
  echo "❌ Private key file not found: $CERT_PATH/$KEY_FILE"
  exit 1
fi

OLD_CHAIN_FILE="${CHAIN_FILE:-}"
prompt_with_default CHAIN_FILE "Chained public certificate filename"
if [[ ! -f "$CERT_PATH/$CHAIN_FILE" ]]; then
  echo "❌ Chained certificate file not found: $CERT_PATH/$CHAIN_FILE"
  exit 1
fi

save_cached_inputs

# Check if the nginx configuration file exists
if [[ ! -f "$NGINX_CONF" ]]; then
    echo "Error: nginx.development.conf file not found in the current directory."
    exit 1
fi

# Check if the docker-compose configuration file exists
if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "Error: docker-compose.yml file not found in the current directory."
    exit 1
fi

update_env_var "PUBLIC_HOST" "$FQDN" "$ENV_FILE"
update_env_var "NGINX_TLS_CERT" "$CHAIN_FILE" "$ENV_FILE"
update_env_var "NGINX_TLS_KEY" "$KEY_FILE" "$ENV_FILE"
replace_value_in_file "$ENV_FILE" "\${PUBLIC_HOST}" "$FQDN" "$OLD_FQDN"
replace_value_in_file "$CONNECTORCONF" "\${PUBLIC_HOST}" "$FQDN" "$OLD_FQDN"
replace_value_in_file "$BASE_DIR/config/omejdn.yml" "\${PUBLIC_HOST}" "$FQDN" "$OLD_FQDN"
replace_value_in_file "$BASE_DIR/connector_registration/Connector Registration.postman_collection.json" "\${PUBLIC_HOST}" "$FQDN" "$OLD_FQDN"
# Check required files
MISSING_FILES=0
CERT_DIR="$BASE_DIR/cert"
REQUIRED_FILES=(
  "$CERT_PATH/$KEY_FILE"
  "$CERT_PATH/$CERT_FILE"
  "$BASE_DIR/conf/config.json"
  "$BASE_DIR/conf/truststore.p12"
)

for FILE in "${REQUIRED_FILES[@]}"; do
  check_file_exists "$FILE" || MISSING_FILES=$((MISSING_FILES + 1))
done


if [ $MISSING_FILES -ne 0 ]; then
  echo "Error: One or more required files are missing. Please check and try again."
  exit 1
fi

# Validate cert/key match (modulus)
say "Validating certificate and key match..."
cert_md5=$(openssl x509 -noout -modulus -in "$CERT_PATH/$CERT_FILE" | openssl md5 | awk '{print $2}')
key_md5=$(openssl rsa  -noout -modulus -in "$CERT_PATH/$KEY_FILE"  | openssl md5 | awk '{print $2}')
if [ "${cert_md5:-x}" != "${key_md5:-y}" ]; then
  err "Certificate and private key do not match (modulus mismatch)."
  exit 1
fi

# Generate PKCS#12 file
echo "Generating Connector PKCS#12 file..."
openssl pkcs12 -export -out "$OUT_FILE" \
    -inkey "$CERT_PATH/$KEY_FILE" \
    -in "$CERT_PATH/$CERT_FILE" \
    -passout pass:password

if [ $? -eq 0 ]; then
  echo "PKCS#12 file successfully generated at $OUT_FILE"
else
  echo "Error: Failed to generate PKCS#12 file."
  exit 1
fi

# Generate PKCS#12 file
echo "Generating Broker PKCS#12 file..."
openssl pkcs12 -export -out "$BASE_DIR/cert/isstbroker-keystore.p12" \
    -inkey "$CERT_PATH/$KEY_FILE" \
    -in "$CERT_PATH/$CERT_FILE" \
    -passout pass:password
if [ $? -eq 0 ]; then
  echo "PKCS#12 file successfully generated at $OUT_FILE"
else
  echo "Error: Failed to generate PKCS#12 file."
  exit 1
fi

chmod -R u=rw,go=r "$BASE_DIR/cert" || true
keytool -importkeystore \
  -srckeystore "$BASE_DIR/cert/isstbroker-keystore.p12" -srcstoretype PKCS12 \
  -destkeystore "$BASE_DIR/cert/isstbroker-keystore.jks" -deststoretype JKS \
  -srcstorepass password -deststorepass password

# Optionally copy JKS to cert path for external usage
cp -f "$BASE_DIR/cert/isstbroker-keystore.jks" "$CERT_PATH/" || true

# Ensure proper permissions for the `conf` directory and generated keystore
echo "Setting permissions for the 'conf' directory and its files..."
chmod -R u=rwX,go=rX "$BASE_DIR/conf" || true

# Reminder for configuration
echo "Please ensure that the produced file name matches the connector's config.json:"
echo '  "ids:keyStore" : {'
echo '    "@id" : "file:///conf/default-connector-keystore.p12"'
echo '  }'
echo "If needed, rename the generated file to 'default-connector-keystore.p12' or update the configuration."

# GHCR pull preflight (one representative public image)
say "Preflight: testing anonymous GHCR pull for omejdn-server:latest"
if ! docker pull -q ghcr.io/data-space-core/dsil-omejdn-server/omejdn-server:latest >/dev/null 2>&1; then
  err "Cannot pull public images anonymously. If images are private, run: docker login ghcr.io (PAT needs read:packages)."
fi

# Docker Compose operations
echo "Stopping and removing existing containers..."
docker compose -f "$COMPOSE_FILE" down -v || true

echo "Pulling updated images..."
docker compose -f "$COMPOSE_FILE" pull

echo "Building and starting services..."
if docker compose -f "$COMPOSE_FILE" up --build -d; then
  echo "Containers started; waiting 180 seconds for initialization..."
  sleep 180
  echo "Running provider-ui migrations..."
  if docker compose -f "$COMPOSE_FILE" exec -T provider-ui python manage.py migrate; then
    echo "Provider-ui migrations complete."
    echo "Running provider-ui license insertion script..."
    if docker compose -f "$COMPOSE_FILE" exec -T provider-ui python /app/tools/insert_licenses.py; then
      echo "License insertion script complete."
      echo "Registering connector clients with DAPS..."
      if register_client "default-connector" "idsc:BASE_SECURITY_PROFILE" "$CERT_PATH/$CERT_FILE" \
        && register_client "default-broker" "idsc:BASE_SECURITY_PROFILE" "$CERT_PATH/$CERT_FILE"; then
        echo "Connector registration step complete."
        echo "All services are running and ready!"
      else
        err "Failed to register connector clients with DAPS."
        exit 1
      fi
    else
      echo "Error: Failed to run provider-ui license insertion script."
      exit 1
    fi
  else
    echo "Error: Failed to run provider-ui migrations."
    exit 1
  fi
else
  echo "Error: Services failed to start. Check logs for details."
  exit 1
fi
