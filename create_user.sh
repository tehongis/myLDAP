#!/usr/bin/env bash
set -euo pipefail

# Configuration (can be overridden via environment variables)
DB_HOST=${DB_HOST:-localhost}
DB_USER=${DB_USER:-ldap}
DB_PASS=${DB_PASS:-ldap}
DB_NAME=${DB_NAME:-ldap_users}

usage() {
  echo "Usage: $0 USERNAME PASSWORD"
  echo "Environment overrides: DB_HOST, DB_USER, DB_PASS, DB_NAME"
  exit 2
}

if [ "$#" -lt 2 ]; then
  usage
fi

USER="$1"
PASS="$2"

# Generate a salted SHA-512 hash for the password.
# Prefer openssl if available, fall back to python3 crypt module.
if command -v openssl >/dev/null 2>&1; then
  HASH=$(openssl passwd -6 -- "${PASS}")
else
  if command -v python3 >/dev/null 2>&1; then
    HASH=$(python3 - <<PY
import crypt,sys
print(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_SHA512)))
PY
"${PASS}")
  else
    echo "Error: neither openssl nor python3 is available to generate password hashes" >&2
    exit 1
  fi
fi

# Escape single quotes for SQL literal by replacing ' with ''
escape_sql() { printf "%s" "$1" | sed "s/'/''/g"; }
USER_ESC=$(escape_sql "${USER}")
HASH_ESC=$(escape_sql "${HASH}")

SQL="CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) PRIMARY KEY, password VARCHAR(512));\n"
SQL+="INSERT INTO users (username,password) VALUES ('${USER_ESC}','${HASH_ESC}') ON DUPLICATE KEY UPDATE password=VALUES(password);"

# Execute SQL via mysql client
mysql -h "${DB_HOST}" -u "${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" -e "$SQL"

if [ $? -eq 0 ]; then
  echo "User '${USER}' created/updated in database '${DB_NAME}'."
else
  echo "Failed to create/update user '${USER}'." >&2
  exit 1
fi
