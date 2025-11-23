#!/usr/bin/env bash
set -euo pipefail

# init_db.sh - initialize MySQL database and create ldap user
# Usage:
#   ROOT_USER and ROOT_PASS environment variables may be used for authentication.
#   Example: ROOT_PASS=your_root_password ./init_db.sh

DB_HOST=${DB_HOST:-localhost}
ROOT_USER=${ROOT_USER:-root}
ROOT_PASS=${ROOT_PASS:-}
DB_NAME=${DB_NAME:-ldap_users}
LDAP_USER=${LDAP_USER:-ldap}
LDAP_PASS=${LDAP_PASS:-ldap}

if [ -z "$ROOT_PASS" ]; then
  echo "Warning: ROOT_PASS is empty. The script will try to connect without a password."
fi

MYSQL_CMD=(mysql -h"${DB_HOST}" -u"${ROOT_USER}")
if [ -n "${ROOT_PASS}" ]; then
  MYSQL_CMD+=( -p"${ROOT_PASS}" )
fi

# Create database and users table
echo "Creating database '${DB_NAME}' and table 'users' (if not exists)..."
"${MYSQL_CMD[@]}" <<SQL
CREATE DATABASE IF NOT EXISTS \\`${DB_NAME}\\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE \\`${DB_NAME}\\`;
CREATE TABLE IF NOT EXISTS \\`users\\` (
  \\`username\\` VARCHAR(255) NOT NULL PRIMARY KEY,
  \\`password\\` VARCHAR(512) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQL

# Create ldap user if not exists and grant privileges
echo "Ensuring MySQL user '${LDAP_USER}'@'localhost' exists and has privileges on '${DB_NAME}'..."
# Check if user exists (MySQL >=5.7 stores users in mysql.user)
USER_EXISTS=$("${MYSQL_CMD[@]}" -sse "SELECT COUNT(*) FROM mysql.user WHERE user='${LDAP_USER}' AND host='localhost';" || echo "0")

if [ "${USER_EXISTS}" = "0" ]; then
  echo "Creating user '${LDAP_USER}'@'localhost'..."
  # Try CREATE USER; if it fails (older MySQL), fall back to GRANT ... IDENTIFIED BY
  if "${MYSQL_CMD[@]}" -e "CREATE USER '${LDAP_USER}'@'localhost' IDENTIFIED BY '${LDAP_PASS}';" 2>/dev/null; then
    echo "User created with CREATE USER"
  else
    echo "CREATE USER failed or unsupported; falling back to GRANT (may create user)"
    "${MYSQL_CMD[@]}" -e "GRANT SELECT, INSERT, UPDATE, DELETE ON \\`${DB_NAME}\\`.* TO '${LDAP_USER}'@'localhost' IDENTIFIED BY '${LDAP_PASS}';"
    echo "User created/updated via GRANT"
  fi
else
  echo "User '${LDAP_USER}'@'localhost' already exists."
  echo "Ensuring privileges are granted..."
  "${MYSQL_CMD[@]}" -e "GRANT SELECT, INSERT, UPDATE, DELETE ON \\`${DB_NAME}\\`.* TO '${LDAP_USER}'@'localhost';"
fi

# Flush privileges
"${MYSQL_CMD[@]}" -e "FLUSH PRIVILEGES;"

echo "Initialization complete. Database='${DB_NAME}', user='${LDAP_USER}'@'localhost'"
