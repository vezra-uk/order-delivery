#!/bin/bash

# Usage: ./launch_container.sh <domain> <tier>
# Tiers: starter, basic, pro

set -e

DOMAIN="$1"
TIER="$2"
EMAIL="$3"

if [ -z "$DOMAIN" ] || [ -z "$TIER" ] || [ -z "$EMAIL"]; then
  echo "Usage: $0 <domain> <tier> <admin_email>"
  echo "Tiers: starter, basic, pro"
  exit 1
fi

# Define limits based on the tier
case "$TIER" in
  starter)
    CPU="0.2"
    RAM="256m"
    ;;
  basic)
    CPU="0.5"
    RAM="512m"
    ;;
  pro)
    CPU="1.0"
    RAM="1g"
    ;;
  *)
    echo "Invalid tier: $TIER. Choose from: starter, basic, pro."
    exit 1
    ;;
esac

# Image name
IMAGE_NAME="wordpress-custom"

# Check if image exists locally
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "Error: Docker image '$IMAGE_NAME' not found locally."
  echo "Please build it first using: docker build -t $IMAGE_NAME ."
  exit 1
fi

# Extract base name (remove the top-level domain)
BASE_NAME="${DOMAIN%%.*}"
BASE_PATH="/home/Ryan/${DOMAIN}"

DB_HOST="10.0.0.10"
DB_NAME="${BASE_NAME}"
DB_USER="${BASE_NAME}_wordpress_user"
DB_PASS=$(tr -dc 'A-Za-z0-9!@#$%^&*-_=+' < /dev/urandom | head -c 16)

# Admin credentials
WP_ADMIN_USER="admin"
WP_ADMIN_PASS=$(openssl rand -base64 14)
WP_ADMIN_EMAIL="${EMAIL}"

# Create project directory
mkdir -p "$BASE_PATH"

# Create MySQL DB and user
echo "Creating MySQL database and user..."
mysql -h ${DB_HOST} -u root -p <<EOF
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;
CREATE USER IF NOT EXISTS '${DB_USER}'@'%' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'%';
FLUSH PRIVILEGES;
EOF

# Write .env file
cat > "${BASE_PATH}/.env" <<EOL
WORDPRESS_DB_NAME=${DB_NAME}
WORDPRESS_DB_USER=${DB_USER}
WORDPRESS_DB_PASSWORD=${DB_PASS}
WORDPRESS_DB_HOST=172.17.0.1:3306
WP_ADMIN_USER=${WP_ADMIN_USER}
WP_ADMIN_PASS=${WP_ADMIN_PASS}
WP_ADMIN_EMAIL=${WP_ADMIN_EMAIL}
WP_DOMAIN=${DOMAIN}
EOL

# Write docker-compose.yml with resource limits
mkdir ${BASE_PATH}/data

cat > "${BASE_PATH}/docker-compose.yml" <<EOL
version: '3.8'
services:
  ${BASE_NAME}:
    image: ${IMAGE_NAME}
    container_name: ${BASE_NAME}
    restart: unless-stopped
    env_file:
      - .env
    volumes:
      - ./data:/var/www/html
    mem_limit: ${RAM}
    cpus: ${CPU}
EOL

# Prompt user for confirmation before launching
echo "-------------------------------------------------"
echo "Domain:           ${DOMAIN}"
echo "Tier:             ${TIER}"
echo "CPU Limit:        ${CPU}"
echo "RAM Limit:        ${RAM}"
echo "DB Name:          ${DB_NAME}"
echo "DB User:          ${DB_USER}"
echo "DB Password:      ${DB_PASS}"
echo "Admin Username:   ${WP_ADMIN_USER}"
echo "Admin Password:   ${WP_ADMIN_PASS}"
echo "Admin Email:      ${WP_ADMIN_EMAIL}"
echo "Files in:         ${BASE_PATH}"
echo "-------------------------------------------------"
read -p "Are you ready to launch the container? (y/n): " CONFIRM

if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
  cd "$BASE_PATH"
  docker compose up -d
  echo "Container launched successfully."
else
  echo "Launch aborted."
  exit 1
fi
