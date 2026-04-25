#!/usr/bin/env bash
# tests/helpers/fixtures.bash — Test fixture generators
# Provides functions to create mock .env files, compose files, and backup archives.

# Create a minimal .env file in a given directory
make_env_file() {
    local dir="$1"
    local domain="${2:-example.com}"
    local email="${3:-admin@example.com}"
    cat > "$dir/.env" <<EOF
DOMAIN=${domain}
SSL_EMAIL=${email}
N8N_IMAGE_TAG=1.108.0
POSTGRES_PASSWORD=testpassword123
N8N_BASIC_AUTH_PASSWORD=basicauthpass
N8N_RUNNERS_AUTH_TOKEN=runnerstoken
N8N_ENCRYPTION_KEY=dGVzdEVuY3J5cHRpb25LZXkzMkJ5dGVzTE9ORw==
COMPOSE_PROJECT_NAME=n8n
SUBDOMAIN_N8N=n8n
SUBDOMAIN_GRAFANA=grafana
SUBDOMAIN_PROMETHEUS=prometheus
N8N_FQDN=n8n.${domain}
GRAFANA_FQDN=grafana.${domain}
PROMETHEUS_FQDN=prometheus.${domain}
COMPOSE_PROFILES=
EXPOSE_PROMETHEUS=false
EXECUTIONS_MODE=regular
EOF
}

# Create a minimal .env file that has a placeholder encryption key
make_env_file_placeholder_key() {
    local dir="$1"
    cat > "$dir/.env" <<EOF
DOMAIN=example.com
SSL_EMAIL=admin@example.com
N8N_IMAGE_TAG=1.108.0
POSTGRES_PASSWORD=testpassword123
N8N_BASIC_AUTH_PASSWORD=basicauthpass
N8N_RUNNERS_AUTH_TOKEN=runnerstoken
N8N_ENCRYPTION_KEY=CHANGE_ME_BASE64_32_BYTES
COMPOSE_PROJECT_NAME=n8n
N8N_FQDN=n8n.example.com
COMPOSE_PROFILES=
EXPOSE_PROMETHEUS=false
EOF
}

# Create a minimal .env file with no encryption key at all
make_env_file_no_key() {
    local dir="$1"
    cat > "$dir/.env" <<EOF
DOMAIN=example.com
SSL_EMAIL=admin@example.com
N8N_IMAGE_TAG=1.108.0
POSTGRES_PASSWORD=testpassword123
N8N_BASIC_AUTH_PASSWORD=basicauthpass
N8N_ENCRYPTION_KEY=
COMPOSE_PROJECT_NAME=n8n
N8N_FQDN=n8n.example.com
COMPOSE_PROFILES=
EOF
}

# Create a minimal docker-compose.yml stub
make_compose_file() {
    local dir="$1"
    cat > "$dir/docker-compose.yml" <<'EOF'
version: "3.8"
services:
  main:
    image: n8nio/n8n:${N8N_IMAGE_TAG}
    container_name: n8n-main
    environment:
      - N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}
      - DB_TYPE=postgresdb
    ports:
      - "5678:5678"
  postgres:
    image: postgres:16
    container_name: n8n-postgres
    environment:
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
volumes:
  n8n-data:
  postgres-data:
EOF
}

# Create a backup archive structure for restore tests
make_backup_archive() {
    local dir="$1"          # where to write the .tar.gz
    local archive_name="${2:-test_backup.tar.gz}"
    local domain="${3:-example.com}"

    local tmp; tmp="$(mktemp -d)"
    # Create the .env.bak with valid encryption key
    cat > "$tmp/.env.bak" <<EOF
DOMAIN=${domain}
SSL_EMAIL=admin@${domain}
N8N_IMAGE_TAG=1.108.0
N8N_ENCRYPTION_KEY=dGVzdEVuY3J5cHRpb25LZXkzMkJ5dGVzTE9ORw==
POSTGRES_PASSWORD=testpassword123
N8N_FQDN=n8n.${domain}
COMPOSE_PROFILES=
EOF

    # Create docker-compose.yml.bak
    cat > "$tmp/docker-compose.yml.bak" <<'EOF'
version: "3.8"
services:
  main:
    image: n8nio/n8n:${N8N_IMAGE_TAG}
  postgres:
    image: postgres:16
EOF

    # Create a fake SQL dump
    cat > "$tmp/n8n_postgres_dump_2025-01-01_00-00-00.sql" <<'EOF'
-- PostgreSQL database dump
-- Dumped from database version 16.0
CREATE TABLE workflows (id SERIAL PRIMARY KEY);
EOF

    # Pack into tar.gz
    tar -czf "$dir/$archive_name" -C "$tmp" .
    rm -rf "$tmp"
}

# Create a backup archive with missing encryption key (for restore failure tests)
make_backup_archive_no_key() {
    local dir="$1"
    local archive_name="${2:-test_backup_no_key.tar.gz}"

    local tmp; tmp="$(mktemp -d)"
    cat > "$tmp/.env.bak" <<EOF
DOMAIN=example.com
SSL_EMAIL=admin@example.com
N8N_IMAGE_TAG=1.108.0
N8N_ENCRYPTION_KEY=
POSTGRES_PASSWORD=testpassword123
EOF
    cat > "$tmp/docker-compose.yml.bak" <<'EOF'
version: "3.8"
services:
  main:
    image: n8nio/n8n:${N8N_IMAGE_TAG}
EOF

    tar -czf "$dir/$archive_name" -C "$tmp" .
    rm -rf "$tmp"
}

# Setup a full N8N_DIR with .env + compose for integration tests
setup_n8n_dir() {
    local n8n_dir="$1"
    local domain="${2:-example.com}"

    mkdir -p "$n8n_dir/backups" "$n8n_dir/logs"
    make_env_file "$n8n_dir" "$domain"
    make_compose_file "$n8n_dir"
}

# Create .env files in deploy templates from their .env.example sources.
# copy_templates_for_mode() requires deploy/single-mode/.env and deploy/queue-mode/.env
# to exist. In the real repo these are .env.example and must be copied once.
# This helper creates a temp mirror of the deploy templates with .env present.
#
# Sets TEMPLATE_SINGLE and TEMPLATE_QUEUE to point to the temp dirs.
setup_template_envs() {
    local repo_root="${1:-$REPO_ROOT}"
    local tmpdir="${2:-$BATS_TEST_TMPDIR}"

    local tmp_single="$tmpdir/templates/single-mode"
    local tmp_queue="$tmpdir/templates/queue-mode"
    mkdir -p "$tmp_single" "$tmp_queue"

    # Copy all files from real templates
    cp -a "$repo_root/deploy/single-mode/." "$tmp_single/"
    cp -a "$repo_root/deploy/queue-mode/."  "$tmp_queue/"

    # Create .env from .env.example if missing
    [[ ! -f "$tmp_single/.env" && -f "$tmp_single/.env.example" ]] \
        && cp "$tmp_single/.env.example" "$tmp_single/.env"
    [[ ! -f "$tmp_queue/.env"  && -f "$tmp_queue/.env.example"  ]] \
        && cp "$tmp_queue/.env.example"  "$tmp_queue/.env"

    export TEMPLATE_SINGLE="$tmp_single"
    export TEMPLATE_QUEUE="$tmp_queue"
}
