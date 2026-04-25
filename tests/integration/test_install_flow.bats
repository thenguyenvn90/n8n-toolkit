#!/usr/bin/env bats
# tests/integration/test_install_flow.bats — Integration tests for install flow
# Coverage: copy_templates_for_mode (single+queue), monitoring flag, FQDN,
#           secrets rotation, wizard TTY guard.

load '../test_helper/common'

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"

setup() {
    setup_stub_bin
    trap '' ERR INT TERM HUP 2>/dev/null || true
    export LOG_LEVEL="INFO"
    export APT_UPDATED=false
    export N8N_DIR="$BATS_TEST_TMPDIR/n8n"
    mkdir -p "$N8N_DIR/logs" "$N8N_DIR/backups"
    export ENV_FILE="$N8N_DIR/.env"
    export COMPOSE_FILE="$N8N_DIR/docker-compose.yml"

    # Build temporary template dirs with .env copied from .env.example
    _TMP_SINGLE="$BATS_TEST_TMPDIR/templates/single-mode"
    _TMP_QUEUE="$BATS_TEST_TMPDIR/templates/queue-mode"
    mkdir -p "$_TMP_SINGLE" "$_TMP_QUEUE"
    cp -a "$REPO_ROOT/deploy/single-mode/." "$_TMP_SINGLE/"
    cp -a "$REPO_ROOT/deploy/queue-mode/."  "$_TMP_QUEUE/"
    # Create .env from .env.example if the template ships only .env.example
    [[ ! -f "$_TMP_SINGLE/.env" && -f "$_TMP_SINGLE/.env.example" ]] \
        && cp "$_TMP_SINGLE/.env.example" "$_TMP_SINGLE/.env"
    [[ ! -f "$_TMP_QUEUE/.env"  && -f "$_TMP_QUEUE/.env.example"  ]] \
        && cp "$_TMP_QUEUE/.env.example"  "$_TMP_QUEUE/.env"
    export TEMPLATE_SINGLE="$_TMP_SINGLE"
    export TEMPLATE_QUEUE="$_TMP_QUEUE"
}

teardown() {
    rm -rf "$BATS_TEST_TMPDIR/n8n" "$BATS_TEST_TMPDIR/templates" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Common preamble snippet for bash -c subshells
# ---------------------------------------------------------------------------
_preamble() {
    # PATH is inherited from bats setup() which already has STUB_BIN prepended
    # via setup_stub_bin — do NOT re-export PATH here (would clobber system tools
    # like cp, sed, grep, date, sort, head that the install flow depends on).
    cat <<PREAMBLE
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='${N8N_DIR}'
        export ENV_FILE="\${N8N_DIR}/.env"
        export COMPOSE_FILE="\${N8N_DIR}/docker-compose.yml"
        export TEMPLATE_SINGLE='${TEMPLATE_SINGLE}'
        export TEMPLATE_QUEUE='${TEMPLATE_QUEUE}'
        source '${REPO_ROOT}/lib/common.sh'
        source '${REPO_ROOT}/lib/install.sh'
        source '${REPO_ROOT}/lib/upgrade.sh'
        source '${REPO_ROOT}/lib/backup.sh'
        source '${REPO_ROOT}/lib/cleanup.sh'
        DATE=\$(date +%F_%H-%M-%S)
        LOG_FILE="\${N8N_DIR}/logs/test.log"
        mkdir -p "\${N8N_DIR}/logs"
PREAMBLE
}

# ---------------------------------------------------------------------------
# install_flow: copy_templates_for_mode — single mode
# ---------------------------------------------------------------------------

@test "install_flow: copy_templates_for_mode copies single-mode files to N8N_DIR" {
    local preamble; preamble="$(_preamble)"
    bash -c "
        $preamble
        DOMAIN='example.com' SSL_EMAIL='admin@example.com'
        INSTALL_MODE='single' MONITORING=false EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        N8N_VERSION='latest' BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        copy_templates_for_mode
    " 2>&1
    [ -f "$N8N_DIR/.env" ]
    [ -f "$N8N_DIR/docker-compose.yml" ]
}

@test "install_flow: copy_templates_for_mode copies queue-mode files to N8N_DIR" {
    local preamble; preamble="$(_preamble)"
    bash -c "
        $preamble
        DOMAIN='example.com' SSL_EMAIL='admin@example.com'
        INSTALL_MODE='queue' MONITORING=false EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        N8N_VERSION='latest' BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        copy_templates_for_mode
    " 2>&1
    [ -f "$N8N_DIR/.env" ]
    [ -f "$N8N_DIR/docker-compose.yml" ]
}

@test "install_flow: copy_templates_for_mode sets DOMAIN in .env" {
    local preamble; preamble="$(_preamble)"
    bash -c "
        $preamble
        DOMAIN='mysite.com' SSL_EMAIL='ops@mysite.com'
        INSTALL_MODE='single' MONITORING=false EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        N8N_VERSION='latest' BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        copy_templates_for_mode
    " 2>&1
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/common.sh" 2>/dev/null
    result="$(read_env_var "$N8N_DIR/.env" DOMAIN)"
    [ "$result" = "mysite.com" ]
}

@test "install_flow: copy_templates_for_mode sets N8N_VERSION (N8N_IMAGE_TAG) in .env" {
    local preamble; preamble="$(_preamble)"
    bash -c "
        $preamble
        DOMAIN='example.com' SSL_EMAIL='admin@example.com'
        INSTALL_MODE='single' MONITORING=false EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        N8N_VERSION='1.107.2' BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        copy_templates_for_mode
    " 2>&1
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/common.sh" 2>/dev/null
    tag="$(read_env_var "$N8N_DIR/.env" N8N_IMAGE_TAG || true)"
    [ -n "$tag" ]
    [[ "$tag" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

@test "install_flow: copy_templates_for_mode rotates N8N_ENCRYPTION_KEY placeholder" {
    local preamble; preamble="$(_preamble)"
    bash -c "
        $preamble
        DOMAIN='example.com' SSL_EMAIL='admin@example.com'
        INSTALL_MODE='single' MONITORING=false EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        N8N_VERSION='latest' BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        copy_templates_for_mode
    " 2>&1
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/common.sh" 2>/dev/null
    key="$(read_env_var "$N8N_DIR/.env" N8N_ENCRYPTION_KEY || true)"
    [ -n "$key" ]
    [ "$key" != "CHANGE_ME_BASE64_32_BYTES" ]
}

# ---------------------------------------------------------------------------
# install_flow: --monitoring flag
# ---------------------------------------------------------------------------

@test "install_flow: --monitoring flag sets COMPOSE_PROFILES=monitoring in .env" {
    local preamble; preamble="$(_preamble)"
    # Create a monitoring dir stub so copy_templates_for_mode doesn't fail
    mkdir -p "$BATS_TEST_TMPDIR/monitoring_src"
    cat > "$BATS_TEST_TMPDIR/monitoring_src/prometheus.yml" <<'EOF'
global:
  scrape_interval: 15s
EOF
    bash -c "
        $preamble
        DOMAIN='example.com' SSL_EMAIL='admin@example.com'
        INSTALL_MODE='single' MONITORING=true EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        N8N_VERSION='latest' BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        SCRIPT_DIR='$REPO_ROOT'
        # Override mon_src inside copy_templates_for_mode by pointing SCRIPT_DIR
        # to a location that has deploy/monitoring with prometheus.yml
        # Use a monkey-patch to skip the monitoring copy:
        copy_monitoring_assets() { true; }
        copy_templates_for_mode
    " 2>&1 || true
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/common.sh" 2>/dev/null
    profiles="$(read_env_var "$N8N_DIR/.env" COMPOSE_PROFILES || true)"
    [ "$profiles" = "monitoring" ]
}

@test "install_flow: without --monitoring COMPOSE_PROFILES is empty in .env" {
    local preamble; preamble="$(_preamble)"
    bash -c "
        $preamble
        DOMAIN='example.com' SSL_EMAIL='admin@example.com'
        INSTALL_MODE='single' MONITORING=false EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        N8N_VERSION='latest' BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        copy_templates_for_mode
    " 2>&1
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/common.sh" 2>/dev/null
    profiles="$(read_env_var "$N8N_DIR/.env" COMPOSE_PROFILES || true)"
    [ "$profiles" = "" ]
}

@test "install_flow: --monitoring copies monitoring/ to N8N_DIR when deploy/monitoring exists" {
    # Only assert that monitoring dir is created when the source dir exists in the repo
    if [[ ! -d "$REPO_ROOT/deploy/monitoring" ]]; then
        skip "deploy/monitoring not present in this repo"
    fi
    local preamble; preamble="$(_preamble)"
    bash -c "
        $preamble
        DOMAIN='example.com' SSL_EMAIL='admin@example.com'
        INSTALL_MODE='single' MONITORING=true EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        N8N_VERSION='latest' BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        SCRIPT_DIR='$REPO_ROOT'
        copy_templates_for_mode
    " 2>&1 || true
    [ -d "$N8N_DIR/monitoring" ]
}

# ---------------------------------------------------------------------------
# install_flow: FQDN construction
# ---------------------------------------------------------------------------

@test "install_flow: copy_templates_for_mode writes N8N_FQDN as n8n.<domain>" {
    local preamble; preamble="$(_preamble)"
    bash -c "
        $preamble
        DOMAIN='example.com' SSL_EMAIL='admin@example.com'
        INSTALL_MODE='single' MONITORING=false EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        N8N_VERSION='latest' BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        copy_templates_for_mode
    " 2>&1
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/common.sh" 2>/dev/null
    fqdn="$(read_env_var "$N8N_DIR/.env" N8N_FQDN || true)"
    [ "$fqdn" = "n8n.example.com" ]
}

@test "install_flow: custom --subdomain-n8n overrides default n8n prefix" {
    local preamble; preamble="$(_preamble)"
    bash -c "
        $preamble
        DOMAIN='example.com' SSL_EMAIL='admin@example.com'
        INSTALL_MODE='single' MONITORING=false EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='app' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        N8N_VERSION='latest' BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        copy_templates_for_mode
    " 2>&1
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/common.sh" 2>/dev/null
    fqdn="$(read_env_var "$N8N_DIR/.env" N8N_FQDN || true)"
    [ "$fqdn" = "app.example.com" ]
}

# ---------------------------------------------------------------------------
# install_flow: queue-mode REDIS_PASSWORD rotation
# ---------------------------------------------------------------------------

@test "install_flow: queue mode rotates REDIS_PASSWORD placeholder" {
    local preamble; preamble="$(_preamble)"
    bash -c "
        $preamble
        DOMAIN='example.com' SSL_EMAIL='admin@example.com'
        INSTALL_MODE='queue' MONITORING=false EXPOSE_PROMETHEUS=false
        SUBDOMAIN_N8N='' SUBDOMAIN_GRAFANA='' SUBDOMAIN_PROMETHEUS=''
        N8N_VERSION='latest' BASIC_AUTH_USER='' BASIC_AUTH_PASS=''
        copy_templates_for_mode
    " 2>&1
    # shellcheck disable=SC1090
    source "$REPO_ROOT/lib/common.sh" 2>/dev/null
    key="$(read_env_var "$N8N_DIR/.env" REDIS_PASSWORD || true)"
    [ -n "$key" ]
    [ "$key" != "CHANGE_ME_BASE64_16_BYTES" ]
}

# ---------------------------------------------------------------------------
# install_flow: wizard guard
# ---------------------------------------------------------------------------

@test "wizard: non-TTY with missing DOMAIN exits 2" {
    # PATH inherited from bats setup() — STUB_BIN already prepended
    run bash -c "
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$BATS_TEST_TMPDIR/n8n_tty'
        mkdir -p \"\$N8N_DIR\"
        export ENV_FILE=\"\$N8N_DIR/.env\"
        export COMPOSE_FILE=\"\$N8N_DIR/docker-compose.yml\"
        export TEMPLATE_SINGLE='$TEMPLATE_SINGLE'
        export TEMPLATE_QUEUE='$TEMPLATE_QUEUE'
        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'
        DOMAIN='' SSL_EMAIL='' INSTALL_MODE='single' MONITORING=false
        wizard_install </dev/null
    " 2>&1
    [ "$status" -eq 2 ]
    [[ "$output" == *"interactive terminal"* ]]
}

@test "wizard: skips all prompts when DOMAIN and SSL_EMAIL pre-set" {
    # PATH inherited from bats setup() — STUB_BIN already prepended
    run bash -c "
        export LOG_LEVEL=INFO APT_UPDATED=false
        export N8N_DIR='$BATS_TEST_TMPDIR/n8n_silent'
        mkdir -p \"\$N8N_DIR\"
        export ENV_FILE=\"\$N8N_DIR/.env\"
        export COMPOSE_FILE=\"\$N8N_DIR/docker-compose.yml\"
        export TEMPLATE_SINGLE='$TEMPLATE_SINGLE'
        export TEMPLATE_QUEUE='$TEMPLATE_QUEUE'
        source '$REPO_ROOT/lib/common.sh'
        source '$REPO_ROOT/lib/install.sh'
        DOMAIN='example.com' SSL_EMAIL='admin@example.com'
        INSTALL_MODE='single' MONITORING=false
        wizard_install </dev/null
        echo \"exit:\$?\"
    " 2>&1
    [ "$status" -eq 0 ]
    [[ "$output" == *"exit:0"* ]]
}

# ---------------------------------------------------------------------------
# install_stack: DOMAIN guard
# ---------------------------------------------------------------------------

@test "install_stack exits 2 when DOMAIN is empty" {
    local preamble; preamble="$(_preamble)"
    run bash -c "
        $preamble
        DOMAIN='' INSTALL_MODE='single' N8N_VERSION='latest'
        install_stack
    " 2>&1
    [ "$status" -eq 2 ]
}
