#!/bin/sh
# Runs the OWASP CRS regression suite (go-ftw) against a real nginx that uses
# the ModSecurity-nginx connector on top of a given libmodsecurity.
#
# The WAF configuration reproduces the `modsec3-nginx` service of CRS's own
# CI (tests/docker-compose.yml + the owasp/modsecurity-crs:nginx image
# templates), and go-ftw is run with CRS's nginx-overrides.yaml, as upstream.
#
# Required environment:
#   LIBMODSEC_DIR  directory holding the libmodsecurity.so to test
#   MODSEC_INC     ModSecurity C headers (…/ModSecurity/headers)
#   CONNECTOR_DIR  ModSecurity-nginx source tree
#   (or MODULE_SO: a prebuilt nginx module to load instead of building the C
#    connector, e.g. the Rust port of ModSecurity-nginx; LIBMODSEC_DIR,
#    MODSEC_INC and CONNECTOR_DIR are then not needed)
#   NGINX_SRC      nginx source tree
#   CRS_DIR        coreruleset checkout (rules/, tests/, crs-setup.conf.example)
#   CRS_DOCKER_DIR modsecurity-crs-docker checkout (configure-rules.sh)
#   FTW            go-ftw binary (v1.0.3, as pinned by CRS CI)
#   ALBEDO         albedo binary (v0.0.14, as pinned by CRS CI)
# Optional: WORK_DIR (default target/crs-<name>), NAME (default "test"),
#   PORT (default 8080), BACKEND_PORT (default 8000), FTW_ARGS (extra args).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
if [ -n "${MODULE_SO:-}" ]; then required="NGINX_SRC CRS_DIR CRS_DOCKER_DIR FTW ALBEDO"
else required="LIBMODSEC_DIR MODSEC_INC CONNECTOR_DIR NGINX_SRC CRS_DIR CRS_DOCKER_DIR FTW ALBEDO"; fi
for v in $required; do
    eval "test -n \"\${$v:-}\"" || { echo "set $v" >&2; exit 2; }
done
NAME=${NAME:-test}
PORT=${PORT:-8080}
BACKEND_PORT=${BACKEND_PORT:-8000}
work=${WORK_DIR:-$root/target/crs-$NAME}
mkdir -p "$work"
work=$(cd "$work" && pwd)

# The library's SONAME is libmodsecurity.so.3 (as with the C++ build);
# provide that name when testing a cargo output directory.
if [ -z "${MODULE_SO:-}" ] && [ -e "$LIBMODSEC_DIR/libmodsecurity.so" ] && [ ! -e "$LIBMODSEC_DIR/libmodsecurity.so.3" ]; then
    ln -s libmodsecurity.so "$LIBMODSEC_DIR/libmodsecurity.so.3"
fi

# --- nginx + connector (dynamic module) linked against LIBMODSEC_DIR ------
# (--with-compat and the same module set as the nginx tree a prebuilt
# MODULE_SO is built against, so its signature and struct layouts match.)
if [ ! -x "$work/nginx/sbin/nginx" ]; then
    if [ -n "${MODULE_SO:-}" ]; then
        add_module=""
    else
        add_module="--add-dynamic-module=$CONNECTOR_DIR"
    fi
    (cd "$NGINX_SRC" && MODSECURITY_INC="${MODSEC_INC:-}" MODSECURITY_LIB="${LIBMODSEC_DIR:-}" \
        ./configure --prefix="$work/nginx" --builddir="$work/objs" --with-compat \
        --with-http_realip_module --with-http_v2_module --with-http_auth_request_module \
        --with-pcre $add_module > "$work/configure.log" 2>&1 &&
     make -f "$work/objs/Makefile" -j"$(nproc)" > "$work/make.log" 2>&1 &&
     make -f "$work/objs/Makefile" install >> "$work/make.log" 2>&1)
fi
if [ -n "${MODULE_SO:-}" ]; then
    mkdir -p "$work/nginx/modules"
    cp "$MODULE_SO" "$work/nginx/modules/ngx_http_modsecurity_module.so"
fi

# --- ModSecurity / CRS configuration (image defaults + CI environment) ----
conf="$work/modsecurity.d"
rm -rf "$conf" "$work/logs" "$work/tmp"
mkdir -p "$conf/owasp-crs" "$work/logs" "$work/tmp/upload" "$work/tmp/data"
cp -r "$CRS_DIR/rules" "$CRS_DIR/plugins" "$conf/owasp-crs/"
cp "$CRS_DIR/crs-setup.conf.example" "$conf/owasp-crs/crs-setup.conf"
cp "$root/unicode.mapping" "$conf/unicode.mapping"

export MODSEC_RULE_ENGINE=DetectionOnly MODSEC_REQ_BODY_ACCESS=on \
    MODSEC_REQ_BODY_LIMIT=13107200 MODSEC_REQ_BODY_NOFILES_LIMIT=131072 \
    MODSEC_REQ_BODY_LIMIT_ACTION=Reject MODSEC_REQ_BODY_JSON_DEPTH_LIMIT=512 \
    MODSEC_ARGUMENTS_LIMIT=1000 MODSEC_PCRE_MATCH_LIMIT=100000 \
    MODSEC_PCRE_MATCH_LIMIT_RECURSION=100000 MODSEC_RESP_BODY_ACCESS=On \
    MODSEC_RESP_BODY_MIMETYPE="text/plain text/html text/xml application/json" \
    MODSEC_RESP_BODY_LIMIT=1048576 MODSEC_RESP_BODY_LIMIT_ACTION=ProcessPartial \
    MODSEC_TMP_DIR="$work/tmp" MODSEC_DATA_DIR="$work/tmp/data" \
    MODSEC_AUDIT_ENGINE=RelevantOnly MODSEC_AUDIT_LOG_RELEVANT_STATUS='^(?:5|4(?!04))' \
    MODSEC_AUDIT_LOG_PARTS=ABIJDEFHZ MODSEC_AUDIT_LOG_TYPE=Serial \
    MODSEC_AUDIT_LOG="$work/logs/modsec_audit.log" MODSEC_ARGUMENT_SEPARATOR='&' \
    MODSEC_COOKIE_FORMAT=0 MODSEC_UNICODE_MAPPING=20127 MODSEC_STATUS_ENGINE=Off \
    MODSEC_AUDIT_LOG_FORMAT=Native MODSEC_AUDIT_STORAGE_DIR="$work/logs/audit/" \
    MODSEC_DEBUG_LOG=/dev/null MODSEC_DEBUG_LOGLEVEL=0 \
    MODSEC_DISABLE_BACKEND_COMPRESSION=Off MODSEC_TMP_SAVE_UPLOADED_FILES=on \
    MODSEC_UPLOAD_DIR="$work/tmp/upload" MODSEC_UPLOAD_FILE_MODE=0600 \
    MODSEC_UPLOAD_KEEP_FILES=Off MODSEC_TAG=modsecurity \
    MODSEC_DEFAULT_PHASE1_ACTION="phase:1,pass,log,tag:'\${MODSEC_TAG}'" \
    MODSEC_DEFAULT_PHASE2_ACTION="phase:2,pass,log,tag:'\${MODSEC_TAG}'"
envsubst < "$CRS_DOCKER_DIR/src/etc/modsecurity.d/modsecurity.conf" > "$conf/modsecurity.conf"
: > "$conf/modsecurity-override.conf"
sed "s#/etc/modsecurity.d#$conf#g" "$CRS_DOCKER_DIR/src/etc/modsecurity.d/setup.conf" > "$conf/setup.conf"

# CRS tx variables, exactly as the image's entrypoint sets them.
env -i PATH="$PATH" MANUAL_MODE=0 CONFIG_FILE="$conf/owasp-crs/crs-setup.conf" \
    ANOMALY_INBOUND=5 ANOMALY_OUTBOUND=4 BLOCKING_PARANOIA=4 \
    COMBINED_FILE_SIZES=65535 MAX_FILE_SIZE=64100 VALIDATE_UTF8_ENCODING=1 \
    ARG_LENGTH=400 CRS_ENABLE_TEST_MARKER=1 MODSEC_TAG=modsecurity \
    MODSEC_DEFAULT_PHASE1_ACTION="phase:1,pass,log,tag:'\${MODSEC_TAG}'" \
    MODSEC_DEFAULT_PHASE2_ACTION="phase:2,pass,log,tag:'\${MODSEC_TAG}'" \
    sh "$CRS_DOCKER_DIR/src/opt/modsecurity/configure-rules.sh" > "$work/configure-rules.log"

cat > "$work/nginx/conf/nginx.conf" <<NGX
load_module modules/ngx_http_modsecurity_module.so;
worker_processes 1;
pid $work/nginx.pid;
error_log $work/logs/error.log info;
events { worker_connections 1024; }
http {
    access_log $work/logs/access.log;
    client_body_temp_path $work/tmp/client_body;
    proxy_temp_path $work/tmp/proxy;
    fastcgi_temp_path $work/tmp/fastcgi;
    uwsgi_temp_path $work/tmp/uwsgi;
    scgi_temp_path $work/tmp/scgi;
    server_tokens off;
    modsecurity on;
    modsecurity_rules_file $conf/setup.conf;
    set_real_ip_from 127.0.0.1;
    real_ip_header X-REAL-IP;
    real_ip_recursive on;
    map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }
    server {
        listen $PORT default_server;
        server_name localhost;
        location / {
            client_max_body_size 0;
            proxy_set_header Host \$host;
            proxy_set_header Proxy "";
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection \$connection_upgrade;
            proxy_set_header X-REAL-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Port \$server_port;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_http_version 1.1;
            proxy_buffering off;
            proxy_connect_timeout 60s;
            proxy_read_timeout 36000s;
            proxy_redirect off;
            proxy_pass_header Authorization;
            proxy_pass http://127.0.0.1:$BACKEND_PORT;
        }
        location /healthz { access_log off; return 200 "OK"; }
    }
}
NGX

# --- run ------------------------------------------------------------------
"$ALBEDO" --port "$BACKEND_PORT" > "$work/logs/albedo.log" 2>&1 &
albedo_pid=$!
"$work/nginx/sbin/nginx" -p "$work/nginx" -c "$work/nginx/conf/nginx.conf"
cleanup() {
    "$work/nginx/sbin/nginx" -p "$work/nginx" -c "$work/nginx/conf/nginx.conf" -s quit 2>/dev/null || true
    kill "$albedo_pid" 2>/dev/null || true
}
trap cleanup EXIT
for _ in $(seq 1 50); do
    curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
    sleep 0.2
done

# The test files target 127.0.0.1:80 (CI maps the container's 8080 there).
cat > "$work/.ftw.yaml" <<FTWCONF
logfile: $work/logs/error.log
testoverride:
  input:
    dest_addr: 127.0.0.1
    port: $PORT
FTWCONF
cd "$work"
set +e
"$FTW" run --config "$work/.ftw.yaml" -d "$CRS_DIR/tests/regression/tests" \
    --overrides "$CRS_DIR/tests/regression/nginx-overrides.yaml" \
    --log-file "$work/logs/error.log" ${FTW_ARGS:-} > "$work/ftw.out" 2>&1
status=$?
set -e
tail -n 30 "$work/ftw.out"
exit $status
