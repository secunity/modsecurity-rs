#!/bin/sh
# A smoke test of the nginx connector with SecRuleEngine On, for what the
# CRS run (test/crs/run.sh: DetectionOnly behind a proxy) does not reach:
# interventions in each phase, static files, headers added by other
# modules, subrequests and a spooled request body.
#
# It builds nothing. Required environment:
#   NGINX_BIN  an nginx binary built --with-compat and
#              --with-http_auth_request_module (test/crs/run.sh builds one at
#              target/crs-<name>/nginx/sbin/nginx)
#   MODULE_SO  the connector module to load, built against that nginx
#              (NGINX_SOURCE_DIR/NGINX_BUILD_DIR, see connectors/nginx)
# Optional: WORK_DIR (default target/nginx-smoke), PORT (default 18209).
#
# Every check is run and reported; the exit status is 1 when one failed.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
for v in NGINX_BIN MODULE_SO; do
    eval "test -n \"\${$v:-}\"" || { echo "set $v" >&2; exit 2; }
done
PORT=${PORT:-18209}
work=${WORK_DIR:-$root/target/nginx-smoke}
rm -rf "$work"
mkdir -p "$work/logs" "$work/tmp" "$work/html/static" "$work/html/added" "$work/html/protected" \
    "$work/html/server" "$work/html/upload"
work=$(cd "$work" && pwd)
cp "$MODULE_SO" "$work/ngx_http_modsecurity_module.so"

printf 'plain static file\n' > "$work/html/static/plain.txt"
printf 'this file holds smoke-secret-body in its text\n' > "$work/html/static/secret.txt"
printf 'added\n' > "$work/html/added/index.txt"
printf 'protected\n' > "$work/html/protected/index.txt"
printf 'server\n' > "$work/html/server/index.txt"
printf 'upload\n' > "$work/html/upload/index.txt"

cat > "$work/rules.conf" <<'RULES'
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 1000
SecRequestBodyLimitAction Reject
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
# phase 1: deny and redirect
SecRule REQUEST_URI "@beginsWith /deny" "id:1001,phase:1,deny,status:403"
SecRule REQUEST_URI "@beginsWith /redirect" "id:1002,phase:1,redirect:http://example.com/target"
# phase 3: a header that the headers filter (add_header) adds
SecRule RESPONSE_HEADERS:X-Smoke-Added "@streq smoke-header-value" "id:1003,phase:3,deny,status:403"
# phase 3: the status of a subrequest must not be seen as the response's
SecRule RESPONSE_STATUS "@streq 204" "id:1004,phase:3,deny,status:403"
# phase 3: the Server header nginx sends (server_tokens off)
SecRule REQUEST_URI "@beginsWith /server/" "id:1005,phase:3,deny,status:403,chain"
    SecRule RESPONSE_HEADERS:Server "@streq nginx"
# phase 4: the body of a static file
SecRule RESPONSE_BODY "@contains smoke-secret-body" "id:1006,phase:4,deny,status:403"
RULES

cat > "$work/nginx.conf" <<NGX
load_module $work/ngx_http_modsecurity_module.so;
worker_processes 1;
pid $work/nginx.pid;
error_log $work/logs/error.log info;
events { worker_connections 64; }
http {
    access_log $work/logs/access.log;
    client_body_temp_path $work/tmp/client_body;
    proxy_temp_path $work/tmp/proxy;
    fastcgi_temp_path $work/tmp/fastcgi;
    uwsgi_temp_path $work/tmp/uwsgi;
    scgi_temp_path $work/tmp/scgi;
    default_type text/plain;
    server_tokens off;
    # Request bodies over 1k go to a file (SecRequestBodyLimit is 1000).
    client_body_buffer_size 1k;
    modsecurity on;
    modsecurity_rules_file $work/rules.conf;
    server {
        listen 127.0.0.1:$PORT;
        root $work/html;
        location /added/ { add_header X-Smoke-Added smoke-header-value; }
        location /protected/ { auth_request /auth; }
        location = /auth { internal; return 204; }
        location /upload/ { error_page 405 =200 \$uri; }
    }
}
NGX

cleanup() {
    "$NGINX_BIN" -p "$work" -c "$work/nginx.conf" -s quit 2>/dev/null || true
}
trap cleanup EXIT
"$NGINX_BIN" -p "$work" -c "$work/nginx.conf"
base="http://127.0.0.1:$PORT"
for _ in $(seq 1 50); do
    curl -s -o /dev/null "$base/static/plain.txt" && break
    sleep 0.1
done

failed=0
pass() { echo "ok      $1"; }
fail() { echo "FAILED  $1: $2"; failed=1; }

# check <name> <expected status> <curl args...>: the status of the response.
check() {
    name=$1 want=$2
    shift 2
    got=$(curl -s -o "$work/body" -w '%{http_code}' "$@") || true
    if [ "$got" = "$want" ]; then pass "$name"; else fail "$name" "status $got, expected $want"; fi
}

check "a request no rule matches is served" 200 "$base/static/plain.txt"

check "phase 1 deny" 403 "$base/deny"

got=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "$base/redirect") || true
if [ "$got" = "302 http://example.com/target" ]; then pass "phase 1 redirect"
else fail "phase 1 redirect" "got '$got', expected '302 http://example.com/target'"; fi

check "phase 3 sees a header added by add_header" 403 "$base/added/index.txt"

check "phase 3 sees the Server header without a NUL byte" 403 "$base/server/index.txt"

check "a 204 auth_request subrequest is not the response's status" 200 "$base/protected/index.txt"

# The headers are already on their way when phase 4 denies: nginx closes the
# connection, so what counts is that the body does not reach the client and
# that the rule matched.
curl -s -o "$work/body" "$base/static/secret.txt" || true
if grep -q smoke-secret-body "$work/body"; then
    fail "phase 4 sees the body of a static file" "the body reached the client"
elif ! grep -q 'id "1006"' "$work/logs/error.log"; then
    fail "phase 4 sees the body of a static file" "rule 1006 did not match"
else
    pass "phase 4 sees the body of a static file"
fi

head -c 5000 /dev/zero | tr '\0' a > "$work/large-body"
check "a request body over SecRequestBodyLimit is rejected" 403 \
    -H 'Content-Type: text/plain' --data-binary "@$work/large-body" "$base/upload/index.txt"

check "a request body under SecRequestBodyLimit is accepted" 200 \
    -H 'Content-Type: text/plain' --data-binary 'small body' "$base/upload/index.txt"

# (The phase 4 deny logs the alert "header already sent": the connector
# ends a request whose headers are out, as the C module does.)
if grep -qE '\[emerg\]|exited on signal' "$work/logs/error.log"; then
    fail "nginx error log" "$(grep -E '\[emerg\]|exited on signal' "$work/logs/error.log" | head -3)"
else
    pass "no worker crash in the error log"
fi

[ "$failed" -eq 0 ] && echo "All checks passed." || echo "Some checks failed (logs in $work/logs)."
exit "$failed"
