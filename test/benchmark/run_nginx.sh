#!/bin/sh
# nginx benchmark: one nginx binary, one worker pinned to CPU 2, wrk pinned
# to CPUs 4-6; the variants differ only in the loaded ModSecurity module.
#
#   NGINX_BIN=/path/to/nginx   (built --with-compat, same ./configure as the modules)
#   MIME_TYPES=/path/to/nginx/conf/mime.types
#   CRS_DIR=/path/to/coreruleset
#   CPP_MODULE=   C connector linked to the C++ libmodsecurity   (optional)
#   RUSTLIB_MODULE= C connector linked to this library            (optional)
#   RUSTCONN_MODULE= the Rust connector port                      (optional)
#   test/benchmark/run_nginx.sh
#
# Scenarios (SecRuleEngine On, CRS PL1): a benign GET of a static page, an
# SQLi GET blocked with 403, and a 1 KB urlencoded POST (answered 405 by the
# static handler after ModSecurity inspected the body). DUR per run, REPS
# repetitions. A variant without ModSecurity gives the nginx baseline.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
: "${NGINX_BIN:?}" "${MIME_TYPES:?}" "${CRS_DIR:?}"
W="$root/target/benchmark"
mkdir -p "$W"
DUR=${DUR:-15s}
REPS=${REPS:-3}
out=$W/nginx_results.txt; : > "$out"
UA='Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)'

sed 's/^SecRuleEngine .*/SecRuleEngine On/; s/^SecAuditEngine .*/SecAuditEngine Off/' \
    "$root/modsecurity.conf-recommended" > "$W/modsecurity_on.conf"
cp "$root/unicode.mapping" "$W/"
printf 'Include %s/modsecurity_on.conf\nInclude %s/crs-setup.conf.example\nInclude %s/rules/*.conf\n' \
    "$W" "$CRS_DIR" "$CRS_DIR" > "$W/pl1_on.conf"
cat > "$W/post.lua" <<'LUA'
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"
local parts = {}
for i = 1, 40 do parts[#parts + 1] = "field" .. i .. "=value" .. i .. "abcdefghij" end
wrk.body = table.concat(parts, "&")
LUA

variants="none"
[ -n "${CPP_MODULE:-}" ] && variants="$variants cpp"
[ -n "${RUSTLIB_MODULE:-}" ] && variants="$variants rustlib"
[ -n "${RUSTCONN_MODULE:-}" ] && variants="$variants rustconn"

module_of() {
  case $1 in
    none) echo "" ;; cpp) echo "$CPP_MODULE" ;; rustlib) echo "$RUSTLIB_MODULE" ;; rustconn) echo "$RUSTCONN_MODULE" ;;
  esac
}

setup() {
  v=$1; p=$W/ng-$v; rm -rf "$p"; mkdir -p "$p/conf" "$p/logs" "$p/html" "$p/tmp"
  head -c 600 /dev/zero | tr '\0' 'x' | sed 's/^/<html><body>/; s/$/<\/body><\/html>/' > "$p/html/index.html"
  mod=$(module_of "$v")
  {
    [ -n "$mod" ] && echo "load_module $mod;"
    echo "worker_processes 1; worker_cpu_affinity 0100; pid $p/nginx.pid; error_log $p/logs/error.log warn;"
    echo "events { worker_connections 4096; }"
    echo "http { access_log off; include $MIME_TYPES; keepalive_requests 1000000;"
    echo "  client_body_temp_path $p/tmp/cb; proxy_temp_path $p/tmp/p; fastcgi_temp_path $p/tmp/f; uwsgi_temp_path $p/tmp/u; scgi_temp_path $p/tmp/s;"
    [ -n "$mod" ] && echo "  modsecurity on; modsecurity_rules_file $W/pl1_on.conf;"
    echo "  server { listen 18080; root $p/html; location / { } } }"
  } > "$p/conf/nginx.conf"
}

run_wrk() {
  case $1 in
    get) taskset -c 4-6 wrk -t3 -c30 -d"$DUR" --latency -H "User-Agent: $UA" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-us,en;q=0.5' -H 'Cookie: PHPSESSID=r2t5uvjq435r4q7ib3vtdjq120' 'http://127.0.0.1:18080/index.html?param1=test&para2=test2' ;;
    attack) taskset -c 4-6 wrk -t3 -c30 -d"$DUR" --latency -H "User-Agent: $UA" 'http://127.0.0.1:18080/index.html?id=1%27%20OR%20%271%27%3D%271' ;;
    post) taskset -c 4-6 wrk -t3 -c30 -d"$DUR" --latency -H "User-Agent: $UA" -s "$W/post.lua" 'http://127.0.0.1:18080/index.html' ;;
  esac
}

for v in $variants; do
  setup "$v"
  for i in 1 2 3; do
    t0=$(date +%s%N); "$NGINX_BIN" -t -q -p "$W/ng-$v" -c conf/nginx.conf; t1=$(date +%s%N)
    echo "variant=$v config_test_ms=$(( (t1 - t0) / 1000000 ))" >> "$out"
  done
done

for rep in $(seq 1 "$REPS"); do
  for v in $variants; do
    "$NGINX_BIN" -p "$W/ng-$v" -c conf/nginx.conf; sleep 1
    for s in get attack post; do
      taskset -c 4-6 wrk -t1 -c4 -d2s "http://127.0.0.1:18080/index.html" > /dev/null
      res=$(run_wrk "$s")
      echo "rep=$rep variant=$v scenario=$s rps=$(echo "$res" | awk '/Requests\/sec/ {print $2}') p50=$(echo "$res" | awk '/^ +50%/ {print $2}') p99=$(echo "$res" | awk '/^ +99%/ {print $2}')" >> "$out"
    done
    wpid=$(pgrep -P "$(cat "$W/ng-$v/nginx.pid")" | head -1)
    echo "rep=$rep variant=$v worker_rss_kb=$(awk '/VmRSS/ {print $2}' /proc/$wpid/status)" >> "$out"
    "$NGINX_BIN" -p "$W/ng-$v" -c conf/nginx.conf -s quit; sleep 1
  done
done
python3 -I "$here/summarize.py" nginx "$out"
