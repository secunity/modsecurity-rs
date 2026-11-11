#!/bin/sh
# Library benchmark: bench_capi.c (C API only) linked against the C++
# libmodsecurity and against this Rust port; same rules, same requests.
#
#   CPP_TREE=/path/to/built/ModSecurity CRS_DIR=/path/to/coreruleset \
#     test/benchmark/run_library.sh
#
# Scenarios: "upstream" (the request of the C++ project's
# test/benchmark/benchmark.cc), "corpus_pl1"/"corpus_pl4" (the
# test/differential corpus at CRS paranoia levels 1 and 4). Rules:
# modsecurity.conf-recommended (audit log off) + CRS. Each run is pinned to
# one CPU (CPU, default 3); REPS repetitions alternate the two libraries.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
: "${CPP_TREE:?set CPP_TREE to a built C++ ModSecurity tree}"
: "${CRS_DIR:?set CRS_DIR to a coreruleset checkout}"
REPS=${REPS:-5}
CPU=${CPU:-3}
work="$root/target/benchmark"
mkdir -p "$work"

(cd "$root" && cargo build --release --lib)
ln -sf libmodsecurity.so "$root/target/release/libmodsecurity.so.3"
gcc -O2 -I"$CPP_TREE/headers" -o "$work/bench_cpp" "$here/bench_capi.c" \
    -L"$CPP_TREE/src/.libs" -lmodsecurity -Wl,-rpath,"$CPP_TREE/src/.libs"
gcc -O2 -I"$CPP_TREE/headers" -o "$work/bench_rs" "$here/bench_capi.c" \
    -L"$root/target/release" -lmodsecurity -Wl,-rpath,"$root/target/release"

cp "$root/unicode.mapping" "$work/"
sed 's/^SecAuditEngine .*/SecAuditEngine Off/' "$root/modsecurity.conf-recommended" > "$work/modsecurity.conf"
printf 'Include %s/modsecurity.conf\nInclude %s/crs-setup.conf.example\nInclude %s/rules/*.conf\n' \
    "$work" "$CRS_DIR" "$CRS_DIR" > "$work/pl1.conf"
printf 'Include %s/modsecurity.conf\nInclude %s/crs-setup.conf.example\nSecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=4,setvar:tx.detection_paranoia_level=4"\nInclude %s/rules/*.conf\n' \
    "$work" "$CRS_DIR" "$CRS_DIR" > "$work/pl4.conf"
python3 -I "$root/test/differential/gen_requests.py" "$work/corpus.txt"

cd "$work"
out=library_results.txt; : > $out
for rep in $(seq 1 "$REPS"); do
  for b in cpp rs; do
    echo "upstream $b $(taskset -c "$CPU" ./bench_$b pl1.conf upstream 10000)" >> $out
    echo "corpus_pl1 $b $(taskset -c "$CPU" ./bench_$b pl1.conf corpus 50 corpus.txt)" >> $out
    echo "corpus_pl4 $b $(taskset -c "$CPU" ./bench_$b pl4.conf corpus 30 corpus.txt)" >> $out
  done
done
python3 -I "$here/summarize.py" library "$work/$out"
