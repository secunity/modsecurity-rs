#!/bin/sh
# Library benchmark: bench_capi.c (C API only) against several builds of the
# library, interleaved, with the same rules and requests.
#
#   test/benchmark/build_variant.sh parent HEAD~1
#   test/benchmark/build_variant.sh candidate
#   test/benchmark/build_variant.sh control HEAD~1     # optional: A/A noise
#   CRS_DIR=/path/to/coreruleset VARIANTS="parent candidate control" \
#     test/benchmark/run_library.sh
#
# VARIANTS: names built by build_variant.sh (the first one is the baseline
# of the ratios), and `cpp` for the C++ libmodsecurity of CPP_TREE. CPP_TREE
# (a built C++ tree) is needed for its headers in any case.
#
# Scenarios: "upstream" (the request of the C++ project's
# test/benchmark/benchmark.cc), "corpus_pl1"/"corpus_pl4" (the
# test/differential corpus at CRS paranoia levels 1 and 4). Rules:
# modsecurity.conf-recommended (audit log off) + CRS. Each run is pinned to
# one CPU (CPU, default 3); REPS rounds (default 5) run every variant in
# turn. summarize.py prints the best and the median of each.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
: "${CPP_TREE:?set CPP_TREE to a built C++ ModSecurity tree (for its headers)}"
: "${CRS_DIR:?set CRS_DIR to a coreruleset checkout}"
: "${VARIANTS:?set VARIANTS, e.g. \"parent candidate\" (see build_variant.sh)}"
REPS=${REPS:-5}
CPU=${CPU:-3}
work="$root/target/benchmark"
mkdir -p "$work/variants/cpp"
ln -sf "$CPP_TREE/src/.libs/libmodsecurity.so.3" "$work/variants/cpp/libmodsecurity.so.3"
for v in $VARIANTS; do
  [ -e "$work/variants/$v/libmodsecurity.so.3" ] || { echo "no build for $v: run build_variant.sh $v" >&2; exit 1; }
done

# One program; the variant's library is chosen at run time.
gcc -O2 -I"$CPP_TREE/headers" -o "$work/bench" "$here/bench_capi.c" -L"$work/variants/cpp" -l:libmodsecurity.so.3

cp "$root/unicode.mapping" "$work/"
sed 's/^SecAuditEngine .*/SecAuditEngine Off/' "$root/modsecurity.conf-recommended" > "$work/modsecurity.conf"
printf 'Include %s/modsecurity.conf\nInclude %s/crs-setup.conf.example\nInclude %s/rules/*.conf\n' \
    "$work" "$CRS_DIR" "$CRS_DIR" > "$work/pl1.conf"
printf 'Include %s/modsecurity.conf\nInclude %s/crs-setup.conf.example\nSecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=4,setvar:tx.detection_paranoia_level=4"\nInclude %s/rules/*.conf\n' \
    "$work" "$CRS_DIR" "$CRS_DIR" > "$work/pl4.conf"
python3 -I "$root/test/differential/gen_requests.py" "$work/corpus.txt"

cd "$work"
out=library_results.txt; : > $out
run() { LD_LIBRARY_PATH="$work/variants/$1" taskset -c "$CPU" ./bench "$2" "$3" "$4" ${5:+"$5"}; }
for rep in $(seq 1 "$REPS"); do
  for v in $VARIANTS; do
    echo "upstream $v $(run "$v" pl1.conf upstream 10000)" >> $out
    echo "corpus_pl1 $v $(run "$v" pl1.conf corpus 50 corpus.txt)" >> $out
    echo "corpus_pl4 $v $(run "$v" pl4.conf corpus 30 corpus.txt)" >> $out
  done
done
python3 -I "$here/summarize.py" library "$work/$out"
