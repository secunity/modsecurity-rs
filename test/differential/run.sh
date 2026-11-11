#!/bin/sh
# Differential check of the Rust port against the C++ libmodsecurity.
#
# Builds the same C program (harness.c, C API only) against both libraries,
# runs the request corpus through the OWASP Core Rule Set (paranoia level 4,
# debug log level 9) and compares:
#   - interventions, matched rule ids and error log lines (must be identical)
#   - the debug logs (identical once non-UTF-8 bytes are decoded the same way)
#
# Usage: CPP_TREE=/path/to/built/ModSecurity CRS_DIR=/path/to/coreruleset \
#        test/differential/run.sh
# (CRS_DIR must contain crs-setup.conf and rules/; the Rust release cdylib is
# built if needed.)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
: "${CPP_TREE:?set CPP_TREE to a built C++ ModSecurity tree}"
: "${CRS_DIR:?set CRS_DIR to a coreruleset checkout}"
# The two debug logs are large (hundreds of MB): work under target/ rather
# than a (possibly small) tmpfs.
mkdir -p "$root/target"
work=$(mktemp -d "$root/target/differential.XXXXXX")
trap 'rm -rf "$work"' EXIT

(cd "$root" && cargo build --release --lib)
# The cdylib's SONAME is libmodsecurity.so.3 (as with the C++ build).
ln -sf libmodsecurity.so "$root/target/release/libmodsecurity.so.3"
gcc -O1 -I"$CPP_TREE/headers" -o "$work/harness_cpp" "$here/harness.c" \
    -L"$CPP_TREE/src/.libs" -lmodsecurity -Wl,-rpath,"$CPP_TREE/src/.libs"
gcc -O1 -I"$CPP_TREE/headers" -o "$work/harness_rs" "$here/harness.c" \
    -L"$root/target/release" -lmodsecurity -Wl,-rpath,"$root/target/release"
sed "s#@CRS_DIR@#$CRS_DIR#g" "$here/rules.conf.in" > "$work/rules.conf"
python3 -I "$here/gen_requests.py" "$work/requests.txt"

for v in cpp rs; do
    mkdir "$work/$v"
    (cd "$work/$v" && "../harness_$v" ../rules.conf ../requests.txt > out.txt)
done

diff "$work/cpp/out.txt" "$work/rs/out.txt"
python3 -I - "$work/cpp/debug.log" "$work/rs/debug.log" <<'PY'
import itertools, sys
# Stream both logs (each is hundreds of MB).
n, bad = 0, []
with open(sys.argv[1], 'rb') as fa, open(sys.argv[2], 'rb') as fb:
    for x, y in itertools.zip_longest(fa, fb):
        n += 1
        if x is None or y is None or x.decode('utf-8', 'replace') != y.decode('utf-8', 'replace'):
            bad.append(n)
            if len(bad) == 10:
                break
assert not bad, f"debug log differs at lines {bad}"
print(f"identical: {n} debug log lines")
PY
echo "requests: $(grep -c '^REQ ' "$work/cpp/out.txt"), outputs identical"
