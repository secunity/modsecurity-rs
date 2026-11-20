#!/bin/sh
# Differential check of the Rust port against the C++ libmodsecurity.
#
# Builds the same C program (harness.c, C API only) against both libraries,
# runs the request corpus through the OWASP Core Rule Set (paranoia level 4,
# debug log level 9) and compares:
#   - interventions, matched rule ids and error log lines (must be identical)
#   - the debug logs (identical once non-UTF-8 bytes are decoded the same way)
# and then the first again with the debug log off, and last the audit logs
# (Serial native with every part, Serial JSON, and Concurrent: the entries
# and the index), identical once the run-specific values are normalized.
#
# Usage: CPP_TREE=/path/to/built/ModSecurity CRS_DIR=/path/to/coreruleset \
#        test/differential/run.sh
# (CRS_DIR must contain crs-setup.conf and rules/; the Rust release cdylib is
# built if needed.) FEATURES: extra cargo features for the Rust build (e.g.
# pm-aho-corasick).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
: "${CPP_TREE:?set CPP_TREE to a built C++ ModSecurity tree}"
: "${CRS_DIR:?set CRS_DIR to a coreruleset checkout}"
# The two debug logs are large (hundreds of MB): work under target/ rather
# than a (possibly small) tmpfs.
mkdir -p "$root/target"
work=$(mktemp -d "$root/target/differential.XXXXXX")
trap '[ -n "${KEEP_WORK:-}" ] || rm -rf "$work"' EXIT

(cd "$root" && cargo build --release -p modsecurity-capi ${FEATURES:+--features "$FEATURES"})
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

# Documented differences (MIGRATION.md): the C++ parser gets some rule line
# numbers wrong (`[line "N"]` is compared without N) and keeps the backslash
# of `\"` in operator parameters (operator parameters are compared with `\"`
# read as `"`).
lines() { sed -E 's/\[line "[0-9]+"\]/[line ""]/g; /with param/s/\\"/"/g' "$1"; }
lines "$work/cpp/out.txt" > "$work/cpp/out.norm"
lines "$work/rs/out.txt" > "$work/rs/out.norm"
# The script reports what differs and goes on (it is a report, not a gate:
# see CLAUDE.md). `same A B what` prints the differences of two files.
same() {
    if diff "$1" "$2" > "$work/last.diff"; then
        echo "$3: identical"
    else
        echo "$3: DIFFERENT ($(grep -c '^[<>]' "$work/last.diff") lines; the first ones follow)"
        head -20 "$work/last.diff"
    fi
}
same "$work/cpp/out.norm" "$work/rs/out.norm" "requests: $(grep -c '^REQ ' "$work/cpp/out.txt"), outputs"

# The debug logs: rule locations (`'<file>:<line>'`) are compared without
# the line, and operator parameters with `\"` read as `"` (see above). Each
# log is hundreds of MB, so they are normalised to files and compared by
# diff. With KEEP_WORK=1 the whole difference stays in debug.diff.
python3 -I - "$work/cpp/debug.log" "$work/rs/debug.log" <<'PY'
import re, sys
loc = re.compile(r"('[^']*):[0-9]+'")
for path in sys.argv[1:]:
    with open(path, 'rb') as log, open(path + '.norm', 'w', encoding='utf-8') as out:
        for line in log:
            line = loc.sub(r"\1:'", line.decode('utf-8', 'replace'))
            out.write(line.replace('\\"', '"') if 'with param' in line else line)
PY
if diff "$work/cpp/debug.log.norm" "$work/rs/debug.log.norm" > "$work/debug.diff"; then
    echo "debug log: identical ($(wc -l < "$work/rs/debug.log.norm") lines)"
else
    echo "debug log: DIFFERENT ($(grep -c '^<' "$work/debug.diff") lines only in C++, $(grep -c '^>' "$work/debug.diff") only here, of $(wc -l < "$work/rs/debug.log.norm"))"
    echo "  kinds of lines that differ:"
    grep '^[<>]' "$work/debug.diff" | sed -E 's/^([<>]) \[[^]]*\] \[[^]]*\] \[[0-9]\] */\1 /; s/[0-9]+/N/g; s/"[^"]*"/"..."/g; s/: .*/: .../' | cut -c1-70 | sort | uniq -c | sort -rn | head -8
fi

# Second pass without the debug log: some paths (e.g. the transformation
# cache) are only taken when the debug level is below 9.
grep -v '^SecDebugLog' "$work/rules.conf" > "$work/rules-nodebug.conf"
for v in cpp rs; do
    mkdir "$work/$v-nodebug"
    (cd "$work/$v-nodebug" && "../harness_$v" ../rules-nodebug.conf ../requests.txt > out.txt)
done
lines "$work/cpp-nodebug/out.txt" > "$work/cpp-nodebug/out.norm"
lines "$work/rs-nodebug/out.txt" > "$work/rs-nodebug/out.norm"
same "$work/cpp-nodebug/out.norm" "$work/rs-nodebug/out.norm" "without debug log: outputs"

# Third pass: the audit logs (an output format of the compatibility
# contract). Run-specific values are normalized: dates, the random native
# boundary, the Concurrent storage paths and the md5 of an entry (it covers
# the date). Rule line numbers and `\"` as above. The size in an index line
# is a whole number here and has six decimals in C++ (see MIGRATION.md).
audit_norm() {
    sed -E \
        -e 's#\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}\]#[DATE]#g' \
        -e 's#"time_stamp":"[^"]*"#"time_stamp":""#g' \
        -e 's#---[a-zA-Z0-9]{8,}---([A-Z])--$#---B---\1--#' \
        -e 's#'"$work"'/audit-[a-z]+-(cpp|rs)/store/[0-9]{8}/[0-9]{8}-[0-9]{4}/[0-9]{8}-[0-9]{6}-#STORE/#g' \
        -e 's#md5:[0-9a-f]{32}#md5:#g' \
        -e 's# ([0-9]+)\.000000 md5:# \1 md5:#' \
        -e 's/\[line "[0-9]+"\]/[line ""]/g' \
        -e 's/"lineNumber":"[0-9]+"/"lineNumber":""/g' \
        -e '/with param/s/\\"/"/g' \
        "$1"
}
for mode in native json concurrent; do
    for v in cpp rs; do
        d=$work/audit-$mode-$v
        mkdir -p "$d/store"
        {
            cat "$work/rules-nodebug.conf"
            echo "SecAuditEngine On"
            echo "SecAuditLogParts ABCDEFGHIJKZ"
            case $mode in
                native) printf 'SecAuditLogType Serial\nSecAuditLogFormat Native\n' ;;
                json) printf 'SecAuditLogType Serial\nSecAuditLogFormat JSON\n' ;;
                concurrent) printf 'SecAuditLogType Concurrent\nSecAuditLogFormat Native\nSecAuditLogStorageDir %s/store\n' "$d" ;;
            esac
            echo "SecAuditLog $d/audit.log"
        } > "$d/rules.conf"
        (cd "$d" && "../harness_$v" rules.conf ../requests.txt > /dev/null)
        # (Empty logs would compare equal: require a line per request.)
        [ "$(wc -l < "$d/audit.log")" -ge "$(grep -c '^###' "$work/requests.txt")" ] ||
            { echo "audit-$mode-$v: fewer audit log lines than requests" >&2; exit 1; }
        audit_norm "$d/audit.log" > "$d/audit.norm"
        if [ "$mode" = concurrent ]; then
            # One file per entry, in transaction id order.
            find "$d/store" -type f | while read -r f; do
                echo "$(basename "$f" | sed -E 's/^[0-9]{8}-[0-9]{6}-//') $f"
            done | sort | while read -r id f; do echo "== $id"; audit_norm "$f"; done > "$d/entries.norm"
        fi
    done
    same "$work/audit-$mode-cpp/audit.norm" "$work/audit-$mode-rs/audit.norm" "audit log ($mode)"
    [ "$mode" != concurrent ] ||
        same "$work/audit-$mode-cpp/entries.norm" "$work/audit-$mode-rs/entries.norm" "audit log ($mode) entries"
done
