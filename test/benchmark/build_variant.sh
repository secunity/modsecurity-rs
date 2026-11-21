#!/bin/sh
# Builds the release C API library of one commit for the benchmarks.
#
#   test/benchmark/build_variant.sh NAME [REV]
#
# REV is a git revision (a commit, a branch, `master`, `HEAD~1`, ...); without
# it the working tree is built as it is. The library goes to
# target/benchmark/variants/NAME/libmodsecurity.so.3, which run_library.sh
# loads for the variant NAME. A revision is built in a worktree of its own
# under target/benchmark/src/NAME with its own target directory, so the
# working tree and its build are left alone. FEATURES: extra cargo features.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
name=${1:?usage: build_variant.sh NAME [REV]}
rev=${2:-}
out="$root/target/benchmark/variants/$name"
mkdir -p "$out"

if [ -z "$rev" ]; then
  src=$root; target=$root/target
else
  src=$root/target/benchmark/src/$name; target=$root/target/benchmark/build/$name
  git -C "$root" worktree remove --force "$src" 2>/dev/null || true
  git -C "$root" worktree add --detach "$src" "$rev" > /dev/null
fi
(cd "$src" && CARGO_TARGET_DIR=$target cargo build --release -p modsecurity-capi ${FEATURES:+--features "$FEATURES"})
cp "$target/release/libmodsecurity.so" "$out/libmodsecurity.so.3"
[ -z "$rev" ] || git -C "$root" worktree remove --force "$src"
echo "$name: $(git -C "$root" rev-parse --short "${rev:-HEAD}")${rev:+} -> $out/libmodsecurity.so.3"
