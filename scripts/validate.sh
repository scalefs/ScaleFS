#!/bin/sh
# Run the full local validation gate: formatting, lints, and tests.
set -eu

cd "$(dirname "$0")/.."

echo '== cargo fmt --all --check'
cargo fmt --all --check

echo '== cargo clippy --workspace --all-targets -- -D warnings'
cargo clippy --workspace --all-targets -- -D warnings

echo '== cargo test --workspace'
cargo test --workspace

echo 'validate: all checks passed'
