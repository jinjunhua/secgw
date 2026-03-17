#!/bin/bash
# =============================================================================
# GM IPSec Test Runner
#
# Runs all unit tests and prints a summary.
# Usage: ./scripts/test.sh [--verbose] [--filter <name>]
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"

VERBOSE=0
FILTER=""

for arg in "$@"; do
    case "$arg" in
        --verbose) VERBOSE=1 ;;
        --filter)  shift; FILTER="$1" ;;
    esac
done

# Ensure build exists
if [ ! -d "$BUILD_DIR" ]; then
    echo "[*] Build not found, running build.sh first..."
    "$SCRIPT_DIR/build.sh"
fi

echo "================================================================"
echo " GM IPSec Unit Tests"
echo "================================================================"
echo ""

PASS=0
FAIL=0
TOTAL=0

run_test() {
    local bin="$1"
    local name="$2"

    if [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]]; then
        return
    fi

    TOTAL=$((TOTAL + 1))
    echo "--- $name ---"
    if [ "$VERBOSE" -eq 1 ]; then
        if "$bin"; then
            PASS=$((PASS + 1))
        else
            FAIL=$((FAIL + 1))
            echo "[FAIL] $name exited with error"
        fi
    else
        OUTPUT=$("$bin" 2>&1)
        EXIT=$?
        if [ "$EXIT" -eq 0 ]; then
            PASS=$((PASS + 1))
            # Show just the summary line
            echo "$OUTPUT" | grep -E "^[0-9]+/[0-9]+ tests passed" || true
            echo ""
        else
            FAIL=$((FAIL + 1))
            echo "[FAIL] $name:"
            echo "$OUTPUT"
            echo ""
        fi
    fi
}

run_test "$BUILD_DIR/test_sm3"   "SM3 Hash"
run_test "$BUILD_DIR/test_sm4"   "SM4 Cipher"
run_test "$BUILD_DIR/test_sm2"   "SM2 Public Key"
run_test "$BUILD_DIR/test_ipsec" "IPSec ESP / DPDK"

echo "================================================================"
echo " Results: $PASS passed, $FAIL failed, $TOTAL total"
echo "================================================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
