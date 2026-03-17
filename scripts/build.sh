#!/bin/bash
# =============================================================================
# GM IPSec Build Script
#
# Builds: GM crypto library, DPDK integration (optional), tests
# Usage:  ./scripts/build.sh [options]
#
# Options:
#   --with-dpdk       Link against DPDK (requires DPDK installed)
#   --with-vpp        Build VPP plugin (requires VPP headers)
#   --debug           Build with debug symbols
#   --clean           Clean build directory
#   --tests-only      Only rebuild tests
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"

WITH_DPDK=OFF
WITH_VPP=OFF
BUILD_TYPE=Release
CLEAN=0
TESTS_ONLY=0

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --with-dpdk)    WITH_DPDK=ON    ;;
        --with-vpp)     WITH_VPP=ON     ;;
        --debug)        BUILD_TYPE=Debug ;;
        --clean)        CLEAN=1         ;;
        --tests-only)   TESTS_ONLY=1    ;;
        --help)
            echo "Usage: $0 [--with-dpdk] [--with-vpp] [--debug] [--clean]"
            exit 0
            ;;
    esac
done

# ---- Clean ---
if [ "$CLEAN" -eq 1 ]; then
    echo "[*] Cleaning build directory..."
    rm -rf "$BUILD_DIR"
fi

# ---- Configure ---
if [ ! -d "$BUILD_DIR" ] || [ ! -f "$BUILD_DIR/Makefile" ] && [ ! -f "$BUILD_DIR/build.ninja" ]; then
    echo "[*] Configuring CMake (type=$BUILD_TYPE, dpdk=$WITH_DPDK, vpp=$WITH_VPP)..."
    mkdir -p "$BUILD_DIR"
    cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DWITH_DPDK="$WITH_DPDK" \
        -DBUILD_VPP_PLUGIN="$WITH_VPP" \
        -DBUILD_TESTS=ON
fi

# ---- Build ---
NCPUS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

if [ "$TESTS_ONLY" -eq 1 ]; then
    echo "[*] Building tests (j=$NCPUS)..."
    cmake --build "$BUILD_DIR" --target test_sm3 test_sm4 test_sm2 test_ipsec -j "$NCPUS"
else
    echo "[*] Building all (j=$NCPUS)..."
    cmake --build "$BUILD_DIR" -j "$NCPUS"
fi

echo ""
echo "[+] Build complete. Artifacts in: $BUILD_DIR"
echo ""
echo "    Binaries:"
for t in test_sm3 test_sm4 test_sm2 test_ipsec test_all; do
    [ -f "$BUILD_DIR/$t" ] && echo "      $BUILD_DIR/$t"
done
echo ""
echo "    Run tests with: ./scripts/test.sh"
