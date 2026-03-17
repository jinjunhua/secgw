#!/bin/bash
# =============================================================================
# GM IPSec Environment Setup
#
# Installs build dependencies for GM IPSec on Ubuntu 20.04/22.04.
# Usage: sudo ./scripts/setup_env.sh
# =============================================================================

set -e

echo "================================================================"
echo " GM IPSec - Dependency Setup"
echo "================================================================"

# ---- Detect distro ----
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    DISTRO="unknown"
fi

echo "[*] Detected: $DISTRO"

install_ubuntu() {
    apt-get update -qq
    apt-get install -y \
        build-essential cmake ninja-build \
        pkg-config git wget curl \
        libssl-dev libgmp-dev \
        linux-headers-$(uname -r) \
        libnuma-dev \
        python3 python3-pip \
        strongswan strongswan-swanctl \
        ipsec-tools

    # DPDK (optional - comment out if not needed)
    echo "[*] Installing DPDK..."
    apt-get install -y dpdk dpdk-dev || \
        echo "  [!] DPDK apt packages not found, install manually from dpdk.org"

    # VPP (optional)
    echo "[*] Installing VPP..."
    if ! dpkg -l vpp &>/dev/null; then
        curl -s https://packagecloud.io/install/repositories/fdio/release/script.deb.sh | bash || true
        apt-get install -y vpp vpp-plugin-core vpp-dev || \
            echo "  [!] VPP not available, install from fd.io"
    fi
}

install_rhel() {
    yum install -y \
        gcc gcc-c++ cmake ninja-build \
        pkgconfig git wget \
        openssl-devel gmp-devel \
        numactl-devel \
        kernel-devel \
        strongswan
}

case "$DISTRO" in
    ubuntu|debian) install_ubuntu ;;
    rhel|centos|fedora) install_rhel ;;
    *)
        echo "[!] Unknown distro: $DISTRO"
        echo "    Please install manually: cmake, gcc, libssl-dev, dpdk-dev, vpp-dev, strongswan"
        ;;
esac

echo ""
echo "[+] Dependencies installed."
echo ""
echo "    Next steps:"
echo "    1. Build:    ./scripts/build.sh"
echo "    2. Test:     ./scripts/test.sh"
echo "    3. Deploy:   sudo ./scripts/run.sh"
