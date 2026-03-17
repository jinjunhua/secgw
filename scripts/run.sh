#!/bin/bash
# =============================================================================
# GM IPSec Runtime Setup & Launch Script
#
# This script:
#   1. Sets up hugepages for DPDK
#   2. Loads the vfio-pci or uio_pci_generic driver
#   3. Configures VPP with the GM-IPSec plugin
#   4. Starts strongSwan (charon) with GM crypto plugin
#   5. Sets up IPSec SAs via swanctl
#
# Usage: sudo ./scripts/run.sh [--dry-run] [--stop]
#
# Environment variables:
#   LOCAL_IP    - Local tunnel endpoint (default: 192.168.1.1)
#   REMOTE_IP   - Remote tunnel endpoint (default: 192.168.1.2)
#   SUBNET_L    - Local protected subnet  (default: 10.0.1.0/24)
#   SUBNET_R    - Remote protected subnet (default: 10.0.2.0/24)
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

DRY_RUN=0
STOP=0
LOCAL_IP="${LOCAL_IP:-192.168.1.1}"
REMOTE_IP="${REMOTE_IP:-192.168.1.2}"
SUBNET_L="${SUBNET_L:-10.0.1.0/24}"
SUBNET_R="${SUBNET_R:-10.0.2.0/24}"
HUGEPAGES="${HUGEPAGES:-1024}"
DPDK_NIC="${DPDK_NIC:-0000:00:08.0}"

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --stop)    STOP=1    ;;
    esac
done

run_cmd() {
    echo "  $ $*"
    if [ "$DRY_RUN" -eq 0 ]; then
        eval "$@"
    fi
}

# ------------------------------------------------------------------ #
# Stop services                                                        #
# ------------------------------------------------------------------ #
if [ "$STOP" -eq 1 ]; then
    echo "[*] Stopping GM IPSec services..."
    run_cmd "swanctl --terminate --ike gm-ike 2>/dev/null || true"
    run_cmd "systemctl stop strongswan 2>/dev/null || true"
    run_cmd "systemctl stop vpp 2>/dev/null || true"
    echo "[+] Stopped."
    exit 0
fi

# ------------------------------------------------------------------ #
# Pre-flight checks                                                    #
# ------------------------------------------------------------------ #
if [ "$(id -u)" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    echo "[!] This script requires root privileges."
    echo "    Re-run with: sudo $0 $*"
    exit 1
fi

echo "================================================================"
echo " GM IPSec Gateway Startup"
echo " Local:  $LOCAL_IP  (protects $SUBNET_L)"
echo " Remote: $REMOTE_IP (protects $SUBNET_R)"
echo "================================================================"

# ------------------------------------------------------------------ #
# Step 1: Hugepages                                                    #
# ------------------------------------------------------------------ #
echo ""
echo "[1] Setting up hugepages ($HUGEPAGES x 2MB)..."
if [ -f /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages ]; then
    run_cmd "echo $HUGEPAGES > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
    run_cmd "mkdir -p /mnt/huge && mount -t hugetlbfs none /mnt/huge 2>/dev/null || true"
fi

# ------------------------------------------------------------------ #
# Step 2: Bind NIC to DPDK driver                                     #
# ------------------------------------------------------------------ #
echo ""
echo "[2] Binding NIC $DPDK_NIC to DPDK..."
if command -v dpdk-devbind.py &>/dev/null; then
    run_cmd "dpdk-devbind.py --status"
    run_cmd "modprobe vfio-pci 2>/dev/null || modprobe uio_pci_generic"
    run_cmd "dpdk-devbind.py --bind=vfio-pci $DPDK_NIC"
elif command -v dpdk_nic_bind &>/dev/null; then
    run_cmd "dpdk_nic_bind --bind=igb_uio $DPDK_NIC"
else
    echo "  [!] DPDK bind tool not found - skipping NIC binding"
fi

# ------------------------------------------------------------------ #
# Step 3: Install VPP plugin                                          #
# ------------------------------------------------------------------ #
echo ""
echo "[3] Installing GM-IPSec VPP plugin..."
BUILD_DIR="$ROOT_DIR/build"
if [ -f "$BUILD_DIR/src/vpp/gm_ipsec_plugin/gm_ipsec_plugin.so" ]; then
    run_cmd "cp $BUILD_DIR/src/vpp/gm_ipsec_plugin/gm_ipsec_plugin.so /usr/lib/vpp_plugins/"
    echo "  [+] Plugin installed"
else
    echo "  [!] VPP plugin not built - run: ./scripts/build.sh --with-vpp"
fi

# ------------------------------------------------------------------ #
# Step 4: Configure VPP                                               #
# ------------------------------------------------------------------ #
echo ""
echo "[4] Starting VPP..."
run_cmd "cp $ROOT_DIR/conf/vpp.conf /etc/vpp/startup.conf"
if command -v vpp &>/dev/null; then
    run_cmd "systemctl start vpp"
    sleep 2
    # Configure VPP interface and IPSec
    run_cmd "vppctl set int state GigabitEthernetX/0/0 up"
    run_cmd "vppctl set int ip address GigabitEthernetX/0/0 $LOCAL_IP/24"
else
    echo "  [!] VPP not installed - skipping"
fi

# ------------------------------------------------------------------ #
# Step 5: strongSwan GM plugin                                        #
# ------------------------------------------------------------------ #
echo ""
echo "[5] Setting up strongSwan with GM plugin..."
SS_PLUGIN_DIR="/usr/lib/ipsec/plugins"
if [ -f "$BUILD_DIR/src/strongswan/plugin/libstrongswan-gm.so" ]; then
    run_cmd "cp $BUILD_DIR/src/strongswan/plugin/libstrongswan-gm.so $SS_PLUGIN_DIR/"
fi

run_cmd "cp $ROOT_DIR/conf/strongswan.conf /etc/strongswan.conf"
run_cmd "cp $ROOT_DIR/conf/ipsec.conf /etc/ipsec.conf"

if command -v ipsec &>/dev/null || command -v swanctl &>/dev/null; then
    # Generate swanctl configuration
    cat > /tmp/gm-ipsec.conf << EOF
connections {
    gm-ipsec {
        version = 2
        local_addrs  = $LOCAL_IP
        remote_addrs = $REMOTE_IP

        local {
            auth = psk
            id   = $LOCAL_IP
        }
        remote {
            auth = psk
            id   = $REMOTE_IP
        }

        # IKEv2 SA using GM algorithms
        proposals = sm4cbc-hmacSm3-prfHmacSm3-sm2_256

        children {
            gm-esp {
                local_ts  = $SUBNET_L
                remote_ts = $SUBNET_R
                # ESP SA using SM4-GCM
                esp_proposals = sm4gcm128
                mode = tunnel
            }
        }
    }
}

secrets {
    ike-gm {
        id = $LOCAL_IP
        secret = "GM-IPSec-PSK-2024-Change-In-Production"
    }
}
EOF
    run_cmd "mkdir -p /etc/swanctl/conf.d"
    run_cmd "cp /tmp/gm-ipsec.conf /etc/swanctl/conf.d/gm-ipsec.conf"
    run_cmd "systemctl start strongswan 2>/dev/null || ipsec start"
    sleep 2
    run_cmd "swanctl --load-all 2>/dev/null || ipsec reload"
    run_cmd "swanctl --initiate --child gm-esp 2>/dev/null || true"
else
    echo "  [!] strongSwan not installed - skipping"
fi

echo ""
echo "================================================================"
echo " [+] GM IPSec Gateway started"
echo "     Local:  $LOCAL_IP -- $SUBNET_L"
echo "     Remote: $REMOTE_IP -- $SUBNET_R"
echo ""
echo "     Check status:  swanctl --list-sas"
echo "     Check VPP:     vppctl show ipsec all"
echo "     Stop:          sudo $0 --stop"
echo "================================================================"
