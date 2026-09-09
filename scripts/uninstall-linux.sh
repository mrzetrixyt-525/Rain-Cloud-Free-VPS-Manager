#!/usr/bin/env bash
set -Eeuo pipefail
if [[ ${EUID} -ne 0 ]]; then echo 'Run as root.' >&2; exit 1; fi
systemctl disable --now rgnodes-vps-protect.service 2>/dev/null || true
rm -f /etc/systemd/system/rgnodes-vps-protect.service
systemctl daemon-reload
# Remove only this product's dedicated nftables objects when present.
if command -v nft >/dev/null 2>&1; then nft delete table inet rgnodes_protect 2>/dev/null || true; fi
# Remove only the dedicated iptables chain/jump created by this product.
if command -v iptables >/dev/null 2>&1; then
  iptables -D INPUT -j RGNODES_PROTECT 2>/dev/null || true
  iptables -F RGNODES_PROTECT 2>/dev/null || true
  iptables -X RGNODES_PROTECT 2>/dev/null || true
fi
rm -rf /opt/rgnodes-vps-protect
printf 'RG Nodes VPS Protect removed.\n'
