#!/bin/sh
# DHCP on the optional third adapter. NetworkManager (Rocky, RHEL) does this by itself.
set -eu
command -v nmcli >/dev/null 2>&1 && exit 0
IF=$(ls /sys/class/net | grep -E '^(enp0s10|eth2)$' | head -1)
[ -n "$IF" ] || exit 0
if command -v netplan >/dev/null 2>&1; then
  printf 'network:\n  version: 2\n  ethernets:\n    %s:\n      dhcp4: true\n' "$IF" > /etc/netplan/60-hostonly.yaml
  chmod 600 /etc/netplan/60-hostonly.yaml
  netplan apply
else
  printf 'allow-hotplug %s\niface %s inet dhcp\n' "$IF" "$IF" > "/etc/network/interfaces.d/$IF"
  ifup "$IF" || true
fi
