#!/bin/bash
set -euo pipefail

# Aegis Infrastructure Setup Script
# Target: Ubuntu Server 24.04 LTS (Toshiba Satellite L50-B)

echo "[*] Enabling IPv4 Forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

echo "[*] Resetting Firewall Rules..."
sudo iptables -F
sudo iptables -t nat -F

echo "[*] Routing WireGuard (wg0) traffic to Aegis (NFQUEUE 1)..."
# Intercept traffic being forwarded from the VPN tunnel
sudo iptables -A FORWARD -i wg0 -j NFQUEUE --queue-num 1

echo "[*] Configuring NAT Masquerade..."
# Replace 'eth0' with your actual internet-facing interface (use 'ip link' to check)
PHYS_IFACE=$(ip route | grep default | awk '{print $5}')
sudo iptables -t nat -A POSTROUTING -o "$PHYS_IFACE" -j MASQUERADE

echo "[+] Aegis Network Infrastructure is READY."