# 🛡️ Aegis Sentinel: Next-Gen Network EDR & Gateway Node

Aegis is a high-performance, asynchronous Network IPS and Sentinel node designed for secure perimeter control. It operates as a transparent gateway, intercepting and auditing traffic from VPN tunnels using kernel-level NFQUEUE integration.

## 🏛️ Architecture
Aegis implements a **Control/Data Plane separation**:
- **Data Plane**: Linux Kernel (WireGuard + nftables) for wire-speed packet movement.
- **Control Plane**: Async Python 3.12+ for deep flow inspection and threat intelligence integration.

## 🚀 Key Features
- **Non-Blocking Interception**: Asynchronous packet analysis using `asyncio` and `NetfilterQueue`.
- **Flow Reputation**: Real-time IP and domain auditing via extensible Threat Intel modules.
- **Gateway Security**: Automated NAT and IP-Forwarding orchestration for specialized hardware (Toshiba Satellite L50 series).

## 🔧 Installation
```bash
# Sychronize environment via uv
uv sync

# Initialize Network Infrastructure
chmod +x scripts/setup_gateway.sh
./scripts/setup_gateway.sh