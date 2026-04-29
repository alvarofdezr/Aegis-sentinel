# 🛡️ Aegis Sentinel: Next-Gen Network EDR & Gateway Node

<p align="center">
    <img src="https://img.shields.io/badge/Python-3.12%2B-blue" alt="Python 3.12+">
    <img src="https://img.shields.io/badge/Architecture-Async_NFQUEUE-orange" alt="Architecture">
    <img src="https://img.shields.io/badge/Platform-Linux_Kernel-lightgrey" alt="Platform">
    <img src="https://img.shields.io/badge/Package_Manager-uv-purple" alt="uv">
    <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License">
</p>

## Overview

**Aegis Sentinel** is a high-performance, asynchronous Network IPS and Sentinel node designed for secure perimeter control. It operates as a transparent gateway, intercepting and auditing traffic from VPN tunnels (e.g., WireGuard) using kernel-level `NFQUEUE` integration.

## 🏛️ Architecture: Control & Data Plane Separation

Aegis is built on modern enterprise networking principles, separating the packet-moving logic from the decision-making logic:

- **Data Plane (Kernel Space)**: Linux Kernel (`nftables` / `iptables`) handles wire-speed packet routing and VPN decapsulation.
- **Control Plane (User Space)**: Async Python 3.12+ engine performs deep flow inspection, state tracking, and external Threat Intelligence integration without blocking kernel queues.

### The Security Pipeline
1. **Flow Table (L1)**: Zero-latency bypass for already verified and established connections.
2. **Policy Engine (L2)**: Local application-level firewall rules and whitelists.
3. **Threat Intel (L3)**: Asynchronous reputation analysis with in-memory TTL caching.

---

## 🚀 Key Features

* **Non-Blocking Interception**: Fully asynchronous packet analysis using `asyncio` and `NetfilterQueue`.
* **Flow State Tracking**: Intelligent memory management to analyze only new flows, maintaining Gigabit speeds on specialized hardware (e.g., Toshiba Satellite L50 series).
* **Structured Telemetry**: JSON-formatted logging via `structlog`, ready for SIEM ingestion (Splunk, ELK).
* **Zero-Friction Environment**: Managed entirely via `uv` for deterministic builds and ultra-fast dependency resolution.

---

## 📂 Project Structure

```text
aegis-sentinel/
├── aegis/
│   ├── core/
│   │   ├── engine.py          # Main asynchronous orchestrator
│   │   ├── interceptor.py     # NFQUEUE handling and pipeline delegation
│   │   └── flow_table.py      # In-memory connection state tracking
│   ├── modules/
│   │   ├── threat_intel.py    # Async external API integration (TTL Cache)
│   │   └── policy_engine.py   # Local dynamic rules evaluation
│   └── common/
│       ├── schemas.py         # Strict Pydantic v2 data models
│       └── logger.py          # Structured SIEM-compatible logging
├── scripts/
│   ├── setup_gateway.sh       # Infrastructure-as-Code for routing
│   └── nftables.conf          # Low-level firewall policies
└── pyproject.toml             # uv dependency and environment definition
```

---

## 🔧 Installation & Quick Start

### Prerequisites

- **OS**: Ubuntu Server 24.04 LTS (or any modern Linux Kernel 5.10+)
- **Dependencies**: `wireguard`, `iptables`/`nftables`, and `uv` installed
- **Privileges**: Root access is strictly required for kernel queue binding
- **Python**: 3.12 or higher

### Setup Instructions

#### 1. Clone and Sync
```bash
git clone https://github.com/alvarofdezr/aegis-sentinel.git
cd aegis-sentinel

# Automatically create the virtual environment and install dependencies
uv sync
```

#### 2. Environment Configuration
```bash
cp .env.example .env
# Edit .env to add your Threat Intelligence API keys (e.g., VirusTotal)
nano .env
```

#### 3. Initialize Network Infrastructure

Configure the Linux Kernel to act as a router and forward VPN traffic to the Aegis engine:
```bash
sudo chmod +x scripts/setup_gateway.sh
sudo ./scripts/setup_gateway.sh
```

#### 4. Start the Engine

Run the asynchronous orchestrator directly from the virtual environment:
```bash
sudo .venv/bin/python -m aegis.core.engine
---

## 📋 Configuration

All configuration is managed through the `.env` file:

```env
# Threat Intelligence
VIRUSTOTAL_API_KEY=your_api_key_here
THREAT_CACHE_TTL=3600

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
```

---

## 🐛 Troubleshooting

### Issue: Permission Denied on NFQUEUE
**Solution**: Ensure you're running with `sudo`. Kernel queue binding requires root privileges.

### Issue: Packets Not Being Intercepted
**Solution**: Verify the nftables rules are loaded:
```bash
sudo nft list ruleset
```

### Issue: High Memory Usage
**Solution**: Check the flow table size and adjust cache TTL in `.env`:
```bash
# Reduce memory footprint
THREAT_CACHE_TTL=1800  # 30 minutes instead of 1 hour
```

---

## 📖 Usage Examples

### Basic Operation
```bash
# Start monitoring with default configuration
sudo .venv/bin/python -m aegis.core.engine
```

### Monitor Logs
```bash
# Stream JSON logs to Splunk or ELK
tail -f /var/log/aegis/engine.log | jq .
```

---

## 🤝 Contributing & Support

Aegis Sentinel is built for cybersecurity research and perimeter defense education.

- **Security Inquiries**: alvarofdezr@outlook.es
- **Issues & Feature Requests**: Please [open an issue](https://github.com/alvarofdezr/aegis-sentinel/issues) outlining the architectural enhancement or bug report

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Álvaro Fernández** - [@alvarofdezr](https://github.com/alvarofdezr)

---

Built with 🛡️ for network defense.