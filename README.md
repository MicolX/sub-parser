# Sub-Parser

A robust, stealthy Python utility designed to fetch, decode, and parse VPN/proxy subscription URLs into modern `clash-rs` (Mihomo) compatible YAML configurations.

It is specifically engineered to bypass subscription providers that use strict TLS fingerprinting or firewalls by impersonating modern browser TLS handshakes and valid iOS client signatures.

## ✨ Features

- **Anti-Blocking Transport:** Uses `curl_cffi` to mimic browser TLS fingerprints (Chrome 120) and a modern Shadowrocket `User-Agent` to prevent providers from dropping connections (`Connection reset by peer`).
- **Advanced Protocol Support:** Natively parses `vless://`, `trojan://`, `hysteria2://`, and `ss://` (Shadowsocks) links.
- **AnyTLS & SIP003 Extraction:** Automatically cracks open Shadowsocks plugin strings to extract hidden `host` and `sni` parameters, mapping them perfectly to `type: anytls` configurations for `clash-rs`.
- **Batch Processing:** Run via CLI for a single link or use a `config.yaml` file to process multiple subscriptions simultaneously with custom routing.
- **Regex Filtering:** Strip out unwanted nodes (like traffic alerts, expired warnings, or specific regions) using Regex exclusion lists.
- **Regional Splitting:** Automatically split Hong Kong (`HK`, `🇭🇰`, `香港`) nodes into a dedicated secondary output file.
- **Diagnostic Logging:** Generates detailed, timestamped execution and debug logs in the `./log/` directory.

## 🚀 Prerequisites & Installation

This project uses [uv](https://github.com/astral-sh/uv) as a unified Python package and environment manager. You do not need to install Python manually.

```bash
# 1. Install uv (if you haven't already)
curl -LsSf [https://astral.sh/uv/install.sh](https://astral.sh/uv/install.sh) | sh

# 2. Clone your repository and navigate to the directory
cd sub-parser

# 3. Synchronize environment and dependencies
uv sync


## config.yaml
# =====================================================================
# GENERAL CONFIG (Global Defaults)
# =====================================================================
split_hk: false
exclude:
  - ".*倍率.*"
  - ".*流量.*"
  - ".*重置.*"

# =====================================================================
# SUBSCRIPTIONS TARGETS
# =====================================================================
subscriptions:
  # -------------------------------------------------------------------
  # Target 1: Minimal Setup
  # Uses all general rules. Outputs to: ./output/fast-proxy.yaml
  # -------------------------------------------------------------------
  - name: "fast-proxy"
    url: "[https://your-subscription-url.com/sub/token1](https://your-subscription-url.com/sub/token1)"

  # -------------------------------------------------------------------
  # Target 2: Advanced Override Setup
  # Turns on HK splitting, custom file path, and completely unique regex rules.
  # Outputs to: ./custom-folder/hk-nodes.yaml & ./custom-folder/hk-nodes-hk.yaml
  # -------------------------------------------------------------------
  - name: "premium-cloud"
    url: "[https://another-url.com/sub/token2](https://another-url.com/sub/token2)"
    file: "./custom-folder/hk-nodes.yaml"
    split_hk: true
    exclude:
      - ".*过期.*"    # Excludes strings containing expiration text
      - "^INFO"       # Excludes informational alert nodes starting with INFO
```
