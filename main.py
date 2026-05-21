import base64
import logging
import urllib.parse
import yaml
from curl_cffi import requests
import os
import argparse
import sys
import re

def setup_subscription_logging(log_filename="subscription_runs.log"):
    """Configures a file logger to append run data without cluttering stdout."""
    logger = logging.getLogger("SubscriptionLogger")
    logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers if script main gets called multiple times
    if not logger.handlers:
        file_handler = logging.FileHandler(log_filename, encoding='utf-8')
        # Format: Timestamp | Message
        formatter = logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger

# --- Protocol Helper Functions ---

def parse_vless(parsed, params):
    security = params.get('security', [''])[0]
    sni = params.get('sni', [None])[0]
    flow = params.get('flow', [None])[0]
    fp = params.get('fp', ['chrome'])[0]
    
    config = {
        "type": "vless",
        "uuid": parsed.username,
        "tls": security in ['tls', 'reality'],
        "servername": sni if sni else parsed.hostname,
        "client-fingerprint": fp
    }
    if flow: config["flow"] = flow
    if security == 'reality':
        config["reality-opts"] = {
            "public-key": params.get('pbk', [''])[0],
            "short-id": params.get('sid', [''])[0]
        }
    return config

def parse_trojan(parsed, params):
    sni = params.get('sni', [None])[0]
    return {
        "type": "trojan",
        "password": parsed.username,
        "sni": sni if sni else parsed.hostname
    }

def parse_hysteria2(parsed, params):
    obfs = params.get('obfs', [None])[0]
    obfs_pw = params.get('obfs-password', params.get('m', [None]))[0]
    config = {
        "type": "hysteria2",
        "password": parsed.username,
        "sni": params.get('sni', [parsed.hostname])[0],
    }
    if params.get('up'): config['up'] = int(params.get('up')[0])
    if params.get('down'): config['down'] = int(params.get('down')[0])
    if params.get('cwnd'): config['cwnd'] = int(params.get('cwnd')[0])
    if obfs:
        config['obfs'] = obfs
        if obfs_pw: config['obfs-password'] = obfs_pw
    return config

def parse_shadowsocks(parsed, params):
    """Parses ss:// links, detecting AnyTLS configurations for Mihomo."""
    # Shadowsocks credentials can be legacy base64 or standard userinfo style
    userinfo = parsed.username
    if not userinfo and parsed.netloc:
        # Handle cases where the netloc itself is entirely base64-encoded
        maybe_encoded = parsed.netloc.split('@')[0]
        try:
            # Fix base64 padding issues
            maybe_encoded += "=" * ((4 - len(maybe_encoded) % 4) % 4)
            decoded_userinfo = base64.b64decode(maybe_encoded).decode('utf-8', errors='ignore')
            if ":" in decoded_userinfo:
                userinfo = decoded_userinfo
        except Exception:
            pass

    # Extract cipher and password
    cipher, password = "aes-128-gcm", ""
    if userinfo and ":" in userinfo:
        cipher, password = userinfo.split(":", 1)
    elif parsed.username:
        password = parsed.username

    sni = params.get('sni', [None])[0]
    
    
    return {
        "type": "anytls",
        "password": password,
        "udp": True,
        "sni": sni if sni else parsed.hostname,
        "alpn": ["http/1.1"]
    }

PROTOCOL_PARSERS = {
    "vless": parse_vless,
    "trojan": parse_trojan,
    "hysteria2": parse_hysteria2,
    "ss": parse_shadowsocks,
    "anytls": parse_shadowsocks
}

# --- Utility Functions ---

def should_exclude(name, exclusion_patterns):
    for pattern in exclusion_patterns:
        try:
            if re.search(pattern, name, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False

def is_hong_kong(name):
    hk_regex = r"(香港|Hong\s*Kong|HK|hong\s*kong|🇭🇰)"
    return re.search(hk_regex, name, re.IGNORECASE) is not None

def convert_subscription(url, output_path, hk_split=False, exclude_file=None):
    logger = setup_subscription_logging()
    exclusion_patterns = []
    if exclude_file and os.path.exists(exclude_file):
        with open(exclude_file, 'r', encoding='utf-8') as f:
            exclusion_patterns = [line.strip() for line in f if line.strip()]

    try:
        print(f"Fetching subscription...")
        response = requests.get(
            url, 
            impersonate="chrome120", 
            timeout=(5, 10),
            headers={"User-Agent": "Shadowrocket/2.2.85 CFNetwork/1498.7 Darwin/24.1.0", "Accept": "*/*"}
        )
        response.raise_for_status()
        
        raw_data = response.text.strip()
        raw_data = re.sub(r'\s+', '', raw_data)
        raw_data += "=" * ((4 - len(raw_data) % 4) % 4)
        
        try:
            decoded_text = base64.b64decode(raw_data).decode('utf-8', errors='ignore')
        except Exception as decode_err:
            print(f"Error while decoding Base64 string: {decode_err}")
            return
            
        log_message = (
            f"\n--- RUN START ---\n"
            f"URL: {url}\n"
            f"DECODED TEXT:\n{decoded_text.strip()}\n"
            f"--- RUN END ---\n"
        )
        logger.info(log_message)

        links = decoded_text.strip().splitlines()
        main_proxies, hk_proxies = [], []

        for link in links:
            link = link.strip()
            if not link:
                continue
                
            parsed = urllib.parse.urlparse(link)
            if parsed.scheme not in PROTOCOL_PARSERS:
                continue
            
            params = urllib.parse.parse_qs(parsed.query)
            name = urllib.parse.unquote(parsed.fragment) or f"{parsed.scheme}-{parsed.hostname}"
            
            if should_exclude(name, exclusion_patterns):
                continue

            proxy = {
                "name": name,
                "server": parsed.hostname,
                "port": int(parsed.port) if parsed.port else 443,
                "udp": True,
                "skip-cert-verify": True,
            }
            
            try:
                proxy.update(PROTOCOL_PARSERS[parsed.scheme](parsed, params))
            except Exception as parse_proto_err:
                print(f"Skipping malformed {parsed.scheme} node [{name}]: {parse_proto_err}")
                continue

            # Transport layer logic (only for protocols that use standard ws/grpc)
            if parsed.scheme not in ["hysteria2", "ss", "anytls"]:
                net_type = params.get('type', ['tcp'])[0]
                if net_type == "ws":
                    proxy["network"] = "ws"
                    proxy["ws-opts"] = {
                        "path": params.get('path', ['/'])[0],
                        "headers": {"Host": params.get('host', [proxy.get('sni') or proxy.get('servername') or parsed.hostname])[0]}
                    }
                elif net_type == "grpc":
                    proxy["network"] = "grpc"
                    proxy["grpc-opts"] = {"grpc-service-name": params.get('serviceName', [''])[0]}

            if hk_split and is_hong_kong(name):
                hk_proxies.append(proxy)
            else:
                main_proxies.append(proxy)

        def save_yaml(data, path):
            if not data: 
                print(f"No proxies found to save for path: {path}")
                return
            with open(path, 'w', encoding='utf-8') as f:
                yaml.dump({"proxies": data}, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            os.chmod(path, 0o644)
            print(f"Generated '{path}' with {len(data)} proxies.")

        save_yaml(main_proxies, output_path)
        if hk_split:
            save_yaml(hk_proxies, output_path.replace(".yaml", "-hk.yaml"))

    except Exception as e:
        print(f"Critical execution error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("-o", "--output", default="provider.yaml")
    parser.add_argument("--hk", action="store_true")
    parser.add_argument("--excluded_KW_file", "--exclude-file", dest="exclude_file")

    args = parser.parse_args()
    convert_subscription(args.url, args.output, args.hk, args.exclude_file)
