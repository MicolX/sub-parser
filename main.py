import base64
import datetime
import logging
import urllib.parse
import yaml
from curl_cffi import requests
import os
import argparse
import sys
import re
from proto_parser import parse_vless, parse_trojan, parse_hysteria2, parse_shadowsocks


def setup_subscription_logging(log_filename=f'{datetime.datetime.now().strftime("%Y%m%d_%H%M%S.log")}'):
    """Configures a file logger to append run data without cluttering stdout."""
    logger = logging.getLogger("SubscriptionLogger")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers if script main gets called multiple times
    if not logger.handlers:
        os.makedirs("./log", exist_ok=True)
        log_file = os.path.join("./log", log_filename)
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        # Format: Timestamp | Message
        formatter = logging.Formatter(
            '%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger


def parse_shadowsocks(parsed, params):
    """Parses ss:// links, detecting AnyTLS configs and hidden SIP003 plugin hosts."""
    userinfo = parsed.username
    if not userinfo and parsed.netloc:
        maybe_encoded = parsed.netloc.split('@')[0]
        try:
            maybe_encoded += "=" * ((4 - len(maybe_encoded) % 4) % 4)
            decoded_userinfo = base64.b64decode(
                maybe_encoded).decode('utf-8', errors='ignore')
            if ":" in decoded_userinfo:
                userinfo = decoded_userinfo
        except Exception:
            pass

    cipher, password = "aes-128-gcm", ""
    if userinfo and ":" in userinfo:
        cipher, password = userinfo.split(":", 1)
    elif parsed.username:
        password = parsed.username

    # 1. Start with top-level SNI if it exists
    sni = params.get('sni', [None])[0]

    # 2. Extract hidden host/sni from inside the SIP003 plugin strings
    plugin = params.get('plugin', [''])[0]
    plugin_opts = params.get('plugin-opts', [''])[0]

    # Combine both and split by semicolon to find the true routing host
    combined_opts = f"{plugin};{plugin_opts}"
    for opt in combined_opts.split(';'):
        opt = opt.strip()
        if opt.startswith('host='):
            sni = opt[5:]
        elif opt.startswith('sni='):
            sni = opt[4:]

    # 3. Generate the pristine AnyTLS format
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


def convert_subscription(url, output_path, logger, hk_split=False, exclusion_patterns=None):

    if exclusion_patterns is None:
        exclusion_patterns = []

    try:
        logger.info(f"Fetching subscription...")
        response = requests.get(
            url,
            impersonate="chrome120",
            timeout=(5, 10),
            headers={
                "User-Agent": "Shadowrocket/2.2.85 CFNetwork/1498.7 Darwin/24.1.0", "Accept": "*/*"}
        )
        response.raise_for_status()

        raw_data = response.text.strip()
        raw_data = re.sub(r'\s+', '', raw_data)
        raw_data += "=" * ((4 - len(raw_data) % 4) % 4)

        try:
            decoded_text = base64.b64decode(
                raw_data).decode('utf-8', errors='ignore')
        except Exception as decode_err:
            logger.error(f"Error while decoding Base64 string: {decode_err}")
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
            name = urllib.parse.unquote(
                parsed.fragment) or f"{parsed.scheme}-{parsed.hostname}"

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
                logger.error(
                    f"Skipping malformed {parsed.scheme} node [{name}]: {parse_proto_err}")
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
                    proxy["grpc-opts"] = {
                        "grpc-service-name": params.get('serviceName', [''])[0]}

            debug_msg = (
                f"\n[DEBUG] Node: {name}\n"
                f"  Raw URL    : {link}\n"
                f"  Parsed Host: {parsed.hostname}\n"
                f"  Plugin Str : {params.get('plugin', [''])[0]}\n"
                f"  Final Proxy: SERVER={proxy.get('server')} | SNI={proxy.get('sni', proxy.get('servername', 'None'))}"
            )

            # Write to subscription_runs.log for historical tracking
            logger.info(debug_msg)

            if hk_split and is_hong_kong(name):
                hk_proxies.append(proxy)
            else:
                main_proxies.append(proxy)

        def save_yaml(data, path):
            if not data:
                logger.warning(f"No proxies found to save for path: {path}")
                return
            with open(path, 'w', encoding='utf-8') as f:
                yaml.dump({"proxies": data}, f, allow_unicode=True,
                          sort_keys=False, default_flow_style=False)
            os.chmod(path, 0o644)
            logger.info(f"Generated '{path}' with {len(data)} proxies.")
            print(f"Generated '{path}' with {len(data)} proxies.")

        save_yaml(main_proxies, output_path)
        if hk_split:
            save_yaml(hk_proxies, output_path.replace(".yaml", "-hk.yaml"))

    except Exception as e:
        logger.error(f"Critical execution error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "url", nargs="?", help="Base64 subscription URL (optional if using config file)")
    parser.add_argument("-o", "--output", default="provider.yaml",
                        help="Output path (for CLI mode)")
    parser.add_argument("--hk", action="store_true",
                        help="Split Hong Kong servers (for CLI mode)")
    parser.add_argument("--excluded_KW_file", "--exclude-file",
                        dest="exclude_file", help="Regex exclusions file (for CLI mode)")
    parser.add_argument("-c", "--config", default="config.yaml",
                        help="Path to YAML config file")

    args = parser.parse_args()
    # Determine execution mode: Config file vs CLI
    using_custom_config = args.config != "config.yaml"
    logger = setup_subscription_logging()

    if using_custom_config or os.path.exists(args.config):
        if not os.path.exists(args.config):
            logger.error(f"Error: Config file '{args.config}' not found.")
            sys.exit(1)

        logger.info(f"Reading configuration from '{args.config}'...")
        with open(args.config, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f) or {}

        # Extract general configurations
        general_split_hk = config.get("split_hk", False)
        general_exclude = config.get("exclude", [])

        subscriptions = config.get("subscriptions", [])
        if not subscriptions:
            logger.warning("No subscriptions found in config file.")
            sys.exit(0)

        for sub in subscriptions:
            name = sub.get("name")
            url = sub.get("url")

            if not name or not url:
                logger.error(
                    "Skipping malformed subscription (missing 'name' or 'url').")
                continue

            # Object fields override general fields
            split_hk = sub.get("split_hk", general_split_hk)
            exclude_list = sub.get("exclude", general_exclude)

            # Default output path handling: ./output/<name>.yaml
            output_path = sub.get("file", f"./output/{name}.yaml")

            # Ensure the output directory exists
            output_dir = os.path.dirname(os.path.abspath(output_path))
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            logger.info(f"\n--- Processing Subscription: {name} ---")
            convert_subscription(url, output_path, logger,
                                 split_hk, exclude_list)

    elif args.url:
        # Fallback to pure CLI mode
        exclusion_patterns = []
        if args.exclude_file and os.path.exists(args.exclude_file):
            with open(args.exclude_file, 'r', encoding='utf-8') as f:
                exclusion_patterns = [line.strip()
                                      for line in f if line.strip()]

        convert_subscription(args.url, args.output, logger,
                             args.hk, exclusion_patterns)

    else:
        print("Error: No config file found and no URL provided via CLI.")
        parser.print_help()
        sys.exit(1)
