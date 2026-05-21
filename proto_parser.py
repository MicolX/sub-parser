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
    if flow:
        config["flow"] = flow
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
    if params.get('up'):
        config['up'] = int(params.get('up')[0])
    if params.get('down'):
        config['down'] = int(params.get('down')[0])
    if params.get('cwnd'):
        config['cwnd'] = int(params.get('cwnd')[0])
    if obfs:
        config['obfs'] = obfs
        if obfs_pw:
            config['obfs-password'] = obfs_pw
    return config


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
