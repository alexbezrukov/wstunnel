# wstunnel

A high-performance TLS WebSocket tunnel that bypasses ISP throttling and DPI filtering. Wraps SOCKS5/HTTP traffic in standard WebSocket-over-TLS, making it indistinguishable from normal HTTPS browser traffic. Supports Cloudflare CDN fronting to hide your server's IP entirely.

```
App → [client] ──WSS──▶ [Cloudflare Edge] ──WSS──▶ [server] ──SOCKS5──▶ Internet
       local                104.x.x.x                 your VPS
```

## Why this exists

Many ISPs apply asymmetric throttling to datacenter IPs — download from a VPS gets throttled to 10–15 Mbps while upload is untouched. Raw TLS tunnels are easy to detect and rate-limit. This tunnel looks like a Chrome browser opening a WebSocket connection to Cloudflare.

## Features

- **Auto-detects SOCKS5 and HTTP CONNECT** — works with Windows system proxy (`socks=` and `https=`)
- **WebSocket transport** — passes through corporate firewalls, CDNs, and DPI systems
- **Cloudflare CDN fronting** — your datacenter IP is never exposed, traffic comes from `104.x.x.x`
- **Browser TLS fingerprint** — ALPN `h2/http1.1`, Chrome User-Agent, standard headers
- **Per-connection HMAC auth** — SHA-256(secret + nonce), replay-protected
- **Cross-platform** — Windows client, Linux server

## Requirements

- **Server**: Linux VPS with a SOCKS5 proxy (e.g. Dante, 3proxy, or Shadowsocks) running on `127.0.0.1`
- **Client**: Windows (or Linux)
- **Rust**: 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **TLS certificate**: Let's Encrypt or self-signed (use `--insecure` on client for self-signed)

## Build

```bash
git clone https://github.com/alexbezrukov/tls-socks-tunnel
cd tls-socks-tunnel
cargo build --release
# Binary: ./target/release/tunnel  (tunnel.exe on Windows)
```

## Quick Start

### 1. Server (Linux VPS)

Make sure you have a SOCKS5 proxy listening locally first:
```bash
# Example: install and run dante
apt install dante-server
# or: 3proxy, microsocks, etc.
# Should listen on 127.0.0.1:1080
```

Get a TLS certificate:
```bash
# Let's Encrypt (recommended)
certbot certonly --standalone -d yourdomain.com

# Or self-signed (for testing)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

Run the tunnel server:
```bash
./tunnel server \
    0.0.0.0:8443 \              # listen address
    127.0.0.1:1080 \            # upstream SOCKS5 proxy
    /etc/ssl/cert.pem \
    /etc/ssl/key.pem \
    "YourSecretKey" \
    /api/v1/stream              # WebSocket path (keep this secret)
```

As a systemd service (`/etc/systemd/system/wstunnel.service`):
```ini
[Unit]
Description=WS Tunnel
After=network-online.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/tunnel server 0.0.0.0:8443 127.0.0.1:1080 \
    /etc/ssl/cert.pem /etc/ssl/key.pem "YourSecretKey" /api/v1/stream
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```
```bash
systemctl enable --now wstunnel
```

### 2. Client (Windows)

**Direct connection** (server has a valid TLS cert):
```bat
tunnel.exe client 127.0.0.1:9050 wss://yourdomain.com:8443/api/v1/stream "YourSecretKey"
```

**Self-signed cert** (skip TLS verification):
```bat
tunnel.exe client 127.0.0.1:9050 wss://1.2.3.4:8443/api/v1/stream "YourSecretKey" --insecure
```

**Via Cloudflare CDN** (recommended — hides your server IP):
```bat
tunnel.exe client 127.0.0.1:9050 wss://tunnel.yourdomain.com/api/v1/stream "YourSecretKey"
```

Then set Windows system proxy:

> Settings → Network → Proxy → Manual proxy setup
> - SOCKS: `127.0.0.1:9050`
> - HTTP/HTTPS: `127.0.0.1:9050`

Or via PowerShell:
```powershell
$settings = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Set-ItemProperty $settings ProxyEnable 1
Set-ItemProperty $settings ProxyServer "socks=127.0.0.1:9050;https=127.0.0.1:9050"
```

### 3. Cloudflare CDN Fronting (optional but recommended)

Generates a Cloudflare Worker script:
```bash
./tunnel worker yourvps.com:8443 /api/v1/stream
```

Copy the printed JS into Cloudflare Dashboard → Workers & Pages → Create, set environment variable `ORIGIN_HOST=yourvps.com:8443`, and route `*.yourdomain.com/api/v1/stream` to the worker. Enable WebSockets in CF Dashboard → Network → WebSockets.

After this, use `wss://tunnel.yourdomain.com/api/v1/stream` as the client URL. Your VPS IP is never visible.

## Usage Reference

```
USAGE:
  tunnel server  <bind> <socks> <cert.pem> <key.pem> <secret> [ws-path]
  tunnel client  <bind> <wss-url> <secret> [--insecure] [--host <cdn-host>]
  tunnel worker  <origin:port> [ws-path]

ARGUMENTS:
  bind        Local address to listen on (e.g. 0.0.0.0:8443 or 127.0.0.1:9050)
  socks       Upstream SOCKS5 proxy address on VPS (e.g. 127.0.0.1:1080)
  wss-url     Full WebSocket URL (e.g. wss://yourdomain.com:8443/api/v1/stream)
  secret      Shared secret for authentication (same on client and server)
  ws-path     WebSocket endpoint path, default: /ws

FLAGS:
  --insecure  Skip TLS certificate verification (for self-signed certs)
  --host      Override Host header for CDN fronting
```

## Security

**Authentication** uses per-connection HMAC-SHA256: `token = SHA256(AUTH_MAGIC || secret || nonce)`. A random 16-byte nonce is generated for each connection and sent as an HTTP header during WebSocket upgrade. The server verifies the token before accepting the connection. Replay attacks are prevented because each nonce is one-time.

**The WebSocket path acts as a second factor.** Any connection to a different path gets a generic 404 nginx response.

**Use a strong secret** (20+ random characters). Anyone who knows the secret and server address can use your tunnel.

⚠️ `--insecure` disables TLS certificate verification. Use only on trusted networks or for testing. In production, use a valid certificate (Let's Encrypt is free).

## Architecture

```
Windows App (browser, curl, etc.)
    │
    │ SOCKS5 or HTTP CONNECT
    ▼
tunnel client (127.0.0.1:9050)
    │  reads target host:port from SOCKS5/HTTP CONNECT handshake
    │  opens WSS connection to server
    │  sends x-target: host:port in WS upgrade headers
    │
    │ WebSocket over TLS (wss://)
    ▼
[optional: Cloudflare Worker — proxies WS, hides VPS IP]
    │
    │ WebSocket over TLS
    ▼
tunnel server (VPS, 0.0.0.0:8443)
    │  verifies HMAC auth token
    │  reads x-target from upgrade headers
    │  connects to upstream SOCKS5
    │
    │ SOCKS5 CONNECT to target
    ▼
Dante / 3proxy (127.0.0.1:1080)
    │
    ▼
api2.cursor.sh:443 (actual destination)
```

## Performance

Measured on a typical VPS with ISP throttling applied to datacenter IPs:

| Mode | Download |
|------|----------|
| Raw TCP to VPS (throttled) | ~14 Mbps |
| This tunnel (direct WSS) | ~40–60 Mbps |
| This tunnel (via Cloudflare) | ~80–90 Mbps |

The improvement comes from CDN IPs being exempt from datacenter throttling rules.

## Troubleshooting

**`TLS close_notify` errors on client** — server crashed or restarted. Check server logs: `journalctl -u wstunnel -n 50`.

**`Missing sec-websocket-key`** — version mismatch between client and server. Make sure both are built from the same source.

**`Auth failed`** — wrong secret or wrong `ws-path`. Must match exactly on both sides.

**`SOCKS5 upstream CONNECT failed: code 4`** — upstream SOCKS proxy on VPS rejected the connection. Check if Dante/3proxy is running: `systemctl status dante`.

**`Cannot block the current thread`** — old server binary still running. Rebuild and restart.

## License

MIT