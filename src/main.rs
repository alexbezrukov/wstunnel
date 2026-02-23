use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock, Semaphore};
use tokio::time::{timeout, Duration};
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::{self, HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{accept_hdr_async, connect_async_tls_with_config};

// ── Tuning ──────────────────────────────────────────────────────────────────
const BUFFER_SIZE: usize = 128 * 1024;
const MAX_CONCURRENT: usize = 10_000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const READ_TIMEOUT: Duration = Duration::from_secs(600);
const SOCKS_TIMEOUT: Duration = Duration::from_secs(15);

// ── Auth ─────────────────────────────────────────────────────────────────────
const AUTH_MAGIC: &[u8] = b"TLS_TUNNEL_V3_WS";

// ── Blacklist ────────────────────────────────────────────────────────────────
static BLACKLIST: &[&str] = &[
    "*.cursor.sh",
    "telemetry.*",
    "*.msn.com",
    "mobile.events.data.microsoft.com",
];

fn is_blacklisted(target: &str) -> bool {
    let host = target.split(':').next().unwrap_or(target).to_lowercase();

    for pattern in BLACKLIST {
        if pattern.starts_with("*.") {
            let suffix = &pattern[2..];
            if host.ends_with(suffix) || host == suffix {
                return true;
            }
        } else if pattern.ends_with(".*") {
            let prefix = &pattern[..pattern.len() - 2];
            if host.starts_with(prefix) {
                return true;
            }
        } else if host == *pattern {
            return true;
        }
    }
    false
}

// ── IP Whitelist ─────────────────────────────────────────────────────────────

/// Holds parsed IP whitelist. Supports exact IPs and CIDR ranges.
#[derive(Default, Clone)]
struct IpWhitelist {
    entries: Vec<IpEntry>,
}

#[derive(Clone)]
enum IpEntry {
    Exact(IpAddr),
    Cidr { base: u128, mask: u128, is_v6: bool },
}

impl IpWhitelist {
    /// Parse whitelist from a string like "1.2.3.4,10.0.0.0/8,::1"
    fn from_str(s: &str) -> Self {
        let mut entries = Vec::new();
        for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
            if let Some(entry) = parse_ip_entry(part) {
                entries.push(entry);
            } else {
                eprintln!("[WHITELIST] Could not parse entry: {}", part);
            }
        }
        Self { entries }
    }

    /// Load whitelist from a file (one entry per line, # comments allowed)
    fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .context(format!("Cannot read IP whitelist file: {}", path))?;
        let joined: String = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect::<Vec<_>>()
            .join(",");
        Ok(Self::from_str(&joined))
    }

    fn contains(&self, addr: IpAddr) -> bool {
        for entry in &self.entries {
            if matches_entry(entry, addr) {
                return true;
            }
        }
        false
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn parse_ip_entry(s: &str) -> Option<IpEntry> {
    if s.contains('/') {
        // CIDR
        let (ip_str, prefix_str) = s.rsplit_once('/')?;
        let prefix: u32 = prefix_str.parse().ok()?;
        let ip: IpAddr = ip_str.parse().ok()?;
        match ip {
            IpAddr::V4(v4) => {
                let base = u32::from(v4) as u128;
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix)
                } as u128;
                Some(IpEntry::Cidr {
                    base: base & mask,
                    mask,
                    is_v6: false,
                })
            }
            IpAddr::V6(v6) => {
                let base = u128::from(v6);
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix)
                };
                Some(IpEntry::Cidr {
                    base: base & mask,
                    mask,
                    is_v6: true,
                })
            }
        }
    } else {
        let ip: IpAddr = s.parse().ok()?;
        Some(IpEntry::Exact(ip))
    }
}

fn matches_entry(entry: &IpEntry, addr: IpAddr) -> bool {
    match entry {
        IpEntry::Exact(e) => *e == addr,
        IpEntry::Cidr { base, mask, is_v6 } => match addr {
            IpAddr::V4(v4) if !is_v6 => {
                let n = u32::from(v4) as u128;
                (n & mask) == *base
            }
            IpAddr::V6(v6) if *is_v6 => {
                let n = u128::from(v6);
                (n & mask) == *base
            }
            _ => false,
        },
    }
}

// ── SOCKS5 constants ─────────────────────────────────────────────────────────
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

// ── Stats ────────────────────────────────────────────────────────────────────
#[derive(Default)]
struct Stats {
    active: AtomicU64,
    total: AtomicU64,
    bytes_rx: AtomicU64,
    bytes_tx: AtomicU64,
    auth_failed: AtomicU64,
    whitelist_allowed: AtomicU64,
}

impl Stats {
    fn report(&self) {
        println!(
            "[STATS] Active:{} Total:{} Failed:{} WL-Allowed:{} RX:{}MB TX:{}MB",
            self.active.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
            self.auth_failed.load(Ordering::Relaxed),
            self.whitelist_allowed.load(Ordering::Relaxed),
            self.bytes_rx.load(Ordering::Relaxed) / 1_000_000,
            self.bytes_tx.load(Ordering::Relaxed) / 1_000_000,
        );
    }
}

// ── Cross-platform socket buffer tuning ──────────────────────────────────────
fn tune_tcp(stream: &TcpStream) {
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};
        let raw = stream.as_raw_socket();
        let sock = unsafe { socket2::Socket::from_raw_socket(raw) };
        let _ = sock.set_recv_buffer_size(512 * 1024);
        let _ = sock.set_send_buffer_size(512 * 1024);
        std::mem::forget(sock);
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let raw = stream.as_raw_fd();
        let sock = unsafe { socket2::Socket::from_raw_fd(raw) };
        let _ = sock.set_recv_buffer_size(512 * 1024);
        let _ = sock.set_send_buffer_size(512 * 1024);
        std::mem::forget(sock);
    }
}

fn tune_listener(listener: &TcpListener) {
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};
        let raw = listener.as_raw_socket();
        let sock = unsafe { socket2::Socket::from_raw_socket(raw) };
        let _ = sock.set_recv_buffer_size(1 << 20);
        let _ = sock.set_send_buffer_size(1 << 20);
        std::mem::forget(sock);
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let raw = listener.as_raw_fd();
        let sock = unsafe { socket2::Socket::from_raw_fd(raw) };
        let _ = sock.set_recv_buffer_size(1 << 20);
        let _ = sock.set_send_buffer_size(1 << 20);
        std::mem::forget(sock);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  SOCKS5 / HTTP CONNECT handshake helpers
// ═════════════════════════════════════════════════════════════════════════════

async fn proxy_handshake(stream: &mut TcpStream) -> Result<String> {
    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .await
        .context("handshake: read first byte")?;

    if first[0] == SOCKS5_VERSION {
        socks5_handshake_rest(stream).await
    } else {
        http_connect_handshake(stream, first[0]).await
    }
}

async fn socks5_handshake_rest(stream: &mut TcpStream) -> Result<String> {
    let mut nmethods_buf = [0u8; 1];
    stream
        .read_exact(&mut nmethods_buf)
        .await
        .context("SOCKS5: nmethods")?;
    let mut methods = vec![0u8; nmethods_buf[0] as usize];
    stream
        .read_exact(&mut methods)
        .await
        .context("SOCKS5: methods")?;
    stream
        .write_all(&[SOCKS5_VERSION, 0x00])
        .await
        .context("SOCKS5: method resp")?;

    let mut req = [0u8; 4];
    stream
        .read_exact(&mut req)
        .await
        .context("SOCKS5: request")?;
    if req[1] != SOCKS5_CMD_CONNECT {
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .ok();
        anyhow::bail!("SOCKS5: unsupported cmd {}", req[1]);
    }

    let host = match req[3] {
        SOCKS5_ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await.context("SOCKS5: ipv4")?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .context("SOCKS5: domain len")?;
            let mut d = vec![0u8; len[0] as usize];
            stream.read_exact(&mut d).await.context("SOCKS5: domain")?;
            String::from_utf8(d).context("SOCKS5: domain utf8")?
        }
        SOCKS5_ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await.context("SOCKS5: ipv6")?;
            let segs: Vec<String> = ip
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            format!("[{}]", segs.join(":"))
        }
        t => anyhow::bail!("SOCKS5: unknown atyp {}", t),
    };

    let mut pb = [0u8; 2];
    stream.read_exact(&mut pb).await.context("SOCKS5: port")?;
    let port = u16::from_be_bytes(pb);
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .context("SOCKS5: reply")?;
    Ok(format!("{}:{}", host, port))
}

async fn http_connect_handshake(stream: &mut TcpStream, first: u8) -> Result<String> {
    let read_headers = async {
        let mut buf = vec![first];
        let mut tmp = [0u8; 1];
        loop {
            stream
                .read_exact(&mut tmp)
                .await
                .context("HTTP CONNECT: read")?;
            buf.push(tmp[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if buf.len() > 8192 {
                anyhow::bail!("HTTP CONNECT: oversized request");
            }
        }
        Ok::<_, anyhow::Error>(buf)
    };
    let buf = timeout(Duration::from_secs(10), read_headers)
        .await
        .context("HTTP CONNECT: timeout reading headers")??;
    let head = std::str::from_utf8(&buf).context("HTTP CONNECT: non-utf8")?;
    let first_line = head.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            .await
            .ok();
        anyhow::bail!("HTTP: unsupported method '{}'", method);
    }
    if !authority.contains(':') {
        anyhow::bail!("HTTP CONNECT: no port in '{}'", authority);
    }
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .context("HTTP CONNECT: write 200")?;
    Ok(authority.to_string())
}

async fn socks5_connect(stream: &mut TcpStream, target: &str) -> Result<()> {
    let (host, port_str) = target
        .rsplit_once(':')
        .context(format!("Invalid target: {}", target))?;
    let port: u16 = port_str.parse().context("Invalid port")?;
    let host = host.trim_matches(|c| c == '[' || c == ']');

    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[1] != 0x00 {
        anyhow::bail!("SOCKS5 upstream requires auth (method={})", resp[1]);
    }

    let host_bytes = host.as_bytes();
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, SOCKS5_ATYP_DOMAIN]);
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        anyhow::bail!("SOCKS5 upstream CONNECT failed: code {}", reply[1]);
    }
    match reply[3] {
        SOCKS5_ATYP_IPV4 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await?;
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize + 2];
            stream.read_exact(&mut b).await?;
        }
        SOCKS5_ATYP_IPV6 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await?;
        }
        _ => {}
    }
    Ok(())
}

// ═════════════════════════════════════════════════════════════════════════════
//  SERVER SIDE
// ═════════════════════════════════════════════════════════════════════════════

pub async fn run_server(
    bind_addr: &str,
    socks_addr: &str,
    cert_path: &str,
    key_path: &str,
    secret_key: &str,
    ws_path: &str,
    plain: bool,
    // IP whitelist — пустой = отключён (нужен secret_key для всех)
    // Если задан — IP из списка пускаются без secret_key
    whitelist: IpWhitelist,
) -> Result<()> {
    let acceptor_opt = if plain {
        println!("[SERVER] Plain WebSocket mode (no TLS)");
        None
    } else {
        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;
        let mut tls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Bad cert/key")?;
        tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        tls_cfg.max_fragment_size = Some(16384);
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg)))
    };

    let listener = TcpListener::bind(bind_addr).await?;
    tune_listener(&listener);

    println!("[SERVER] Listening on {}", bind_addr);
    println!("[SERVER] WebSocket path: {}", ws_path);
    println!("[SERVER] Upstream SOCKS: {}", socks_addr);

    if whitelist.is_empty() {
        println!("[SERVER] IP whitelist: disabled (secret_key required for all)");
    } else {
        println!(
            "[SERVER] IP whitelist: {} entries (whitelisted IPs skip secret_key)",
            whitelist.entries.len()
        );
    }

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret_key.to_string());
    let ws_path = Arc::new(ws_path.to_string());
    let whitelist = Arc::new(whitelist);

    let s = stats.clone();
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(30));
        loop {
            iv.tick().await;
            s.report();
        }
    });

    loop {
        let (tcp, peer) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        tune_tcp(&tcp);

        let acceptor_opt = acceptor_opt.clone();
        let socks = socks_addr.to_string();
        let sem = sem.clone();
        let stats = stats.clone();
        let secret = secret.clone();
        let ws_path = ws_path.clone();
        let whitelist = whitelist.clone();

        tokio::spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };
            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);

            // Извлекаем IP из peer адреса (за NAT/proxy можно читать X-Forwarded-For,
            // но для прямого подключения peer.ip() достаточно)
            let peer_ip = peer.ip();

            if let Err(e) = handle_server_conn_plain(
                tcp,
                acceptor_opt,
                &socks,
                &secret,
                &ws_path,
                stats.clone(),
                peer,
                peer_ip,
                whitelist,
            )
            .await
            {
                let msg = e.to_string();
                if !msg.contains("Auth") && !msg.contains("auth") && !msg.contains("401") {
                    eprintln!("[SERVER] {} — {}", peer, e);
                }
            }
            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn handle_server_conn_plain(
    tcp: TcpStream,
    acceptor_opt: Option<tokio_rustls::TlsAcceptor>,
    socks_addr: &str,
    secret_key: &str,
    ws_path: &str,
    stats: Arc<Stats>,
    peer: std::net::SocketAddr,
    peer_ip: IpAddr,
    whitelist: Arc<IpWhitelist>,
) -> Result<()> {
    // Определяем режим аутентификации:
    // - IP в whitelist → secret_key не нужен
    // - IP не в whitelist (или whitelist пустой) → требуем secret_key
    let require_secret = whitelist.is_empty() || !whitelist.contains(peer_ip);

    if !require_secret {
        println!(
            "[SERVER] {} — whitelisted IP, skipping secret_key auth",
            peer_ip
        );
    }

    if let Some(acceptor) = acceptor_opt {
        handle_server_conn(
            tcp,
            acceptor,
            socks_addr,
            secret_key,
            ws_path,
            stats,
            peer,
            require_secret,
        )
        .await
    } else {
        handle_server_conn_notls(
            tcp,
            socks_addr,
            secret_key,
            ws_path,
            stats,
            peer,
            require_secret,
        )
        .await
    }
}

async fn handle_server_conn_notls(
    tcp: TcpStream,
    socks_addr: &str,
    secret_key: &str,
    ws_path: &str,
    stats: Arc<Stats>,
    peer: std::net::SocketAddr,
    require_secret: bool,
) -> Result<()> {
    let expected_path = ws_path.to_string();
    let secret = secret_key.to_string();
    let auth_ok = Arc::new(std::sync::Mutex::new(false));
    let auth_cb = auth_ok.clone();
    let target_cell: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let target_cb = target_cell.clone();

    let ws = timeout(
        HANDSHAKE_TIMEOUT,
        accept_hdr_async(tcp, move |req: &Request, mut resp: Response| {
            if req.uri().path() != expected_path {
                let body = Some(
                    "<html>\n<head><title>404 Not Found</title></head>\n\
                    <body>\n<center><h1>404 Not Found</h1></center>\n\
                    <hr><center>nginx/1.24.0</center>\n</body>\n</html>\n"
                        .to_string(),
                );
                return Err(http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header("Server", "nginx/1.24.0")
                    .header("Content-Type", "text/html")
                    .body(body)
                    .unwrap());
            }

            // ── Логика аутентификации ─────────────────────────────────────
            // Если IP в whitelist (require_secret=false) — пускаем без проверки токена.
            // Если нет — проверяем x-auth / x-nonce как обычно.
            let authenticated = if !require_secret {
                // Whitelist — достаточно наличия x-target
                true
            } else {
                // Обычная проверка по HMAC токену
                if let (Some(a), Some(n)) =
                    (req.headers().get("x-auth"), req.headers().get("x-nonce"))
                {
                    let nonce = n.to_str().unwrap_or("");
                    a.to_str().unwrap_or("") == compute_token(&secret, nonce)
                } else {
                    false
                }
            };

            if authenticated {
                if let Some(t) = req.headers().get("x-target") {
                    if let Ok(mut g) = target_cb.lock() {
                        *g = Some(t.to_str().unwrap_or("").to_string());
                    }
                }
                if let Ok(mut g) = auth_cb.lock() {
                    *g = true;
                }
                resp.headers_mut()
                    .insert("server", HeaderValue::from_static("cloudflare"));
                return Ok(resp);
            }

            let body = Some(
                "<html>\n<head><title>401 Authorization Required</title></head>\n\
                <body>\n<center><h1>401 Authorization Required</h1></center>\n\
                <hr><center>nginx/1.24.0</center>\n</body>\n</html>\n"
                    .to_string(),
            );
            Err(http::Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Server", "nginx/1.24.0")
                .header("Content-Type", "text/html")
                .body(body)
                .unwrap())
        }),
    )
    .await
    .context("WS upgrade timeout")??;

    if !*auth_ok.lock().unwrap_or_else(|e| e.into_inner()) {
        stats.auth_failed.fetch_add(1, Ordering::Relaxed);
        return Err(anyhow::anyhow!("Auth failed from {}", peer));
    }
    if !require_secret {
        stats.whitelist_allowed.fetch_add(1, Ordering::Relaxed);
    }

    let target = target_cell
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .context("Missing x-target header")?;

    let mut socks = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(socks_addr))
        .await
        .context("SOCKS connect timeout")??;
    let _ = socks.set_nodelay(true);
    tune_tcp(&socks);
    timeout(SOCKS_TIMEOUT, socks5_connect(&mut socks, &target))
        .await
        .context("SOCKS5 upstream timeout")?
        .context(format!("SOCKS5 upstream connect to {}", target))?;

    proxy_ws_tcp(ws, socks, stats).await
}

async fn handle_server_conn(
    tcp: TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    socks_addr: &str,
    secret_key: &str,
    ws_path: &str,
    stats: Arc<Stats>,
    peer: std::net::SocketAddr,
    require_secret: bool,
) -> Result<()> {
    let tls = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
        .await
        .context("TLS timeout")??;

    let expected_path = ws_path.to_string();
    let secret = secret_key.to_string();
    let auth_ok = Arc::new(std::sync::Mutex::new(false));
    let auth_cb = auth_ok.clone();
    let target_cell: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let target_cb = target_cell.clone();

    let ws = timeout(
        HANDSHAKE_TIMEOUT,
        accept_hdr_async(tls, move |req: &Request, mut resp: Response| {
            if req.uri().path() != expected_path {
                let body = Some(
                    "<html>\n<head><title>404 Not Found</title></head>\n\
                    <body>\n<center><h1>404 Not Found</h1></center>\n\
                    <hr><center>nginx/1.24.0</center>\n</body>\n</html>\n"
                        .to_string(),
                );
                return Err(http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header("Server", "nginx/1.24.0")
                    .header("Content-Type", "text/html")
                    .body(body)
                    .unwrap());
            }

            let authenticated = if !require_secret {
                true
            } else {
                if let (Some(a), Some(n)) =
                    (req.headers().get("x-auth"), req.headers().get("x-nonce"))
                {
                    let nonce = n.to_str().unwrap_or("");
                    a.to_str().unwrap_or("") == compute_token(&secret, nonce)
                } else {
                    false
                }
            };

            if authenticated {
                if let Some(t) = req.headers().get("x-target") {
                    if let Ok(mut g) = target_cb.lock() {
                        *g = Some(t.to_str().unwrap_or("").to_string());
                    }
                }
                if let Ok(mut g) = auth_cb.lock() {
                    *g = true;
                }
                resp.headers_mut()
                    .insert("server", HeaderValue::from_static("cloudflare"));
                return Ok(resp);
            }

            let body = Some(
                "<html>\n<head><title>401 Authorization Required</title></head>\n\
                <body>\n<center><h1>401 Authorization Required</h1></center>\n\
                <hr><center>nginx/1.24.0</center>\n</body>\n</html>\n"
                    .to_string(),
            );
            Err(http::Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Server", "nginx/1.24.0")
                .header("Content-Type", "text/html")
                .body(body)
                .unwrap())
        }),
    )
    .await
    .context("WS upgrade timeout")??;

    if !*auth_ok.lock().unwrap_or_else(|e| e.into_inner()) {
        stats.auth_failed.fetch_add(1, Ordering::Relaxed);
        return Err(anyhow::anyhow!("Auth failed from {}", peer));
    }
    if !require_secret {
        stats.whitelist_allowed.fetch_add(1, Ordering::Relaxed);
    }

    let target = target_cell
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .context("Missing x-target header")?;

    let mut socks = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(socks_addr))
        .await
        .context("SOCKS connect timeout")??;
    let _ = socks.set_nodelay(true);
    tune_tcp(&socks);
    timeout(SOCKS_TIMEOUT, socks5_connect(&mut socks, &target))
        .await
        .context("SOCKS5 upstream timeout")?
        .context(format!("SOCKS5 upstream connect to {}", target))?;

    proxy_ws_tcp(ws, socks, stats).await
}

// ═════════════════════════════════════════════════════════════════════════════
//  CLIENT SIDE (без изменений)
// ═════════════════════════════════════════════════════════════════════════════

pub async fn run_client(
    bind_addr: &str,
    server_url: &str,
    secret_key: &str,
    skip_verify: bool,
    host_header: Option<&str>,
) -> Result<()> {
    let server_url = {
        let s = if server_url.starts_with("wss://") || server_url.starts_with("ws://") {
            server_url.to_string()
        } else {
            format!("wss://{}", server_url)
        };
        if s.matches('/').count() < 3 {
            format!("{}/ws", s)
        } else {
            s
        }
    };

    let listener = TcpListener::bind(bind_addr).await?;
    tune_listener(&listener);

    println!("[CLIENT] SOCKS5 proxy listening on {}", bind_addr);
    println!("[CLIENT] Tunnel server: {}", server_url);
    if let Some(h) = host_header {
        println!("[CLIENT] CDN fronting: {}", h);
    }
    if skip_verify {
        println!("[WARNING] TLS verification DISABLED");
    }

    let tls_cfg = build_client_tls(skip_verify)?;
    let connector = Arc::new(tokio_tungstenite::Connector::Rustls(Arc::new(tls_cfg)));
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret_key.to_string());
    let url = Arc::new(server_url);
    let host_hdr = Arc::new(host_header.map(|h| h.to_string()));

    let s = stats.clone();
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(30));
        loop {
            iv.tick().await;
            s.report();
        }
    });

    loop {
        let (mut tcp, peer) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        tune_tcp(&tcp);

        let sem = sem.clone();
        let stats = stats.clone();
        let secret = secret.clone();
        let url = url.clone();
        let host_hdr = host_hdr.clone();
        let connector = connector.clone();

        tokio::spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };
            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = handle_client_conn(
                &mut tcp,
                &url,
                &secret,
                host_hdr.as_deref(),
                connector,
                stats.clone(),
            )
            .await
            {
                eprintln!("[CLIENT] {} — {:#}", peer, e);
            }
            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn handle_client_conn(
    local: &mut TcpStream,
    server_url: &str,
    secret_key: &str,
    host_override: Option<&str>,
    connector: Arc<tokio_tungstenite::Connector>,
    stats: Arc<Stats>,
) -> Result<()> {
    let target = timeout(SOCKS_TIMEOUT, proxy_handshake(local))
        .await
        .context("SOCKS5 handshake timeout")?
        .context("SOCKS5 handshake failed")?;

    eprintln!("[CLIENT] SOCKS5 → target: {}", target);

    if is_blacklisted(&target) {
        let _ = local
            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        anyhow::bail!("Target blacklisted");
    }

    let nonce = {
        let mut b = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut b);
        B64.encode(b)
    };
    let token = compute_token(secret_key, &nonce);
    let ws_key = {
        let mut k = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut k);
        B64.encode(k)
    };
    let url_host = server_url
        .trim_start_matches("wss://")
        .trim_start_matches("ws://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    let mut builder = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(server_url)
        .header("Host", &url_host)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Key", &ws_key)
        .header("Sec-WebSocket-Version", "13")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("x-auth", &token)
        .header("x-nonce", &nonce)
        .header("x-target", &target);

    if let Some(host) = host_override {
        builder = builder.header("Host", host);
    }

    let req = builder.body(()).context("Failed to build WS request")?;
    let (ws, _) = timeout(
        HANDSHAKE_TIMEOUT,
        connect_async_tls_with_config(req, None, false, Some((*connector).clone())),
    )
    .await
    .context("WS connect timeout")??;

    proxy_ws_tcp_ref(ws, local, stats).await
}

// ═════════════════════════════════════════════════════════════════════════════
//  BIDIRECTIONAL PROXY
// ═════════════════════════════════════════════════════════════════════════════

async fn proxy_ws_tcp_ref<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    tcp: &mut TcpStream,
    stats: Arc<Stats>,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (mut tcp_rx, mut tcp_tx) = tcp.split();

    let stats_up = stats.clone();
    let tcp_to_ws = async move {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;
        loop {
            match timeout(READ_TIMEOUT, tcp_rx.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    if ws_tx
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    total += n as u64;
                }
            }
        }
        let _ = ws_tx.close().await;
        stats_up.bytes_tx.fetch_add(total, Ordering::Relaxed);
        total
    };

    let stats_down = stats;
    let ws_to_tcp = async move {
        let mut total = 0u64;
        loop {
            match timeout(READ_TIMEOUT, ws_rx.next()).await {
                Ok(Some(Ok(Message::Binary(data)))) => {
                    if tcp_tx.write_all(&data).await.is_err() {
                        break;
                    }
                    total += data.len() as u64;
                }
                Ok(Some(Ok(Message::Ping(_)))) => {}
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) => break,
                Ok(Some(Err(_))) => break,
                _ => {}
            }
        }
        let _ = tcp_tx.flush().await;
        stats_down.bytes_rx.fetch_add(total, Ordering::Relaxed);
        total
    };

    let (tx, rx) = tokio::join!(tcp_to_ws, ws_to_tcp);
    if tx > 0 || rx > 0 {
        println!("[CONN] Closed TX:{}KB RX:{}KB", tx / 1024, rx / 1024);
    }
    Ok(())
}

async fn proxy_ws_tcp<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    tcp: TcpStream,
    stats: Arc<Stats>,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (mut tcp_rx, mut tcp_tx) = tokio::io::split(tcp);

    let stats_up = stats.clone();
    let tcp_to_ws = async move {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;
        loop {
            match timeout(READ_TIMEOUT, tcp_rx.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    if ws_tx
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    total += n as u64;
                }
            }
        }
        let _ = ws_tx.close().await;
        stats_up.bytes_tx.fetch_add(total, Ordering::Relaxed);
        total
    };

    let stats_down = stats;
    let ws_to_tcp = async move {
        let mut total = 0u64;
        loop {
            match timeout(READ_TIMEOUT, ws_rx.next()).await {
                Ok(Some(Ok(Message::Binary(data)))) => {
                    if tcp_tx.write_all(&data).await.is_err() {
                        break;
                    }
                    total += data.len() as u64;
                }
                Ok(Some(Ok(Message::Ping(_)))) => {}
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) => break,
                Ok(Some(Err(_))) => break,
                _ => {}
            }
        }
        let _ = tcp_tx.flush().await;
        stats_down.bytes_rx.fetch_add(total, Ordering::Relaxed);
        total
    };

    let (tx, rx) = tokio::join!(tcp_to_ws, ws_to_tcp);
    if tx > 0 || rx > 0 {
        println!("[CONN] Closed TX:{}KB RX:{}KB", tx / 1024, rx / 1024);
    }
    Ok(())
}

// ═════════════════════════════════════════════════════════════════════════════
//  CLOUDFLARE WORKER JS
// ═════════════════════════════════════════════════════════════════════════════

fn print_cf_worker(origin: &str, ws_path: &str) {
    println!(
        r#"
// Cloudflare Worker
export default {{
  async fetch(request, env) {{
    const url = new URL(request.url);
    if (url.pathname !== "{ws_path}") {{
      return new Response("<h1>404</h1>", {{ status: 404, headers: {{ "Server": "nginx/1.24.0" }} }});
    }}
    if ((request.headers.get("Upgrade")||"").toLowerCase() !== "websocket") {{
      return new Response("Expected WebSocket", {{ status: 426 }});
    }}
    const headers = new Headers(request.headers);
    headers.set("Host", env.ORIGIN_HOST.split(":")[0]);
    return fetch(`wss://${{env.ORIGIN_HOST}}{ws_path}`, {{ method: request.method, headers, body: request.body }});
  }},
}};
"#
    );
}

// ═════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ═════════════════════════════════════════════════════════════════════════════

fn compute_token(secret: &str, nonce: &str) -> String {
    let mut h = Sha256::new();
    h.update(AUTH_MAGIC);
    h.update(secret.as_bytes());
    h.update(nonce.as_bytes());
    B64.encode(h.finalize())
}

fn build_client_tls(skip_verify: bool) -> Result<rustls::ClientConfig> {
    let cfg = if skip_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    Ok(cfg)
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let f = std::fs::File::open(path).context(format!("Cannot open cert: {}", path))?;
    let mut r = std::io::BufReader::new(f);
    Ok(rustls_pemfile::certs(&mut r).collect::<Result<Vec<_>, _>>()?)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let f = std::fs::File::open(path).context(format!("Cannot open key: {}", path))?;
    let mut r = std::io::BufReader::new(f);
    Ok(rustls_pemfile::private_key(&mut r)?.context("No private key found")?)
}

#[derive(Debug)]
struct NoCertVerifier;
impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer,
        _: &[CertificateDer],
        _: &rustls::pki_types::ServerName,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  MAIN
// ═════════════════════════════════════════════════════════════════════════════

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let args: Vec<String> = std::env::args().collect();

    let help = |prog: &str| {
        eprintln!(
            r#"TLS WebSocket Tunnel v3

USAGE:
  server  <bind> <socks> <cert.pem> <key.pem> <secret> [ws-path] [--plain] [--whitelist <ip-list|file>]
  client  <bind> <server-url> <secret> [--insecure] [--host <cdn>]
  worker  <origin:port> [ws-path]

WHITELIST:
  --whitelist "1.2.3.4,10.0.0.0/8"   — список IP через запятую
  --whitelist /etc/tunnel/whitelist.txt — путь к файлу (по одному IP/CIDR в строке, # комментарии)

  Если IP в whitelist — secret_key не нужен (для сторонних клиентов).
  Если whitelist не задан — secret_key нужен всем.

EXAMPLES:
  {prog} server 0.0.0.0:443 127.0.0.1:1080 cert.pem key.pem MySecret /api/v1/ws
  {prog} server 0.0.0.0:443 127.0.0.1:1080 cert.pem key.pem MySecret /ws --whitelist "1.2.3.4,5.6.7.0/24"
  {prog} server 0.0.0.0:443 127.0.0.1:1080 cert.pem key.pem MySecret /ws --whitelist /etc/whitelist.txt
  {prog} client 127.0.0.1:9050 wss://yourserver.com/ws MySecret
"#
        );
    };

    match args.get(1).map(|s| s.as_str()) {
        Some("server") => {
            if args.len() < 7 {
                help(&args[0]);
                std::process::exit(1);
            }
            let ws_path = args.get(7).map(|s| s.as_str()).unwrap_or("/ws");
            let plain = args.iter().any(|a| a == "--plain");

            // Парсим --whitelist
            let whitelist = args
                .windows(2)
                .find(|w| w[0] == "--whitelist")
                .map(|w| w[1].as_str())
                .map(|wl| {
                    // Если начинается с '/' или './' — читаем как файл
                    if wl.starts_with('/') || wl.starts_with("./") || wl.ends_with(".txt") {
                        IpWhitelist::from_file(wl).unwrap_or_else(|e| {
                            eprintln!("[ERROR] {}", e);
                            std::process::exit(1);
                        })
                    } else {
                        IpWhitelist::from_str(wl)
                    }
                })
                .unwrap_or_default();

            run_server(
                &args[2], &args[3], &args[4], &args[5], &args[6], ws_path, plain, whitelist,
            )
            .await?;
        }
        Some("client") => {
            if args.len() < 5 {
                help(&args[0]);
                std::process::exit(1);
            }
            let skip_verify = args.iter().any(|a| a == "--insecure");
            let host_override = args
                .windows(2)
                .find(|w| w[0] == "--host")
                .map(|w| w[1].as_str());
            run_client(&args[2], &args[3], &args[4], skip_verify, host_override).await?;
        }
        Some("worker") => {
            let origin = args.get(2).map(|s| s.as_str()).unwrap_or("YOUR_VPS:443");
            let ws_path = args.get(3).map(|s| s.as_str()).unwrap_or("/ws");
            print_cf_worker(origin, ws_path);
        }
        _ => {
            help(&args[0]);
            std::process::exit(1);
        }
    }
    Ok(())
}
