use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::{self, HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{accept_hdr_async, connect_async_tls_with_config};

// ── Tuning ───────────────────────────────────────────────────────────────────
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

#[derive(Default, Clone)]
pub struct IpWhitelist {
    entries: Vec<IpEntry>,
}

#[derive(Clone)]
enum IpEntry {
    Exact(IpAddr),
    Cidr { base: u128, mask: u128, is_v6: bool },
}

impl IpWhitelist {
    pub fn from_str(s: &str) -> Self {
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

    pub fn from_file(path: &str) -> Result<Self> {
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

    pub fn contains(&self, addr: IpAddr) -> bool {
        self.entries.iter().any(|e| matches_entry(e, addr))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn parse_ip_entry(s: &str) -> Option<IpEntry> {
    if s.contains('/') {
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
        Some(IpEntry::Exact(s.parse().ok()?))
    }
}

fn matches_entry(entry: &IpEntry, addr: IpAddr) -> bool {
    match entry {
        IpEntry::Exact(e) => *e == addr,
        IpEntry::Cidr { base, mask, is_v6 } => match addr {
            IpAddr::V4(v4) if !is_v6 => (u32::from(v4) as u128 & mask) == *base,
            IpAddr::V6(v6) if *is_v6 => (u128::from(v6) & mask) == *base,
            _ => false,
        },
    }
}

// ── SOCKS5 Users (login:password) ────────────────────────────────────────────

/// Таблица разрешённых логин/пароль для SOCKS5 авторизации.
#[derive(Default, Clone)]
pub struct Socks5Users {
    map: HashMap<String, String>,
}

impl Socks5Users {
    /// Парсит "user1:pass1,user2:pass2"
    pub fn from_str(s: &str) -> Self {
        let mut map = HashMap::new();
        for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
            if let Some((u, p)) = part.split_once(':') {
                map.insert(u.to_string(), p.to_string());
            } else {
                eprintln!(
                    "[SOCKS5-USERS] Malformed entry (expected user:pass): {}",
                    part
                );
            }
        }
        Self { map }
    }

    /// Парсит файл: строки вида "user:pass", # — комментарии
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .context(format!("Cannot read SOCKS5 users file: {}", path))?;
        let joined: String = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect::<Vec<_>>()
            .join(",");
        Ok(Self::from_str(&joined))
    }

    pub fn check(&self, user: &str, pass: &str) -> bool {
        self.map.get(user).map(|p| p == pass).unwrap_or(false)
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ── SOCKS5 constants ─────────────────────────────────────────────────────────
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_AUTH_USERPASS: u8 = 0x02;
const SOCKS5_AUTH_NO_ACCEPTABLE: u8 = 0xFF;

// ── Stats ────────────────────────────────────────────────────────────────────
#[derive(Default)]
struct Stats {
    active: AtomicU64,
    total: AtomicU64,
    bytes_rx: AtomicU64,
    bytes_tx: AtomicU64,
    auth_failed: AtomicU64,
    whitelist_allowed: AtomicU64,
    socks5_direct: AtomicU64,
}

impl Stats {
    fn report(&self) {
        println!(
            "[STATS] Active:{} Total:{} Failed:{} WL:{} SOCKS5-TLS:{} RX:{}MB TX:{}MB",
            self.active.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
            self.auth_failed.load(Ordering::Relaxed),
            self.whitelist_allowed.load(Ordering::Relaxed),
            self.socks5_direct.load(Ordering::Relaxed),
            self.bytes_rx.load(Ordering::Relaxed) / 1_000_000,
            self.bytes_tx.load(Ordering::Relaxed) / 1_000_000,
        );
    }
}

// ── Socket tuning ────────────────────────────────────────────────────────────
fn tune_tcp(stream: &TcpStream) {
    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let raw = stream.as_raw_fd();
        let sock = unsafe { socket2::Socket::from_raw_fd(raw) };
        let _ = sock.set_recv_buffer_size(512 * 1024);
        let _ = sock.set_send_buffer_size(512 * 1024);
        std::mem::forget(sock);
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};
        let raw = stream.as_raw_socket();
        let sock = unsafe { socket2::Socket::from_raw_socket(raw) };
        let _ = sock.set_recv_buffer_size(512 * 1024);
        let _ = sock.set_send_buffer_size(512 * 1024);
        std::mem::forget(sock);
    }
}

fn tune_listener(listener: &TcpListener) {
    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let raw = listener.as_raw_fd();
        let sock = unsafe { socket2::Socket::from_raw_fd(raw) };
        let _ = sock.set_recv_buffer_size(1 << 20);
        let _ = sock.set_send_buffer_size(1 << 20);
        std::mem::forget(sock);
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};
        let raw = listener.as_raw_socket();
        let sock = unsafe { socket2::Socket::from_raw_socket(raw) };
        let _ = sock.set_recv_buffer_size(1 << 20);
        let _ = sock.set_send_buffer_size(1 << 20);
        std::mem::forget(sock);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  КЛИЕНТСКАЯ СТОРОНА: SOCKS5/HTTP CONNECT handshake (принимаем от локального
//  приложения на Windows)
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
    // Отвечаем no-auth (мы локальный прокси, авторизация не нужна)
    stream
        .write_all(&[SOCKS5_VERSION, 0x00])
        .await
        .context("SOCKS5: method resp")?;
    read_socks5_request_tcp(stream).await
}

async fn read_socks5_request_tcp(stream: &mut TcpStream) -> Result<String> {
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
    let host = read_socks5_addr_tcp(stream, req[3]).await?;
    let mut pb = [0u8; 2];
    stream.read_exact(&mut pb).await.context("SOCKS5: port")?;
    let port = u16::from_be_bytes(pb);
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .context("SOCKS5: reply")?;
    Ok(format!("{}:{}", host, port))
}

async fn read_socks5_addr_tcp(stream: &mut TcpStream, atyp: u8) -> Result<String> {
    match atyp {
        SOCKS5_ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await.context("SOCKS5: ipv4")?;
            Ok(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .context("SOCKS5: domain len")?;
            let mut d = vec![0u8; len[0] as usize];
            stream.read_exact(&mut d).await.context("SOCKS5: domain")?;
            String::from_utf8(d).context("SOCKS5: domain utf8")
        }
        SOCKS5_ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await.context("SOCKS5: ipv6")?;
            let segs: Vec<String> = ip
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            Ok(format!("[{}]", segs.join(":")))
        }
        t => anyhow::bail!("SOCKS5: unknown atyp {}", t),
    }
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
        .context("HTTP CONNECT: timeout")??;
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

// ── SOCKS5 upstream connect (исходящий к апстриму на VPS) ────────────────────
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
//  СЕРВЕРНАЯ СТОРОНА — SOCKS5+TLS handler
//
//  Клиент уже прошёл TLS. Первый байт = 0x05 (SOCKS5).
//  nmethods ещё не читан — читаем здесь.
//
//  Авторизация:
//    IP в whitelist  → no-auth (метод 0x00)
//    иначе           → username/password (метод 0x02), если users не пустой
//    иначе           → отказ (0xFF)
// ═════════════════════════════════════════════════════════════════════════════

async fn server_socks5_handshake(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    peer_ip: IpAddr,
    whitelist: &IpWhitelist,
    users: &Socks5Users,
) -> Result<String> {
    // Читаем nmethods (первый байт 0x05 уже прочитан снаружи)
    let mut nmethods_buf = [0u8; 1];
    stream
        .read_exact(&mut nmethods_buf)
        .await
        .context("SOCKS5-srv: nmethods")?;
    let mut methods = vec![0u8; nmethods_buf[0] as usize];
    stream
        .read_exact(&mut methods)
        .await
        .context("SOCKS5-srv: methods")?;

    let ip_ok = !whitelist.is_empty() && whitelist.contains(peer_ip);
    let pass_ok = !users.is_empty() && methods.contains(&SOCKS5_AUTH_USERPASS);

    if ip_ok {
        // IP в whitelist — no-auth
        stream
            .write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NONE])
            .await?;
    } else if pass_ok {
        // Парольная авторизация (RFC 1929)
        stream
            .write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_USERPASS])
            .await?;

        let mut ver = [0u8; 1];
        stream
            .read_exact(&mut ver)
            .await
            .context("SOCKS5-srv: auth ver")?;
        let mut ulen = [0u8; 1];
        stream
            .read_exact(&mut ulen)
            .await
            .context("SOCKS5-srv: ulen")?;
        let mut uname = vec![0u8; ulen[0] as usize];
        stream
            .read_exact(&mut uname)
            .await
            .context("SOCKS5-srv: uname")?;
        let mut plen = [0u8; 1];
        stream
            .read_exact(&mut plen)
            .await
            .context("SOCKS5-srv: plen")?;
        let mut passwd = vec![0u8; plen[0] as usize];
        stream
            .read_exact(&mut passwd)
            .await
            .context("SOCKS5-srv: passwd")?;

        let user = String::from_utf8_lossy(&uname);
        let pass = String::from_utf8_lossy(&passwd);

        if users.check(&user, &pass) {
            stream.write_all(&[0x01, 0x00]).await?; // success
        } else {
            stream.write_all(&[0x01, 0x01]).await.ok(); // failure
            anyhow::bail!("SOCKS5-srv: bad credentials for user '{}'", user);
        }
    } else {
        // Нет подходящего метода
        stream
            .write_all(&[SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPTABLE])
            .await
            .ok();
        anyhow::bail!("SOCKS5-srv: no acceptable auth for {}", peer_ip);
    }

    // Читаем CONNECT запрос
    let mut req = [0u8; 4];
    stream
        .read_exact(&mut req)
        .await
        .context("SOCKS5-srv: request header")?;
    if req[0] != SOCKS5_VERSION {
        anyhow::bail!("SOCKS5-srv: bad version {}", req[0]);
    }
    if req[1] != SOCKS5_CMD_CONNECT {
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .ok();
        anyhow::bail!("SOCKS5-srv: unsupported cmd {}", req[1]);
    }

    let host = read_socks5_addr_tls(stream, req[3]).await?;
    let mut pb = [0u8; 2];
    stream
        .read_exact(&mut pb)
        .await
        .context("SOCKS5-srv: port")?;
    let port = u16::from_be_bytes(pb);

    Ok(format!("{}:{}", host, port))
}

async fn read_socks5_addr_tls(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    atyp: u8,
) -> Result<String> {
    match atyp {
        SOCKS5_ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream
                .read_exact(&mut ip)
                .await
                .context("SOCKS5-srv: ipv4")?;
            Ok(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]))
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .context("SOCKS5-srv: domain len")?;
            let mut d = vec![0u8; len[0] as usize];
            stream
                .read_exact(&mut d)
                .await
                .context("SOCKS5-srv: domain")?;
            String::from_utf8(d).context("SOCKS5-srv: domain utf8")
        }
        SOCKS5_ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream
                .read_exact(&mut ip)
                .await
                .context("SOCKS5-srv: ipv6")?;
            let segs: Vec<String> = ip
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            Ok(format!("[{}]", segs.join(":")))
        }
        t => anyhow::bail!("SOCKS5-srv: unknown atyp {}", t),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  SERVER SIDE — основной accept loop
// ═════════════════════════════════════════════════════════════════════════════

pub async fn run_server(
    bind_addr: &str,
    socks_addr: &str,
    cert_path: &str,
    key_path: &str,
    secret_key: &str,
    ws_path: &str,
    plain: bool,
    whitelist: IpWhitelist,
    socks5_users: Socks5Users,
) -> Result<()> {
    let acceptor_opt = if plain {
        println!("[SERVER] Plain WebSocket mode (no TLS) — SOCKS5+TLS unavailable");
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

    if !whitelist.is_empty() {
        println!("[SERVER] IP whitelist: {} entries", whitelist.entries.len());
    }
    if !socks5_users.is_empty() {
        println!(
            "[SERVER] SOCKS5+TLS users: {} accounts",
            socks5_users.map.len()
        );
    }
    let socks5_enabled = !whitelist.is_empty() || !socks5_users.is_empty();
    println!(
        "[SERVER] SOCKS5+TLS mode: {}",
        if socks5_enabled {
            "ENABLED"
        } else {
            "disabled"
        }
    );

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret_key.to_string());
    let ws_path = Arc::new(ws_path.to_string());
    let whitelist = Arc::new(whitelist);
    let socks5_users = Arc::new(socks5_users);
    let socks_addr = Arc::new(socks_addr.to_string());

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
        let socks_addr = socks_addr.clone();
        let sem = sem.clone();
        let stats = stats.clone();
        let secret = secret.clone();
        let ws_path = ws_path.clone();
        let whitelist = whitelist.clone();
        let socks5_users = socks5_users.clone();

        tokio::spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };
            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);

            let peer_ip = peer.ip();
            if let Err(e) = dispatch_server_conn(
                tcp,
                acceptor_opt,
                &socks_addr,
                &secret,
                &ws_path,
                stats.clone(),
                peer,
                peer_ip,
                whitelist,
                socks5_users,
            )
            .await
            {
                let msg = e.to_string();
                // Не спамим в лог для ожидаемых ошибок авторизации
                if !msg.contains("Auth")
                    && !msg.contains("auth")
                    && !msg.contains("401")
                    && !msg.contains("credentials")
                    && !msg.contains("no acceptable")
                {
                    eprintln!("[SERVER] {} — {}", peer, e);
                } else {
                    eprintln!("[SERVER] {} — auth error: {}", peer, msg);
                }
            }
            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// После TLS handshake читает первый байт и маршрутизирует:
///   0x05 → SOCKS5+TLS
///   всё остальное → WebSocket (HTTP)
async fn dispatch_server_conn(
    tcp: TcpStream,
    acceptor_opt: Option<tokio_rustls::TlsAcceptor>,
    socks_addr: &str,
    secret_key: &str,
    ws_path: &str,
    stats: Arc<Stats>,
    peer: std::net::SocketAddr,
    peer_ip: IpAddr,
    whitelist: Arc<IpWhitelist>,
    socks5_users: Arc<Socks5Users>,
) -> Result<()> {
    // plain режим — только WS, без детектирования
    let Some(acceptor) = acceptor_opt else {
        let require_secret = whitelist.is_empty() || !whitelist.contains(peer_ip);
        return handle_ws_plain(
            tcp,
            socks_addr,
            secret_key,
            ws_path,
            stats,
            peer,
            require_secret,
        )
        .await;
    };

    // TLS handshake
    let mut tls = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
        .await
        .context("TLS timeout")??;

    // Читаем первый байт — детектируем протокол
    let mut first = [0u8; 1];
    timeout(HANDSHAKE_TIMEOUT, tls.read_exact(&mut first))
        .await
        .context("first byte timeout")?
        .context("first byte read")?;

    if first[0] == SOCKS5_VERSION {
        // ── SOCKS5+TLS ────────────────────────────────────────────────────
        stats.socks5_direct.fetch_add(1, Ordering::Relaxed);

        let target = match timeout(
            HANDSHAKE_TIMEOUT,
            server_socks5_handshake(&mut tls, peer_ip, &whitelist, &socks5_users),
        )
        .await
        {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => {
                stats.auth_failed.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
            Err(_) => anyhow::bail!("SOCKS5-srv: handshake timeout"),
        };

        if is_blacklisted(&target) {
            tls.write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .ok();
            anyhow::bail!("SOCKS5-srv: blacklisted {}", target);
        }

        // Отправляем success reply клиенту
        tls.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .context("SOCKS5-srv: success reply")?;

        if whitelist.contains(peer_ip) {
            stats.whitelist_allowed.fetch_add(1, Ordering::Relaxed);
        }

        println!("[SOCKS5-TLS] {} → {}", peer_ip, target);

        let mut upstream = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(socks_addr))
            .await
            .context("SOCKS connect timeout")??;
        let _ = upstream.set_nodelay(true);
        tune_tcp(&upstream);
        timeout(SOCKS_TIMEOUT, socks5_connect(&mut upstream, &target))
            .await
            .context("SOCKS5 upstream timeout")?
            .context(format!("SOCKS5 upstream connect to {}", target))?;

        proxy_tls_tcp(tls, upstream, stats).await
    } else {
        // ── WebSocket ─────────────────────────────────────────────────────
        // Нужно "вернуть" первый байт обратно. tokio_rustls не поддерживает
        // unread, поэтому прокидываем его через Chain.
        let require_secret = whitelist.is_empty() || !whitelist.contains(peer_ip);
        let prefix = std::io::Cursor::new(vec![first[0]]);
        let chained = tokio::io::join(prefix, tls);
        handle_ws_generic(
            chained,
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

/// Двунаправленный прокси: TLS stream ↔ plain TCP upstream
async fn proxy_tls_tcp(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    upstream: TcpStream,
    stats: Arc<Stats>,
) -> Result<()> {
    let (mut tls_rx, mut tls_tx) = tokio::io::split(tls);
    let (mut up_rx, mut up_tx) = tokio::io::split(upstream);

    let stats_up = stats.clone();
    let client_to_up = async move {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;
        loop {
            match timeout(READ_TIMEOUT, tls_rx.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    if up_tx.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    total += n as u64;
                }
            }
        }
        let _ = up_tx.flush().await;
        stats_up.bytes_tx.fetch_add(total, Ordering::Relaxed);
        total
    };

    let stats_down = stats;
    let up_to_client = async move {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;
        loop {
            match timeout(READ_TIMEOUT, up_rx.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    if tls_tx.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    total += n as u64;
                }
            }
        }
        let _ = tls_tx.flush().await;
        stats_down.bytes_rx.fetch_add(total, Ordering::Relaxed);
        total
    };

    let (tx, rx) = tokio::join!(client_to_up, up_to_client);
    if tx > 0 || rx > 0 {
        println!("[CONN] Closed TX:{}KB RX:{}KB", tx / 1024, rx / 1024);
    }
    Ok(())
}

// ── WebSocket handlers ────────────────────────────────────────────────────────

async fn handle_ws_plain(
    tcp: TcpStream,
    socks_addr: &str,
    secret_key: &str,
    ws_path: &str,
    stats: Arc<Stats>,
    peer: std::net::SocketAddr,
    require_secret: bool,
) -> Result<()> {
    handle_ws_generic(
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

async fn handle_ws_generic<S>(
    stream: S,
    socks_addr: &str,
    secret_key: &str,
    ws_path: &str,
    stats: Arc<Stats>,
    peer: std::net::SocketAddr,
    require_secret: bool,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let expected_path = ws_path.to_string();
    let secret = secret_key.to_string();
    let auth_ok = Arc::new(std::sync::Mutex::new(false));
    let auth_cb = auth_ok.clone();
    let target_cell: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let target_cb = target_cell.clone();

    let ws = timeout(
        HANDSHAKE_TIMEOUT,
        accept_hdr_async(stream, move |req: &Request, mut resp: Response| {
            if req.uri().path() != expected_path {
                return Err(http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header("Server", "nginx/1.24.0")
                    .header("Content-Type", "text/html")
                    .body(Some(nginx_page("404 Not Found")))
                    .unwrap());
            }

            let authenticated = if !require_secret {
                true
            } else if let (Some(a), Some(n)) =
                (req.headers().get("x-auth"), req.headers().get("x-nonce"))
            {
                let nonce = n.to_str().unwrap_or("");
                a.to_str().unwrap_or("") == compute_token(&secret, nonce)
            } else {
                false
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

            Err(http::Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Server", "nginx/1.24.0")
                .header("Content-Type", "text/html")
                .body(Some(nginx_page("401 Authorization Required")))
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

fn nginx_page(title: &str) -> String {
    format!(
        "<html>\n<head><title>{t}</title></head>\n\
        <body>\n<center><h1>{t}</h1></center>\n\
        <hr><center>nginx/1.24.0</center>\n</body>\n</html>\n",
        t = title
    )
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
    println!(
        "[CLIENT] Set Windows proxy: socks=127.0.0.1:{}",
        bind_addr.split(':').last().unwrap_or("9050")
    );

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
//  BIDIRECTIONAL PROXY (WebSocket ↔ TCP)
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
    Ok(if skip_verify {
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
    })
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let f = std::fs::File::open(path).context(format!("Cannot open cert: {}", path))?;
    Ok(rustls_pemfile::certs(&mut std::io::BufReader::new(f)).collect::<Result<Vec<_>, _>>()?)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let f = std::fs::File::open(path).context(format!("Cannot open key: {}", path))?;
    Ok(
        rustls_pemfile::private_key(&mut std::io::BufReader::new(f))?
            .context("No private key found")?,
    )
}

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
            r#"TLS WebSocket Tunnel v4

USAGE:
  server  <bind> <socks> <cert.pem> <key.pem> <secret> [ws-path] [OPTIONS]
  client  <bind> <server-url> <secret> [--insecure] [--host <cdn>]
  worker  <origin:port> [ws-path]

SERVER OPTIONS:
  --plain                      Без TLS (только WS, SOCKS5+TLS недоступен)
  --whitelist  <ips|file>      IP/CIDR — пускать без пароля (WS и SOCKS5+TLS)
  --socks5-users <users|file>  Логины для SOCKS5+TLS: "user:pass,user2:pass2"

ПРОТОКОЛЫ (один порт, автодетект по первому байту после TLS):
  WebSocket    — наш клиент, авторизация: secret_key или whitelist IP
  SOCKS5+TLS   — curl/браузер/любой SOCKS5 клиент, авторизация: whitelist IP или login:password

EXAMPLES:
  # Только IP whitelist (нет пароля для IP из списка):
  {prog} server 0.0.0.0:443 127.0.0.1:1080 cert.pem key.pem MySecret /ws \
    --whitelist "1.2.3.4,10.0.0.0/8"

  # Плюс SOCKS5+TLS с паролями для остальных:
  {prog} server 0.0.0.0:443 127.0.0.1:1080 cert.pem key.pem MySecret /ws \
    --whitelist "1.2.3.4" --socks5-users "alice:s3cr3t,bob:hunter2"

  # Пользователи из файла (одна строка = user:pass, # комментарии):
  {prog} server 0.0.0.0:443 127.0.0.1:1080 cert.pem key.pem MySecret /ws \
    --socks5-users /etc/tunnel/users.txt

  # Наш клиент (WebSocket):
  {prog} client 127.0.0.1:9050 wss://yourserver.com/ws MySecret

СТОРОННИЕ КЛИЕНТЫ (SOCKS5+TLS):
  curl  --proxy socks5h://alice:s3cr3t@yourserver.com:443 https://example.com
  curl  --proxy socks5h://yourserver.com:443 https://example.com   # если IP в whitelist
  # В браузере: SOCKS5 хост=yourserver.com порт=443 логин=alice пароль=s3cr3t
  # Нужно добавить сертификат сервера в доверенные (или самоподписанный с --insecure в curl)
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

            let whitelist = find_flag(&args, "--whitelist")
                .map(|s| {
                    if looks_like_path(s) {
                        IpWhitelist::from_file(s).unwrap_or_else(|e| {
                            eprintln!("[ERROR] {}", e);
                            std::process::exit(1);
                        })
                    } else {
                        IpWhitelist::from_str(s)
                    }
                })
                .unwrap_or_default();

            let socks5_users = find_flag(&args, "--socks5-users")
                .map(|s| {
                    if looks_like_path(s) {
                        Socks5Users::from_file(s).unwrap_or_else(|e| {
                            eprintln!("[ERROR] {}", e);
                            std::process::exit(1);
                        })
                    } else {
                        Socks5Users::from_str(s)
                    }
                })
                .unwrap_or_default();

            run_server(
                &args[2],
                &args[3],
                &args[4],
                &args[5],
                &args[6],
                ws_path,
                plain,
                whitelist,
                socks5_users,
            )
            .await?;
        }
        Some("client") => {
            if args.len() < 5 {
                help(&args[0]);
                std::process::exit(1);
            }
            let skip_verify = args.iter().any(|a| a == "--insecure");
            let host_override = find_flag(&args, "--host");
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

fn find_flag<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].as_str())
}

fn looks_like_path(s: &str) -> bool {
    s.starts_with('/') || s.starts_with("./") || s.ends_with(".txt")
}
