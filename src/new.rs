/// tunnel v4 — unified WS/TLS proxy + DNS forwarder
///
/// SERVER: tunnel server <bind> <socks5-upstream> <cert.pem> <key.pem> <secret> [--path /ws] [--plain] [--dns 1.1.1.1:53]
/// CLIENT: tunnel client <socks5-bind> <dns-bind> <wss://host/ws> <secret> [--insecure] [--host <cdn>]
///
/// Windows DNS fix: set IPv4 DNS → 127.0.0.1, leave IPv6 DNS blank.
/// Or bind dns to 0.0.0.0:53 so both 127.0.0.1 and ::1 queries hit it.
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    time::timeout,
};
use tokio_tungstenite::{
    accept_hdr_async, connect_async_tls_with_config,
    tungstenite::{
        handshake::server::{Request, Response},
        http::{self, HeaderValue, StatusCode},
        protocol::Message,
    },
};

trait IoStream: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> IoStream for T {}

type DynStream = Box<dyn IoStream + Send + Unpin>;

// ── Constants ────────────────────────────────────────────────────────────────
const AUTH_MAGIC: &[u8] = b"TLS_TUNNEL_V4_WS";
const BUF: usize = 128 * 1024;
const MAX_CONN: usize = 10_000;
const T_HS: Duration = Duration::from_secs(20);
const T_IO: Duration = Duration::from_secs(600);
const T_SOCKS: Duration = Duration::from_secs(15);
const T_DNS: Duration = Duration::from_secs(5);
const DNS_BUF: usize = 4096;
const DEFAULT_UPSTREAM_DNS: &str = "1.1.1.1:53";
/// Send WS ping every N seconds to keep NAT/CDN sessions alive
const PING_INTERVAL: Duration = Duration::from_secs(30);

// ── Shared helpers ───────────────────────────────────────────────────────────
fn hmac_token(secret: &str, nonce: &str) -> String {
    let mut h = Sha256::new();
    h.update(AUTH_MAGIC);
    h.update(secret.as_bytes());
    h.update(nonce.as_bytes());
    B64.encode(h.finalize())
}

fn rand_nonce() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    B64.encode(b)
}

fn rand_wskey() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    B64.encode(b)
}

// ── Stats ────────────────────────────────────────────────────────────────────
#[derive(Default)]
struct Stats {
    active: AtomicU64,
    total: AtomicU64,
    bytes_tx: AtomicU64,
    bytes_rx: AtomicU64,
    auth_failed: AtomicU64,
    dns_queries: AtomicU64,
    dns_errors: AtomicU64,
}
impl Stats {
    fn spawn_reporter(self: &Arc<Self>) {
        let s = self.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(30));
            loop {
                iv.tick().await;
                println!(
                    "[STATS] conns={}/{} tx={}MB rx={}MB auth_fail={} dns={}/err={}",
                    s.active.load(Ordering::Relaxed),
                    s.total.load(Ordering::Relaxed),
                    s.bytes_tx.load(Ordering::Relaxed) / 1_000_000,
                    s.bytes_rx.load(Ordering::Relaxed) / 1_000_000,
                    s.auth_failed.load(Ordering::Relaxed),
                    s.dns_queries.load(Ordering::Relaxed),
                    s.dns_errors.load(Ordering::Relaxed),
                );
            }
        });
    }
}

// ── TLS ──────────────────────────────────────────────────────────────────────
fn load_certs(p: &str) -> Result<Vec<CertificateDer<'static>>> {
    let f = std::fs::File::open(p).context(format!("cert: {p}"))?;
    Ok(rustls_pemfile::certs(&mut std::io::BufReader::new(f)).collect::<Result<Vec<_>, _>>()?)
}
fn load_key(p: &str) -> Result<PrivateKeyDer<'static>> {
    let f = std::fs::File::open(p).context(format!("key: {p}"))?;
    Ok(rustls_pemfile::private_key(&mut std::io::BufReader::new(f))?.context("no private key")?)
}

fn client_tls(skip: bool) -> Result<rustls::ClientConfig> {
    Ok(if skip {
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
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── Socket tuning ─────────────────────────────────────────────────────────────
#[cfg(unix)]
fn tune<T: std::os::unix::io::AsRawFd>(s: &T) {
    use std::os::unix::io::FromRawFd;
    let raw = s.as_raw_fd();
    let sock = unsafe { socket2::Socket::from_raw_fd(raw) };
    let _ = sock.set_recv_buffer_size(512 * 1024);
    let _ = sock.set_send_buffer_size(512 * 1024);
    std::mem::forget(sock);
}

#[cfg(windows)]
fn tune<T: std::os::windows::io::AsRawSocket>(s: &T) {
    use std::os::windows::io::FromRawSocket;
    let raw = s.as_raw_socket();
    let sock = unsafe { socket2::Socket::from_raw_socket(raw) };
    let _ = sock.set_recv_buffer_size(512 * 1024);
    let _ = sock.set_send_buffer_size(512 * 1024);
    std::mem::forget(sock);
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────
fn resp404() -> http::Response<Option<String>> {
    http::Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Server", "nginx/1.24.0")
        .body(Some("404".into()))
        .unwrap()
}
fn resp401() -> http::Response<Option<String>> {
    http::Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Server", "nginx/1.24.0")
        .body(Some("401".into()))
        .unwrap()
}

// ═════════════════════════════════════════════════════════════════════════════
//  SOCKS5 helpers
// ═════════════════════════════════════════════════════════════════════════════
const S5: u8 = 0x05;

async fn socks5_parse_target(s: &mut TcpStream) -> Result<String> {
    let mut nm = [0u8; 1];
    s.read_exact(&mut nm).await?;
    let mut methods = vec![0u8; nm[0] as usize];
    s.read_exact(&mut methods).await?;
    s.write_all(&[S5, 0x00]).await?; // no-auth

    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[1] == 0x03 {
        // UDP ASSOCIATE — tell client to send UDP to same address:0
        // (we don't support UDP relay, just ack and let it time out)
        s.write_all(&[S5, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .ok();
        return Ok("__UDP__".into());
    }
    anyhow::ensure!(
        req[1] == 0x01,
        "SOCKS5: only CONNECT supported (got {})",
        req[1]
    );

    let host = parse_addr_host(s, req[3]).await?;
    let mut pb = [0u8; 2];
    s.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);
    s.write_all(&[S5, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(format!("{host}:{port}"))
}

async fn parse_addr_host(s: &mut TcpStream, atyp: u8) -> Result<String> {
    Ok(match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            s.read_exact(&mut d).await?;
            String::from_utf8(d)?
        }
        0x04 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            let segs: Vec<_> = b
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            format!("[{}]", segs.join(":"))
        }
        t => anyhow::bail!("unknown SOCKS5 atyp {t}"),
    })
}

/// Connect to local SOCKS5 upstream, send CONNECT for target
async fn socks5_connect_upstream(s: &mut TcpStream, target: &str) -> Result<()> {
    let (host, port_s) = target.rsplit_once(':').context("bad target addr")?;
    let port: u16 = port_s.parse()?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    let hb = host.as_bytes();

    s.write_all(&[S5, 0x01, 0x00]).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    anyhow::ensure!(
        r[1] == 0x00,
        "upstream SOCKS5 requires auth (not supported)"
    );

    let mut req = Vec::with_capacity(7 + hb.len());
    req.extend_from_slice(&[S5, 0x01, 0x00, 0x03]);
    req.push(hb.len() as u8);
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    let mut rep = [0u8; 4];
    s.read_exact(&mut rep).await?;
    anyhow::ensure!(
        rep[1] == 0x00,
        "upstream SOCKS5 CONNECT failed: code {}",
        rep[1]
    );
    // consume BND.ADDR
    match rep[3] {
        0x01 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await?;
        }
        _ => {}
    }
    Ok(())
}

/// HTTP CONNECT (first byte already consumed)
async fn http_connect_target(s: &mut TcpStream, first: u8) -> Result<String> {
    let mut buf = vec![first];
    let mut tmp = [0u8; 1];
    loop {
        s.read_exact(&mut tmp).await?;
        buf.push(tmp[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        anyhow::ensure!(buf.len() <= 8192, "HTTP CONNECT: request too large");
    }
    let head = std::str::from_utf8(&buf)?;
    let first_line = head.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");
    anyhow::ensure!(
        method.eq_ignore_ascii_case("CONNECT"),
        "not a CONNECT request"
    );
    anyhow::ensure!(authority.contains(':'), "CONNECT target missing port");
    s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    Ok(authority.to_string())
}

/// Auto-detect SOCKS5 vs HTTP-CONNECT from first byte
async fn proxy_handshake(s: &mut TcpStream) -> Result<String> {
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await?;
    if b[0] == S5 {
        socks5_parse_target(s).await
    } else {
        http_connect_target(s, b[0]).await
    }
}

// ═════════════════════════════════════════════════════════════════════════════
//  BIDIRECTIONAL WS ↔ TCP  (single generic implementation)
// ═════════════════════════════════════════════════════════════════════════════

/// Relay bytes between a WebSocket stream and a TCP stream.
/// Sends WS pings every PING_INTERVAL to keep NAT/CDN sessions alive.
async fn relay_ws_tcp<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    mut tcp: TcpStream,
    stats: Arc<Stats>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut wt, mut wr) = ws.split();
    let (mut tr, mut tw) = tcp.split();

    let st = stats.clone();
    let up = async move {
        let mut buf = vec![0u8; BUF];
        let mut n_total = 0u64;
        let mut ping_tick = tokio::time::interval(PING_INTERVAL);
        ping_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                res = timeout(T_IO, tr.read(&mut buf)) => {
                    match res {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                        Ok(Ok(n)) => {
                            if wt.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                                break;
                            }
                            n_total += n as u64;
                        }
                    }
                }
                _ = ping_tick.tick() => {
                    if wt.send(Message::Ping(vec![].into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = wt.close().await;
        st.bytes_tx.fetch_add(n_total, Ordering::Relaxed);
        n_total
    };

    let dn = async move {
        let mut n_total = 0u64;
        loop {
            match timeout(T_IO, wr.next()).await {
                Ok(Some(Ok(Message::Binary(d)))) => {
                    if tw.write_all(&d).await.is_err() {
                        break;
                    }
                    n_total += d.len() as u64;
                }
                // respond to pings from the other side
                Ok(Some(Ok(Message::Ping(_)))) => {}
                Ok(Some(Ok(Message::Pong(_)))) => {}
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) => break,
                Ok(Some(Err(_))) => break,
                _ => {}
            }
        }
        let _ = tw.flush().await;
        stats.bytes_rx.fetch_add(n_total, Ordering::Relaxed);
        n_total
    };

    let (tx, rx) = tokio::join!(up, dn);
    if tx > 0 || rx > 0 {
        eprintln!("[CONN] tx={}k rx={}k", tx / 1024, rx / 1024);
    }
    Ok(())
}

// ═════════════════════════════════════════════════════════════════════════════
//  SERVER — WebSocket accept logic (shared between TLS and plain)
// ═════════════════════════════════════════════════════════════════════════════

/// Perform WS handshake with auth check, returns (ws_stream, target)
async fn ws_accept<IO>(
    io: IO,
    secret: &str,
    path: &str,
) -> Result<(tokio_tungstenite::WebSocketStream<IO>, String)>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    let sec = secret.to_string();
    let expected = path.to_string();
    let auth = Arc::new(std::sync::Mutex::new(false));
    let target = Arc::new(std::sync::Mutex::new(None::<String>));
    let (a2, t2) = (auth.clone(), target.clone());

    let ws = timeout(
        T_HS,
        accept_hdr_async(io, move |req: &Request, mut resp: Response| {
            if req.uri().path() != expected {
                return Err(resp404());
            }
            match (req.headers().get("x-auth"), req.headers().get("x-nonce")) {
                (Some(a), Some(n))
                    if a.to_str().unwrap_or("") == hmac_token(&sec, n.to_str().unwrap_or("")) =>
                {
                    if let Some(t) = req.headers().get("x-target") {
                        *t2.lock().unwrap() = Some(t.to_str().unwrap_or("").to_string());
                    }
                    *a2.lock().unwrap() = true;
                    resp.headers_mut()
                        .insert("server", HeaderValue::from_static("nginx"));
                    Ok(resp)
                }
                _ => Err(resp401()),
            }
        }),
    )
    .await
    .context("WS handshake timeout")??;

    if !*auth.lock().unwrap() {
        anyhow::bail!("Auth failed");
    }
    let tgt = target
        .lock()
        .unwrap()
        .clone()
        .context("missing x-target header")?;
    Ok((ws, tgt))
}

// ═════════════════════════════════════════════════════════════════════════════
//  SERVER
// ═════════════════════════════════════════════════════════════════════════════

pub async fn run_server(
    bind: &str,
    socks: &str,
    cert: &str,
    key: &str,
    secret: &str,
    ws_path: &str,
    plain: bool,
    upstream_dns: &str,
) -> Result<()> {
    let acceptor = if plain {
        println!("[SERVER] plain WS mode (no TLS)");
        None
    } else {
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(load_certs(cert)?, load_key(key)?)
            .context("invalid cert/key")?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        cfg.max_fragment_size = Some(16384);
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
    };

    let listener = TcpListener::bind(bind).await?;
    tune(&listener);
    println!("[SERVER] bind={bind} socks={socks} path={ws_path} dns_upstream={upstream_dns}");

    let sem = Arc::new(Semaphore::new(MAX_CONN));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret.to_string());
    let path = Arc::new(ws_path.to_string());
    let socks = Arc::new(socks.to_string());
    let upstream_dns = Arc::new(upstream_dns.to_string());
    stats.spawn_reporter();

    loop {
        let (tcp, peer) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        tune(&tcp);

        let (acceptor, socks, sem, stats, secret, path, upstream_dns) = (
            acceptor.clone(),
            socks.clone(),
            sem.clone(),
            stats.clone(),
            secret.clone(),
            path.clone(),
            upstream_dns.clone(),
        );

        tokio::spawn(async move {
            let _p = sem.acquire().await.unwrap();
            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);

            if let Err(e) = server_conn(
                tcp,
                acceptor,
                &socks,
                &secret,
                &path,
                &upstream_dns,
                stats.clone(),
                peer,
            )
            .await
            {
                let m = e.to_string();
                if !m.contains("401") && !m.contains("Auth failed") {
                    eprintln!("[SERVER] {peer}: {e:#}");
                }
            }
            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn server_conn(
    tcp: TcpStream,
    acc: Option<tokio_rustls::TlsAcceptor>,
    socks: &str,
    secret: &str,
    path: &str,
    upstream_dns: &str,
    stats: Arc<Stats>,
    _peer: SocketAddr,
) -> Result<()> {
    // Унифицируем тип
    let stream: DynStream = if let Some(acc) = acc {
        let tls = timeout(T_HS, acc.accept(tcp))
            .await
            .context("TLS accept timeout")??;
        Box::new(tls)
    } else {
        Box::new(tcp)
    };

    let (ws, tgt) = ws_accept(stream, secret, path).await.map_err(|e| {
        stats.auth_failed.fetch_add(1, Ordering::Relaxed);
        e
    })?;

    dispatch_ws(ws, tgt, socks.to_string(), upstream_dns.to_string(), stats).await
}

async fn dispatch_ws<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    target: String,
    socks: String,
    upstream_dns: String,
    stats: Arc<Stats>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if target == "__DNS__" {
        return handle_dns_ws(ws, &upstream_dns, stats).await;
    }

    let mut upstream = timeout(T_HS, TcpStream::connect(&socks))
        .await
        .context("socks connect timeout")??;
    let _ = upstream.set_nodelay(true);
    tune(&upstream);

    timeout(T_SOCKS, socks5_connect_upstream(&mut upstream, &target))
        .await
        .context("socks negotiation timeout")?
        .context(format!("socks CONNECT to {target}"))?;

    relay_ws_tcp(ws, upstream, stats).await
}

// ── DNS over WS (server side) ─────────────────────────────────────────────────

async fn handle_dns_ws<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    upstream_dns: &str,
    stats: Arc<Stats>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut wt, mut wr) = ws.split();
    while let Some(msg) = wr.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                stats.dns_queries.fetch_add(1, Ordering::Relaxed);
                let resp = match dns_upstream(&data, upstream_dns).await {
                    Ok(r) => r,
                    Err(e) => {
                        stats.dns_errors.fetch_add(1, Ordering::Relaxed);
                        eprintln!("[DNS] upstream error: {e}");
                        // Return SERVFAIL (QR=1 AA=0 TC=0 RD=1 RA=1 RCODE=2)
                        let mut f = data.to_vec();
                        if f.len() >= 4 {
                            f[2] = 0x81; // QR+RD
                            f[3] = 0x82; // RA + SERVFAIL
                        }
                        f
                    }
                };
                if wt.send(Message::Binary(resp.into())).await.is_err() {
                    break;
                }
            }
            Ok(Message::Ping(p)) => {
                let _ = wt.send(Message::Pong(p)).await;
            }
            Ok(Message::Close(_)) | Err(_) => break,
            _ => {}
        }
    }
    Ok(())
}

// ═════════════════════════════════════════════════════════════════════════════
//  CLIENT  (SOCKS5 listener  +  DNS listener)
// ═════════════════════════════════════════════════════════════════════════════

pub async fn run_client(
    socks_bind: &str,
    dns_bind: &str,
    server_url: &str,
    secret: &str,
    skip_verify: bool,
    host_hdr: Option<&str>,
) -> Result<()> {
    let url = normalise_url(server_url);

    let tls_cfg = client_tls(skip_verify)?;
    let connector = Arc::new(tokio_tungstenite::Connector::Rustls(Arc::new(tls_cfg)));
    let sem = Arc::new(Semaphore::new(MAX_CONN));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret.to_string());
    let url = Arc::new(url);
    let host_hdr = Arc::new(host_hdr.map(|s| s.to_string()));

    stats.spawn_reporter();

    // ── DNS UDP listeners (IPv4 + IPv6) ───────────────────────────────────────
    {
        let sock_v4 = Arc::new(UdpSocket::bind(dns_bind).await.context(format!(
            "DNS bind {dns_bind} — run as Administrator/root, or use port >1024"
        ))?);

        let ipv6_bind = dns_bind
            .replace("0.0.0.0", "[::]")
            .replace("127.0.0.1", "[::]");
        let sock_v6 = UdpSocket::bind(&ipv6_bind).await.ok().map(Arc::new);

        println!("[DNS] IPv4 listener: {dns_bind}");
        if sock_v6.is_some() {
            println!("[DNS] IPv6 listener: {ipv6_bind}");
        } else {
            println!(
                "[DNS] IPv6 bind {ipv6_bind} failed — set IPv4-only DNS in Windows (recommended)"
            );
        }

        {
            let (st, url2, sec2, con2) = (
                stats.clone(),
                url.clone(),
                secret.clone(),
                connector.clone(),
            );
            let sock4 = sock_v4.clone();
            tokio::spawn(async move {
                dns_loop(sock4, &url2, &sec2, con2, st).await;
            });
        }

        if let Some(s6) = sock_v6 {
            let (st2, url3, sec3, con3) = (
                stats.clone(),
                url.clone(),
                secret.clone(),
                connector.clone(),
            );
            tokio::spawn(async move {
                dns_loop(s6, &url3, &sec3, con3, st2).await;
            });
        }
    }

    // ── SOCKS5 TCP listener ───────────────────────────────────────────────────
    let listener = TcpListener::bind(socks_bind).await?;
    tune(&listener);
    println!("[CLIENT] SOCKS5 listener: {socks_bind}");
    println!("[CLIENT] Tunnel server:   {url}");
    if skip_verify {
        println!("[WARN]   TLS certificate verification DISABLED");
    }
    println!();
    println!("  Windows setup:");
    println!(
        "    1. Proxy:  Settings → Network → Proxy → Manual → SOCKS5 → {}",
        socks_bind
    );
    println!(
        "    2. DNS:    ncpa.cpl → adapter → IPv4 → DNS = {}",
        dns_bind.split(':').next().unwrap_or("127.0.0.1")
    );
    println!("       Leave IPv6 DNS blank.");

    loop {
        let (mut tcp, peer) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        tune(&tcp);

        let (sem, stats, secret, url, host_hdr, connector) = (
            sem.clone(),
            stats.clone(),
            secret.clone(),
            url.clone(),
            host_hdr.clone(),
            connector.clone(),
        );

        tokio::spawn(async move {
            let _p = sem.acquire().await.unwrap();
            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = client_conn(
                &mut tcp,
                &url,
                &secret,
                host_hdr.as_deref(),
                connector,
                stats.clone(),
            )
            .await
            {
                eprintln!("[CLIENT] {peer}: {e:#}");
            }
            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn normalise_url(s: &str) -> String {
    let s = if s.starts_with("wss://") || s.starts_with("ws://") {
        s.to_string()
    } else {
        format!("wss://{s}")
    };
    // Append /ws if no path given
    if s.matches('/').count() < 3 {
        format!("{s}/ws")
    } else {
        s
    }
}

// ── DNS over WebSocket (client side) ─────────────────────────────────────────

async fn dns_loop(
    sock: Arc<UdpSocket>,
    url: &str,
    secret: &str,
    connector: Arc<tokio_tungstenite::Connector>,
    stats: Arc<Stats>,
) {
    let mut buf = vec![0u8; DNS_BUF];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[DNS] recv error: {e}");
                continue;
            }
        };
        let query = buf[..n].to_vec();
        let sock2 = sock.clone();
        let url = url.to_string();
        let secret = secret.to_string();
        let stats = stats.clone();
        let conn = connector.clone();

        tokio::spawn(async move {
            stats.dns_queries.fetch_add(1, Ordering::Relaxed);
            let resp = match dns_forward(&query, &url, &secret, conn).await {
                Ok(d) => d,
                Err(e) => {
                    stats.dns_errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!("[DNS] {peer}: {e:#}");
                    // SERVFAIL
                    let mut f = query.clone();
                    if f.len() >= 4 {
                        f[2] = 0x81;
                        f[3] = 0x82;
                    }
                    f
                }
            };
            let _ = sock2.send_to(&resp, peer).await;
        });
    }
}

/// Forward a single DNS query through the WS tunnel, return the response.
/// Opens a new WS connection per query — acceptable for DNS (low frequency,
/// latency-tolerant). A persistent DNS WS session would require coordinating
/// concurrent in-flight queries by transaction ID, adding complexity.
async fn dns_forward(
    query: &[u8],
    url: &str,
    secret: &str,
    connector: Arc<tokio_tungstenite::Connector>,
) -> Result<Vec<u8>> {
    let nonce = rand_nonce();
    let token = hmac_token(secret, &nonce);
    let wskey = rand_wskey();
    let host = ws_host(url);

    let req = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(url)
        .header("Host", &host)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Key", &wskey)
        .header("Sec-WebSocket-Version", "13")
        .header("x-auth", &token)
        .header("x-nonce", &nonce)
        .header("x-target", "__DNS__")
        .body(())
        .context("build DNS WS request")?;

    let (ws, _) = timeout(
        T_HS,
        connect_async_tls_with_config(req, None, false, Some((*connector).clone())),
    )
    .await
    .context("DNS WS connect timeout")??;

    let (mut tx, mut rx) = ws.split();
    tx.send(Message::Binary(query.to_vec().into())).await?;

    match timeout(T_DNS, rx.next())
        .await
        .context("DNS response timeout")?
    {
        Some(Ok(Message::Binary(d))) => Ok(d.to_vec()),
        other => anyhow::bail!("unexpected DNS WS message: {:?}", other),
    }
}

fn ws_host(url: &str) -> String {
    url.trim_start_matches("wss://")
        .trim_start_matches("ws://")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

// ── SOCKS5/HTTP-CONNECT connection handler ────────────────────────────────────

async fn client_conn(
    local: &mut TcpStream,
    url: &str,
    secret: &str,
    host_hdr: Option<&str>,
    connector: Arc<tokio_tungstenite::Connector>,
    stats: Arc<Stats>,
) -> Result<()> {
    let target = timeout(T_SOCKS, proxy_handshake(local))
        .await
        .context("proxy handshake timeout")??;

    if target == "__UDP__" {
        // UDP ASSOCIATE: we've already responded to the SOCKS client.
        // The app will now send UDP directly (no actual relay needed here).
        return Ok(());
    }
    eprintln!("[TUNNEL] → {target}");

    let nonce = rand_nonce();
    let token = hmac_token(secret, &nonce);
    let wskey = rand_wskey();
    let host = ws_host(url);

    let req = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(url)
        .header("Host", if let Some(h) = host_hdr { h } else { &host })
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Key", &wskey)
        .header("Sec-WebSocket-Version", "13")
        .header("User-Agent", "Mozilla/5.0")
        .header("x-auth", &token)
        .header("x-nonce", &nonce)
        .header("x-target", &target)
        .body(())
        .context("build tunnel WS request")?;

    let (ws, _) = timeout(
        T_HS,
        connect_async_tls_with_config(req, None, false, Some((*connector).clone())),
    )
    .await
    .context("WS connect timeout")??;

    // relay_ws_tcp takes ownership; split local TCP manually
    relay_ws_tcp_ref(ws, local, stats).await
}

/// Same as relay_ws_tcp but works with a &mut TcpStream (borrowed from caller)
async fn relay_ws_tcp_ref<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    tcp: &mut TcpStream,
    stats: Arc<Stats>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut wt, mut wr) = ws.split();
    let (mut tr, mut tw) = tcp.split();

    let st = stats.clone();
    let up = async move {
        let mut buf = vec![0u8; BUF];
        let mut tot = 0u64;
        let mut ping_tick = tokio::time::interval(PING_INTERVAL);
        ping_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                res = timeout(T_IO, tr.read(&mut buf)) => {
                    match res {
                        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                        Ok(Ok(n)) => {
                            if wt.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                                break;
                            }
                            tot += n as u64;
                        }
                    }
                }
                _ = ping_tick.tick() => {
                    if wt.send(Message::Ping(vec![].into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = wt.close().await;
        st.bytes_tx.fetch_add(tot, Ordering::Relaxed);
        tot
    };

    let dn = async move {
        let mut tot = 0u64;
        loop {
            match timeout(T_IO, wr.next()).await {
                Ok(Some(Ok(Message::Binary(d)))) => {
                    if tw.write_all(&d).await.is_err() {
                        break;
                    }
                    tot += d.len() as u64;
                }
                Ok(Some(Ok(Message::Ping(_)))) => {}
                Ok(Some(Ok(Message::Pong(_)))) => {}
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Err(_) => break,
                Ok(Some(Err(_))) => break,
                _ => {}
            }
        }
        let _ = tw.flush().await;
        stats.bytes_rx.fetch_add(tot, Ordering::Relaxed);
        tot
    };

    let (tx, rx) = tokio::join!(up, dn);
    if tx > 0 || rx > 0 {
        eprintln!("[CONN] tx={}k rx={}k", tx / 1024, rx / 1024);
    }
    Ok(())
}

// ═════════════════════════════════════════════════════════════════════════════
//  DNS upstream (server side) — forward raw UDP to upstream resolver
// ═════════════════════════════════════════════════════════════════════════════

async fn dns_upstream(query: &[u8], upstream: &str) -> Result<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(upstream).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; DNS_BUF];
    let n = timeout(T_DNS, sock.recv(&mut buf))
        .await
        .context("DNS upstream timeout")??;
    buf.truncate(n);
    Ok(buf)
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
    let prog = &args[0];

    let help = || {
        eprintln!(
            r#"
tunnel v4 — TCP + DNS WebSocket proxy

SERVER (VPS):
  {prog} server <bind> <socks5-upstream> <cert.pem> <key.pem> <secret> \
         [--path /ws] [--plain] [--dns 1.1.1.1:53]

  Examples:
    {prog} server 0.0.0.0:443 127.0.0.1:1080 cert.pem key.pem MySecret
    {prog} server 0.0.0.0:443 127.0.0.1:1080 cert.pem key.pem MySecret --dns 8.8.8.8:53

CLIENT (Windows / local):
  {prog} client <socks5-bind> <dns-bind> <wss://host/ws> <secret> \
         [--insecure] [--host <cdn-host>]

  Examples:
    {prog} client 127.0.0.1:9050 0.0.0.0:53 wss://yourserver.com/ws MySecret
    {prog} client 127.0.0.1:9050 0.0.0.0:53 wss://cdn.example.com/ws MySecret --host yourserver.com

Windows setup (run tunnel.exe as Administrator):
  1. SOCKS5 proxy:  Settings → Network → Proxy → Manual → SOCKS5 127.0.0.1:9050
  2. DNS:           ncpa.cpl → adapter → IPv4 → DNS server = 127.0.0.1
                    Leave IPv6 DNS BLANK (or disable IPv6).

Notes:
  --plain       Server: accept plain WS (no TLS), useful behind reverse proxy
  --insecure    Client: skip TLS certificate verification (e.g. self-signed cert)
  --host        Client: send different Host header (for CDN/SNI fronting)
  --dns         Server: upstream DNS resolver (default: 1.1.1.1:53)
  --path        Server: WebSocket path (default: /ws)
"#
        );
    };

    match args.get(1).map(|s| s.as_str()) {
        Some("server") => {
            if args.len() < 7 {
                help();
                std::process::exit(1);
            }
            let path = args
                .windows(2)
                .find(|w| w[0] == "--path")
                .map(|w| w[1].as_str())
                .unwrap_or("/ws");
            let plain = args.iter().any(|a| a == "--plain");
            let dns = args
                .windows(2)
                .find(|w| w[0] == "--dns")
                .map(|w| w[1].as_str())
                .unwrap_or(DEFAULT_UPSTREAM_DNS);
            run_server(
                &args[2], &args[3], &args[4], &args[5], &args[6], path, plain, dns,
            )
            .await?;
        }
        Some("client") => {
            if args.len() < 6 {
                help();
                std::process::exit(1);
            }
            let skip = args.iter().any(|a| a == "--insecure");
            let host = args
                .windows(2)
                .find(|w| w[0] == "--host")
                .map(|w| w[1].as_str());
            run_client(&args[2], &args[3], &args[4], &args[5], skip, host).await?;
        }
        _ => {
            help();
            std::process::exit(1);
        }
    }
    Ok(())
}
