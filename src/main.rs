/// tunnel — unified WS/TLS proxy + DNS forwarder
///
/// SERVER: tunnel server <bind> <socks5-upstream> <cert.pem> <key.pem> <secret> [--path /ws] [--plain]
/// CLIENT: tunnel client <socks5-bind> <dns-bind> <wss://host/ws> <secret> [--insecure] [--host <cdn>]
///
/// Windows DNS fix: set IPv4 DNS → 127.0.0.1, leave IPv6 DNS blank.
/// Or bind dns to 0.0.0.0:53 so both 127.0.0.1 and ::1 queries hit it.
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures_util::future::Either;
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
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    time::timeout,
};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::{
    accept_hdr_async, connect_async_tls_with_config,
    tungstenite::{
        handshake::server::{Request, Response},
        http::{self, HeaderValue, StatusCode},
        protocol::Message,
    },
};

// ── Constants ────────────────────────────────────────────────────────────────
const AUTH_MAGIC: &[u8] = b"TLS_TUNNEL_V3_WS";
const BUF: usize = 128 * 1024;
const MAX_CONN: usize = 10_000;
const T_HS: Duration = Duration::from_secs(20);
const T_IO: Duration = Duration::from_secs(600);
const T_SOCKS: Duration = Duration::from_secs(15);
const T_DNS: Duration = Duration::from_secs(5);
const DNS_BUF: usize = 4096;
const UPSTREAM_DNS: &str = "1.1.1.1:53";

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
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
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
    // already consumed version byte — read nmethods
    let mut nm = [0u8; 1];
    s.read_exact(&mut nm).await?;
    let mut methods = vec![0u8; nm[0] as usize];
    s.read_exact(&mut methods).await?;
    s.write_all(&[S5, 0x00]).await?; // no-auth

    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[1] == 0x03 {
        // UDP ASSOCIATE
        s.write_all(&[S5, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .ok();
        return Ok("__UDP__".into());
    }
    anyhow::ensure!(req[1] == 0x01, "SOCKS5: only CONNECT");

    let host = parse_addr_host(s, req[3]).await?;
    let mut pb = [0u8; 2];
    s.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);
    s.write_all(&[S5, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?; // success
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
        t => anyhow::bail!("unknown atyp {t}"),
    })
}

/// Connect to local SOCKS5 (for client→server relay), send CONNECT
async fn socks5_connect_upstream(s: &mut TcpStream, target: &str) -> Result<()> {
    let (host, port_s) = target.rsplit_once(':').context("bad target")?;
    let port: u16 = port_s.parse()?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    let hb = host.as_bytes();

    s.write_all(&[S5, 0x01, 0x00]).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    anyhow::ensure!(r[1] == 0x00, "upstream SOCKS5 needs auth");

    let mut req = Vec::with_capacity(7 + hb.len());
    req.extend_from_slice(&[S5, 0x01, 0x00, 0x03]);
    req.push(hb.len() as u8);
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    let mut rep = [0u8; 4];
    s.read_exact(&mut rep).await?;
    anyhow::ensure!(rep[1] == 0x00, "upstream SOCKS5 CONNECT failed: {}", rep[1]);
    // consume BND
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

/// HTTP CONNECT (first byte already read)
async fn http_connect_target(s: &mut TcpStream, first: u8) -> Result<String> {
    let mut buf = vec![first];
    let mut tmp = [0u8; 1];
    loop {
        s.read_exact(&mut tmp).await?;
        buf.push(tmp[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        anyhow::ensure!(buf.len() <= 8192, "HTTP CONNECT: oversized");
    }
    let head = std::str::from_utf8(&buf)?;
    let first_line = head.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let authority = parts.next().unwrap_or("");
    anyhow::ensure!(method.eq_ignore_ascii_case("CONNECT"), "not CONNECT");
    anyhow::ensure!(authority.contains(':'), "no port");
    s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    Ok(authority.to_string())
}

/// Detect SOCKS5 vs HTTP-CONNECT
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
//  BIDIRECTIONAL WS ↔ TCP
// ═════════════════════════════════════════════════════════════════════════════

async fn relay<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    tcp: TcpStream,
    stats: Arc<Stats>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut wt, mut wr) = ws.split();
    let (mut tr, mut tw) = tokio::io::split(tcp);

    let st = stats.clone();
    let up = async move {
        let mut buf = vec![0u8; BUF];
        let mut n_total = 0u64;
        loop {
            match timeout(T_IO, tr.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    if wt
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    n_total += n as u64;
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
                Ok(Some(Ok(Message::Ping(_)))) => {}
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
) -> Result<()> {
    let acceptor = if plain {
        println!("[SERVER] plain WS (no TLS)");
        None
    } else {
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(load_certs(cert)?, load_key(key)?)
            .context("bad cert/key")?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        cfg.max_fragment_size = Some(16384);
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
    };

    let listener = TcpListener::bind(bind).await?;
    tune(&listener);
    println!("[SERVER] listen={bind} socks={socks} path={ws_path}");

    let sem = Arc::new(Semaphore::new(MAX_CONN));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret.to_string());
    let path = Arc::new(ws_path.to_string());
    let socks = Arc::new(socks.to_string());
    stats.spawn_reporter();

    loop {
        let (tcp, peer) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        tune(&tcp);

        let (acceptor, socks, sem, stats, secret, path) = (
            acceptor.clone(),
            socks.clone(),
            sem.clone(),
            stats.clone(),
            secret.clone(),
            path.clone(),
        );

        tokio::spawn(async move {
            let _p = sem.acquire().await.unwrap();
            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);

            if let Err(e) =
                server_conn(tcp, acceptor, &socks, &secret, &path, stats.clone(), peer).await
            {
                let m = e.to_string();
                if !m.contains("401") && !m.contains("Auth") {
                    eprintln!("[SERVER] {peer}: {e}");
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
    stats: Arc<Stats>,
    peer: SocketAddr,
) -> Result<()> {
    let (ws_either, target) = if let Some(acc) = acc {
        let tls = timeout(T_HS, acc.accept(tcp))
            .await
            .context("TLS timeout")??;

        let expected = path.to_string();
        let sec = secret.to_string();
        let auth = Arc::new(std::sync::Mutex::new(false));
        let target = Arc::new(std::sync::Mutex::new(None::<String>));
        let (a2, t2) = (auth.clone(), target.clone());

        let ws = timeout(
            T_HS,
            accept_hdr_async(tls, move |req: &Request, mut resp: Response| {
                if req.uri().path() != expected {
                    return Err(resp404());
                }
                match (req.headers().get("x-auth"), req.headers().get("x-nonce")) {
                    (Some(a), Some(n))
                        if a.to_str().unwrap_or("")
                            == hmac_token(&sec, n.to_str().unwrap_or("")) =>
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
        .context("WS timeout")??;

        if !*auth.lock().unwrap() {
            stats
                .auth_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            anyhow::bail!("Auth failed from {}", peer);
        }
        let tgt = target.lock().unwrap().clone().context("missing x-target")?;
        (Either::Left(ws), tgt)
    } else {
        let expected = path.to_string();
        let sec = secret.to_string();
        let auth = Arc::new(std::sync::Mutex::new(false));
        let target = Arc::new(std::sync::Mutex::new(None::<String>));
        let (a2, t2) = (auth.clone(), target.clone());

        let ws = timeout(
            T_HS,
            accept_hdr_async(tcp, move |req: &Request, mut resp: Response| {
                if req.uri().path() != expected {
                    return Err(resp404());
                }
                match (req.headers().get("x-auth"), req.headers().get("x-nonce")) {
                    (Some(a), Some(n))
                        if a.to_str().unwrap_or("")
                            == hmac_token(&sec, n.to_str().unwrap_or("")) =>
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
        .context("WS timeout")??;

        if !*auth.lock().unwrap() {
            stats
                .auth_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            anyhow::bail!("Auth failed from {}", peer);
        }
        let tgt = target.lock().unwrap().clone().context("missing x-target")?;
        (Either::Right(ws), tgt)
    };

    if target == "__DNS__" {
        match ws_either {
            Either::Left(ws) => handle_dns_ws(ws, stats).await?,
            Either::Right(ws) => handle_dns_ws(ws, stats).await?,
        }
        return Ok(());
    }

    let mut upstream = timeout(T_HS, TcpStream::connect(socks))
        .await
        .context("socks connect timeout")??;
    let _ = upstream.set_nodelay(true);
    tune(&upstream);

    timeout(T_SOCKS, socks5_connect_upstream(&mut upstream, &target))
        .await
        .context("socks timeout")?
        .context(format!("socks connect to {}", target))?;

    match ws_either {
        Either::Left(ws) => relay(ws, upstream, stats).await?,
        Either::Right(ws) => relay(ws, upstream, stats).await?,
    }

    Ok(())
}

async fn handle_dns_ws<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
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
                let resp = match dns_upstream(&data).await {
                    Ok(r) => r,
                    Err(e) => {
                        stats.dns_errors.fetch_add(1, Ordering::Relaxed);
                        eprintln!("[DNS] upstream: {e}");
                        let mut f = data.to_vec();
                        if f.len() >= 4 {
                            f[2] = 0x81;
                            f[3] = 0x82;
                        }
                        f
                    }
                };
                if wt.send(Message::Binary(resp.into())).await.is_err() {
                    break;
                }
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
    dns_bind: &str, // e.g. "0.0.0.0:53"  — bind both IPv4+IPv6 if 0.0.0.0
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

    // ── DNS UDP listener ──────────────────────────────────────────────────────
    // Bind 0.0.0.0:53 to catch both 127.0.0.1 and ::1 queries from Windows.
    // Windows sends to ::1 when IPv6 DNS is set, 127.0.0.1 for IPv4 DNS.
    // With 0.0.0.0 we catch IPv4; for ::1 use [::]:53 separately or set
    // only IPv4 DNS = 127.0.0.1 in ncpa.cpl (recommended, simplest fix).
    {
        let sock_v4 = Arc::new(UdpSocket::bind(dns_bind).await.context(format!(
            "DNS bind {dns_bind} — run as admin/root or use port >1024"
        ))?);

        // Also try to bind IPv6 for ::1 support
        let ipv6_bind = dns_bind
            .replace("0.0.0.0", "[::]")
            .replace("127.0.0.1", "[::]");
        let sock_v6 = UdpSocket::bind(&ipv6_bind).await.ok().map(Arc::new);

        println!("[DNS] listening on {dns_bind}");
        if sock_v6.is_some() {
            println!("[DNS] listening on {ipv6_bind}");
        } else {
            println!("[DNS] IPv6 bind {ipv6_bind} failed — set IPv4-only DNS in Windows");
        }

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
    println!("[CLIENT] SOCKS5 on {socks_bind}  server={url}");
    if skip_verify {
        println!("[WARN] TLS verify disabled");
    }
    println!(
        "[CLIENT] Windows proxy: Settings → Proxy → Manual → SOCKS 127.0.0.1:{}",
        socks_bind.split(':').last().unwrap_or("9050")
    );
    println!(
        "[CLIENT] Windows DNS:   ncpa.cpl → IPv4 → DNS = {}",
        dns_bind.split(':').next().unwrap_or("127.0.0.1")
    );

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
    if s.matches('/').count() < 3 {
        format!("{s}/ws")
    } else {
        s
    }
}

// ── DNS over WebSocket ────────────────────────────────────────────────────────

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
                    eprintln!("[DNS] {peer}: {e}");
                    // return SERVFAIL
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

/// Send DNS query over WebSocket tunnel, get response
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
        .header("x-target", "__DNS__") // server recognises this special target
        .body(())
        .context("build dns ws req")?;

    let (ws, _) = timeout(
        T_HS,
        connect_async_tls_with_config(req, None, false, Some((*connector).clone())),
    )
    .await
    .context("dns ws timeout")??;

    let (mut tx, mut rx) = ws.split();
    tx.send(Message::Binary(query.to_vec().into())).await?;

    match timeout(T_DNS, rx.next())
        .await
        .context("dns resp timeout")?
    {
        Some(Ok(Message::Binary(d))) => Ok(d.to_vec()),
        other => anyhow::bail!("unexpected dns ws msg: {:?}", other),
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

// ── SOCKS5 connection handler ─────────────────────────────────────────────────

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
        .context("handshake timeout")??;

    if target == "__UDP__" {
        return Ok(());
    }
    eprintln!("[TUNNEL] → {target}");

    let nonce = rand_nonce();
    let token = hmac_token(secret, &nonce);
    let wskey = rand_wskey();
    let host = ws_host(url);

    let mut b = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(url)
        .header("Host", if let Some(h) = host_hdr { h } else { &host })
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Key", &wskey)
        .header("Sec-WebSocket-Version", "13")
        .header("User-Agent", "Mozilla/5.0")
        .header("x-auth", &token)
        .header("x-nonce", &nonce)
        .header("x-target", &target);

    let req = b.body(()).context("build ws req")?;

    let (ws, _) = timeout(
        T_HS,
        connect_async_tls_with_config(req, None, false, Some((*connector).clone())),
    )
    .await
    .context("WS connect timeout")??;

    relay_ref(ws, local, stats).await
}

async fn relay_ref<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    tcp: &mut TcpStream,
    stats: Arc<Stats>,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut wt, mut wr) = ws.split();
    let (mut tr, mut tw) = tcp.split();

    let st = stats.clone();
    let up = async move {
        let mut buf = vec![0u8; BUF];
        let mut tot = 0u64;
        loop {
            match timeout(T_IO, tr.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    if wt
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    tot += n as u64;
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
//  SERVER DNS handler  (x-target == "__DNS__")
// ═════════════════════════════════════════════════════════════════════════════

async fn dns_upstream(query: &[u8]) -> Result<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(UPSTREAM_DNS).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; DNS_BUF];
    let n = timeout(T_DNS, sock.recv(&mut buf))
        .await
        .context("dns upstream timeout")??;
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
tunnel v3 — unified TCP+DNS WebSocket proxy

SERVER (VPS):
  {prog} server <bind> <socks5-upstream> <cert.pem> <key.pem> <secret> [--path /ws] [--plain]
  Example:
    {prog} server 0.0.0.0:443 127.0.0.1:1080 cert.pem key.pem MySecret

CLIENT (Windows/local):
  {prog} client <socks5-bind> <dns-bind> <wss://host/ws> <secret> [--insecure] [--host <cdn-host>]
  Example:
    {prog} client 127.0.0.1:9050 0.0.0.0:53 wss://yourserver.com/ws MySecret

  Windows setup:
    1. Set system proxy:  Settings → Network → Proxy → Manual → SOCKS5 127.0.0.1:9050
    2. Set IPv4 DNS:      ncpa.cpl → adapter → IPv4 → DNS server = 127.0.0.1
       Leave IPv6 DNS blank (or remove IPv6 entirely).
    3. Run as Administrator (port 53 requires it).
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
            run_server(
                &args[2], &args[3], &args[4], &args[5], &args[6], path, plain,
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
