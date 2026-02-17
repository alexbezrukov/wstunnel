use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{timeout, Duration};
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{accept_hdr_async, connect_async_tls_with_config};

// ── Tuning ─────────────────────────────────────────────────────────────────
const BUFFER_SIZE: usize = 128 * 1024;
const MAX_CONCURRENT: usize = 10_000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const READ_TIMEOUT: Duration = Duration::from_secs(600);
// const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

// ── Auth ────────────────────────────────────────────────────────────────────
const AUTH_MAGIC: &[u8] = b"TLS_TUNNEL_V3_WS";

// ── Stats ───────────────────────────────────────────────────────────────────
#[derive(Default)]
struct Stats {
    active: AtomicU64,
    total: AtomicU64,
    bytes_rx: AtomicU64,
    bytes_tx: AtomicU64,
    auth_failed: AtomicU64,
}

impl Stats {
    fn report(&self) {
        println!(
            "[STATS] Active:{} Total:{} Failed:{} RX:{}MB TX:{}MB",
            self.active.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
            self.auth_failed.load(Ordering::Relaxed),
            self.bytes_rx.load(Ordering::Relaxed) / 1_000_000,
            self.bytes_tx.load(Ordering::Relaxed) / 1_000_000,
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  SERVER
// ═══════════════════════════════════════════════════════════════════════════

pub async fn run_server(
    bind_addr: &str,
    socks_addr: &str,
    cert_path: &str,
    key_path: &str,
    secret_key: &str,
    ws_path: &str,
) -> Result<()> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Bad cert/key")?;

    // Advertise h2 + http/1.1 — looks like a normal HTTPS server
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tls_cfg.max_fragment_size = Some(16384);

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));
    let listener = TcpListener::bind(bind_addr).await?;
    set_sock_buf(&listener);

    println!("[SERVER] Listening on {}", bind_addr);
    println!("[SERVER] WebSocket path: {}", ws_path);
    println!("[SERVER] Forwarding to SOCKS: {}", socks_addr);

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret_key.to_string());
    let ws_path = Arc::new(ws_path.to_string());

    // Stats reporter
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
        set_tcp_buf(&tcp);

        let acceptor = acceptor.clone();
        let socks = socks_addr.to_string();
        let sem = sem.clone();
        let stats = stats.clone();
        let secret = secret.clone();
        let ws_path = ws_path.clone();

        tokio::spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };
            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);

            if let Err(e) = handle_server_conn(
                tcp,
                acceptor,
                &socks,
                &secret,
                &ws_path,
                stats.clone(),
                peer,
            )
            .await
            {
                let s = e.to_string();
                if !s.contains("Auth") && !s.contains("auth") {
                    eprintln!("[SERVER] {} — {}", peer, e);
                }
            }
            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn handle_server_conn(
    tcp: TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    socks_addr: &str,
    secret_key: &str,
    ws_path: &str,
    stats: Arc<Stats>,
    peer: std::net::SocketAddr,
) -> Result<()> {
    // ── TLS handshake ───────────────────────────────────────────────────────
    let tls = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
        .await
        .context("TLS timeout")??;

    // ── WebSocket upgrade with auth check in headers ────────────────────────
    let expected_path = ws_path.to_string();
    let secret = secret_key.to_string();
    let auth_ok = Arc::new(Mutex::new(false));
    let auth_ok_cb = auth_ok.clone();

    let ws = timeout(
        HANDSHAKE_TIMEOUT,
        accept_hdr_async(tls, move |req: &Request, mut resp: Response| {
            // 1. Path check
            if req.uri().path() != expected_path {
                *resp.status_mut() = StatusCode::NOT_FOUND;
                return Err(resp.map(|_| None));
            }

            // 2. Auth token in header: X-Auth: HMAC-SHA256(secret, nonce)
            //    Nonce is sent as X-Nonce header by client
            if let (Some(auth_hdr), Some(nonce_hdr)) =
                (req.headers().get("x-auth"), req.headers().get("x-nonce"))
            {
                let nonce = nonce_hdr.to_str().unwrap_or("");
                let expected_token = compute_token(&secret, nonce);
                if auth_hdr.to_str().unwrap_or("") == expected_token {
                    *auth_ok_cb.blocking_lock() = true;
                    // Add server headers to look like a normal WS upgrade
                    resp.headers_mut()
                        .insert("server", HeaderValue::from_static("cloudflare"));
                    return Ok(resp);
                }
            }

            *resp.status_mut() = StatusCode::UNAUTHORIZED;
            Err(resp.map(|_| None))
        }),
    )
    .await
    .context("WS handshake timeout")??;

    if !*auth_ok.lock().await {
        stats.auth_failed.fetch_add(1, Ordering::Relaxed);
        return Err(anyhow::anyhow!("Auth failed from {}", peer));
    }

    // ── Connect to local SOCKS ──────────────────────────────────────────────
    let socks = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(socks_addr))
        .await
        .context("SOCKS timeout")??;
    let _ = socks.set_nodelay(true);
    set_tcp_buf(&socks);

    proxy_ws_tcp(ws, socks, stats).await
}

// ═══════════════════════════════════════════════════════════════════════════
//  CLIENT
// ═══════════════════════════════════════════════════════════════════════════

pub async fn run_client(
    bind_addr: &str,
    server_url: &str, // wss://host:port/path  OR  wss://cdn-host/path?target=origin
    secret_key: &str,
    skip_verify: bool,
    host_header: Option<&str>, // CDN fronting: SNI = cdn, Host = cdn, but connect to origin IP
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    set_sock_buf(&listener);

    println!("[CLIENT] Local SOCKS on {}", bind_addr);
    println!("[CLIENT] Tunnel URL: {}", server_url);
    if let Some(h) = host_header {
        println!("[CLIENT] CDN fronting host: {}", h);
    }

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret_key.to_string());
    let url = Arc::new(server_url.to_string());
    let host_hdr = host_header.map(|h| h.to_string());
    let host_hdr = Arc::new(host_hdr);

    let tls_cfg = build_client_tls(skip_verify)?;
    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls_cfg));
    let connector = Arc::new(connector);

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
        set_tcp_buf(&tcp);

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
                tcp,
                &url,
                &secret,
                host_hdr.as_deref(),
                connector,
                stats.clone(),
            )
            .await
            {
                eprintln!("[CLIENT] {} — {}", peer, e);
            }
            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn handle_client_conn(
    local: TcpStream,
    server_url: &str,
    secret_key: &str,
    host_override: Option<&str>,
    connector: Arc<tokio_tungstenite::Connector>,
    stats: Arc<Stats>,
) -> Result<()> {
    // Build nonce + auth token
    let nonce = {
        let mut b = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut b);
        B64.encode(b)
    };
    let token = compute_token(secret_key, &nonce);

    // Build request with browser-like headers
    let mut req = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(server_url)
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("x-auth", &token)
        .header("x-nonce", &nonce);

    // CDN fronting: override Host header
    if let Some(host) = host_override {
        req = req.header("Host", host);
    }

    let req = req.body(()).context("Bad request")?;

    let (ws, _resp) = timeout(
        HANDSHAKE_TIMEOUT,
        connect_async_tls_with_config(req, None, false, Some((*connector).clone())),
    )
    .await
    .context("WS connect timeout")??;

    proxy_ws_tcp(ws, local, stats).await
}

// ═══════════════════════════════════════════════════════════════════════════
//  BIDIRECTIONAL PROXY: WebSocket ↔ raw TCP
// ═══════════════════════════════════════════════════════════════════════════

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

    let stats_a = stats.clone();
    // TCP → WebSocket (upload direction)
    let tcp_to_ws = async move {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;
        loop {
            match timeout(READ_TIMEOUT, tcp_rx.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => {
                    let msg = Message::Binary(buf[..n].to_vec().into());
                    if ws_tx.send(msg).await.is_err() {
                        break;
                    }
                    total += n as u64;
                }
            }
        }
        let _ = ws_tx.close().await;
        stats_a.bytes_tx.fetch_add(total, Ordering::Relaxed);
        total
    };

    let stats_b = stats;
    // WebSocket → TCP (download direction — this is what gets throttled)
    let ws_to_tcp = async move {
        let mut total = 0u64;
        while let Ok(Some(msg)) = timeout(READ_TIMEOUT, ws_rx.next()).await {
            match msg {
                Ok(Message::Binary(data)) => {
                    if tcp_tx.write_all(&data).await.is_err() {
                        break;
                    }
                    total += data.len() as u64;
                }
                Ok(Message::Ping(d)) => {
                    /* pong handled by tungstenite */
                    let _ = d;
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
        let _ = tcp_tx.flush().await;
        stats_b.bytes_rx.fetch_add(total, Ordering::Relaxed);
        total
    };

    let (tx, rx) = tokio::join!(tcp_to_ws, ws_to_tcp);
    if tx > 0 || rx > 0 {
        println!("[CONN] Closed TX:{}KB RX:{}KB", tx / 1024, rx / 1024);
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
//  CLOUDFLARE WORKER  (JS — printed to stdout, copy-paste to CF dashboard)
// ═══════════════════════════════════════════════════════════════════════════

fn print_cf_worker(origin: &str, ws_path: &str) {
    println!(
        r#"
// ── Cloudflare Worker (paste into CF Dashboard → Workers) ──────────────────
// Routes: *.your-zone.com/*  →  this worker
// Environment variable: ORIGIN_HOST = "{origin}"  (ip:port of your server)
// ───────────────────────────────────────────────────────────────────────────

export default {{
  async fetch(request, env) {{
    const url = new URL(request.url);

    // Only proxy our tunnel path
    if (url.pathname !== "{ws_path}") {{
      return new Response("Not Found", {{ status: 404 }});
    }}

    // Forward WebSocket upgrade to origin
    const originUrl = "wss://" + env.ORIGIN_HOST + "{ws_path}";
    const headers = new Headers(request.headers);
    headers.set("Host", env.ORIGIN_HOST.split(":")[0]);

    // CF handles the TLS to origin automatically
    return fetch(originUrl, {{
      method: request.method,
      headers,
      body: request.body,
    }});
  }},
}};
// ─────────────────────────────────────────────────────────────────────────
"#
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════════════

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

fn set_sock_buf<T: std::os::fd::AsFd>(s: &T) {
    let sock = socket2::SockRef::from(s);
    let _ = sock.set_recv_buffer_size(1 << 20); // 1 MB
    let _ = sock.set_send_buffer_size(1 << 20);
}

fn set_tcp_buf(s: &TcpStream) {
    let sock = socket2::SockRef::from(s);
    let _ = sock.set_recv_buffer_size(512 * 1024);
    let _ = sock.set_send_buffer_size(512 * 1024);
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let f = std::fs::File::open(path)?;
    let mut r = std::io::BufReader::new(f);
    Ok(rustls_pemfile::certs(&mut r).collect::<Result<Vec<_>, _>>()?)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let f = std::fs::File::open(path)?;
    let mut r = std::io::BufReader::new(f);
    Ok(rustls_pemfile::private_key(&mut r)?.context("No private key")?)
}

// ── NoCertVerifier (for --insecure) ────────────────────────────────────────
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

// ═══════════════════════════════════════════════════════════════════════════
//  MAIN
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let help = || {
        eprintln!(
            r#"TLS WebSocket Tunnel v3 (CDN-fronting ready)

USAGE:
  server  <bind> <socks> <cert> <key> <secret> [ws-path]
  client  <bind> <wss-url> <secret> [--insecure] [--host <cdn-host>]
  worker  <origin-host:port> [ws-path]

EXAMPLES:
  # Server (your VPS):
  {0} server 0.0.0.0:443 127.0.0.1:1080 cert.pem key.pem MySecret /api/v1/stream

  # Client — direct:
  {0} client 127.0.0.1:1080 wss://server.com:443/api/v1/stream MySecret

  # Client — through Cloudflare (CDN fronting):
  {0} client 127.0.0.1:1080 wss://your-cf-worker.your-zone.com/api/v1/stream MySecret

  # Print Cloudflare Worker JS to copy-paste:
  {0} worker server.com:443 /api/v1/stream
"#,
            args[0]
        );
    };

    match args.get(1).map(|s| s.as_str()) {
        Some("server") => {
            if args.len() < 7 {
                help();
                std::process::exit(1);
            }
            let ws_path = args.get(7).map(|s| s.as_str()).unwrap_or("/ws");
            run_server(&args[2], &args[3], &args[4], &args[5], &args[6], ws_path).await?;
        }
        Some("client") => {
            if args.len() < 5 {
                help();
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
            let origin = args.get(2).map(|s| s.as_str()).unwrap_or("YOUR_SERVER:443");
            let ws_path = args.get(3).map(|s| s.as_str()).unwrap_or("/ws");
            print_cf_worker(origin, ws_path);
        }
        _ => {
            help();
            std::process::exit(1);
        }
    }
    Ok(())
}
