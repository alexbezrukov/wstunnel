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
use tokio_tungstenite::tungstenite::http::{self, HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{accept_hdr_async, connect_async_tls_with_config};

// ── Tuning ──────────────────────────────────────────────────────────────────
const BUFFER_SIZE: usize = 128 * 1024;
const MAX_CONCURRENT: usize = 10_000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const READ_TIMEOUT: Duration = Duration::from_secs(600);

// ── Auth ─────────────────────────────────────────────────────────────────────
const AUTH_MAGIC: &[u8] = b"TLS_TUNNEL_V3_WS";

// ── Stats ────────────────────────────────────────────────────────────────────
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

// ── Cross-platform socket buffer tuning ──────────────────────────────────────
// Uses cfg-guarded raw socket access — no unix-only traits in signature

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
//  SERVER
// ═════════════════════════════════════════════════════════════════════════════

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

    // Advertise h2 + http/1.1 — DPI sees normal HTTPS fingerprint
    tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tls_cfg.max_fragment_size = Some(16384);

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg));
    let listener = TcpListener::bind(bind_addr).await?;
    tune_listener(&listener);

    println!("[SERVER] Listening on {}", bind_addr);
    println!("[SERVER] WebSocket path: {}", ws_path);
    println!("[SERVER] Forwarding to SOCKS: {}", socks_addr);

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret_key.to_string());
    let ws_path = Arc::new(ws_path.to_string());

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
                let msg = e.to_string();
                if !msg.contains("Auth") && !msg.contains("auth") && !msg.contains("401") {
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
    let tls = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
        .await
        .context("TLS timeout")??;

    let expected_path = ws_path.to_string();
    let secret = secret_key.to_string();
    let auth_ok = Arc::new(Mutex::new(false));
    let auth_cb = auth_ok.clone();

    let ws = timeout(
        HANDSHAKE_TIMEOUT,
        accept_hdr_async(tls, move |req: &Request, mut resp: Response| {
            if req.uri().path() != expected_path {
                let mut err = http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(None)
                    .unwrap();
                *err.headers_mut() = resp.headers().clone();
                return Err(err);
            }
            if let (Some(auth_hdr), Some(nonce_hdr)) =
                (req.headers().get("x-auth"), req.headers().get("x-nonce"))
            {
                let nonce = nonce_hdr.to_str().unwrap_or("");
                if auth_hdr.to_str().unwrap_or("") == compute_token(&secret, nonce) {
                    *auth_cb.blocking_lock() = true;
                    resp.headers_mut()
                        .insert("server", HeaderValue::from_static("cloudflare"));
                    return Ok(resp);
                }
            }
            let err = http::Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(None)
                .unwrap();
            Err(err)
        }),
    )
    .await
    .context("WS upgrade timeout")??;

    if !*auth_ok.lock().await {
        stats.auth_failed.fetch_add(1, Ordering::Relaxed);
        return Err(anyhow::anyhow!("Auth failed from {}", peer));
    }

    let socks = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(socks_addr))
        .await
        .context("SOCKS connect timeout")??;
    let _ = socks.set_nodelay(true);
    tune_tcp(&socks);

    proxy_ws_tcp(ws, socks, stats).await
}

// ═════════════════════════════════════════════════════════════════════════════
//  CLIENT
// ═════════════════════════════════════════════════════════════════════════════

pub async fn run_client(
    bind_addr: &str,
    server_url: &str,
    secret_key: &str,
    skip_verify: bool,
    host_header: Option<&str>,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    tune_listener(&listener);

    println!("[CLIENT] Local SOCKS on {}", bind_addr);
    println!("[CLIENT] Tunnel URL: {}", server_url);
    if let Some(h) = host_header {
        println!("[CLIENT] CDN fronting host: {}", h);
    }
    if skip_verify {
        println!("[WARNING] Certificate verification DISABLED");
    }

    let tls_cfg = build_client_tls(skip_verify)?;
    let connector = Arc::new(tokio_tungstenite::Connector::Rustls(Arc::new(tls_cfg)));

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret_key.to_string());
    let url = Arc::new(server_url.to_string());
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
        let (tcp, peer) = listener.accept().await?;
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
    // Per-connection random nonce → replay protection
    let nonce = {
        let mut b = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut b);
        B64.encode(b)
    };
    let token = compute_token(secret_key, &nonce);

    let mut builder = tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(server_url)
        // Browser-like headers — DPI treats this as normal HTTPS traffic
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        )
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("x-auth", &token)
        .header("x-nonce", &nonce);

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

    proxy_ws_tcp(ws, local, stats).await
}

// ═════════════════════════════════════════════════════════════════════════════
//  BIDIRECTIONAL PROXY  WebSocket ↔ raw TCP
// ═════════════════════════════════════════════════════════════════════════════

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
                    let msg = Message::Binary(buf[..n].to_vec().into());
                    if ws_tx.send(msg).await.is_err() {
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
                Ok(Some(Ok(Message::Ping(_)))) => {} // pong auto-handled by tungstenite
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
// Cloudflare Worker — paste into CF Dashboard → Workers & Pages → Create
// Add env variable: ORIGIN_HOST = "{origin}"
// Route:  *.yourdomain.com{ws_path}
// Enable: CF Dashboard → Network → WebSockets → ON

export default {{
  async fetch(request, env) {{
    const url = new URL(request.url);
    if (url.pathname !== "{ws_path}") {{
      return new Response(
        "<html><body><h1>404 Not Found</h1><hr><p>nginx/1.24.0</p></body></html>",
        {{ status: 404, headers: {{ "Server": "nginx/1.24.0", "Content-Type": "text/html" }} }}
      );
    }}
    const upgradeHeader = request.headers.get("Upgrade") || "";
    if (upgradeHeader.toLowerCase() !== "websocket") {{
      return new Response("Expected WebSocket", {{ status: 426 }});
    }}
    const headers = new Headers(request.headers);
    headers.set("Host", env.ORIGIN_HOST.split(":")[0]);
    return fetch(`wss://${{env.ORIGIN_HOST}}{ws_path}`, {{
      method: request.method,
      headers,
      body: request.body,
    }});
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

// ── NoCertVerifier (--insecure mode) ─────────────────────────────────────────
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
    // Explicitly install ring as the rustls crypto provider.
    // Required when multiple providers could be present in the dependency tree
    // (e.g. tokio-tungstenite pulling aws-lc-rs on some platforms).
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ok() — ignore error if already installed (e.g. called twice)

    let args: Vec<String> = std::env::args().collect();

    let help = |prog: &str| {
        eprintln!(
            r#"TLS WebSocket Tunnel v3 (Windows + Linux, CDN-fronting ready)

USAGE:
  server  <bind> <socks> <cert.pem> <key.pem> <secret> [ws-path]
  client  <bind> <wss-url> <secret> [--insecure] [--host <cdn-host>]
  worker  <origin:port> [ws-path]

EXAMPLES:
  Server (VPS/Linux):
    {prog} server 0.0.0.0:443 127.0.0.1:1080 cert.pem key.pem MySecret /api/v1/ws

  Client direct (Windows):
    {prog} client 127.0.0.1:1080 wss://yourserver.com/api/v1/ws MySecret

  Client via Cloudflare CDN (bypasses DC throttling):
    {prog} client 127.0.0.1:1080 wss://tunnel.yourdomain.com/api/v1/ws MySecret

  Client self-signed (dev):
    {prog} client 127.0.0.1:1080 wss://1.2.3.4:443/api/v1/ws MySecret --insecure

  Print Cloudflare Worker JS:
    {prog} worker 1.2.3.4:443 /api/v1/ws
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
            run_server(&args[2], &args[3], &args[4], &args[5], &args[6], ws_path).await?;
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
