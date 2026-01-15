use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{timeout, Duration, Instant};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const BUFFER_SIZE: usize = 64 * 1024;
const MAX_CONCURRENT: usize = 10000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const READ_TIMEOUT: Duration = Duration::from_secs(300);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

// Session management
const SESSION_TOKEN_SIZE: usize = 32;
const SESSION_LIFETIME: Duration = Duration::from_secs(3600); // 1 hour
const SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(300); // 5 min

const AUTH_MAGIC: &[u8] = b"TLS_TUNNEL_V2_SESSION";
const AUTH_CHALLENGE_SIZE: usize = 32;
const AUTH_RESPONSE_SIZE: usize = 32;

#[derive(Default)]
struct Stats {
    active: AtomicU64,
    total: AtomicU64,
    bytes_rx: AtomicU64,
    bytes_tx: AtomicU64,
    auth_failed: AtomicU64,
    sessions_created: AtomicU64,
    sessions_reused: AtomicU64,
}

impl Stats {
    fn report(&self) {
        let active = self.active.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        let rx_mb = self.bytes_rx.load(Ordering::Relaxed) / 1_000_000;
        let tx_mb = self.bytes_tx.load(Ordering::Relaxed) / 1_000_000;
        let failed = self.auth_failed.load(Ordering::Relaxed);
        let created = self.sessions_created.load(Ordering::Relaxed);
        let reused = self.sessions_reused.load(Ordering::Relaxed);

        println!(
            "[STATS] Active: {}, Total: {}, Failed: {}, Sessions: {}/{}, RX: {} MB, TX: {} MB",
            active, total, failed, created, reused, rx_mb, tx_mb
        );
    }
}

// Session tracking
struct Session {
    token: [u8; SESSION_TOKEN_SIZE],
    created_at: Instant,
    last_used: Instant,
}

type SessionStore = Arc<Mutex<HashMap<[u8; SESSION_TOKEN_SIZE], Session>>>;

// ============ SERVER SIDE ============

pub async fn run_server(
    bind_addr: &str,
    socks_addr: &str,
    cert_path: &str,
    key_path: &str,
    secret_key: &str,
) -> Result<()> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Invalid cert/key")?;

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.max_fragment_size = Some(16384);

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(bind_addr).await?;

    let socket = socket2::SockRef::from(&listener);
    let _ = socket.set_recv_buffer_size(512 * 1024);
    let _ = socket.set_send_buffer_size(512 * 1024);

    println!("[SERVER] Listening on {}", bind_addr);
    println!("[SERVER] Forwarding to SOCKS at {}", socks_addr);
    println!(
        "[SERVER] Session-based auth enabled (lifetime: {}s)",
        SESSION_LIFETIME.as_secs()
    );

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret_key.to_string());
    let sessions: SessionStore = Arc::new(Mutex::new(HashMap::new()));

    // Stats reporter
    let stats_clone = stats.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            stats_clone.report();
        }
    });

    // Session cleanup task
    let sessions_clone = sessions.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SESSION_CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            cleanup_expired_sessions(&sessions_clone).await;
        }
    });

    loop {
        let (stream, peer) = listener.accept().await?;
        let _ = stream.set_nodelay(true);

        if let Ok(socket) = socket2::SockRef::from(&stream).set_recv_buffer_size(256 * 1024) {
            let _ = socket;
        }
        if let Ok(socket) = socket2::SockRef::from(&stream).set_send_buffer_size(256 * 1024) {
            let _ = socket;
        }

        let acceptor = acceptor.clone();
        let socks = socks_addr.to_string();
        let semaphore = semaphore.clone();
        let stats = stats.clone();
        let secret = secret.clone();
        let sessions = sessions.clone();

        tokio::spawn(async move {
            let permit = match semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);

            let result = handle_server_connection(
                stream,
                acceptor,
                &socks,
                &secret,
                sessions,
                stats.clone(),
                peer,
            )
            .await;

            if let Err(e) = result {
                if !e.to_string().contains("Authentication failed") {
                    eprintln!("[SERVER] Error from {}: {}", peer, e);
                }
            }

            stats.active.fetch_sub(1, Ordering::Relaxed);
            drop(permit);
        });
    }
}

async fn handle_server_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    socks_addr: &str,
    secret_key: &str,
    sessions: SessionStore,
    stats: Arc<Stats>,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let mut tls_stream = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .context("TLS handshake timeout")??;

    // Read first byte to determine if this is auth or session reuse
    let mut mode_byte = [0u8; 1];
    timeout(AUTH_TIMEOUT, tls_stream.read_exact(&mut mode_byte))
        .await
        .context("Mode byte timeout")??;

    match mode_byte[0] {
        0x01 => {
            // New authentication
            if !authenticate_client_new(&mut tls_stream, secret_key).await? {
                stats.auth_failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("[SERVER] Auth failed: {}", peer);
                send_decoy_response(&mut tls_stream).await?;
                return Err(anyhow::anyhow!("Authentication failed"));
            }

            // Generate and send session token
            let token = generate_session_token();
            tls_stream.write_all(&token).await?;
            tls_stream.flush().await?;

            // Store session
            let session = Session {
                token,
                created_at: Instant::now(),
                last_used: Instant::now(),
            };
            sessions.lock().await.insert(token, session);
            stats.sessions_created.fetch_add(1, Ordering::Relaxed);

            println!("[SERVER] New session: {}", peer);
        }
        0x02 => {
            // Session reuse
            let mut token = [0u8; SESSION_TOKEN_SIZE];
            timeout(AUTH_TIMEOUT, tls_stream.read_exact(&mut token))
                .await
                .context("Session token timeout")??;

            let mut sessions_lock = sessions.lock().await;
            if let Some(session) = sessions_lock.get_mut(&token) {
                // Check if session is still valid
                if session.created_at.elapsed() < SESSION_LIFETIME {
                    session.last_used = Instant::now();
                    drop(sessions_lock);

                    // Send success
                    tls_stream.write_all(&[0x01]).await?;
                    tls_stream.flush().await?;

                    stats.sessions_reused.fetch_add(1, Ordering::Relaxed);
                } else {
                    // Session expired
                    sessions_lock.remove(&token);
                    drop(sessions_lock);

                    tls_stream.write_all(&[0x00]).await?;
                    tls_stream.flush().await?;

                    return Err(anyhow::anyhow!("Session expired"));
                }
            } else {
                drop(sessions_lock);

                // Invalid session
                tls_stream.write_all(&[0x00]).await?;
                tls_stream.flush().await?;

                stats.auth_failed.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow::anyhow!("Invalid session token"));
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Invalid mode byte"));
        }
    }

    // Connect to SOCKS
    let socks_stream = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(socks_addr))
        .await
        .context("SOCKS connect timeout")??;

    let _ = socks_stream.set_nodelay(true);

    if let Ok(socket) = socket2::SockRef::from(&socks_stream).set_recv_buffer_size(256 * 1024) {
        let _ = socket;
    }
    if let Ok(socket) = socket2::SockRef::from(&socks_stream).set_send_buffer_size(256 * 1024) {
        let _ = socket;
    }

    bidirectional_copy(tls_stream, socks_stream, stats).await
}

async fn authenticate_client_new<S>(stream: &mut S, secret_key: &str) -> Result<bool>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut challenge = [0u8; AUTH_CHALLENGE_SIZE];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut challenge);

    stream.write_all(&challenge).await?;
    stream.flush().await?;

    let mut response = [0u8; AUTH_RESPONSE_SIZE];
    timeout(AUTH_TIMEOUT, stream.read_exact(&mut response))
        .await
        .context("Auth timeout")??;

    let expected = compute_auth_response(&challenge, secret_key);
    Ok(response == expected)
}

fn generate_session_token() -> [u8; SESSION_TOKEN_SIZE] {
    let mut token = [0u8; SESSION_TOKEN_SIZE];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut token);
    token
}

async fn cleanup_expired_sessions(sessions: &SessionStore) {
    let mut sessions = sessions.lock().await;
    let before = sessions.len();
    sessions.retain(|_, session| session.created_at.elapsed() < SESSION_LIFETIME);
    let after = sessions.len();
    if before != after {
        println!("[SERVER] Cleaned {} expired sessions", before - after);
    }
}

fn compute_auth_response(challenge: &[u8], secret: &str) -> [u8; AUTH_RESPONSE_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(AUTH_MAGIC);
    hasher.update(challenge);
    hasher.update(secret.as_bytes());
    let result = hasher.finalize();

    let mut output = [0u8; AUTH_RESPONSE_SIZE];
    output.copy_from_slice(&result[..AUTH_RESPONSE_SIZE]);
    output
}

async fn send_decoy_response<S>(stream: &mut S) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let response = b"HTTP/1.1 404 Not Found\r\n\
        Server: nginx/1.18.0\r\n\
        Content-Length: 146\r\n\
        Connection: close\r\n\
        \r\n\
        <html><head><title>404 Not Found</title></head>\
        <body><center><h1>404 Not Found</h1></center></body></html>\r\n";

    let _ = stream.write_all(response).await;
    Ok(())
}

// ============ CLIENT SIDE ============

pub async fn run_client(
    bind_addr: &str,
    server_addr: &str,
    secret_key: &str,
    skip_verify: bool,
) -> Result<()> {
    let mut config = if skip_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.max_fragment_size = Some(16384);
    config.resumption = rustls::client::Resumption::default();

    let connector = TlsConnector::from(Arc::new(config));
    let listener = TcpListener::bind(bind_addr).await?;

    let socket = socket2::SockRef::from(&listener);
    let _ = socket.set_recv_buffer_size(512 * 1024);
    let _ = socket.set_send_buffer_size(512 * 1024);

    println!("[CLIENT] Local SOCKS proxy on {}", bind_addr);
    println!("[CLIENT] Tunneling to {}", server_addr);
    println!("[CLIENT] Session-based auth enabled");
    if skip_verify {
        println!("[WARNING] Certificate verification DISABLED!");
    }

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret_key.to_string());
    let session_token: Arc<Mutex<Option<[u8; SESSION_TOKEN_SIZE]>>> = Arc::new(Mutex::new(None));

    let stats_clone = stats.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            stats_clone.report();
        }
    });

    loop {
        let (stream, peer) = listener.accept().await?;
        let _ = stream.set_nodelay(true);

        if let Ok(socket) = socket2::SockRef::from(&stream).set_recv_buffer_size(256 * 1024) {
            let _ = socket;
        }
        if let Ok(socket) = socket2::SockRef::from(&stream).set_send_buffer_size(256 * 1024) {
            let _ = socket;
        }

        let connector = connector.clone();
        let server = server_addr.to_string();
        let semaphore = semaphore.clone();
        let stats = stats.clone();
        let secret = secret.clone();
        let session_token = session_token.clone();

        tokio::spawn(async move {
            let permit = match semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);

            let result = handle_client_connection(
                stream,
                connector,
                &server,
                &secret,
                session_token,
                stats.clone(),
            )
            .await;

            if let Err(e) = result {
                eprintln!("[CLIENT] Error from {}: {}", peer, e);
            }

            stats.active.fetch_sub(1, Ordering::Relaxed);
            drop(permit);
        });
    }
}

async fn handle_client_connection(
    local_stream: TcpStream,
    connector: TlsConnector,
    server_addr: &str,
    secret_key: &str,
    session_token: Arc<Mutex<Option<[u8; SESSION_TOKEN_SIZE]>>>,
    stats: Arc<Stats>,
) -> Result<()> {
    let server_name = server_addr.split(':').next().unwrap();

    let tcp_stream = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(server_addr))
        .await
        .context("Server connect timeout")??;

    let _ = tcp_stream.set_nodelay(true);

    if let Ok(socket) = socket2::SockRef::from(&tcp_stream).set_recv_buffer_size(256 * 1024) {
        let _ = socket;
    }
    if let Ok(socket) = socket2::SockRef::from(&tcp_stream).set_send_buffer_size(256 * 1024) {
        let _ = socket;
    }

    let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
    let mut tls_stream = timeout(HANDSHAKE_TIMEOUT, connector.connect(domain, tcp_stream))
        .await
        .context("TLS handshake timeout")??;

    // Try to reuse existing session
    let token = session_token.lock().await.clone();

    if let Some(token) = token {
        // Try session reuse
        tls_stream.write_all(&[0x02]).await?; // Mode: reuse
        tls_stream.write_all(&token).await?;
        tls_stream.flush().await?;

        let mut response = [0u8; 1];
        timeout(AUTH_TIMEOUT, tls_stream.read_exact(&mut response))
            .await
            .context("Session response timeout")??;

        if response[0] == 0x01 {
            // Session accepted
            stats.sessions_reused.fetch_add(1, Ordering::Relaxed);
        } else {
            // Session rejected, need full auth
            drop(tls_stream);

            // Reconnect
            let tcp_stream = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(server_addr))
                .await
                .context("Server reconnect timeout")??;
            let _ = tcp_stream.set_nodelay(true);

            let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
            tls_stream = timeout(HANDSHAKE_TIMEOUT, connector.connect(domain, tcp_stream))
                .await
                .context("TLS handshake timeout")??;

            authenticate_and_get_token(&mut tls_stream, secret_key, session_token.clone()).await?;
            stats.sessions_created.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        // No session, do full auth
        authenticate_and_get_token(&mut tls_stream, secret_key, session_token.clone()).await?;
        stats.sessions_created.fetch_add(1, Ordering::Relaxed);
    }

    bidirectional_copy(local_stream, tls_stream, stats).await
}

async fn authenticate_and_get_token<S>(
    stream: &mut S,
    secret_key: &str,
    session_token: Arc<Mutex<Option<[u8; SESSION_TOKEN_SIZE]>>>,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Send auth mode
    stream.write_all(&[0x01]).await?; // Mode: new auth
    stream.flush().await?;

    // Receive challenge
    let mut challenge = [0u8; AUTH_CHALLENGE_SIZE];
    timeout(AUTH_TIMEOUT, stream.read_exact(&mut challenge))
        .await
        .context("Auth challenge timeout")??;

    // Send response
    let response = compute_auth_response(&challenge, secret_key);
    stream.write_all(&response).await?;
    stream.flush().await?;

    // Receive session token
    let mut token = [0u8; SESSION_TOKEN_SIZE];
    timeout(AUTH_TIMEOUT, stream.read_exact(&mut token))
        .await
        .context("Session token timeout")??;

    // Store token
    *session_token.lock().await = Some(token);
    println!("[CLIENT] New session established");

    Ok(())
}

// ============ BIDIRECTIONAL COPY ============

async fn bidirectional_copy<A, B>(a: A, b: B, stats: Arc<Stats>) -> Result<()>
where
    A: AsyncReadExt + AsyncWriteExt + Unpin,
    B: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let stats_ab = stats.clone();
    let copy_a_to_b = async move {
        let mut buf = Box::new([0u8; BUFFER_SIZE]);
        let mut total = 0u64;

        loop {
            let read_result = tokio::time::timeout(READ_TIMEOUT, a_read.read(&mut buf[..])).await;

            match read_result {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    if b_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    total += n as u64;

                    if total % (BUFFER_SIZE as u64 * 4) == 0 {
                        let _ = b_write.flush().await;
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }

        let _ = b_write.flush().await;
        stats_ab.bytes_rx.fetch_add(total, Ordering::Relaxed);

        drop(buf);
        total
    };

    let stats_ba = stats;
    let copy_b_to_a = async move {
        let mut buf = Box::new([0u8; BUFFER_SIZE]);
        let mut total = 0u64;

        loop {
            let read_result = tokio::time::timeout(READ_TIMEOUT, b_read.read(&mut buf[..])).await;

            match read_result {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    if a_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    total += n as u64;

                    if total % (BUFFER_SIZE as u64 * 4) == 0 {
                        let _ = a_write.flush().await;
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }

        let _ = a_write.flush().await;
        stats_ba.bytes_tx.fetch_add(total, Ordering::Relaxed);

        drop(buf);
        total
    };

    let (rx, tx) = tokio::join!(copy_a_to_b, copy_b_to_a);

    if rx > 0 || tx > 0 {
        println!("[CONN] Closed: RX {} KB, TX {} KB", rx / 1024, tx / 1024);
    }

    Ok(())
}

// ============ HELPER FUNCTIONS ============

#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
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

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let keys = rustls_pemfile::private_key(&mut reader)?.context("No private key found")?;
    Ok(keys)
}

// ============ MAIN ============

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("TLS Tunnel (Session-Based Auth)\n");
        eprintln!("Usage:");
        eprintln!(
            "  Server: {} server <bind> <socks> <cert.pem> <key.pem> <secret>",
            args[0]
        );
        eprintln!(
            "  Client: {} client <bind> <server> <secret> [--insecure]\n",
            args[0]
        );
        eprintln!("Example:");
        eprintln!(
            "  {} server 0.0.0.0:8443 127.0.0.1:1080 cert.pem key.pem Secret123",
            args[0]
        );
        eprintln!(
            "  {} client 127.0.0.1:1080 server.com:8443 Secret123",
            args[0]
        );
        std::process::exit(1);
    }

    match args[1].as_str() {
        "server" => {
            if args.len() < 7 {
                eprintln!("Server needs: <bind> <socks> <cert.pem> <key.pem> <secret>");
                std::process::exit(1);
            }
            run_server(&args[2], &args[3], &args[4], &args[5], &args[6]).await?;
        }
        "client" => {
            if args.len() < 5 {
                eprintln!("Client needs: <bind> <server> <secret> [--insecure]");
                std::process::exit(1);
            }
            let skip_verify = args.get(5).map(|s| s == "--insecure").unwrap_or(false);
            run_client(&args[2], &args[3], &args[4], skip_verify).await?;
        }
        _ => {
            eprintln!("Unknown mode. Use 'server' or client'");
            std::process::exit(1);
        }
    }

    Ok(())
}
