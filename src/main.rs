use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// Оптимизированные настройки производительности
const BUFFER_SIZE: usize = 1024 * 1024; // 1MB буфер для высокой пропускной способности
const MAX_CONCURRENT: usize = 10000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const READ_TIMEOUT: Duration = Duration::from_secs(300); // Увеличен для медленных соединений
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

// Протокол аутентификации
const AUTH_MAGIC: &[u8] = b"TLS_TUNNEL_V1";
const AUTH_CHALLENGE_SIZE: usize = 32;
const AUTH_RESPONSE_SIZE: usize = 32;

// Статистика
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
            "[STATS] Active: {}, Total: {}, Failed auth: {}, RX: {} MB, TX: {} MB",
            self.active.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
            self.auth_failed.load(Ordering::Relaxed),
            self.bytes_rx.load(Ordering::Relaxed) / 1_000_000,
            self.bytes_tx.load(Ordering::Relaxed) / 1_000_000,
        );
    }
}

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

    // Увеличенные буферы сокетов
    let socket = socket2::SockRef::from(&listener);
    let _ = socket.set_recv_buffer_size(2 * 1024 * 1024); // 2MB
    let _ = socket.set_send_buffer_size(2 * 1024 * 1024); // 2MB

    println!("[SERVER] Listening on {}", bind_addr);
    println!("[SERVER] Forwarding to SOCKS at {}", socks_addr);
    println!("[SERVER] Authentication: ENABLED");
    println!("[SERVER] Buffer size: {} KB", BUFFER_SIZE / 1024);

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret_key.to_string());

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

        // Критически важно: TCP_NODELAY для минимальной задержки
        let _ = stream.set_nodelay(true);

        // Увеличенные буферы для каждого соединения
        if let Ok(socket) = socket2::SockRef::from(&stream).set_recv_buffer_size(1024 * 1024) {
            let _ = socket;
        }
        if let Ok(socket) = socket2::SockRef::from(&stream).set_send_buffer_size(1024 * 1024) {
            let _ = socket;
        }

        let acceptor = acceptor.clone();
        let socks = socks_addr.to_string();
        let semaphore = semaphore.clone();
        let stats = stats.clone();
        let secret = secret.clone();

        tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);

            if let Err(e) =
                handle_server_connection(stream, acceptor, &socks, &secret, stats.clone(), peer)
                    .await
            {
                if !e.to_string().contains("Authentication failed") {
                    eprintln!("[SERVER] Error from {}: {}", peer, e);
                }
            }

            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn handle_server_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    socks_addr: &str,
    secret_key: &str,
    stats: Arc<Stats>,
    peer: std::net::SocketAddr,
) -> Result<()> {
    let mut tls_stream = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .context("TLS handshake timeout")??;

    // Аутентификация клиента
    if !authenticate_client(&mut tls_stream, secret_key).await? {
        stats.auth_failed.fetch_add(1, Ordering::Relaxed);
        eprintln!("[SERVER] Authentication failed from {}", peer);
        send_decoy_response(&mut tls_stream).await?;
        return Err(anyhow::anyhow!("Authentication failed"));
    }

    println!("[SERVER] Client authenticated: {}", peer);

    // Подключение к SOCKS
    let socks_stream = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(socks_addr))
        .await
        .context("SOCKS connect timeout")??;

    let _ = socks_stream.set_nodelay(true);

    // Увеличенные буферы для SOCKS соединения
    if let Ok(socket) = socket2::SockRef::from(&socks_stream).set_recv_buffer_size(1024 * 1024) {
        let _ = socket;
    }
    if let Ok(socket) = socket2::SockRef::from(&socks_stream).set_send_buffer_size(1024 * 1024) {
        let _ = socket;
    }

    bidirectional_copy(tls_stream, socks_stream, stats).await
}

async fn authenticate_client<S>(stream: &mut S, secret_key: &str) -> Result<bool>
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
        Date: Mon, 01 Jan 2024 00:00:00 GMT\r\n\
        Content-Type: text/html\r\n\
        Content-Length: 146\r\n\
        Connection: close\r\n\
        \r\n\
        <html>\r\n\
        <head><title>404 Not Found</title></head>\r\n\
        <body>\r\n\
        <center><h1>404 Not Found</h1></center>\r\n\
        <hr><center>nginx/1.18.0</center>\r\n\
        </body>\r\n\
        </html>\r\n";

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

    // Увеличенные буферы сокетов
    let socket = socket2::SockRef::from(&listener);
    let _ = socket.set_recv_buffer_size(2 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(2 * 1024 * 1024);

    println!("[CLIENT] Local SOCKS proxy on {}", bind_addr);
    println!("[CLIENT] Tunneling to {}", server_addr);
    println!("[CLIENT] Authentication: ENABLED");
    println!("[CLIENT] Buffer size: {} KB", BUFFER_SIZE / 1024);
    if skip_verify {
        println!("[WARNING] Certificate verification DISABLED!");
    }

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());
    let secret = Arc::new(secret_key.to_string());

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

        // Увеличенные буферы
        if let Ok(socket) = socket2::SockRef::from(&stream).set_recv_buffer_size(1024 * 1024) {
            let _ = socket;
        }
        if let Ok(socket) = socket2::SockRef::from(&stream).set_send_buffer_size(1024 * 1024) {
            let _ = socket;
        }

        let connector = connector.clone();
        let server = server_addr.to_string();
        let semaphore = semaphore.clone();
        let stats = stats.clone();
        let secret = secret.clone();

        tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);

            if let Err(e) =
                handle_client_connection(stream, connector, &server, &secret, stats.clone()).await
            {
                eprintln!("[CLIENT] Error from {}: {}", peer, e);
            }

            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn handle_client_connection(
    local_stream: TcpStream,
    connector: TlsConnector,
    server_addr: &str,
    secret_key: &str,
    stats: Arc<Stats>,
) -> Result<()> {
    let server_name = server_addr.split(':').next().unwrap();

    let tcp_stream = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(server_addr))
        .await
        .context("Server connect timeout")??;

    let _ = tcp_stream.set_nodelay(true);

    // Увеличенные буферы для серверного соединения
    if let Ok(socket) = socket2::SockRef::from(&tcp_stream).set_recv_buffer_size(1024 * 1024) {
        let _ = socket;
    }
    if let Ok(socket) = socket2::SockRef::from(&tcp_stream).set_send_buffer_size(1024 * 1024) {
        let _ = socket;
    }

    let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
    let mut tls_stream = timeout(HANDSHAKE_TIMEOUT, connector.connect(domain, tcp_stream))
        .await
        .context("TLS handshake timeout")??;

    authenticate_with_server(&mut tls_stream, secret_key).await?;

    bidirectional_copy(local_stream, tls_stream, stats).await
}

async fn authenticate_with_server<S>(stream: &mut S, secret_key: &str) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut challenge = [0u8; AUTH_CHALLENGE_SIZE];
    timeout(AUTH_TIMEOUT, stream.read_exact(&mut challenge))
        .await
        .context("Auth challenge timeout")??;

    let response = compute_auth_response(&challenge, secret_key);
    stream.write_all(&response).await?;
    stream.flush().await?;

    Ok(())
}

// ============ МАКСИМАЛЬНО ОПТИМИЗИРОВАННОЕ КОПИРОВАНИЕ ============

async fn bidirectional_copy<A, B>(a: A, b: B, stats: Arc<Stats>) -> Result<()>
where
    A: AsyncReadExt + AsyncWriteExt + Unpin,
    B: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let stats_ab = stats.clone();
    let copy_a_to_b = async move {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;

        loop {
            match tokio::time::timeout(READ_TIMEOUT, a_read.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    match b_write.write_all(&buf[..n]).await {
                        Ok(_) => {
                            total += n as u64;
                            // Периодический flush для баланса задержки и пропускной способности
                            if total % (BUFFER_SIZE as u64 * 4) == 0 {
                                let _ = b_write.flush().await;
                            }
                        }
                        Err(_) => break,
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => break, // Timeout
            }
        }

        let _ = b_write.flush().await;
        stats_ab.bytes_rx.fetch_add(total, Ordering::Relaxed);
        total
    };

    let stats_ba = stats.clone();
    let copy_b_to_a = async move {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;

        loop {
            match tokio::time::timeout(READ_TIMEOUT, b_read.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    match a_write.write_all(&buf[..n]).await {
                        Ok(_) => {
                            total += n as u64;
                            // Периодический flush
                            if total % (BUFFER_SIZE as u64 * 4) == 0 {
                                let _ = a_write.flush().await;
                            }
                        }
                        Err(_) => break,
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => break, // Timeout
            }
        }

        let _ = a_write.flush().await;
        stats_ba.bytes_tx.fetch_add(total, Ordering::Relaxed);
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
        eprintln!("High-Performance TLS Tunnel with Authentication");
        eprintln!("\nUsage:");
        eprintln!(
            "  Server: {} server <bind_addr> <socks_addr> <cert.pem> <key.pem> <secret_key>",
            args[0]
        );
        eprintln!(
            "  Client: {} client <bind_addr> <server_addr> <secret_key> [--insecure]",
            args[0]
        );
        eprintln!("\nExample:");
        eprintln!(
            "  Server: {} server 0.0.0.0:8443 127.0.0.1:1080 cert.pem key.pem MySecretKey123",
            args[0]
        );
        eprintln!(
            "  Client: {} client 127.0.0.1:1080 server.example.com:8443 MySecretKey123",
            args[0]
        );
        std::process::exit(1);
    }

    match args[1].as_str() {
        "server" => {
            if args.len() < 7 {
                eprintln!(
                    "Server needs: <bind_addr> <socks_addr> <cert.pem> <key.pem> <secret_key>"
                );
                std::process::exit(1);
            }
            run_server(&args[2], &args[3], &args[4], &args[5], &args[6]).await?;
        }
        "client" => {
            if args.len() < 5 {
                eprintln!("Client needs: <bind_addr> <server_addr> <secret_key> [--insecure]");
                std::process::exit(1);
            }
            let skip_verify = args.get(5).map(|s| s == "--insecure").unwrap_or(false);
            run_client(&args[2], &args[3], &args[4], skip_verify).await?;
        }
        _ => {
            eprintln!("Unknown mode. Use 'server' or 'client'");
            std::process::exit(1);
        }
    }

    Ok(())
}
