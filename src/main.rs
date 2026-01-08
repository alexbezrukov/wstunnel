// Cargo.toml dependencies:
// [dependencies]
// tokio = { version = "1", features = ["full"] }
// tokio-rustls = "0.25"
// rustls = { version = "0.22", features = ["dangerous_configuration"] }
// rustls-pemfile = "2.0"
// anyhow = "1.0"

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration, Instant};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// Настройки производительности
const BUFFER_SIZE: usize = 64 * 1024; // 64KB буферы
const MAX_CONCURRENT: usize = 5000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const COPY_TIMEOUT: Duration = Duration::from_secs(600);

// Статистика
#[derive(Default)]
struct Stats {
    active: AtomicU64,
    total: AtomicU64,
    bytes_rx: AtomicU64,
    bytes_tx: AtomicU64,
}

impl Stats {
    fn report(&self) {
        println!(
            "[STATS] Active: {}, Total: {}, RX: {} MB, TX: {} MB",
            self.active.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
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
) -> Result<()> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Invalid cert/key")?;

    // TLS оптимизации
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.max_fragment_size = Some(16384);

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(bind_addr).await?;

    // TCP оптимизации на уровне listener
    let socket = socket2::SockRef::from(&listener);
    let _ = socket.set_recv_buffer_size(256 * 1024);
    let _ = socket.set_send_buffer_size(256 * 1024);

    println!("[SERVER] Listening on {}", bind_addr);
    println!("[SERVER] Forwarding to SOCKS at {}", socks_addr);

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());

    // Периодический отчет
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

        // TCP оптимизации на соединении
        let _ = stream.set_nodelay(true);

        let acceptor = acceptor.clone();
        let socks = socks_addr.to_string();
        let semaphore = semaphore.clone();
        let stats = stats.clone();

        tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);

            if let Err(e) = handle_server_connection(stream, acceptor, &socks, stats.clone()).await
            {
                eprintln!("[SERVER] Error from {}: {}", peer, e);
            }

            stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn handle_server_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    socks_addr: &str,
    stats: Arc<Stats>,
) -> Result<()> {
    // TLS handshake с таймаутом
    let tls_stream = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .context("TLS handshake timeout")??;

    // Подключение к SOCKS
    let socks_stream = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(socks_addr))
        .await
        .context("SOCKS connect timeout")??;

    let _ = socks_stream.set_nodelay(true);

    // Bidirectional копирование
    bidirectional_copy(tls_stream, socks_stream, stats).await
}

// ============ CLIENT SIDE ============

pub async fn run_client(bind_addr: &str, server_addr: &str, skip_verify: bool) -> Result<()> {
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

    // TLS оптимизации
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.max_fragment_size = Some(16384);
    config.resumption = rustls::client::Resumption::default();

    let connector = TlsConnector::from(Arc::new(config));
    let listener = TcpListener::bind(bind_addr).await?;

    // TCP оптимизации
    let socket = socket2::SockRef::from(&listener);
    let _ = socket.set_recv_buffer_size(256 * 1024);
    let _ = socket.set_send_buffer_size(256 * 1024);

    println!("[CLIENT] Local SOCKS proxy on {}", bind_addr);
    println!("[CLIENT] Tunneling to {}", server_addr);
    if skip_verify {
        println!("[WARNING] Certificate verification DISABLED!");
    }

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT));
    let stats = Arc::new(Stats::default());

    // Периодический отчет
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

        // TCP оптимизации
        let _ = stream.set_nodelay(true);

        let connector = connector.clone();
        let server = server_addr.to_string();
        let semaphore = semaphore.clone();
        let stats = stats.clone();

        tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            stats.active.fetch_add(1, Ordering::Relaxed);
            stats.total.fetch_add(1, Ordering::Relaxed);

            if let Err(e) =
                handle_client_connection(stream, connector, &server, stats.clone()).await
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
    stats: Arc<Stats>,
) -> Result<()> {
    let server_name = server_addr.split(':').next().unwrap();

    // Подключение к серверу
    let tcp_stream = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(server_addr))
        .await
        .context("Server connect timeout")??;

    let _ = tcp_stream.set_nodelay(true);

    // TLS handshake
    let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
    let tls_stream = timeout(HANDSHAKE_TIMEOUT, connector.connect(domain, tcp_stream))
        .await
        .context("TLS handshake timeout")??;

    // Bidirectional копирование
    bidirectional_copy(local_stream, tls_stream, stats).await
}

// ============ ОПТИМИЗИРОВАННОЕ КОПИРОВАНИЕ ============

async fn bidirectional_copy<A, B>(mut a: A, mut b: B, stats: Arc<Stats>) -> Result<()>
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
        let mut last_activity = Instant::now();

        loop {
            tokio::select! {
                result = a_read.read(&mut buf) => {
                    match result {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Err(e) = b_write.write_all(&buf[..n]).await {
                                eprintln!("[COPY] Write error: {}", e);
                                break;
                            }
                            total += n as u64;
                            last_activity = Instant::now();
                        }
                        Err(e) => {
                            // Игнорируем нормальные закрытия соединений
                            let err_str = e.to_string();
                            if !err_str.contains("close_notify")
                                && !err_str.contains("Connection reset")
                                && !err_str.contains("Broken pipe") {
                                eprintln!("[COPY] Read error: {}", e);
                            }
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    if last_activity.elapsed() > IDLE_TIMEOUT {
                        break;
                    }
                }
            }
        }

        stats_ab.bytes_rx.fetch_add(total, Ordering::Relaxed);
        total
    };

    let stats_ba = stats.clone();
    let copy_b_to_a = async move {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;
        let mut last_activity = Instant::now();

        loop {
            tokio::select! {
                result = b_read.read(&mut buf) => {
                    match result {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Err(e) = a_write.write_all(&buf[..n]).await {
                                eprintln!("[COPY] Write error: {}", e);
                                break;
                            }
                            total += n as u64;
                            last_activity = Instant::now();
                        }
                        Err(e) => {
                            // Игнорируем нормальные закрытия соединений
                            let err_str = e.to_string();
                            if !err_str.contains("close_notify")
                                && !err_str.contains("Connection reset")
                                && !err_str.contains("Broken pipe") {
                                eprintln!("[COPY] Read error: {}", e);
                            }
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    if last_activity.elapsed() > IDLE_TIMEOUT {
                        break;
                    }
                }
            }
        }

        stats_ba.bytes_tx.fetch_add(total, Ordering::Relaxed);
        total
    };

    // Запускаем оба направления с общим таймаутом
    let result = timeout(COPY_TIMEOUT, async {
        let (rx, tx) = tokio::join!(copy_a_to_b, copy_b_to_a);
        (rx, tx)
    })
    .await;

    match result {
        Ok((rx, tx)) => {
            if rx > 0 || tx > 0 {
                println!("[CONN] Closed: RX {} KB, TX {} KB", rx / 1024, tx / 1024);
            }
            Ok(())
        }
        Err(_) => {
            eprintln!("[CONN] Connection timeout");
            Ok(())
        }
    }
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
        eprintln!("Optimized TLS Tunnel");
        eprintln!("\nUsage:");
        eprintln!(
            "  Server: {} server <bind_addr> <socks_addr> <cert.pem> <key.pem>",
            args[0]
        );
        eprintln!(
            "  Client: {} client <bind_addr> <server_addr> [--insecure]",
            args[0]
        );
        eprintln!("\nExample:");
        eprintln!(
            "  Server: {} server 0.0.0.0:8443 127.0.0.1:1080 cert.pem key.pem",
            args[0]
        );
        eprintln!(
            "  Client: {} client 127.0.0.1:1080 server.example.com:8443",
            args[0]
        );
        std::process::exit(1);
    }

    match args[1].as_str() {
        "server" => {
            if args.len() < 6 {
                eprintln!("Server needs: <bind_addr> <socks_addr> <cert.pem> <key.pem>");
                std::process::exit(1);
            }
            run_server(&args[2], &args[3], &args[4], &args[5]).await?;
        }
        "client" => {
            if args.len() < 4 {
                eprintln!("Client needs: <bind_addr> <server_addr> [--insecure]");
                std::process::exit(1);
            }
            let skip_verify = args.get(4).map(|s| s == "--insecure").unwrap_or(false);
            run_client(&args[2], &args[3], skip_verify).await?;
        }
        _ => {
            eprintln!("Unknown mode. Use 'server' or 'client'");
            std::process::exit(1);
        }
    }

    Ok(())
}
