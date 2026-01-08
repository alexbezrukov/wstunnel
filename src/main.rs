// Cargo.toml dependencies:
// [dependencies]
// tokio = { version = "1", features = ["full"] }
// tokio-rustls = "0.25"
// rustls = { version = "0.22", features = ["dangerous_configuration"] }
// rustls-pemfile = "2.0"
// anyhow = "1.0"
// socket2 = "0.5"
// dashmap = "5.5"

use anyhow::{Context, Result};
use dashmap::DashMap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration, Instant};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const BUFFER_SIZE: usize = 64 * 1024; // 64KB буферы
const MAX_CONCURRENT_CLIENTS: usize = 10000;
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);

// Статистика производительности
#[derive(Default)]
struct Stats {
    active_connections: AtomicU64,
    total_bytes_rx: AtomicU64,
    total_bytes_tx: AtomicU64,
    total_connections: AtomicU64,
}

impl Stats {
    fn report(&self) {
        println!(
            "[STATS] Active: {}, Total: {}, RX: {} MB, TX: {} MB",
            self.active_connections.load(Ordering::Relaxed),
            self.total_connections.load(Ordering::Relaxed),
            self.total_bytes_rx.load(Ordering::Relaxed) / 1_000_000,
            self.total_bytes_tx.load(Ordering::Relaxed) / 1_000_000,
        );
    }
}

// Пул соединений для переиспользования
struct ConnectionPool {
    connections: DashMap<String, Vec<TcpStream>>,
    max_idle: usize,
}

impl ConnectionPool {
    fn new(max_idle: usize) -> Self {
        Self {
            connections: DashMap::new(),
            max_idle,
        }
    }

    async fn get_or_create(&self, addr: &str) -> Result<TcpStream> {
        // Попытка получить из пула
        if let Some(mut entry) = self.connections.get_mut(addr) {
            if let Some(stream) = entry.pop() {
                // Проверка, что соединение живо
                if stream.peer_addr().is_ok() {
                    return Ok(stream);
                }
            }
        }

        // Создаём новое соединение
        let stream = create_optimized_socket(addr).await?;
        Ok(stream)
    }

    fn return_connection(&self, addr: String, stream: TcpStream) {
        let mut entry = self.connections.entry(addr).or_insert_with(Vec::new);
        if entry.len() < self.max_idle {
            entry.push(stream);
        }
    }
}

// ============ ОПТИМИЗИРОВАННЫЙ СОКЕТ ============

async fn create_optimized_socket(addr: &str) -> Result<TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

    let socket_addr: SocketAddr = addr.parse()?;
    let domain = if socket_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // TCP оптимизации
    socket.set_nodelay(true)?; // Отключаем алгоритм Nagle
    socket.set_keepalive(true)?;
    socket.set_reuse_address(true)?;

    #[cfg(unix)]
    {
        // socket.set_reuse_port(true)?;
        // Увеличиваем буферы
        socket.set_send_buffer_size(256 * 1024)?;
        socket.set_recv_buffer_size(256 * 1024)?;
    }

    socket.set_nonblocking(true)?;
    socket.connect(&socket_addr.into())?;

    let std_stream: std::net::TcpStream = socket.into();
    Ok(TcpStream::from_std(std_stream)?)
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
        .with_single_cert(certs, key)?;

    // TLS оптимизации
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.max_fragment_size = Some(16384); // 16KB фрагменты
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(1024);

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = create_server_listener(bind_addr).await?;

    println!("[SERVER] High-performance mode on {}", bind_addr);
    println!("[SERVER] Forwarding to SOCKS at {}", socks_addr);

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
    let stats = Arc::new(Stats::default());
    let pool = Arc::new(ConnectionPool::new(100));

    // Статистика каждые 30 секунд
    let stats_clone = stats.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            stats_clone.report();
        }
    });

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let socks = socks_addr.to_string();
        let semaphore = semaphore.clone();
        let stats = stats.clone();
        let pool = pool.clone();

        tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            stats.active_connections.fetch_add(1, Ordering::Relaxed);
            stats.total_connections.fetch_add(1, Ordering::Relaxed);

            if let Err(e) =
                handle_client_optimized(stream, acceptor, &socks, stats.clone(), pool).await
            {
                eprintln!("[SERVER] Error: {}", e);
            }

            stats.active_connections.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn create_server_listener(addr: &str) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

    let socket_addr: SocketAddr = addr.parse()?;
    let domain = if socket_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;

    #[cfg(unix)]
    {
        socket.set_reuse_port(true)?;
    }

    socket.set_nonblocking(true)?;
    socket.bind(&socket_addr.into())?;
    socket.listen(4096)?; // Большая очередь

    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

async fn handle_client_optimized(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    socks_addr: &str,
    stats: Arc<Stats>,
    pool: Arc<ConnectionPool>,
) -> Result<()> {
    // TLS handshake с таймаутом
    let tls_stream = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .context("TLS handshake timeout")??;

    // Получаем или создаём соединение к SOCKS
    let socks_stream = timeout(HANDSHAKE_TIMEOUT, pool.get_or_create(socks_addr))
        .await
        .context("SOCKS connect timeout")??;

    // Bidirectional копирование с оптимизацией
    let result = bidirectional_copy_optimized(tls_stream, socks_stream, stats).await;

    result
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
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.max_fragment_size = Some(16384);
    config.resumption = rustls::client::Resumption::default();

    let connector = TlsConnector::from(Arc::new(config));
    let listener = create_server_listener(bind_addr).await?;

    println!("[CLIENT] High-performance local SOCKS on {}", bind_addr);
    println!("[CLIENT] Tunneling to {}", server_addr);
    if skip_verify {
        println!("[WARNING] Certificate verification DISABLED!");
    }

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
    let stats = Arc::new(Stats::default());
    let pool = Arc::new(ConnectionPool::new(50));

    // Статистика
    let stats_clone = stats.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            stats_clone.report();
        }
    });

    loop {
        let (stream, _) = listener.accept().await?;
        let connector = connector.clone();
        let server = server_addr.to_string();
        let semaphore = semaphore.clone();
        let stats = stats.clone();
        let pool = pool.clone();

        tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };

            stats.active_connections.fetch_add(1, Ordering::Relaxed);
            stats.total_connections.fetch_add(1, Ordering::Relaxed);

            if let Err(e) =
                handle_local_optimized(stream, connector, &server, stats.clone(), pool).await
            {
                eprintln!("[CLIENT] Error: {}", e);
            }

            stats.active_connections.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn handle_local_optimized(
    local_stream: TcpStream,
    connector: TlsConnector,
    server_addr: &str,
    stats: Arc<Stats>,
    pool: Arc<ConnectionPool>,
) -> Result<()> {
    let server_name = server_addr.split(':').next().unwrap();

    // Получаем соединение из пула или создаём новое
    let tcp_stream = timeout(HANDSHAKE_TIMEOUT, pool.get_or_create(server_addr))
        .await
        .context("Server connect timeout")??;

    let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
    let tls_stream = timeout(HANDSHAKE_TIMEOUT, connector.connect(domain, tcp_stream))
        .await
        .context("TLS handshake timeout")??;

    bidirectional_copy_optimized(local_stream, tls_stream, stats).await
}

// ============ ОПТИМИЗИРОВАННОЕ КОПИРОВАНИЕ ============

async fn bidirectional_copy_optimized<A, B>(
    mut stream_a: A,
    mut stream_b: B,
    stats: Arc<Stats>,
) -> Result<()>
where
    A: AsyncReadExt + AsyncWriteExt + Unpin,
    B: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let (mut a_read, mut a_write) = tokio::io::split(stream_a);
    let (mut b_read, mut b_write) = tokio::io::split(stream_b);

    let stats_clone = stats.clone();
    let copy_a_to_b = async {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;
        let mut last_activity = Instant::now();

        loop {
            // Чтение с keepalive проверкой
            let read_timeout = tokio::time::sleep(KEEPALIVE_INTERVAL);
            tokio::pin!(read_timeout);

            tokio::select! {
                result = a_read.read(&mut buf) => {
                    match result {
                        Ok(0) => break,
                        Ok(n) => {
                            a_write.write_all(&buf[..n]).await?;
                            total += n as u64;
                            last_activity = Instant::now();
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                _ = &mut read_timeout => {
                    if last_activity.elapsed() > IDLE_TIMEOUT {
                        return Err(anyhow::anyhow!("Idle timeout"));
                    }
                }
            }
        }

        stats_clone
            .total_bytes_rx
            .fetch_add(total, Ordering::Relaxed);
        Ok::<_, anyhow::Error>(total)
    };

    let stats_clone = stats.clone();
    let copy_b_to_a = async {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;
        let mut last_activity = Instant::now();

        loop {
            let read_timeout = tokio::time::sleep(KEEPALIVE_INTERVAL);
            tokio::pin!(read_timeout);

            tokio::select! {
                result = b_read.read(&mut buf) => {
                    match result {
                        Ok(0) => break,
                        Ok(n) => {
                            b_write.write_all(&buf[..n]).await?;
                            total += n as u64;
                            last_activity = Instant::now();
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                _ = &mut read_timeout => {
                    if last_activity.elapsed() > IDLE_TIMEOUT {
                        return Err(anyhow::anyhow!("Idle timeout"));
                    }
                }
            }
        }

        stats_clone
            .total_bytes_tx
            .fetch_add(total, Ordering::Relaxed);
        Ok::<_, anyhow::Error>(total)
    };

    // Запускаем оба направления параллельно
    let result = tokio::try_join!(copy_a_to_b, copy_b_to_a);

    match result {
        Ok((rx, tx)) => {
            println!("[CONN] Closed: RX {} KB, TX {} KB", rx / 1024, tx / 1024);
            Ok(())
        }
        Err(e) => Err(e),
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
        eprintln!("High-Performance TLS Tunnel");
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
