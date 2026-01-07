// Cargo.toml dependencies:
// [dependencies]
// tokio = { version = "1", features = ["full"] }
// tokio-rustls = "0.25"
// rustls = { version = "0.22", features = ["dangerous_configuration"] }
// rustls-pemfile = "2.0"
// anyhow = "1.0"

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ============ SERVER SIDE (на зарубежном сервере) ============

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

    // Поддержка TLS 1.2 для лучшей совместимости
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(bind_addr).await?;

    println!("[SERVER] Listening on {}", bind_addr);
    println!("[SERVER] Forwarding to SOCKS at {}", socks_addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let socks = socks_addr.to_string();

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, acceptor, &socks).await {
                eprintln!("[SERVER] Error from {}: {}", peer, e);
            }
        });
    }
}

async fn handle_client(stream: TcpStream, acceptor: TlsAcceptor, socks_addr: &str) -> Result<()> {
    let mut tls_stream = acceptor.accept(stream).await?;
    println!("[SERVER] TLS connection established");

    let mut socks_stream = TcpStream::connect(socks_addr).await?;
    println!("[SERVER] Connected to SOCKS proxy");

    let (mut tls_r, mut tls_w) = tokio::io::split(tls_stream);
    let (mut socks_r, mut socks_w) = tokio::io::split(socks_stream);

    let t1 = tokio::io::copy(&mut tls_r, &mut socks_w);
    let t2 = tokio::io::copy(&mut socks_r, &mut tls_w);

    tokio::try_join!(t1, t2)?;
    Ok(())
}

// ============ CLIENT SIDE (локально в вашей стране) ============

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

    // Поддержка TLS 1.2 для лучшей совместимости
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(config));
    let listener = TcpListener::bind(bind_addr).await?;

    println!("[CLIENT] Local SOCKS proxy on {}", bind_addr);
    println!("[CLIENT] Tunneling to {}", server_addr);
    if skip_verify {
        println!("[WARNING] Certificate verification DISABLED!");
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        let connector = connector.clone();
        let server = server_addr.to_string();

        tokio::spawn(async move {
            if let Err(e) = handle_local(stream, connector, &server).await {
                eprintln!("[CLIENT] Error from {}: {}", peer, e);
            }
        });
    }
}

async fn handle_local(
    mut local_stream: TcpStream,
    connector: TlsConnector,
    server_addr: &str,
) -> Result<()> {
    let server_name = server_addr.split(':').next().unwrap();
    let tcp_stream = TcpStream::connect(server_addr).await?;

    let domain = rustls::pki_types::ServerName::try_from(server_name.to_string())?;
    let mut tls_stream = connector.connect(domain, tcp_stream).await?;

    println!("[CLIENT] TLS tunnel established");

    let (mut local_r, mut local_w) = tokio::io::split(local_stream);
    let (mut tls_r, mut tls_w) = tokio::io::split(tls_stream);

    let t1 = tokio::io::copy(&mut local_r, &mut tls_w);
    let t2 = tokio::io::copy(&mut tls_r, &mut local_w);

    tokio::try_join!(t1, t2)?;
    Ok(())
}

// ============ HELPER FUNCTIONS ============

// Отключение проверки сертификата (для самоподписанных)
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
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
        eprintln!("Usage:");
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
            "  Client: {} client 127.0.0.1:1080 server.example.com:8443 --insecure",
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
