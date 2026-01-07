// Cargo.toml dependencies:
// tokio = { version = "1", features = ["full"] }
// tokio-rustls = "0.25"
// rustls = "0.22"
// rustls-pemfile = "2.0"
// anyhow = "1.0"

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Invalid cert/key")?;

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

pub async fn run_client(bind_addr: &str, server_addr: &str) -> Result<()> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let listener = TcpListener::bind(bind_addr).await?;

    println!("[CLIENT] Local SOCKS proxy on {}", bind_addr);
    println!("[CLIENT] Tunneling to {}", server_addr);

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
        eprintln!("  Client: {} client <bind_addr> <server_addr>", args[0]);
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
                eprintln!("Client needs: <bind_addr> <server_addr>");
                std::process::exit(1);
            }
            run_client(&args[2], &args[3]).await?;
        }
        _ => {
            eprintln!("Unknown mode. Use 'server' or 'client'");
            std::process::exit(1);
        }
    }

    Ok(())
}
