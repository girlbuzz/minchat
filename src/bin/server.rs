
use std::io;
use std::fs;
use std::sync::Arc;
use tokio::net;

use tokio::io::AsyncWriteExt;

fn load_certs(filename: &str) -> Vec<pki_types::CertificateDer<'static>> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = io::BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .map(|result| result.unwrap())
        .collect()
}

fn load_private_key(filename: &str) -> pki_types::PrivateKeyDer<'static> {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = io::BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return key.into(),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return key.into(),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return key.into(),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let addr: std::net::SocketAddr = "0.0.0.0:7700".parse().unwrap();

    let certs = load_certs("cert/server.crt");
    let key = load_private_key("cert/server.key");

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::from(config));
    let listener = net::TcpListener::bind(&addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let stream = acceptor.accept(stream).await?;

        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, peer_addr).await {
                eprintln!("{:?}", err);
            }
        });
    }
}

async fn handle_connection(stream: tokio_rustls::server::TlsStream<net::TcpStream>, _addr: std::net::SocketAddr) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let _ = tokio::io::copy(&mut reader, &mut writer).await?;
    writer.flush().await?;

    Ok(())
}
