use std::io::Write;
use std::net;
use std::io;
use std::fs;
use std::sync::Arc;

use std::io::Read as _;

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

fn main() -> io::Result<()> {
    let mut listener = mio::net::TcpListener::bind("0.0.0.0:7700".parse().unwrap())
        .expect("failed to bind addr");

    let suites = rustls::crypto::ring::ALL_CIPHER_SUITES.to_vec();
    let versions = rustls::ALL_VERSIONS.to_vec();

    let client_cert_verifier = rustls::server::WebPkiClientVerifier::no_client_auth();

    let cert_chain = load_certs("cert/server.crt");
    let key_der = load_private_key("cert/server.key");

    let config = Arc::new(rustls::ServerConfig::builder_with_provider(
            rustls::crypto::CryptoProvider {
                cipher_suites: suites,
                ..rustls::crypto::ring::default_provider()
            }
            .into()
        ).with_protocol_versions(&versions)
        .expect("inconsistent cipher-suites/versions specified")
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(cert_chain, key_der)
        .expect("bad certificates/private key"));

    let mut poll = mio::Poll::new().unwrap();

    let mut events = mio::Events::with_capacity(1024);

    poll.registry().register(&mut listener, mio::Token(0), mio::Interest::READABLE).unwrap();

    let mut streams: std::collections::HashMap<usize, (mio::net::TcpStream, rustls::server::ServerConnection)> = std::collections::HashMap::new();
    let mut inc: usize = 1;

    loop {
        poll.poll(&mut events, None).unwrap();

        for event in &events {
            match event.token() {
                mio::Token(0) => {
                    let (mut stream, _) = listener.accept().unwrap();
                    let tls_conn = rustls::server::ServerConnection::new(config.clone()).unwrap();
                    poll.registry().register(&mut stream, mio::Token(inc), mio::Interest::READABLE | mio::Interest::WRITABLE).unwrap();
                    streams.insert(inc, (stream, tls_conn));
                    inc += 1;
                },
                mio::Token(n) => {
                    let mut shutdown = false;

                    if event.is_writable() {
                        let (stream, tls) = streams.get_mut(&n).unwrap();
                        tls.write_tls(stream).unwrap();
                    }

                    if event.is_readable() {
                        let (stream, tls) = streams.get_mut(&n).unwrap();
                        let mut buf = [0u8; 1024];

                        tls.read_tls(stream).unwrap();
                        tls.process_new_packets().unwrap();

                        let size = match tls.reader().read(&mut buf) {
                            Ok(sz) => sz,
                            Err(e) => {
                                if e.kind() == io::ErrorKind::WouldBlock {
                                    0
                                } else if e.kind() == io::ErrorKind::UnexpectedEof {
                                    poll.registry().deregister(stream).unwrap();
                                    stream.shutdown(net::Shutdown::Both).unwrap();
                                    shutdown = true;
                                    0
                                } else {
                                    panic!("{:?}", e);
                                }
                            }
                        };

                        if shutdown {
                            streams.remove(&n);
                        } else {
                            tls.writer().write(&buf[..size]).unwrap();
                            tls.write_tls(stream).unwrap();
                        }
                    }
                }
            }
        }
    }
}
