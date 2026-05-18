/// DNS-over-TLS (RFC 7858) — listens on port 853, frames DNS messages with the
/// same 2-byte length prefix as plain TCP. Each accepted TLS connection is
/// handed to the existing DNS query pipeline.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig as TlsServerConfig, ServerConnection, StreamOwned};

use crate::server::{State, handle_query_public};
use crate::threadpool::ThreadPool;

pub fn run(bind: String, cert_path: String, key_path: String, state: Arc<State>, pool: Arc<ThreadPool>) {
    let tls_cfg = match load_tls_config(&cert_path, &key_path) {
        Ok(c) => Arc::new(c),
        Err(e) => { eprintln!("[dot] TLS config: {}", e); return; }
    };

    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => { eprintln!("[dot] bind {}: {}", bind, e); return; }
    };
    eprintln!("[dot] listening on {}", bind);

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let tls_cfg = Arc::clone(&tls_cfg);
        let state = Arc::clone(&state);
        let peer_ip = stream.peer_addr().map(|a| a.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        pool.submit(move || {
            let conn = match ServerConnection::new(tls_cfg) {
                Ok(c) => c,
                Err(e) => { eprintln!("[dot] tls handshake init: {}", e); return; }
            };
            let mut tls = StreamOwned::new(conn, stream);
            handle_tls_stream(&mut tls, &state, peer_ip);
        });
    }
}

fn handle_tls_stream<S: Read + Write>(tls: &mut S, state: &State, peer_ip: IpAddr) {
    loop {
        let mut len_buf = [0u8; 2];
        if tls.read_exact(&mut len_buf).is_err() { return; }
        let qlen = u16::from_be_bytes(len_buf) as usize;
        if qlen == 0 { return; }
        let mut data = vec![0u8; qlen];
        if tls.read_exact(&mut data).is_err() { return; }

        state.metrics.record_tcp_query();
        if let Some(resp) = handle_query_public(&data, state, peer_ip) {
            let rlen = (resp.len() as u16).to_be_bytes();
            if tls.write_all(&rlen).is_err() { return; }
            if tls.write_all(&resp).is_err() { return; }
        }
    }
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<TlsServerConfig, String> {
    let cert_file = File::open(cert_path).map_err(|e| format!("open cert: {}", e))?;
    let mut cr = BufReader::new(cert_file);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cr)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("parse cert: {}", e))?;

    let key_file = File::open(key_path).map_err(|e| format!("open key: {}", e))?;
    let mut kr = BufReader::new(key_file);
    let key: PrivateKeyDer = rustls_pemfile::private_key(&mut kr)
        .map_err(|e| format!("parse key: {}", e))?
        .ok_or_else(|| "no private key in PEM".to_string())?;

    // Install the default crypto provider for this process if not yet set.
    let _ = rustls::crypto::ring::default_provider().install_default();

    TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls config: {}", e))
}
