/// DNS-over-HTTPS (RFC 8484) — minimal HTTP/1.1 server over TLS that accepts
/// `POST /dns-query` with `application/dns-message`. GET with base64url `?dns=`
/// is also supported.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig as TlsServerConfig, ServerConnection, StreamOwned};

use crate::server::{State, handle_query_public};
use crate::threadpool::ThreadPool;

pub fn run(bind: String, cert_path: String, key_path: String, state: Arc<State>, pool: Arc<ThreadPool>) {
    let tls_cfg = match load_tls_config(&cert_path, &key_path) {
        Ok(c) => Arc::new(c),
        Err(e) => { eprintln!("[doh] TLS config: {}", e); return; }
    };

    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => { eprintln!("[doh] bind {}: {}", bind, e); return; }
    };
    eprintln!("[doh] listening on https://{}/dns-query", bind);

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let tls_cfg = Arc::clone(&tls_cfg);
        let state = Arc::clone(&state);
        let peer_ip = stream.peer_addr().map(|a| a.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        pool.submit(move || {
            let conn = match ServerConnection::new(tls_cfg) {
                Ok(c) => c,
                Err(e) => { eprintln!("[doh] tls handshake init: {}", e); return; }
            };
            let mut tls = StreamOwned::new(conn, stream);
            handle_http(&mut tls, &state, peer_ip);
        });
    }
}

fn handle_http<S: Read + Write>(s: &mut S, state: &State, peer_ip: IpAddr) {
    let mut buf = vec![0u8; 8192];
    let mut total = 0usize;

    // Read until we have full headers.
    let header_end = loop {
        let n = match s.read(&mut buf[total..]) {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };
        total += n;
        if let Some(idx) = find_double_crlf(&buf[..total]) { break idx; }
        if total == buf.len() { write_status(s, 431, "Request Header Fields Too Large"); return; }
    };

    let header_str = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s.to_string(),
        Err(_) => { write_status(s, 400, "Bad Request"); return; }
    };
    let mut lines = header_str.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    let mut content_length = 0usize;
    let mut content_type = String::new();
    for line in lines {
        if let Some(v) = strip_header(line, "content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = strip_header(line, "content-type:") {
            content_type = v.trim().to_ascii_lowercase();
        }
    }

    let dns_msg: Vec<u8> = match method {
        "POST" if target.starts_with("/dns-query") => {
            if content_type != "application/dns-message" {
                write_status(s, 415, "Unsupported Media Type"); return;
            }
            let body_start = header_end + 4;
            let already = total.saturating_sub(body_start);
            let mut body = buf[body_start..total].to_vec();
            while body.len() < content_length {
                let mut tmp = vec![0u8; content_length - body.len()];
                match s.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                    Err(_) => return,
                }
            }
            let _ = already;
            body.truncate(content_length);
            body
        }
        "GET" if target.starts_with("/dns-query?") => {
            let qs = &target["/dns-query?".len()..];
            let dns_param = qs.split('&').find_map(|kv| kv.strip_prefix("dns="));
            match dns_param.and_then(|p| URL_SAFE_NO_PAD.decode(p).ok()) {
                Some(b) => b,
                None => { write_status(s, 400, "Bad Request"); return; }
            }
        }
        _ => { write_status(s, 404, "Not Found"); return; }
    };

    state.metrics.record_tcp_query();
    let resp_body = handle_query_public(&dns_msg, state, peer_ip).unwrap_or_default();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp_body.len()
    );
    let _ = s.write_all(header.as_bytes());
    let _ = s.write_all(&resp_body);
}

fn find_double_crlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

fn strip_header<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    if line.len() < prefix.len() { return None; }
    if line[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&line[prefix.len()..])
    } else { None }
}

fn write_status<S: Write>(s: &mut S, code: u16, reason: &str) {
    let _ = write!(s, "HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, reason);
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

    let _ = rustls::crypto::ring::default_provider().install_default();

    TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls config: {}", e))
}
