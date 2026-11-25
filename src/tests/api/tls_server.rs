use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

fn self_signed_listener() -> (Arc<ServerConfig>, TcpListener, String) {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key.into())
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    (config, listener, url)
}

// Serves HTTPS on a loopback port with a fresh self-signed certificate and returns its URL.
pub fn serve_self_signed_https() -> String {
    let (config, listener, url) = self_signed_listener();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut tls = StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), stream);
            // a client rejecting the certificate aborts the handshake, so this read fails
            let mut request = [0u8; 4096];
            if tls.read(&mut request).is_ok() {
                let _ = tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        }
    });
    url
}

/// What the scripted server does with one request, in arrival order.
#[derive(Clone, Debug)]
pub enum Step {
    /// Reads the request, then closes the connection without an answer.
    Drop,
    /// Answers this status and body after the delay.
    Respond {
        status: u16,
        body: String,
        delay: Duration,
    },
}

impl Step {
    pub fn status(status: u16, body: &str) -> Step {
        Step::Respond {
            status,
            body: body.to_string(),
            delay: Duration::ZERO,
        }
    }

    pub fn delayed(delay: Duration, status: u16, body: &str) -> Step {
        Step::Respond {
            status,
            body: body.to_string(),
            delay,
        }
    }
}

/// One request the scripted server received: its request line, its body, and the status it
/// answered (None when the step dropped it).
#[derive(Clone, Debug)]
pub struct Received {
    pub request_line: String,
    pub body: String,
    pub answered: Option<u16>,
}

fn read_request(tls: &mut StreamOwned<ServerConnection, TcpStream>) -> Option<(String, String)> {
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = tls.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&chunk[..n]);
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let head = String::from_utf8_lossy(&data[..header_end]).to_string();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    while data.len() < header_end + content_length {
        let n = tls.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..n]);
    }
    let request_line = head.lines().next().unwrap_or_default().to_string();
    let body = String::from_utf8_lossy(&data[header_end..]).to_string();
    Some((request_line, body))
}

/// Serves HTTPS with a self-signed certificate, playing `steps` one per request, then answering
/// 500 to any extra request. Returns the URL and the log of the requests received.
pub fn serve_scripted_https(steps: Vec<Step>) -> (String, Arc<Mutex<Vec<Received>>>) {
    let (config, listener, url) = self_signed_listener();
    let received = Arc::new(Mutex::new(Vec::new()));
    let log = received.clone();
    let mut steps: VecDeque<Step> = steps.into();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut tls = StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), stream);
            let Some((request_line, body)) = read_request(&mut tls) else {
                continue;
            };
            let step = steps
                .pop_front()
                .unwrap_or_else(|| Step::status(500, "script exhausted"));
            match step {
                Step::Drop => {
                    log.lock().unwrap().push(Received {
                        request_line,
                        body,
                        answered: None,
                    });
                    let _ = tls.sock.shutdown(std::net::Shutdown::Both);
                }
                Step::Respond {
                    status,
                    body: answer,
                    delay,
                } => {
                    thread::sleep(delay);
                    log.lock().unwrap().push(Received {
                        request_line,
                        body,
                        answered: Some(status),
                    });
                    let response = format!(
                        "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                        answer.len()
                    );
                    let _ = tls.write_all(response.as_bytes());
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                }
            }
        }
    });
    (url, received)
}
