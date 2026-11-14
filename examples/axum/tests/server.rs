//! The example server over real sockets.

use std::io::{Read, Write};
use std::net::TcpStream;

use modsecurity::RulesSet;

/// Sends a raw HTTP/1.1 request; returns the status code and the body.
fn send(address: std::net::SocketAddr, request: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response[9..12].parse().unwrap();
    let body = response.split_once("\r\n\r\n").map_or("", |(_, b)| b).to_string();
    (status, body)
}

#[test]
fn protects_the_application() {
    let mut rules = RulesSet::new();
    rules
        .load(
            "SecRuleEngine On\nSecRequestBodyAccess On\n\
             SecRule ARGS \"@contains <script>\" \"id:1,phase:2,deny,status:403\"\n\
             SecRule REMOTE_ADDR \"!@ipMatch 127.0.0.1\" \"id:2,phase:1,deny,status:401\"\n\
             SecRule SERVER_PORT \"@eq 0\" \"id:3,phase:1,deny,status:500\"\n",
        )
        .unwrap();

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let address = listener.local_addr().unwrap();
    runtime.spawn(modsecurity_axum_example::serve(listener, modsecurity_axum_example::app(rules)));

    let post = |body: &str| {
        format!(
            "POST /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    };
    assert_eq!(send(address, &post("a=hello")), (200, "a=hello".to_string()));
    assert_eq!(send(address, &post("a=<script>")).0, 403);
    // ARGS are URL-decoded.
    let get = "GET /?q=%3Cscript%3E HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    assert_eq!(send(address, get).0, 403);
}
