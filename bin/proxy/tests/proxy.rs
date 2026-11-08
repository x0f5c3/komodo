#![cfg(unix)]
#![allow(unused_crate_dependencies)]

use std::{
  fs,
  io::{Read, Write},
  net::{SocketAddr, TcpListener, TcpStream},
  path::Path,
  process::{Child, Command, Stdio},
  time::{Duration, Instant},
};

use axum::{
  Json, Router,
  body::Bytes,
  extract::ws::WebSocketUpgrade,
  http::{HeaderMap, Uri},
  response::IntoResponse,
  routing::get,
};
use openssl::{
  asn1::Asn1Time,
  bn::BigNum,
  hash::MessageDigest,
  pkey::PKey,
  ssl::{
    SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode,
  },
  x509::{X509, X509NameBuilder, extension::SubjectAlternativeName},
};
use reqwest::{Client, Version, tls::TlsInfo};
use serde_json::{Value, json};

struct ProxyProcess(Child);

impl Drop for ProxyProcess {
  fn drop(&mut self) {
    let _ = self.0.kill();
    let _ = self.0.wait();
  }
}

fn certificate(directory: &Path, serial: u32) -> Vec<u8> {
  fs::create_dir_all(directory).unwrap();
  let key = PKey::generate_ed25519().unwrap();
  let mut name = X509NameBuilder::new().unwrap();
  name.append_entry_by_text("CN", "app.example.com").unwrap();
  let name = name.build();
  let mut cert = X509::builder().unwrap();
  cert.set_version(2).unwrap();
  let serial =
    BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap();
  cert.set_serial_number(&serial).unwrap();
  cert.set_subject_name(&name).unwrap();
  cert.set_issuer_name(&name).unwrap();
  cert.set_pubkey(&key).unwrap();
  cert
    .set_not_before(&Asn1Time::days_from_now(0).unwrap())
    .unwrap();
  cert
    .set_not_after(&Asn1Time::days_from_now(7).unwrap())
    .unwrap();
  let san = SubjectAlternativeName::new()
    .dns("app.example.com")
    .dns("pass.example.com")
    .dns("ws.example.com")
    .build(&cert.x509v3_context(None, None))
    .unwrap();
  cert.append_extension(san).unwrap();
  cert.sign(&key, MessageDigest::null()).unwrap();
  let cert = cert.build();
  fs::write(directory.join("tls.crt"), cert.to_pem().unwrap())
    .unwrap();
  fs::write(
    directory.join("tls.key"),
    key.private_key_to_pem_pkcs8().unwrap(),
  )
  .unwrap();
  cert.to_der().unwrap()
}

fn unused_address() -> SocketAddr {
  TcpListener::bind("127.0.0.1:0")
    .unwrap()
    .local_addr()
    .unwrap()
}

fn client(address: SocketAddr, http1: bool) -> Client {
  let builder = Client::builder()
    .no_proxy()
    .danger_accept_invalid_certs(true)
    .timeout(Duration::from_secs(5))
    .pool_max_idle_per_host(0)
    .tls_info(true)
    .resolve("app.example.com", address)
    .resolve("pass.example.com", address);
  if http1 { builder.http1_only() } else { builder }
    .build()
    .unwrap()
}

fn write_config(
  path: &Path,
  certs: &Path,
  origin: SocketAddr,
  passthrough: SocketAddr,
  https: SocketAddr,
  prefix: &str,
) {
  let config = json!({
    "https_port": https.port(),
    "routes": [
      { "domain": "app.example.com", "upstream": format!("http://{origin}{prefix}"), "certificate_directory": certs },
      { "domain": "ws.example.com", "upstream": format!("http://{origin}"), "certificate_directory": certs },
      { "domain": "pass.example.com", "upstream": passthrough.to_string(), "certificate_directory": null }
    ]
  });
  let temporary = path.with_extension("tmp");
  fs::write(&temporary, serde_json::to_vec(&config).unwrap())
    .unwrap();
  fs::rename(temporary, path).unwrap();
}

async fn echo(
  uri: Uri,
  headers: HeaderMap,
  body: Bytes,
) -> Json<Value> {
  Json(json!({
    "path": uri.to_string(), "length": body.len(),
    "forwarded_for": headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
    "proto": headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()),
    "forwarded": headers.get("forwarded").and_then(|v| v.to_str().ok()),
  }))
}

async fn websocket(upgrade: WebSocketUpgrade) -> impl IntoResponse {
  upgrade.on_upgrade(|mut socket| async move {
    while let Some(Ok(message)) = socket.recv().await {
      if socket.send(message).await.is_err() {
        break;
      }
    }
  })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routes_tls_http2_websockets_and_rotates_without_restarting()
{
  let temp = tempfile::tempdir().unwrap();
  let certs = temp.path().join("certificates");
  let first = certificate(&certs.join("v1"), 1);
  let second = certificate(&certs.join("v2"), 2);
  std::os::unix::fs::symlink("v1", certs.join("current")).unwrap();
  let passthrough_cert =
    certificate(&temp.path().join("passthrough"), 3);
  let mut acceptor =
    SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
  acceptor
    .set_certificate_chain_file(
      temp.path().join("passthrough/tls.crt"),
    )
    .unwrap();
  acceptor
    .set_private_key_file(
      temp.path().join("passthrough/tls.key"),
      SslFiletype::PEM,
    )
    .unwrap();
  let acceptor = acceptor.build();
  let passthrough = TcpListener::bind("127.0.0.1:0").unwrap();
  let passthrough_address = passthrough.local_addr().unwrap();
  passthrough.set_nonblocking(true).unwrap();
  let tls_origin = std::thread::spawn(move || {
    let deadline = Instant::now() + Duration::from_secs(20);
    let stream = loop {
      match passthrough.accept() {
        Ok((stream, _)) => break stream,
        Err(error)
          if error.kind() == std::io::ErrorKind::WouldBlock
            && Instant::now() < deadline =>
        {
          std::thread::sleep(Duration::from_millis(20))
        }
        Err(error) => panic!("Passthrough origin: {error}"),
      }
    };
    stream
      .set_read_timeout(Some(Duration::from_secs(5)))
      .unwrap();
    stream
      .set_write_timeout(Some(Duration::from_secs(5)))
      .unwrap();
    let mut tls = acceptor.accept(stream).unwrap();
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
      let mut byte = [0];
      tls.read_exact(&mut byte).unwrap();
      request.push(byte[0]);
    }
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\npassthrough").unwrap();
  });
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let origin = listener.local_addr().unwrap();
  let application =
    Router::new().route("/ws", get(websocket)).fallback(echo);
  let origin_task = tokio::spawn(async move {
    axum::serve(listener, application).await.unwrap()
  });
  let http = unused_address();
  let https = unused_address();
  let config = temp.path().join("routes.json");
  write_config(
    &config,
    &certs,
    origin,
    passthrough_address,
    https,
    "/base",
  );
  let logs = temp.path().join("proxy.log");
  let child = Command::new(env!("CARGO_BIN_EXE_proxy"))
    .args([
      "--config",
      config.to_str().unwrap(),
      "--http-listen",
      &http.to_string(),
      "--https-listen",
      &https.to_string(),
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(fs::File::create(&logs).unwrap())
    .spawn()
    .unwrap();
  let mut process = ProxyProcess(child);
  let direct = Client::builder()
    .no_proxy()
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .unwrap();
  let deadline = Instant::now() + Duration::from_secs(10);
  loop {
    if direct.get(format!("http://{http}/")).send().await.is_ok() {
      break;
    }
    assert!(
      process.0.try_wait().unwrap().is_none(),
      "Proxy exited: {}",
      fs::read_to_string(&logs).unwrap()
    );
    assert!(Instant::now() < deadline, "Proxy startup timed out");
    tokio::time::sleep(Duration::from_millis(50)).await;
  }
  let response = direct
    .get(format!("http://{http}/a?q=1"))
    .header("host", "app.example.com")
    .send()
    .await
    .unwrap();
  assert_eq!(response.status(), 308);
  assert_eq!(
    response.headers()["location"],
    format!("https://app.example.com:{}/a?q=1", https.port())
  );
  assert_eq!(
    direct
      .get(format!("http://{http}/"))
      .header("host", "unknown.example.com")
      .send()
      .await
      .unwrap()
      .status(),
    404
  );
  let http1 = client(https, true);
  let app =
    format!("https://app.example.com:{}/echo?q=1", https.port());
  let response = http1
    .post(&app)
    .header("x-forwarded-for", "spoofed")
    .header("forwarded", "for=spoofed")
    .body(vec![b'x'; 256 * 1024])
    .send()
    .await
    .unwrap();
  assert_eq!(
    response
      .extensions()
      .get::<TlsInfo>()
      .unwrap()
      .peer_certificate()
      .unwrap(),
    first
  );
  let body: Value = response.json().await.unwrap();
  assert_eq!(body["path"], "/base/echo?q=1");
  assert_eq!(body["length"], 256 * 1024);
  assert_eq!(body["forwarded_for"], "127.0.0.1");
  assert_eq!(body["proto"], "https");
  assert!(body["forwarded"].is_null());
  let response = client(https, false).get(&app).send().await.unwrap();
  assert_eq!(response.version(), Version::HTTP_2);
  assert_eq!(response.status(), 200);
  let response = http1
    .get(&app)
    .header("host", "ws.example.com")
    .send()
    .await
    .unwrap();
  assert_eq!(response.status(), 421);
  let response = http1
    .get(format!("https://pass.example.com:{}/", https.port()))
    .send()
    .await
    .unwrap();
  assert_eq!(
    response
      .extensions()
      .get::<TlsInfo>()
      .unwrap()
      .peer_certificate()
      .unwrap(),
    passthrough_cert
  );
  assert_eq!(response.text().await.unwrap(), "passthrough");
  tls_origin.join().unwrap();

  let mut connector =
    SslConnector::builder(SslMethod::tls()).unwrap();
  connector.set_verify(SslVerifyMode::NONE);
  let tcp = TcpStream::connect(https).unwrap();
  tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
  tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
  let tls = connector.build().connect("ws.example.com", tcp).unwrap();
  let (mut socket, response) =
    tokio_tungstenite::tungstenite::client::client(
      format!("wss://ws.example.com:{}/ws", https.port()),
      tls,
    )
    .unwrap();
  assert_eq!(response.status(), 101);
  socket
    .send(tokio_tungstenite::tungstenite::Message::Text(
      "hello".into(),
    ))
    .unwrap();
  assert_eq!(socket.read().unwrap().into_text().unwrap(), "hello");

  std::os::unix::fs::symlink("v2", certs.join("next")).unwrap();
  fs::rename(certs.join("next"), certs.join("current")).unwrap();
  write_config(
    &config,
    &certs,
    origin,
    passthrough_address,
    https,
    "/changed",
  );
  let deadline = Instant::now() + Duration::from_secs(5);
  loop {
    let response = http1.get(&app).send().await.unwrap();
    let cert = response
      .extensions()
      .get::<TlsInfo>()
      .unwrap()
      .peer_certificate()
      .unwrap()
      .to_vec();
    let body: Value = response.json().await.unwrap();
    if body["path"] == "/changed/echo?q=1" && cert == second {
      break;
    }
    assert!(
      Instant::now() < deadline,
      "Proxy did not reload routes and certificate"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }
  fs::write(&config, b"{").unwrap();
  tokio::time::sleep(Duration::from_millis(1500)).await;
  assert_eq!(http1.get(&app).send().await.unwrap().status(), 200);
  assert!(
    fs::read_to_string(&logs)
      .unwrap()
      .contains("reload rejected")
  );
  assert!(
    !Command::new(env!("CARGO_BIN_EXE_proxy"))
      .args(["--check", "--config", config.to_str().unwrap()])
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .status()
      .unwrap()
      .success()
  );
  assert!(process.0.try_wait().unwrap().is_none());
  socket
    .send(tokio_tungstenite::tungstenite::Message::Text(
      "still connected".into(),
    ))
    .unwrap();
  assert_eq!(
    socket.read().unwrap().into_text().unwrap(),
    "still connected"
  );
  socket.close(None).unwrap();
  origin_task.abort();
}
