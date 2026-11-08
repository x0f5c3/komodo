#![cfg_attr(test, allow(unused_crate_dependencies))]

use std::{
  path::PathBuf,
  sync::{Arc, Mutex},
};

use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use pingora_core::{
  server::Server,
  services::{background::background_service, listening::Service},
};
use pingora_proxy::{HttpProxy, http_proxy_service};

mod config;
mod proxy;
mod stream;

fn main() -> anyhow::Result<()> {
  env_logger::Builder::from_env(
    env_logger::Env::default().default_filter_or("info"),
  )
  .init();
  let mut path = PathBuf::from("/etc/komodo-proxy/routes.json");
  let mut check = false;
  let mut health_check = false;
  let mut http_listen: std::net::SocketAddr =
    "0.0.0.0:8080".parse()?;
  let mut https_listen: std::net::SocketAddr =
    "0.0.0.0:8443".parse()?;
  let mut args = std::env::args().skip(1);
  while let Some(arg) = args.next() {
    match arg.as_str() {
      "--config" => {
        path = args.next().context("--config requires a path")?.into()
      }
      "--check" => check = true,
      "--http-listen" => {
        http_listen = args
          .next()
          .context("--http-listen requires an address")?
          .parse()?
      }
      "--https-listen" => {
        https_listen = args
          .next()
          .context("--https-listen requires an address")?
          .parse()?
      }
      "--health" => health_check = true,
      _ => bail!("Unknown proxy argument: {arg}"),
    }
  }
  if health_check {
    return health(http_listen);
  }
  let source = config::Source::read(&path)?;
  let snapshot = source.compile()?;
  if check {
    return Ok(());
  }
  let state = Arc::new(ArcSwap::from_pointee(snapshot));
  let mut server = Server::new(None)?;
  server.bootstrap();
  let mut http = HttpProxy::new(
    proxy::Proxy {
      state: state.clone(),
      redirect: false,
    },
    server.configuration.clone(),
  );
  http.handle_init_modules();
  let mut ingress = Service::new(
    "Komodo TLS".into(),
    proxy::Ingress {
      state: state.clone(),
      http: Arc::new(http),
    },
  );
  ingress.add_tcp(&https_listen.to_string());
  server.add_service(ingress);
  let mut redirect = http_proxy_service(
    &server.configuration,
    proxy::Proxy {
      state: state.clone(),
      redirect: true,
    },
  );
  redirect.add_tcp(&http_listen.to_string());
  server.add_service(redirect);
  server.add_service(background_service(
    "Reload routes and certificates",
    config::Reload {
      path,
      state,
      initial: Mutex::new(Some(source)),
    },
  ));
  server.run_forever();
}

fn health(mut address: std::net::SocketAddr) -> anyhow::Result<()> {
  use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
  };
  if address.ip().is_unspecified() {
    address.set_ip(if address.is_ipv4() {
      std::net::Ipv4Addr::LOCALHOST.into()
    } else {
      std::net::Ipv6Addr::LOCALHOST.into()
    });
  }
  let mut stream =
    TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
  stream.set_read_timeout(Some(Duration::from_secs(2)))?;
  stream.set_write_timeout(Some(Duration::from_secs(2)))?;
  stream.write_all(b"GET / HTTP/1.1\r\nHost: health.invalid\r\nConnection: close\r\n\r\n")?;
  let mut bytes = [0; 12];
  stream.read_exact(&mut bytes)?;
  if !bytes.starts_with(b"HTTP/1.1 ") {
    bail!("Proxy HTTP listener is not responding");
  }
  Ok(())
}
