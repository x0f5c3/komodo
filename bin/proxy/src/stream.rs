use std::{
  io::{self, Cursor},
  pin::Pin,
  sync::Arc,
  task::{Context, Poll},
};

use anyhow::{Context as _, bail};
use async_trait::async_trait;
use pingora_core::protocols::{
  GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown,
  SocketDigest, Ssl, Stream, TimingDigest, UniqueID, UniqueIDType,
  raw_connect::ProxyDigest,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

pub async fn client_hello(
  mut stream: Stream,
) -> anyhow::Result<(String, Replay)> {
  let mut acceptor = rustls::server::Acceptor::default();
  let mut prefix = Vec::new();
  loop {
    if prefix.len() >= 65_536 {
      bail!("TLS ClientHello exceeds 64 KiB");
    }
    let mut bytes = [0; 4096];
    let limit = bytes.len().min(65_536 - prefix.len());
    let count = stream.read(&mut bytes[..limit]).await?;
    if count == 0 {
      bail!("Connection closed before TLS ClientHello");
    }
    prefix.extend_from_slice(&bytes[..count]);
    let mut input = Cursor::new(&bytes[..count]);
    while input.position() < count as u64 {
      if acceptor.read_tls(&mut input)? == 0 {
        bail!("TLS ClientHello reader made no progress");
      }
      if let Some(accepted) =
        acceptor.accept().map_err(|(error, _)| {
          anyhow::anyhow!("Invalid TLS ClientHello: {error}")
        })?
      {
        let domain = accepted
          .client_hello()
          .server_name()
          .context("TLS routing requires SNI")?
          .to_ascii_lowercase();
        return Ok((
          domain,
          Replay {
            prefix: Cursor::new(prefix),
            inner: stream,
          },
        ));
      }
    }
  }
}

#[derive(Debug)]
pub struct Replay {
  prefix: Cursor<Vec<u8>>,
  inner: Stream,
}

impl AsyncRead for Replay {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    if self.prefix.position() < self.prefix.get_ref().len() as u64 {
      Pin::new(&mut self.prefix).poll_read(cx, buf)
    } else {
      Pin::new(&mut self.inner).poll_read(cx, buf)
    }
  }
}

impl AsyncWrite for Replay {
  fn poll_write(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &[u8],
  ) -> Poll<io::Result<usize>> {
    Pin::new(&mut self.inner).poll_write(cx, buf)
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_flush(cx)
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<io::Result<()>> {
    Pin::new(&mut self.inner).poll_shutdown(cx)
  }
}

#[async_trait]
impl Shutdown for Replay {
  async fn shutdown(&mut self) {
    self.inner.shutdown().await;
  }
}
impl UniqueID for Replay {
  fn id(&self) -> UniqueIDType {
    self.inner.id()
  }
}
impl Ssl for Replay {}
impl Peek for Replay {}
impl GetTimingDigest for Replay {
  fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
    self.inner.get_timing_digest()
  }
}
impl GetProxyDigest for Replay {
  fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
    self.inner.get_proxy_digest()
  }
}
impl GetSocketDigest for Replay {
  fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
    self.inner.get_socket_digest()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rustls::{
    ClientConfig, ClientConnection, RootCertStore,
    pki_types::ServerName,
  };
  use tokio::io::AsyncWriteExt;

  #[tokio::test]
  async fn recognizes_fragmented_hello_and_replays_every_byte() {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let config =
      ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let mut client = ClientConnection::new(
      Arc::new(config),
      ServerName::try_from("app.example.com").unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let (mut writer, reader) = tokio::io::duplex(128);
    let expected = hello.clone();
    let sender = tokio::spawn(async move {
      for chunk in hello.chunks(7) {
        writer.write_all(chunk).await.unwrap();
        tokio::task::yield_now().await;
      }
      writer.write_all(b"after hello").await.unwrap();
    });
    let (domain, mut replay) =
      client_hello(Box::new(reader)).await.unwrap();
    assert_eq!(domain, "app.example.com");
    let mut bytes = Vec::new();
    replay.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..expected.len()], expected);
    assert_eq!(&bytes[expected.len()..], b"after hello");
    sender.await.unwrap();
  }

  #[tokio::test]
  async fn rejects_plaintext_and_incomplete_handshakes() {
    assert!(
      client_hello(Box::new(Cursor::new(
        b"GET / HTTP/1.1\r\n".to_vec()
      )))
      .await
      .is_err()
    );
    assert!(
      client_hello(Box::new(Cursor::new(Vec::<u8>::new())))
        .await
        .is_err()
    );
  }
}
