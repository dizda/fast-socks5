use tokio::net::{TcpListener};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use std::time::Duration;
use tokio::time::timeout;
use tokio_test::assert_ok;
use fast_socks5::client::{Config, Socks5Stream};

#[tokio::test]
async fn test_socks5_connection() -> io::Result<()> {
    let socks_server = TcpListener::bind("127.0.0.1:0").await?;
    let addr = socks_server.local_addr()?;

    tokio::spawn(async move {
        let (mut stream, _) = socks_server.accept().await.expect("Server accept failed");
        let mut buf = [0u8; 100];

        let bytes_read = stream.read(&mut buf).await.expect("Read initial handshake");
        assert_eq!(&buf[..bytes_read], [0x05, 0x01, 0x00]);
        stream.write_all(&[0x05, 0x00]).await.expect("Write handshake response");

        let bytes_read = stream.read(&mut buf).await.expect("Read request");
        assert_eq!(&buf[..bytes_read], &[0x05, 0x01, 0x00, 0x03, 0x05, b't', b'e', b'.', b's', b't', 0x00, 0x50]);
        stream.write_all(&[0x05,0x00,0x00,0x01,0xff, 0x00,0x00,0x01,0x00,0x50]).await.expect("Write response");

        let bytes_read = stream.read(&mut buf).await.expect("Read 'get' request");
        assert_eq!(&buf[..bytes_read], &[b'g', b'e', b't']);
        stream.write_all(b"all ok").await.expect("Write 'all ok'");
        stream.shutdown().await.expect("Shutdown stream");
    });

    let mut socks_client = assert_ok!(Socks5Stream::connect(
        addr,
        "te.st".to_string(),
        80,
        Config::default()
    ).await);
    socks_client.write_all(b"get").await?;

    let mut resp = String::new();
    timeout(Duration::from_secs(1), async {
        socks_client.read_to_string(&mut resp).await.expect("Read response");
    }).await?;

    assert_eq!(resp, "all ok");
    Ok(())
}
