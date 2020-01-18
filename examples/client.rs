#[forbid(unsafe_code)]
#[macro_use]
extern crate log;

use anyhow::Context;
use async_std::task;
use fast_socks5::client::Config;
use fast_socks5::{client::Socks5Stream, Result};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use structopt::StructOpt;

/// # How to use it:
///
/// GET / of web server by IPv4 address:
///   `$ RUST_LOG=debug cargo run --example client -- --socks-server 127.0.0.1:1337 --username admin --password password -a 208.97.177.124 -p 80`
///
/// GET / of web server by IPv6 address:
///   `$ RUST_LOG=debug cargo run --example client -- --socks-server 127.0.0.1:1337 --username admin --password password -a ::ffff:208.97.177.124 -p 80`
///
/// GET / of web server by domain name:
///   `$ RUST_LOG=debug cargo run --example client -- --socks-server 127.0.0.1:1337 --username admin --password password -a perdu.com -p 80`
///
#[derive(Debug, StructOpt)]
#[structopt(name = "socks5-client", about = "A simple example of a socks5-client.")]
struct Opt {
    /// Socks5 server address + port. eg. `127.0.0.1:1080`
    #[structopt(short, long)]
    pub socks_server: String,

    /// Target address server (not the socks server)
    #[structopt(short = "a", long)]
    pub target_addr: String,

    /// Target port server (not the socks server)
    #[structopt(short = "p", long)]
    pub target_port: u16,

    #[structopt(short, long)]
    pub username: Option<String>,

    #[structopt(long)]
    pub password: Option<String>,

    /// Don't perform the auth handshake, send directly the command request
    #[structopt(short = "k", long)]
    pub skip_auth: bool,
}

fn main() -> Result<()> {
    env_logger::init();

    task::block_on(spawn_socks_client())
}

async fn spawn_socks_client() -> Result<()> {
    let opt: Opt = Opt::from_args();
    let domain = opt.target_addr.clone();
    let mut socks;
    let mut config = Config::default();
    config.set_skip_auth(opt.skip_auth);

    // Creating a SOCKS stream to the target address thru the socks server
    if opt.username.is_some() {
        socks = Socks5Stream::connect_with_password(
            opt.socks_server,
            opt.target_addr,
            opt.target_port,
            opt.username.unwrap(),
            opt.password.expect("Please fill the password"),
            config,
        )
        .await?;
    } else {
        socks = Socks5Stream::connect(opt.socks_server, opt.target_addr, opt.target_port, config)
            .await?;
    }

    // Once connection is completed, can start to communicate with the server
    http_request(&mut socks, domain).await?;

    Ok(())
}

/// Simple HTTP request
async fn http_request<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    domain: String,
) -> Result<()> {
    debug!("Requesting body...");

    // construct our request, with a dynamic domain
    let mut headers = vec![];
    headers.extend_from_slice("GET / HTTP/1.1\r\nHost: ".as_bytes());
    headers.extend_from_slice(domain.as_bytes());
    headers
        .extend_from_slice("\r\nUser-Agent: fast-socks5/0.1.0\r\nAccept: */*\r\n\r\n".as_bytes());

    // flush headers
    stream
        .write_all(&headers)
        .await
        .context("Can't write HTTP Headers")?;

    debug!("Reading body response...");
    let mut result = [0u8; 1024];
    // warning: read_to_end() method sometimes await forever when the web server
    // doesn't write EOF char (\r\n\r\n).
    // read() seems more appropriate
    stream
        .read(&mut result)
        .await
        .context("Can't read HTTP Response")?;

    info!("Response: {}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.1"));
    //assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));

    Ok(())
}
