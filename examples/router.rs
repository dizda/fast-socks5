#[forbid(unsafe_code)]
#[macro_use]
extern crate log;

use anyhow::{anyhow, Context};
use fast_socks5::{
    client::{self, Socks5Stream},
    server::{Config, SimpleUserPassword, Socks5Server, Socks5Socket},
    Result, SocksError,
};
use std::io::ErrorKind;
use std::net::ToSocketAddrs;
use structopt::StructOpt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task;
use tokio_stream::StreamExt;

/// # How to use it:
///
/// Listen on a local address, authentication-free:
///     `$ RUST_LOG=debug cargo run --example router -- --listen-addr 127.0.0.1:1337 --proxy-addr 127.0.0.1:1338 no-auth`
///
/// Listen on a local address, with basic username/password requirement:
///     `$ RUST_LOG=debug cargo run --example router -- --listen-addr 127.0.0.1:1337 --proxy-addr 127.0.0.1:1338 password --username admin --password password`
///
#[derive(Debug, StructOpt)]
#[structopt(
    name = "socks5-server",
    about = "A simple implementation of a socks5-server."
)]
struct Opt {
    /// Bind on address for incoming traffic. eg. `127.0.0.1:1080`
    #[structopt(short, long)]
    pub listen_addr: String,

    /// Bind on proxy address. eg. `127.0.0.1:1081`
    #[structopt(short, long)]
    pub proxy_addr: String,

    /// Request timeout
    #[structopt(short = "t", long, default_value = "10")]
    pub request_timeout: u64,

    /// Choose authentication type
    #[structopt(subcommand, name = "auth")] // Note that we mark a field as a subcommand
    pub auth: AuthMode,

    /// Don't perform the auth handshake, send directly the command request
    #[structopt(short = "k", long)]
    pub skip_auth: bool,
}

/// Choose the authentication type
#[derive(StructOpt, Debug)]
enum AuthMode {
    NoAuth,
    Password {
        #[structopt(short, long)]
        username: String,

        #[structopt(short, long)]
        password: String,
    },
}

/// Useful read 1. https://blog.yoshuawuyts.com/rust-streams/
/// Useful read 2. https://blog.yoshuawuyts.com/futures-concurrency/
/// Useful read 3. https://blog.yoshuawuyts.com/streams-concurrency/
/// error-libs benchmark: https://blog.yoshuawuyts.com/error-handling-survey/
///
/// TODO: Write functional tests: https://github.com/ark0f/async-socks5/blob/master/src/lib.rs#L762
/// TODO: Write functional tests with cURL?
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    spawn_socks_server().await
}

async fn spawn_socks_server() -> Result<()> {
    let opt: Opt = Opt::from_args();
    let mut config = Config::default();
    config.set_request_timeout(opt.request_timeout);
    config.set_skip_auth(opt.skip_auth);
    config.set_dns_resolve(false);
    config.set_transfer_data(false);

    match opt.auth {
        AuthMode::NoAuth => warn!("No authentication has been set!"),
        AuthMode::Password { username, password } => {
            if opt.skip_auth {
                return Err(SocksError::ArgumentInputError(
                    "Can't use skip-auth flag and authentication altogether.",
                ));
            }

            config.set_authentication(SimpleUserPassword { username, password });
            info!("Simple auth system has been set.");
        }
    }

    let mut listener = Socks5Server::bind(&opt.listen_addr).await?;
    listener.set_config(config);

    let mut incoming = listener.incoming();

    info!(
        "Listen for socks connections @ {}, using proxy @ {}",
        &opt.listen_addr, &opt.proxy_addr
    );

    // Standard TCP loop
    while let Some(socket_res) = incoming.next().await {
        match socket_res {
            Ok(socket) => {
                let proxy_addr = opt.proxy_addr.clone();
                task::spawn(async move {
                    if let Err(err) = handle_socket(socket, proxy_addr).await {
                        error!("socket handle error = {:#}", err);
                    }
                });
            }
            Err(err) => {
                error!("accept error = {:#}", err);
            }
        }
    }

    Ok(())
}

async fn handle_socket<T>(socket: Socks5Socket<T>, proxy_addr: String) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // upgrade socket to SOCKS5 proxy
    let mut socks5_socket = socket
        .upgrade_to_socks5()
        .await
        .context("upgrade incoming socket to socks5")?;

    let unresolved_target_addr = socks5_socket
        .target_addr()
        .context("find unresolved target address for incoming socket")?;
    debug!(
        "incoming request for target address: {}",
        unresolved_target_addr
    );

    // resolve dns
    socks5_socket
        .resolve_dns()
        .await
        .context("resolve target dns for incoming socket")?;

    // get actual socket address
    let target_addr = socks5_socket
        .target_addr()
        .context("find target address for incoming socket")?;
    debug!(
        "incoming request resolved target address to: {}",
        target_addr
    );

    let socket_addr = target_addr
        .to_socket_addrs()
        .context("convert target address of incoming socket to socket addresses")?
        .next()
        .context("reach out to target of incoming socket")?;

    // connect to downstream proxy
    let mut stream = Socks5Stream::connect(
        proxy_addr,
        socket_addr.ip().to_string(),
        socket_addr.port(),
        client::Config::default(),
    )
    .await
    .context("connect to downstream proxy for incoming socket")?;

    // copy data between our incoming client and the used downstream proxy
    match tokio::io::copy_bidirectional(&mut stream, &mut socks5_socket).await {
        Ok(res) => {
            info!("socket transfer closed ({}, {})", res.0, res.1);
            Ok(())
        }
        Err(err) => match err.kind() {
            ErrorKind::NotConnected => {
                info!("socket transfer closed by client");
                Ok(())
            }
            ErrorKind::ConnectionReset => {
                info!("socket transfer closed by downstream proxy");
                Ok(())
            }
            _ => Err(SocksError::Other(anyhow!(
                "socket transfer error: {:#}",
                err
            ))),
        },
    }
}
