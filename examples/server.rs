#[forbid(unsafe_code)]
#[macro_use]
extern crate log;

use fast_socks5::{
    server::{Config, SimpleUserPassword, Socks5Server, Socks5Socket},
    Result, SocksError,
};
use std::future::Future;
use std::net::SocketAddr;
use std::str::FromStr;
use structopt::StructOpt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task;
use tokio_stream::StreamExt;

/// # How to use it:
///
/// Listen on a local address, authentication-free:
///     `$ RUST_LOG=debug cargo run --example server -- --listen-addr 127.0.0.1:1337 no-auth`
///
/// Listen on a local address, with basic username/password requirement:
///     `$ RUST_LOG=debug cargo run --example server -- --listen-addr 127.0.0.1:1337 password --username admin --password password`
///
#[derive(Debug, StructOpt)]
#[structopt(
    name = "socks5-server",
    about = "A simple implementation of a socks5-server."
)]
struct Opt {
    /// Bind on address address. eg. `127.0.0.1:1080`
    #[structopt(short, long)]
    pub listen_addr: String,

    /// Request timeout
    #[structopt(short = "t", long, default_value = "10")]
    pub request_timeout: u64,

    /// Choose authentication type
    #[structopt(subcommand, name = "auth")] // Note that we mark a field as a subcommand
    pub auth: AuthMode,

    /// Don't perform the auth handshake, send directly the command request
    #[structopt(short = "k", long)]
    pub skip_auth: bool,

    /// Outgoing address
    #[structopt(short, long)]
    pub outgoing_addr: Option<String>,
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

    if let Some(outgoing_addr) = opt.outgoing_addr {
        config.set_outgoing_addr(Some(SocketAddr::from_str(&outgoing_addr)?));
    }

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

    info!("Listen for socks connections @ {}", &opt.listen_addr);

    // Standard TCP loop
    while let Some(socket_res) = incoming.next().await {
        match socket_res {
            Ok(socket) => {
                spawn_and_log_error(socket.upgrade_to_socks5());
            }
            Err(err) => {
                error!("accept error = {:?}", err);
            }
        }
    }

    Ok(())
}

fn spawn_and_log_error<F, T>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<Socks5Socket<T>>> + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin,
{
    task::spawn(async move {
        if let Err(e) = fut.await {
            error!("{:#}", &e);
        }
    })
}
