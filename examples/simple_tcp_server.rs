#[forbid(unsafe_code)]
#[macro_use]
extern crate log;

use fast_socks5::{
    server::{Authentication, Config, SimpleUserPassword, Socks5Socket},
    Result,
};
use std::future::Future;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::task;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};

/// # How to use it:
///
/// Listen on a local address, authentication-free:
///     `$ RUST_LOG=debug cargo run --example simple_tcp_server -- --listen-addr 127.0.0.1:1337 no-auth`
///
/// Listen on a local address, with basic username/password requirement:
///     `$ RUST_LOG=debug cargo run --example simple_tcp_server -- --listen-addr 127.0.0.1:1337 password --username admin --password password`
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
/// TODO: Command to use the socks server with a simple user/password
/// TODO: Write functional tests: https://github.com/ark0f/async-socks5/blob/master/src/lib.rs#L762
/// TODO: Write functional tests with cURL?
/// TODO: Move this to as a standalone library
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    spawn_socks_server().await
}

async fn spawn_socks_server() -> Result<()> {
    let opt: Opt = Opt::from_args();
    let mut config = Config::default();
    config.set_request_timeout(opt.request_timeout);

    let config = match opt.auth {
        AuthMode::NoAuth => {
            warn!("No authentication has been set!");
            config
        }
        AuthMode::Password { username, password } => {
            info!("Simple auth system has been set.");
            config.with_authentication(SimpleUserPassword { username, password })
        }
    };

    let config = Arc::new(config);

    let listener = TcpListener::bind(&opt.listen_addr).await?;
    //    listener.set_config(config);

    info!("Listen for socks connections @ {}", &opt.listen_addr);

    // Standard TCP loop
    loop {
        match listener.accept().await {
            Ok((socket, _addr)) => {
                info!("Connection from {}", socket.peer_addr()?);
                let socket = Socks5Socket::new(socket, config.clone());

                spawn_and_log_error(socket.upgrade_to_socks5());
            }
            Err(err) => error!("accept error = {:?}", err),
        }
    }
}

fn spawn_and_log_error<F, T, A>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<Socks5Socket<T, A>>> + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send,
    A: Authentication,
{
    task::spawn(async move {
        if let Err(e) = fut.await {
            error!("{:#}", &e);
        }
    })
}
