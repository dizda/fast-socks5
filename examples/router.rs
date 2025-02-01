#[forbid(unsafe_code)]
#[macro_use]
extern crate log;

use fast_socks5::{
    client,
    server::{transfer, Socks5ServerProtocol},
    util::target_addr::TargetAddr,
    ReplyError, Result, Socks5Command, SocksError,
};
use std::{
    collections::HashSet,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use structopt::StructOpt;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::RwLock,
    task,
};

/// # How to use it:
///
/// Listen on a local address, authentication-free:
///     `$ RUST_LOG=debug cargo run --example router -- --listen-addr 127.0.0.1:1080 no-auth`
///
/// Listen on a local address, with basic username/password requirement:
///     `$ RUST_LOG=debug cargo run --example router -- --listen-addr 127.0.0.1:1080 password --username admin --password password`
///
/// Now, connections will be refused since there are no backends.
///
/// Run a backend proxy, with skipped authentication mode (-k):
///     `$ RUST_LOG=debug cargo run --example server -- --listen-addr 127.0.0.1:1337 --public-addr 127.0.0.1 -k no-auth`
///
/// Connect to the secret admin console and add the backend:
///     `$ socat --experimental SOCKS5-CONNECT:127.0.0.1:admin.internal:1234 READLINE`
///     `ADD 127.0.0.1:1337`
///
/// You can add more backends and they'll be used in a round-robin fashion.
///
#[derive(Debug, StructOpt)]
#[structopt(
    name = "socks5-router",
    about = "A socks5 demo 'router' proxying requests to further downstream socks5 servers."
)]
struct Opt {
    /// Bind on address address. eg. `127.0.0.1:1080`
    #[structopt(short, long)]
    pub listen_addr: String,

    /// Choose authentication type
    #[structopt(subcommand, name = "auth")] // Note that we mark a field as a subcommand
    pub auth: AuthMode,
}

/// Choose the authentication type
#[derive(StructOpt, Debug, PartialEq)]
enum AuthMode {
    NoAuth,
    Password {
        #[structopt(short, long)]
        username: String,

        #[structopt(short, long)]
        password: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    spawn_socks_server().await
}

async fn spawn_socks_server() -> Result<()> {
    let opt: &'static Opt = Box::leak(Box::new(Opt::from_args()));

    let backends = Arc::new(RwLock::new(HashSet::new()));

    let listener = TcpListener::bind(&opt.listen_addr).await?;

    info!("Listen for socks connections @ {}", &opt.listen_addr);

    // Standard TCP loop
    loop {
        match listener.accept().await {
            Ok((socket, _client_addr)) => {
                spawn_and_log_error(serve_socks5(opt, backends.clone(), socket));
            }
            Err(err) => {
                error!("accept error = {:?}", err);
            }
        }
    }
}

static CONN_NUM: AtomicUsize = AtomicUsize::new(0);

async fn serve_socks5(
    opt: &Opt,
    backends: Arc<RwLock<HashSet<String>>>,
    socket: tokio::net::TcpStream,
) -> Result<(), SocksError> {
    let (proto, cmd, target_addr) = match &opt.auth {
        AuthMode::NoAuth => Socks5ServerProtocol::accept_no_auth(socket).await?,
        AuthMode::Password { username, password } => {
            Socks5ServerProtocol::accept_password_auth(socket, |user, pass| {
                user == *username && pass == *password
            })
            .await?
            .0
        }
    }
    .read_command()
    .await?;

    if cmd != Socks5Command::TCPConnect {
        proto.reply_error(&ReplyError::CommandNotSupported).await?;
        return Err(ReplyError::CommandNotSupported.into());
    }

    // Not the most reasonable way to implement an admin interface,
    // but rather an example of conditional interception (i.e. just
    // not proxying at all and doing something else in-process).
    if let TargetAddr::Domain(ref domain, _) = target_addr {
        if domain == "admin.internal" {
            let inner = proto
                .reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
                .await?;
            return serve_admin_console(backends, inner).await;
        }
    }

    let (target_addr, target_port) = target_addr.into_string_and_port();

    let backends = backends.read().await;
    let backends: Vec<_> = backends.iter().collect(); // not good but this is just a demo
    if backends.is_empty() {
        warn!("No backends! Go add one using the console");
        proto.reply_error(&ReplyError::NetworkUnreachable).await?;
        return Ok(());
    }
    let n = CONN_NUM.fetch_add(1, Ordering::SeqCst);

    let mut config = client::Config::default();
    config.set_skip_auth(true);
    let client = client::Socks5Stream::connect(
        backends[n % backends.len()],
        target_addr,
        target_port,
        config,
    )
    .await?;
    drop(backends);

    let inner = proto
        .reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
        .await?;

    transfer(inner, client).await
}

async fn serve_admin_console(
    backends: Arc<RwLock<HashSet<String>>>,
    socket: tokio::net::TcpStream,
) -> Result<(), SocksError> {
    let mut stream = tokio::io::BufReader::new(socket);
    stream.write_all(b"Welcome to the router admin console! Use LIST, ADD, or REMOVE commands to manage proxies.\n").await?;
    let mut buf = String::with_capacity(128);
    while let Ok(_) = stream.read_line(&mut buf).await {
        if buf.starts_with("LIST") {
            let backends = backends.read().await;
            for addr in backends.iter() {
                stream.write_all(addr.as_bytes()).await?;
                stream.write_all(b"\n").await?;
            }
        } else if buf.starts_with("ADD ") {
            let mut backends = backends.write().await;
            if let Some(adr) = buf.strip_prefix("ADD ") {
                backends.insert(adr.trim().to_owned());
            }
        } else if buf.starts_with("REMOVE ") {
            let mut backends = backends.write().await;
            if let Some(adr) = buf.strip_prefix("REMOVE ") {
                backends.remove(adr.trim());
            }
        }
        buf.clear();
    }
    Ok(())
}

fn spawn_and_log_error<F>(fut: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    task::spawn(async move {
        match fut.await {
            Ok(()) => {}
            Err(err) => error!("{:#}", &err),
        }
    })
}
