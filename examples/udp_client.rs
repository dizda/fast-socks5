#[forbid(unsafe_code)]
#[macro_use]
extern crate log;

use fast_socks5::{client::Socks5Datagram, Result};
use structopt::StructOpt;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

/// # How to use it:
///
/// Query by IPv4 address:
///   `$ RUST_LOG=debug cargo run --example udp_client -- --socks-server 127.0.0.1:1337 --username admin --password password -a 8.8.8.8 -d github.com`
///
/// Query by IPv6 address:
///   `$ RUST_LOG=debug cargo run --example udp_client -- --socks-server 127.0.0.1:1337 --username admin --password password -a 2001:4860:4860::8888 -d github.com`
///
/// Query by domain name:
///   `$ RUST_LOG=debug cargo run --example udp_client -- --socks-server 127.0.0.1:1337 --username admin --password password -a dns.google -d github.com`
///
#[derive(Debug, StructOpt)]
#[structopt(
    name = "socks5-udp-client",
    about = "A simple example of a socks5 UDP client (proxied DNS client)."
)]
struct Opt {
    /// Socks5 server address + port, e.g. `127.0.0.1:1080`
    #[structopt(short, long)]
    pub socks_server: String,

    /// Target (DNS) server address, e.g. `8.8.8.8`
    #[structopt(short = "a", long)]
    pub target_server: String,

    /// Target (DNS) server port, by default 53
    #[structopt(short = "p", long)]
    pub target_port: Option<u16>,

    #[structopt(short = "d", long)]
    pub query_domain: String,

    #[structopt(short, long)]
    pub username: Option<String>,

    #[structopt(long)]
    pub password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    spawn_socks_client().await
}

async fn spawn_socks_client() -> Result<()> {
    let opt: Opt = Opt::from_args();

    // Creating a SOCKS stream to the target address through the socks server
    let backing_socket = TcpStream::connect(opt.socks_server).await?;
    let mut socks = match opt.username {
        Some(username) => {
            Socks5Datagram::bind_with_password(
                backing_socket,
                "[::]:0",
                &username,
                &opt.password.expect("Please fill the password"),
            )
            .await?
        }

        _ => Socks5Datagram::bind(backing_socket, "[::]:0").await?,
    };

    // Once socket creation is completed, can start to communicate with the server
    dns_request(
        &mut socks,
        opt.target_server,
        opt.target_port.unwrap_or(53),
        opt.query_domain,
    )
    .await?;

    Ok(())
}

/// Simple DNS request
async fn dns_request<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut Socks5Datagram<S>,
    server: String,
    port: u16,
    domain: String,
) -> Result<()> {
    debug!("Requesting results...");

    let mut query: Vec<u8> = vec![
        0x13, 0x37, // txid
        0x01, 0x00, // flags
        0x00, 0x01, // questions
        0x00, 0x00, // answer RRs
        0x00, 0x00, // authority RRs
        0x00, 0x00, // additional RRs
    ];
    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend(part.chars().map(|c| c as u8));
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    debug!("query: {:?}", query);

    let _sent = socket.send_to(&query, (&server[..], port)).await?;

    let mut buf = [0u8; 256];
    let (len, adr) = socket.recv_from(&mut buf).await?;
    let msg = &buf[..len];
    info!("response: {:?} from {:?}", msg, adr);

    assert_eq!(msg[0], 0x13);
    assert_eq!(msg[1], 0x37);

    Ok(())
}
