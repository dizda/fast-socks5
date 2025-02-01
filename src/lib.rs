//! Fast SOCKS5 client/server implementation written in Rust async/.await (with tokio).
//!
//! This library is maintained by [anyip.io](https://anyip.io/) a residential and mobile socks5 proxy provider.
//!
//! ## Features
//!
//! - An `async`/`.await` [SOCKS5](https://tools.ietf.org/html/rfc1928) implementation.
//! - An `async`/`.await` [SOCKS4 Client](https://www.openssh.com/txt/socks4.protocol) implementation.
//! - An `async`/`.await` [SOCKS4a Client](https://www.openssh.com/txt/socks4a.protocol) implementation.
//! - No **unsafe** code
//! - Built on top of the [Tokio](https://tokio.rs/) runtime
//! - Ultra lightweight and scalable
//! - No system dependencies
//! - Cross-platform
//! - Infinitely extensible, explicit server API based on typestates for safety
//!   - You control the request handling, the library only ensures you follow the proper protocol flow
//!   - Can skip DNS resolution
//!   - Can skip the authentication/handshake process (not RFC-compliant, for private use, to save on useless round-trips)
//!   - Instead of proxying in-process, swap out `run_tcp_proxy` for custom handling to build a router or to use a custom accelerated proxying method
//! - Authentication methods:
//!   - No-Auth method (`0x00`)
//!   - Username/Password auth method (`0x02`)
//!   - Custom auth methods can be implemented on the server side via the `AuthMethod` Trait
//!     - Multiple auth methods with runtime negotiation can be supported, with fast *static* dispatch (enums can be generated with the `auth_method_enums` macro)
//! - UDP is supported
//! - All SOCKS5 RFC errors (replies) should be mapped
//! - `IPv4`, `IPv6`, and `Domains` types are supported
//!
//! ## Install
//!
//! Open in [crates.io](https://crates.io/crates/fast-socks5).
//!
//!
//! ## Examples
//!
//! Please check [`examples`](https://github.com/dizda/fast-socks5/tree/master/examples) directory.

#![forbid(unsafe_code)]
#[macro_use]
extern crate log;

pub mod client;
pub mod server;
pub mod util;

#[cfg(feature = "socks4")]
pub mod socks4;

use anyhow::Context;
use std::fmt;
use std::io;
use thiserror::Error;
use util::target_addr::read_address;
use util::target_addr::AddrError;
use util::target_addr::TargetAddr;
use util::target_addr::ToTargetAddr;

use tokio::io::AsyncReadExt;

#[rustfmt::skip]
pub mod consts {
    pub const SOCKS5_VERSION:                          u8 = 0x05;

    pub const SOCKS5_AUTH_METHOD_NONE:                 u8 = 0x00;
    pub const SOCKS5_AUTH_METHOD_GSSAPI:               u8 = 0x01;
    pub const SOCKS5_AUTH_METHOD_PASSWORD:             u8 = 0x02;
    pub const SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE:       u8 = 0xff;

    pub const SOCKS5_CMD_TCP_CONNECT:                  u8 = 0x01;
    pub const SOCKS5_CMD_TCP_BIND:                     u8 = 0x02;
    pub const SOCKS5_CMD_UDP_ASSOCIATE:                u8 = 0x03;

    pub const SOCKS5_ADDR_TYPE_IPV4:                   u8 = 0x01;
    pub const SOCKS5_ADDR_TYPE_DOMAIN_NAME:            u8 = 0x03;
    pub const SOCKS5_ADDR_TYPE_IPV6:                   u8 = 0x04;

    pub const SOCKS5_REPLY_SUCCEEDED:                  u8 = 0x00;
    pub const SOCKS5_REPLY_GENERAL_FAILURE:            u8 = 0x01;
    pub const SOCKS5_REPLY_CONNECTION_NOT_ALLOWED:     u8 = 0x02;
    pub const SOCKS5_REPLY_NETWORK_UNREACHABLE:        u8 = 0x03;
    pub const SOCKS5_REPLY_HOST_UNREACHABLE:           u8 = 0x04;
    pub const SOCKS5_REPLY_CONNECTION_REFUSED:         u8 = 0x05;
    pub const SOCKS5_REPLY_TTL_EXPIRED:                u8 = 0x06;
    pub const SOCKS5_REPLY_COMMAND_NOT_SUPPORTED:      u8 = 0x07;
    pub const SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

#[derive(Debug, PartialEq)]
pub enum Socks5Command {
    TCPConnect,
    TCPBind,
    UDPAssociate,
}

#[allow(dead_code)]
impl Socks5Command {
    #[inline]
    #[rustfmt::skip]
    fn as_u8(&self) -> u8 {
        match self {
            Socks5Command::TCPConnect   => consts::SOCKS5_CMD_TCP_CONNECT,
            Socks5Command::TCPBind      => consts::SOCKS5_CMD_TCP_BIND,
            Socks5Command::UDPAssociate => consts::SOCKS5_CMD_UDP_ASSOCIATE,
        }
    }

    #[inline]
    #[rustfmt::skip]
    fn from_u8(code: u8) -> Option<Socks5Command> {
        match code {
            consts::SOCKS5_CMD_TCP_CONNECT      => Some(Socks5Command::TCPConnect),
            consts::SOCKS5_CMD_TCP_BIND         => Some(Socks5Command::TCPBind),
            consts::SOCKS5_CMD_UDP_ASSOCIATE    => Some(Socks5Command::UDPAssociate),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum AuthenticationMethod {
    None,
    Password { username: String, password: String },
}

impl AuthenticationMethod {
    #[inline]
    #[rustfmt::skip]
    fn as_u8(&self) -> u8 {
        match self {
            AuthenticationMethod::None => consts::SOCKS5_AUTH_METHOD_NONE,
            AuthenticationMethod::Password {..} =>
                consts::SOCKS5_AUTH_METHOD_PASSWORD
        }
    }

    #[inline]
    #[rustfmt::skip]
    fn from_u8(code: u8) -> Option<AuthenticationMethod> {
        match code {
            consts::SOCKS5_AUTH_METHOD_NONE     => Some(AuthenticationMethod::None),
            consts::SOCKS5_AUTH_METHOD_PASSWORD => Some(AuthenticationMethod::Password { username: "test".to_string(), password: "test".to_string()}),
            _                                   => None,
        }
    }
}

impl fmt::Display for AuthenticationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            AuthenticationMethod::None => f.write_str("AuthenticationMethod::None"),
            AuthenticationMethod::Password { .. } => f.write_str("AuthenticationMethod::Password"),
        }
    }
}

//impl Vec<AuthenticationMethod> {
//    pub fn as_bytes(&self) -> &[u8] {
//        self.iter().map(|l| l.as_u8()).collect()
//    }
//}
//
//impl From<&[AuthenticationMethod]> for &[u8] {
//    fn from(_: Vec<AuthenticationMethod>) -> Self {
//        &[0x00]
//    }
//}

#[derive(Error, Debug)]
pub enum SocksError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("the data for key `{0}` is not available")]
    Redaction(String),
    #[error("invalid header (expected {expected:?}, found {found:?})")]
    InvalidHeader { expected: String, found: String },

    #[error("Auth method unacceptable `{0:?}`.")]
    AuthMethodUnacceptable(Vec<u8>),
    #[error("Unsupported SOCKS version `{0}`.")]
    UnsupportedSocksVersion(u8),
    #[error("Domain exceeded max sequence length")]
    ExceededMaxDomainLen(usize),
    #[error("Authentication failed `{0}`")]
    AuthenticationFailed(String),
    #[error("Authentication rejected `{0}`")]
    AuthenticationRejected(String),

    #[error(transparent)]
    AddrError(#[from] AddrError),

    #[error("Error with reply: {0}.")]
    ReplyError(#[from] ReplyError),

    #[cfg(feature = "socks4")]
    #[error("Error with reply: {0}.")]
    ReplySocks4Error(#[from] socks4::ReplyError),

    #[error("Argument input error: `{0}`.")]
    ArgumentInputError(&'static str),

    //    #[error("Other: `{0}`.")]
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T, E = SocksError> = core::result::Result<T, E>;

/// SOCKS5 reply code
#[derive(Error, Debug, Copy, Clone)]
pub enum ReplyError {
    #[error("Succeeded")]
    Succeeded,
    #[error("General failure")]
    GeneralFailure,
    #[error("Connection not allowed by ruleset")]
    ConnectionNotAllowed,
    #[error("Network unreachable")]
    NetworkUnreachable,
    #[error("Host unreachable")]
    HostUnreachable,
    #[error("Connection refused")]
    ConnectionRefused,
    #[error("Connection timeout")]
    ConnectionTimeout,
    #[error("TTL expired")]
    TtlExpired,
    #[error("Command not supported")]
    CommandNotSupported,
    #[error("Address type not supported")]
    AddressTypeNotSupported,
    //    OtherReply(u8),
}

impl ReplyError {
    #[inline]
    #[rustfmt::skip]
    pub fn as_u8(self) -> u8 {
        match self {
            ReplyError::Succeeded               => consts::SOCKS5_REPLY_SUCCEEDED,
            ReplyError::GeneralFailure          => consts::SOCKS5_REPLY_GENERAL_FAILURE,
            ReplyError::ConnectionNotAllowed    => consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
            ReplyError::NetworkUnreachable      => consts::SOCKS5_REPLY_NETWORK_UNREACHABLE,
            ReplyError::HostUnreachable         => consts::SOCKS5_REPLY_HOST_UNREACHABLE,
            ReplyError::ConnectionRefused       => consts::SOCKS5_REPLY_CONNECTION_REFUSED,
            ReplyError::ConnectionTimeout       => consts::SOCKS5_REPLY_TTL_EXPIRED,
            ReplyError::TtlExpired              => consts::SOCKS5_REPLY_TTL_EXPIRED,
            ReplyError::CommandNotSupported     => consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
            ReplyError::AddressTypeNotSupported => consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
//            ReplyError::OtherReply(c)           => c,
        }
    }

    #[inline]
    #[rustfmt::skip]
    pub fn from_u8(code: u8) -> ReplyError {
        match code {
            consts::SOCKS5_REPLY_SUCCEEDED                  => ReplyError::Succeeded,
            consts::SOCKS5_REPLY_GENERAL_FAILURE            => ReplyError::GeneralFailure,
            consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED     => ReplyError::ConnectionNotAllowed,
            consts::SOCKS5_REPLY_NETWORK_UNREACHABLE        => ReplyError::NetworkUnreachable,
            consts::SOCKS5_REPLY_HOST_UNREACHABLE           => ReplyError::HostUnreachable,
            consts::SOCKS5_REPLY_CONNECTION_REFUSED         => ReplyError::ConnectionRefused,
            consts::SOCKS5_REPLY_TTL_EXPIRED                => ReplyError::TtlExpired,
            consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED      => ReplyError::CommandNotSupported,
            consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => ReplyError::AddressTypeNotSupported,
//            _                                               => ReplyError::OtherReply(code),
            _                                               => unreachable!("ReplyError code unsupported."),
        }
    }
}

/// Generate UDP header
///
/// # UDP Request header structure.
/// ```text
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
///
/// The fields in the UDP request header are:
///
///     o  RSV  Reserved X'0000'
///     o  FRAG    Current fragment number
///     o  ATYP    address type of following addresses:
///        o  IP V4 address: X'01'
///        o  DOMAINNAME: X'03'
///        o  IP V6 address: X'04'
///     o  DST.ADDR       desired destination address
///     o  DST.PORT       desired destination port
///     o  DATA     user data
/// ```
pub fn new_udp_header<T: ToTargetAddr>(target_addr: T) -> Result<Vec<u8>> {
    let mut header = vec![
        0, 0, // RSV
        0, // FRAG
    ];
    header.append(&mut target_addr.to_target_addr()?.to_be_bytes()?);

    Ok(header)
}

/// Parse data from UDP client on raw buffer, return (frag, target_addr, payload).
pub async fn parse_udp_request<'a>(mut req: &'a [u8]) -> Result<(u8, TargetAddr, &'a [u8])> {
    let rsv = read_exact!(req, [0u8; 2]).context("Malformed request")?;

    if !rsv.eq(&[0u8; 2]) {
        return Err(ReplyError::GeneralFailure.into());
    }

    let [frag, atyp] = read_exact!(req, [0u8; 2]).context("Malformed request")?;

    let target_addr = read_address(&mut req, atyp).await.map_err(|e| {
        // print explicit error
        error!("{:#}", e);
        // then convert it to a reply
        ReplyError::AddressTypeNotSupported
    })?;

    Ok((frag, target_addr, req))
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use tokio::{
        net::{TcpListener, TcpStream, UdpSocket},
        sync::oneshot::Sender,
    };

    use crate::{client, server, ReplyError, Socks5Command};
    use std::{
        net::{SocketAddr, ToSocketAddrs},
        num::ParseIntError,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;
    use tokio_test::block_on;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    async fn setup_socks_server(proxy_addr: &str, tx: Sender<SocketAddr>) -> Result<()> {
        let reply_ip = proxy_addr.parse::<SocketAddr>().unwrap().ip();

        let listener = TcpListener::bind(proxy_addr).await?;
        tx.send(listener.local_addr()?).unwrap();

        loop {
            let (stream, _) = listener.accept().await?; // NOTE: not spawning for test
            let proto = server::Socks5ServerProtocol::accept_no_auth(stream).await?;
            let (proto, cmd, mut target_addr) = proto.read_command().await?;
            target_addr = target_addr.resolve_dns().await?;
            match cmd {
                Socks5Command::TCPConnect => {
                    server::run_tcp_proxy(proto, &target_addr, 10, false).await?;
                }
                Socks5Command::UDPAssociate => {
                    server::run_udp_proxy(proto, &target_addr, reply_ip).await?;
                }
                Socks5Command::TCPBind => {
                    proto.reply_error(&ReplyError::CommandNotSupported).await?;
                }
            }
        }
    }

    async fn google(mut socket: TcpStream) -> Result<()> {
        socket.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
        let mut result = vec![];
        socket.read_to_end(&mut result).await?;

        println!("{}", String::from_utf8_lossy(&result));
        assert!(result.starts_with(b"HTTP/1.0"));
        assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));

        Ok(())
    }

    #[test]
    fn google_no_auth() {
        init();
        block_on(async {
            let (tx, rx) = oneshot::channel();
            tokio::spawn(setup_socks_server("[::1]:0", tx));

            let socket = client::Socks5Stream::connect(
                rx.await.unwrap(),
                "google.com".to_owned(),
                80,
                client::Config::default(),
            )
            .await
            .unwrap();
            google(socket.get_socket()).await.unwrap();
        });
    }

    #[test]
    fn mock_udp_assosiate_no_auth() {
        init();
        block_on(async {
            const MOCK_ADDRESS: &str = "[::1]:40235";

            let (tx, rx) = oneshot::channel();
            tokio::spawn(setup_socks_server("[::1]:0", tx));
            let backing_socket = TcpStream::connect(rx.await.unwrap()).await.unwrap();

            // Creates a UDP tunnel which can be used to forward UDP packets, "[::]:0" indicates the
            // binding source address used to communicate with the socks5 server.
            let tunnel = client::Socks5Datagram::bind(backing_socket, "[::]:0")
                .await
                .unwrap();
            let mock_udp_server = UdpSocket::bind(MOCK_ADDRESS).await.unwrap();

            tunnel
                .send_to(
                    b"hello world!",
                    MOCK_ADDRESS.to_socket_addrs().unwrap().next().unwrap(),
                )
                .await
                .unwrap();
            println!("Send packet to {}", MOCK_ADDRESS);

            let mut buf = [0; 13];
            let (len, addr) = mock_udp_server.recv_from(&mut buf).await.unwrap();
            assert_eq!(len, 12);
            assert_eq!(&buf[..12], b"hello world!");

            mock_udp_server
                .send_to(b"hello world!", addr)
                .await
                .unwrap();

            println!("Recieve packet from {}", MOCK_ADDRESS);
            let len = tunnel.recv_from(&mut buf).await.unwrap().0;
            assert_eq!(len, 12);
            assert_eq!(&buf[..12], b"hello world!");
        });
    }

    #[test]
    fn dns_udp_assosiate_no_auth() {
        init();
        block_on(async {
            const DNS_SERVER: &str = "1.1.1.1:53";

            let (tx, rx) = oneshot::channel();
            tokio::spawn(setup_socks_server("[::1]:0", tx));
            let backing_socket = TcpStream::connect(rx.await.unwrap()).await.unwrap();

            // Creates a UDP tunnel which can be used to forward UDP packets, "[::]:0" indicates the
            // binding source address used to communicate with the socks5 server.
            let tunnel = client::Socks5Datagram::bind(backing_socket, "[::]:0")
                .await
                .unwrap();

            #[rustfmt::skip]
            tunnel.send_to(
                &decode_hex(&(
                    "AAAA".to_owned()   // ID
                    + "0100"            // Query parameters
                    + "0001"            // Number of questions
                    + "0000"            // Number of answers
                    + "0000"            // Number of authority records
                    + "0000"            // Number of additional records
                    + "076578616d706c65"// Length + hex("example")
                    + "03636f6d00"      // Length + hex("com") + zero byte
                    + "0001"            // QTYPE
                    + "0001"            // QCLASS
                ))
                .unwrap(),
                DNS_SERVER.to_socket_addrs().unwrap().next().unwrap(),
            ).await.unwrap();
            println!("Send packet to {}", DNS_SERVER);

            let mut buf = [0; 128];
            println!("Recieve packet from {}", DNS_SERVER);
            tunnel.recv_from(&mut buf).await.unwrap();
            println!("dns response {:?}", buf);

            #[rustfmt::skip]
            assert!(buf.starts_with(&decode_hex(&(
                "AAAA".to_owned()   // ID
                + "8180"            // FLAGS: RCODE=0, No errors reported
                + "0001"            // One question
            )).unwrap()));
        });
    }

    fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }
}
