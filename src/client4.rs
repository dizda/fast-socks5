#[forbid(unsafe_code)]
use crate::read_exact;
use crate::util::target_addr::{read_address, TargetAddr, ToTargetAddr};
use crate::{consts, new_udp_header, parse_udp_request, AuthenticationMethod, ReplyError, Result, SocksError, Socks4Command};
use anyhow::Context;
use std::io;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::task::Poll;
use env_logger::Target;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const MAX_ADDR_LEN: usize = 260;

/// A SOCKS4 client.
/// `Socks4Stream` implements [`AsyncRead`] and [`AsyncWrite`].
#[derive(Debug)]
pub struct Socks4Stream<S: AsyncRead + AsyncWrite + Unpin> {
    socket: S,
    target_addr: Option<TargetAddr>,
}

impl<S> Socks4Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Possibility to use a stream already created rather than
    /// creating a whole new `TcpStream::connect()`.
    pub fn use_stream(
        socket: S,
    ) -> Result<Self> {
        let mut stream = Socks4Stream {
            socket,
            target_addr: None,
        };
        Ok(stream)
    }

    /// https://www.openssh.com/txt/socks4.protocol
    /// https://www.openssh.com/txt/socks4a.protocol
    ///
    /// 1) CONNECT
    ///
    ///           +----+----+----+----+----+----+----+----+----+----+....+----+
    ///           | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
    ///           +----+----+----+----+----+----+----+----+----+----+....+----+
    /// #of bytes    1    1      2              4           variable       1
    ///
    ///   VN is the SOCKS protocol version number and should be 4. CD is the
    ///   SOCKS command code and should be 1 for CONNECT request. NULL is a byte
    ///   of all zero bits.
    ///
    ///   The SOCKS server checks to see whether such a request should be granted
    ///   based on any combination of source IP address, destination IP address,
    ///   destination port number, the userid, and information it may obtain by
    ///   consulting IDENT, cf. RFC 1413.  If the request is granted, the SOCKS
    ///   server makes a connection to the specified port of the destination host.
    ///   A reply packet is sent to the client when this connection is established,
    ///   or when the request is rejected or the operation fails.
    ///
    ///  Response:
    ///
    ///           +----+----+----+----+----+----+----+----+
    ///           | VN | CD | DSTPORT |      DSTIP        |
    ///           +----+----+----+----+----+----+----+----+
    /// #of bytes    1    1      2              4
    ///
    ///   VN is the version of the reply code and should be 0. CD is the result
    ///   code with one of the following values:
    ///
    ///   	90: request granted
    ///   	91: request rejected or failed
    ///   	92: request rejected becasue SOCKS server cannot connect to
    ///   	    identd on the client
    ///   	93: request rejected because the client program and identd
    ///  	    report different user-ids
    ///
    pub async fn request(
        &mut self,
        cmd: Socks4Command,
        target_addr: TargetAddr,
        resolve_locally:  bool,
    ) -> Result<()> {
        let resolved = if target_addr.is_domain() && resolve_locally {
            target_addr.resolve_dns().await?
        } else {
            target_addr
        };
        self.target_addr = Some(resolved);
        self.send_command_request(&cmd).await?;
        self.read_command_request().await?;

        Ok(())
    }

    async fn send_command_request(&mut self, cmd: &Socks4Command) -> Result<()> {
        let mut packet = [0u8; MAX_ADDR_LEN + 3];
        packet[0] = consts::SOCKS4_VERSION;
        packet[1] = cmd.as_u8();

        match &self.target_addr {
            Some(TargetAddr::Ip(SocketAddr::V4(addr))) => {
                packet[2] = (addr.port() >> 8) as u8;
                packet[3] = addr.port() as u8;
                packet[4..8].copy_from_slice(&(addr.ip()).octets());
                Ok(())
            }
            Some(TargetAddr::Ip(SocketAddr::V6(addr))) => {
                // TODO: use other error
                Err(SocksError::ReplyError(ReplyError::AddressTypeNotSupported))
            }
            Some(TargetAddr::Domain(domain, port)) => {
                println!("domain");
                packet[2] = (port >> 8) as u8;
                packet[3] = *port as u8;
                packet[4..8].copy_from_slice(&[0, 0, 0, 1]);
                packet[8..domain.len()].copy_from_slice(domain.as_bytes());
                Ok(())
            }
            _ => { panic!("Unreachable case"); }
        }?;
        self.socket.write_all(&packet).await?;
        Ok(())
    }

    async fn read_command_request(&mut self) -> Result<()> {
        let [vn, cd, p0, p1, i0, i1, i2, i3] = read_exact!(self.socket, [0u8; 8])?;
        match cd {
            90 => Ok(()),
            // TODO: use separate replies for Socks4
            91 => Err(SocksError::ReplyError(ReplyError::ConnectionRefused)),
            92 => Err(SocksError::ReplyError(ReplyError::HostUnreachable)),
            93 => Err(SocksError::ReplyError(ReplyError::RejectDifferentUserId)),
            _  => Err(SocksError::ReplyError(ReplyError::UnknownResponse)),
        }
    }

    pub fn get_socket(self) -> S {
        self.socket
    }

    pub fn get_socket_ref(&self) -> &S {
        &self.socket
    }

    pub fn get_socket_mut(&mut self) -> &mut S {
        &mut self.socket
    }
}

/// Api if you want to use TcpStream to create a new connection to the SOCKS4 server.
impl Socks4Stream<TcpStream> {
    /// Connects to a target server through a SOCKS4 proxy.
    pub async fn connect<T>(
        socks_server: T,
        target_addr: String,
        target_port: u16,
        resolve_locally: bool,
    ) -> Result<Self>
    where
        T: ToSocketAddrs,
    {
        Self::connect_raw(
            Socks4Command::Connect,
            socks_server,
            target_addr,
            target_port,
            resolve_locally,
        )
        .await
    }

    /// Process clients SOCKS requests
    /// This is the entry point where a whole request is processed.
    pub async fn connect_raw<T>(
        cmd: Socks4Command,
        socks_server: T,
        target_addr: String,
        target_port: u16,
        resolve_locally: bool,
    ) -> Result<Self>
    where
        T: ToSocketAddrs,
    {
        let socket = TcpStream::connect(
            socks_server
                .to_socket_addrs()?
                .next()
                .context("unreachable")?,
        )
        .await?;
        info!("Connected @ {}", &socket.peer_addr()?);

        // Specify the target, here domain name, dns will be resolved on the server side
        let target_addr = (target_addr.as_str(), target_port)
            .to_target_addr()
            .context("Can't convert address to TargetAddr format")?;

        // upgrade the TcpStream to Socks4Stream
        let mut socks_stream = Self::use_stream(socket)?;
        socks_stream.request(cmd, target_addr, resolve_locally).await?;

        Ok(socks_stream)
    }
}

/// Allow us to read directly from the struct
impl<S> AsyncRead for Socks4Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.socket).poll_read(context, buf)
    }
}

/// Allow us to write directly into the struct
impl<S> AsyncWrite for Socks4Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(context, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(context)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    pub async fn test_query() {
        // TODO: replace with local socks4 server
        //       it requires implementation
        let tcp = TcpStream::connect("217.17.56.160:4145")
            .await
            .expect("should connect to remote");

        let mut socks = Socks4Stream::use_stream(tcp)
            .expect("should wrap to socks stream");

        let domain = "www.google.com";
        socks.request(
            Socks4Command::Connect,
            TargetAddr::Domain(domain.to_string(), 80),
            true
        ).await.expect("should send connect successfully");


        let headers =
                format!("GET /humans.txt HTTP/1.1\r\n\
                         Host: {}\r\n\
                         User-Agent: fast-socks5/0.1.0\r\n\
                         Accept: */*\r\n\r\n",
                domain);

        println!("{:?}", headers);
        socks
            .write_all(headers.as_bytes())
            .await
            .expect("should successfully write");

        let mut response = &mut [0u8; 2048];
        socks.read(response)
            .await
            .expect("should successfully read");

        let response_str = String::from_utf8_lossy(response);
        let response_body = response_str
            .split("\n")
            .into_iter()
            .filter(|x| x.starts_with("Google"))
            .last();

        assert!(response_body.is_some(), "should contain response body");

        let expected =
            "Google is built by a large team of engineers, designers, researchers, robots, \
        and others in many different sites across the globe. It is updated continuously, \
        and built with more tools and technologies than we can shake a stick at. If you'd \
        like to help us out, see careers.google.com.";
        assert_eq!(expected, response_body.unwrap());
    }
}