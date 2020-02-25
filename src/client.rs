#[forbid(unsafe_code)]
use crate::read_exact;
use crate::util::target_addr::{read_address, TargetAddr, ToTargetAddr};
use crate::{consts, AuthenticationMethod, ReplyError, Result, SocksError};
use anyhow::Context;
use async_std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use futures::{task::Poll, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::io;
use std::pin::Pin;

const MAX_ADDR_LEN: usize = 260;

#[derive(Debug)]
pub struct Config {
    /// Avoid useless roundtrips if we don't need the Authentication layer
    /// make sure to also activate it on the server side.
    skip_auth: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { skip_auth: false }
    }
}

impl Config {
    pub fn set_skip_auth(&mut self, value: bool) -> &mut Self {
        self.skip_auth = value;
        self
    }
}

/// A SOCKS5 client.
/// `Socks5Stream` implements [`AsyncRead`] and [`AsyncWrite`].
#[derive(Debug)]
pub struct Socks5Stream<S: AsyncRead + AsyncWrite + Unpin> {
    socket: S,
    target_addr: TargetAddr,
    config: Config,
}

impl<S> Socks5Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Possibility to use a stream already created rather than
    /// creating a whole new `TcpStream::connect()`.
    pub async fn use_stream(
        socket: S,
        target_addr: TargetAddr,
        auth: Option<AuthenticationMethod>,
        config: Config,
    ) -> Result<Self> {
        let mut stream = Socks5Stream {
            socket,
            target_addr,
            config,
        };

        // Auth none is always used by default.
        let mut methods = vec![AuthenticationMethod::None];

        if let Some(method) = auth {
            // add any other method if supplied
            methods.push(method);
        }

        // Handshake Lifecycle
        if stream.config.skip_auth == false {
            let methods = stream.send_version_and_methods(methods).await?;
            stream.which_method_accepted(methods).await?;
        } else {
            debug!("skipping auth");
        }

        // Request Lifecycle
        info!("Requesting headers `{:?}`...", &stream.target_addr);
        stream.request_header().await?;
        stream.read_request_reply().await?;

        Ok(stream)
    }

    /// Decide to whether or not, accept the authentication method
    /// A client send a list of methods that he supports, he could send
    ///
    ///   - 0: Non auth
    ///   - 2: Auth with username/password
    ///
    /// Altogether, then the server choose to use of of these,
    /// or deny the handshake (thus the connection).
    ///
    /// # Examples
    ///
    ///                    {SOCKS Version, methods-length}
    ///     eg. (non-auth) {5, 2}
    ///     eg. (auth)     {5, 3}
    ///
    async fn send_version_and_methods(
        &mut self,
        methods: Vec<AuthenticationMethod>,
    ) -> Result<Vec<AuthenticationMethod>> {
        debug!(
            "Send version and method len [{}, {}]",
            consts::SOCKS5_VERSION,
            methods.len()
        );
        // write the first 2 bytes which contains the SOCKS version and the methods len()
        self.socket
            .write(&[consts::SOCKS5_VERSION, methods.len() as u8])
            .await
            .context("Couldn't write SOCKS version & methods len")?;

        let auth = methods.iter().map(|l| l.as_u8()).collect::<Vec<_>>();

        debug!("client auth methods supported: {:?}", &auth);
        self.socket
            .write(&auth)
            .await
            .context("Couldn't write supported auth methods")?;

        // Return methods available
        Ok(methods)
    }

    /// Decide to whether or not, accept the authentication method.
    /// Don't forget that the methods list sent by the client, contains one or more methods.
    ///
    /// # Request
    ///
    ///  Client send an array of 3 entries: [0, 1, 2]
    ///
    ///                          {SOCKS Version,  Authentication chosen}
    ///     eg. (non-auth)       {5, 0}
    ///     eg. (GSSAPI)         {5, 1}
    ///     eg. (auth)           {5, 2}
    ///
    /// # Response
    ///
    ///     eg. (accept non-auth) {5, 0x00}
    ///     eg. (non-acceptable)  {5, 0xff}
    ///
    async fn which_method_accepted(&mut self, methods: Vec<AuthenticationMethod>) -> Result<()> {
        let [version, method] =
            read_exact!(self.socket, [0u8; 2]).context("Can't get chosen auth method")?;
        debug!(
            "Socks version ({version}), method chosen: {method}.",
            version = version,
            method = method,
        );

        if version != consts::SOCKS5_VERSION {
            return Err(SocksError::UnsupportedSocksVersion(version));
        }

        match method {
            consts::SOCKS5_AUTH_METHOD_NONE => info!("No auth will be used"),
            consts::SOCKS5_AUTH_METHOD_PASSWORD => self.use_password_auth(methods).await?,
            _ => {
                debug!("Don't support this auth method, reply with (0xff)");
                self.socket
                    .write(&[
                        consts::SOCKS5_VERSION,
                        consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE,
                    ])
                    .await
                    .context("Can't write that the methods are unsupported.")?;

                return Err(SocksError::AuthMethodUnacceptable(vec![method]))?;
            }
        }

        Ok(())
    }

    async fn use_password_auth(&mut self, methods: Vec<AuthenticationMethod>) -> Result<()> {
        info!("Password will be used");
        let (username, password) = match methods[1] {
            AuthenticationMethod::None => unreachable!(),
            AuthenticationMethod::Password {
                ref username,
                ref password,
            } => (username, password),
        };

        let user_bytes = username.as_bytes();
        let pass_bytes = password.as_bytes();

        // send username len
        self.socket
            .write(&[1, user_bytes.len() as u8])
            .await
            .context("Can't send username len")?;
        self.socket
            .write(user_bytes)
            .await
            .context("Can't send username")?;

        // send password len
        self.socket
            .write(&[pass_bytes.len() as u8])
            .await
            .context("Can't send password len")?;
        self.socket
            .write(pass_bytes)
            .await
            .context("Can't send password")?;

        // Check the server reply, if whether it approved the auth or not
        let [version, is_success] =
            read_exact!(self.socket, [0u8; 2]).context("Can't read is_success")?;
        debug!(
            "Auth: [version: {version}, is_success: {is_success}]",
            version = version,
            is_success = is_success,
        );

        if is_success != consts::SOCKS5_REPLY_SUCCEEDED {
            return Err(SocksError::AuthenticationRejected(format!(
                "Authentication with username `{}`, rejected.",
                username
            )));
        }

        Ok(())
    }

    /// Decide to whether or not, accept the authentication method.
    /// Don't forget that the methods list sent by the client, contains one or more methods.
    ///
    /// # Request
    ///
    ///          +----+-----+-------+------+----------+----------+
    ///          |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    ///          +----+-----+-------+------+----------+----------+
    ///          | 1  |  1  |   1   |  1   | Variable |    2     |
    ///          +----+-----+-------+------+----------+----------+
    ///
    ///
    /// # Help
    ///
    /// To debug request use a netcat server with hexadecimal output to parse the hidden bytes:
    ///
    /// ```
    ///    $ nc -k -l 80 | hexdump -C
    /// ```
    ///
    async fn request_header(&mut self) -> Result<()> {
        let mut packet = [0u8; MAX_ADDR_LEN + 3];
        let padding; // maximum len of the headers sent
                     // build our request packet with (socks version, Command, reserved)
        packet[..3].copy_from_slice(&[
            consts::SOCKS5_VERSION,
            consts::SOCKS5_CMD_TCP_CONNECT,
            0x00,
        ]);

        match self.target_addr {
            TargetAddr::Ip(SocketAddr::V4(addr)) => {
                debug!("TargetAddr::IpV4");
                padding = 10;

                packet[3] = 0x01;
                debug!("addr ip {:?}", (*addr.ip()).octets());
                packet[4..8].copy_from_slice(&(addr.ip()).octets()); // ip
                packet[8..padding].copy_from_slice(&addr.port().to_be_bytes()); // port
            }
            TargetAddr::Ip(SocketAddr::V6(addr)) => {
                debug!("TargetAddr::IpV6");
                padding = 22;

                packet[3] = 0x04;
                debug!("addr ip {:?}", (*addr.ip()).octets());
                packet[4..20].copy_from_slice(&(addr.ip()).octets()); // ip
                packet[20..padding].copy_from_slice(&addr.port().to_be_bytes());
                // port
            }
            TargetAddr::Domain(ref domain, port) => {
                debug!("TargetAddr::Domain");
                if domain.len() > u8::max_value() as usize {
                    return Err(SocksError::ExceededMaxDomainLen(domain.len()))?;
                }
                padding = 5 + domain.len() + 2;

                packet[3] = 0x03; // Specify domain type
                packet[4] = domain.len() as u8; // domain length
                packet[5..(5 + domain.len())].copy_from_slice(domain.as_bytes()); // domain content
                packet[(5 + domain.len())..padding].copy_from_slice(&port.to_be_bytes());
                // port content (.to_be_bytes() convert from u16 to u8 type)
            }
        }

        debug!("Bytes long version: {:?}", &packet[..]);
        debug!("Bytes shorted version: {:?}", &packet[..padding]);
        debug!("Padding: {}", &padding);

        // we limit the end of the packet right after the domain + port number, we don't need to print
        // useless 0 bytes, otherwise other protocol won't understand the request (like HTTP servers).
        self.socket
            .write_all(&packet[..padding])
            .await
            .context("Can't write request header's packet.")?;

        Ok(())
    }

    /// The server send a confirmation (reply) that he had successfully connected (or not) to the
    /// remote server.
    async fn read_request_reply(&mut self) -> Result<()> {
        let [version, reply, rsv, address_type] =
            read_exact!(self.socket, [0u8; 4]).context("Received malformed reply")?;

        debug!(
            "Reply received: [version: {version}, reply: {reply}, rsv: {rsv}, address_type: {address_type}]",
            version = version,
            reply = reply,
            rsv = rsv,
            address_type = address_type,
        );

        if version != consts::SOCKS5_VERSION {
            return Err(SocksError::UnsupportedSocksVersion(version));
        }

        if reply != consts::SOCKS5_REPLY_SUCCEEDED {
            return Err(ReplyError::from_u8(reply))?; // Convert reply received into correct error
        }

        let address = read_address(&mut self.socket, address_type).await?;
        info!("Remote server connected to {}.", address);

        Ok(())
    }
}

/// Api if you want to use TcpStream to create a new connection to the SOCKS5 server.
impl Socks5Stream<TcpStream> {
    /// Connects to a target server through a SOCKS5 proxy.
    pub async fn connect<T>(
        socks_server: T,
        target_addr: String,
        target_port: u16,
        config: Config,
    ) -> Result<Self>
    where
        T: ToSocketAddrs,
    {
        Self::connect_raw(socks_server, target_addr, target_port, None, config).await
    }

    /// Connect with credentials
    pub async fn connect_with_password<T>(
        socks_server: T,
        target_addr: String,
        target_port: u16,
        username: String,
        password: String,
        config: Config,
    ) -> Result<Self>
    where
        T: ToSocketAddrs,
    {
        let auth = AuthenticationMethod::Password { username, password };

        Self::connect_raw(socks_server, target_addr, target_port, Some(auth), config).await
    }

    /// Process clients SOCKS requests
    /// This is the entry point where a whole request is processed.
    async fn connect_raw<T>(
        socks_server: T,
        target_addr: String,
        target_port: u16,
        auth: Option<AuthenticationMethod>,
        config: Config,
    ) -> Result<Self>
    where
        T: ToSocketAddrs,
    {
        let socket = TcpStream::connect(&socks_server).await?;
        info!("Connected @ {}", &socket.peer_addr()?);

        // Specify the target, here domain name, dns will be resolved on the server side
        let target_addr = (target_addr.as_str(), target_port)
            .to_target_addr()
            .context("Can't convert address to TargetAddr format")?;

        // upgrade the TcpStream to Socks5Stream
        let socks_stream = Self::use_stream(socket, target_addr, auth, config).await?;

        Ok(socks_stream)
    }
}

/// Allow us to read directly from the struct
impl<S> AsyncRead for Socks5Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_read(context, buf)
    }
}

/// Allow us to write directly into the struct
impl<S> AsyncWrite for Socks5Stream<S>
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

    fn poll_close(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_close(context)
    }
}
