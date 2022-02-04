use crate::read_exact;
use crate::ready;
use crate::util::target_addr::{read_address, TargetAddr};
use crate::Socks5Command;
use crate::{consts, AuthenticationMethod, ReplyError, Result, SocksError};
use anyhow::Context;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::{SocketAddr, ToSocketAddrs as StdToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as AsyncContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs as AsyncToSocketAddrs};
use tokio::time::timeout;
use tokio_stream::Stream;

#[derive(Clone)]
pub struct Config {
    /// Timeout of the command request
    request_timeout: u64,
    /// Avoid useless roundtrips if we don't need the Authentication layer
    skip_auth: bool,
    /// Enable dns-resolving
    dns_resolve: bool,
    /// Enable command execution
    execute_command: bool,
    auth: Option<Arc<dyn Authentication>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            request_timeout: 10,
            skip_auth: false,
            dns_resolve: true,
            execute_command: true,
            auth: None,
        }
    }
}

/// Use this trait to handle a custom authentication on your end.
pub trait Authentication: Send + Sync {
    fn authenticate(&self, username: &str, password: &str) -> bool;
}

/// Basic user/pass auth method provided.
pub struct SimpleUserPassword {
    pub username: String,
    pub password: String,
}

impl Authentication for SimpleUserPassword {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        username == &self.username && password == &self.password
    }
}

impl Config {
    /// How much time it should wait until the request timeout.
    pub fn set_request_timeout(&mut self, n: u64) -> &mut Self {
        self.request_timeout = n;
        self
    }

    /// Skip the entire auth/handshake part, which means the server will directly wait for
    /// the command request.
    pub fn set_skip_auth(&mut self, value: bool) -> &mut Self {
        self.skip_auth = value;
        self
    }

    /// Enable authentication
    /// 'static lifetime for Authentication avoid us to use `dyn Authentication`
    /// and set the Arc before calling the function.
    pub fn set_authentication<T: Authentication + 'static>(
        &mut self,
        authentication: T,
    ) -> &mut Self {
        self.auth = Some(Arc::new(authentication));
        self
    }

    /// Set whether or not to execute commands
    pub fn set_execute_command(&mut self, value: bool) -> &mut Self {
        self.execute_command = value;
        self
    }

    /// Will the server perform dns resolve
    pub fn set_dns_resolve(&mut self, value: bool) -> &mut Self {
        self.dns_resolve = value;
        self
    }
}

/// Wrapper of TcpListener
/// Useful if you don't use any existing TcpListener's streams.
pub struct Socks5Server {
    listener: TcpListener,
    config: Arc<Config>,
}

impl Socks5Server {
    pub async fn bind<A: AsyncToSocketAddrs>(addr: A) -> io::Result<Socks5Server> {
        let listener = TcpListener::bind(&addr).await?;
        let config = Arc::new(Config::default());

        Ok(Socks5Server { listener, config })
    }

    /// Set a custom config
    pub fn set_config(&mut self, config: Config) {
        self.config = Arc::new(config);
    }

    /// Can loop on `incoming().next()` to iterate over incoming connections.
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming(self, None)
    }
}

/// `Incoming` implements [`futures::stream::Stream`].
pub struct Incoming<'a>(
    &'a Socks5Server,
    Option<Pin<Box<dyn Future<Output = io::Result<(TcpStream, SocketAddr)>> + Send + Sync + 'a>>>,
);

/// Iterator for each incoming stream connection
/// this wrapper will convert async_std TcpStream into Socks5Socket.
impl<'a> Stream for Incoming<'a> {
    type Item = Result<Socks5Socket<TcpStream>>;

    /// this code is mainly borrowed from [`Incoming::poll_next()` of `TcpListener`][tcpListener]
    /// [tcpListener]: https://docs.rs/async-std/1.8.0/async_std/net/struct.TcpListener.html#method.incoming
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut AsyncContext<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.1.is_none() {
                self.1 = Some(Box::pin(self.0.listener.accept()));
            }

            if let Some(f) = &mut self.1 {
                // early returns if pending
                let (socket, peer_addr) = ready!(f.as_mut().poll(cx))?;
                self.1 = None;

                let local_addr = socket.local_addr()?;
                debug!(
                    "incoming connection from peer {} @ {}",
                    &peer_addr, &local_addr
                );

                // Wrap the TcpStream into Socks5Socket
                let socket = Socks5Socket::new(socket, self.0.config.clone());

                return Poll::Ready(Some(Ok(socket)));
            }
        }
    }
}

/// Wrap TcpStream and contains Socks5 protocol implementation.
pub struct Socks5Socket<T: AsyncRead + AsyncWrite + Unpin> {
    inner: T,
    config: Arc<Config>,
    auth: AuthenticationMethod,
    target_addr: Option<TargetAddr>,
    cmd: Option<Socks5Command>,
    /// Socket address which will be used in the reply message.
    reply_ip: Option<IpAddr>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Socks5Socket<T> {
    pub fn new(socket: T, config: Arc<Config>) -> Self {
        Socks5Socket {
            inner: socket,
            config,
            auth: AuthenticationMethod::None,
            target_addr: None,
            cmd: None,
            reply_ip: None,
        }
    }

    /// Set the bind IP address in Socks5Reply.
    /// 
    /// Only the inner socket owner knows the correct reply bind addr, so leave this field to be 
    /// populated. For those strict clients, users can use this function to set the correct IP 
    /// address.
    /// 
    /// Most popular SOCKS5 clients [1] [2] ignore BND.ADDR and BND.PORT the reply of command 
    /// CONNECT, but this field could be useful in some other command, such as UDP ASSOCIATE.
    /// 
    /// [1]. https://github.com/chromium/chromium/blob/bd2c7a8b65ec42d806277dd30f138a673dec233a/net/socket/socks5_client_socket.cc#L481
    /// [2]. https://github.com/curl/curl/blob/d15692ebbad5e9cfb871b0f7f51a73e43762cee2/lib/socks.c#L978
    pub fn set_reply_ip(&mut self, addr: IpAddr) {
        self.reply_ip = Some(addr);
    }

    /// Process clients SOCKS requests
    /// This is the entry point where a whole request is processed.
    pub async fn upgrade_to_socks5(mut self) -> Result<Socks5Socket<T>> {
        trace!("upgrading to socks5...");

        // Handshake
        if !self.config.skip_auth {
            let methods = self.get_methods().await?;

            self.can_accept_method(methods).await?;

            if self.config.auth.is_some() {
                let credentials = self.authenticate().await?;
                self.auth = AuthenticationMethod::Password {
                    username: credentials.0,
                    password: credentials.1,
                };
            }
        } else {
            debug!("skipping auth");
        }

        match self.request().await {
            Ok(_) => {}
            Err(SocksError::ReplyError(e)) => {
                // If a reply error has been returned, we send it to the client
                self.reply_error(&e).await?;
                return Err(e.into()); // propagate the error to end this connection's task
            }
            // if any other errors has been detected, we simply end connection's task
            Err(d) => return Err(d),
        };

        Ok(self)
    }

    /// Read the authentication method provided by the client.
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
    async fn get_methods(&mut self) -> Result<Vec<u8>> {
        trace!("Socks5Socket: get_methods()");
        // read the first 2 bytes which contains the SOCKS version and the methods len()
        let [version, methods_len] =
            read_exact!(self.inner, [0u8; 2]).context("Can't read methods")?;
        debug!(
            "Handshake headers: [version: {version}, methods len: {len}]",
            version = version,
            len = methods_len,
        );

        if version != consts::SOCKS5_VERSION {
            return Err(SocksError::UnsupportedSocksVersion(version));
        }

        // {METHODS available from the client}
        // eg. (non-auth) {0, 1}
        // eg. (auth)     {0, 1, 2}
        let methods = read_exact!(self.inner, vec![0u8; methods_len as usize])
            .context("Can't get methods.")?;
        debug!("methods supported sent by the client: {:?}", &methods);

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
    async fn can_accept_method(&mut self, client_methods: Vec<u8>) -> Result<()> {
        let method_supported;

        if self.config.auth.is_some() {
            method_supported = consts::SOCKS5_AUTH_METHOD_PASSWORD;
        } else {
            method_supported = consts::SOCKS5_AUTH_METHOD_NONE;
        }

        if !client_methods.contains(&method_supported) {
            debug!("Don't support this auth method, reply with (0xff)");
            self.inner
                .write(&[
                    consts::SOCKS5_VERSION,
                    consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE,
                ])
                .await
                .context("Can't reply with method not acceptable.")?;

            return Err(SocksError::AuthMethodUnacceptable(client_methods));
        }

        debug!(
            "Reply with method {} ({})",
            AuthenticationMethod::from_u8(method_supported).context("Method not supported")?,
            method_supported
        );
        self.inner
            .write(&[consts::SOCKS5_VERSION, method_supported])
            .await
            .context("Can't reply with method auth-none")?;
        Ok(())
    }

    /// Only called if
    ///  - the client supports authentication via username/password
    ///  - this server has `Authentication` trait implemented.
    async fn authenticate(&mut self) -> Result<(String, String)> {
        trace!("Socks5Socket: authenticate()");
        let [version, user_len] =
            read_exact!(self.inner, [0u8; 2]).context("Can't read user len")?;
        debug!(
            "Auth: [version: {version}, user len: {len}]",
            version = version,
            len = user_len,
        );

        if user_len < 1 {
            return Err(SocksError::AuthenticationFailed(format!(
                "Username malformed ({} chars)",
                user_len
            )));
        }

        let username =
            read_exact!(self.inner, vec![0u8; user_len as usize]).context("Can't get username.")?;
        debug!("username bytes: {:?}", &username);

        let [pass_len] = read_exact!(self.inner, [0u8; 1]).context("Can't read pass len")?;
        debug!("Auth: [pass len: {len}]", len = pass_len,);

        if pass_len < 1 {
            return Err(SocksError::AuthenticationFailed(format!(
                "Password malformed ({} chars)",
                pass_len
            )));
        }

        let password =
            read_exact!(self.inner, vec![0u8; pass_len as usize]).context("Can't get password.")?;
        debug!("password bytes: {:?}", &password);

        let username = String::from_utf8(username).context("Failed to convert username")?;
        let password = String::from_utf8(password).context("Failed to convert password")?;
        let auth = self.config.auth.as_ref().context("No auth module")?;

        if auth.authenticate(&username, &password) {
            self.inner
                .write(&[1, consts::SOCKS5_REPLY_SUCCEEDED])
                .await
                .context("Can't reply auth success")?;
        } else {
            self.inner
                .write(&[1, consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE])
                .await
                .context("Can't reply with auth method not acceptable.")?;

            return Err(SocksError::AuthenticationRejected(format!(
                "Authentication with username `{}`, rejected.",
                username
            )));
        }

        info!("User `{}` logged successfully.", username);

        Ok((username, password))
    }

    /// Wrapper to principally cover ReplyError types for both functions read & execute request.
    async fn request(&mut self) -> Result<()> {
        self.read_command().await?;

        if self.config.dns_resolve {
            self.resolve_dns().await?;
        } else {
            debug!("Domain won't be resolved because `dns_resolve`'s config has been turned off.")
        }

        if self.config.execute_command {
            self.execute_command().await?;
        }

        Ok(())
    }

    /// Reply error to the client with the reply code according to the RFC.
    async fn reply_error(&mut self, error: &ReplyError) -> Result<()> {
        let reply = new_reply(error, "0.0.0.0:0".parse().unwrap());
        debug!("reply error to be written: {:?}", &reply);

        self.inner
            .write(&reply)
            .await
            .context("Can't write the reply!")?;

        self.inner.flush().await.context("Can't flush the reply!")?;

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
    /// It the request is correct, it should returns a ['SocketAddr'].
    ///
    async fn read_command(&mut self) -> Result<()> {
        let [version, cmd, rsv, address_type] =
            read_exact!(self.inner, [0u8; 4]).context("Malformed request")?;
        debug!(
            "Request: [version: {version}, command: {cmd}, rev: {rsv}, address_type: {address_type}]",
            version = version,
            cmd = cmd,
            rsv = rsv,
            address_type = address_type,
        );

        if version != consts::SOCKS5_VERSION {
            return Err(SocksError::UnsupportedSocksVersion(version));
        }

        match Socks5Command::from_u8(cmd) {
            None => return Err(ReplyError::CommandNotSupported.into()),
            Some(cmd) => match cmd {
                Socks5Command::TCPConnect => {
                    self.cmd = Some(cmd);
                }
                Socks5Command::TCPBind | Socks5Command::UDPAssociate => {
                    return Err(ReplyError::CommandNotSupported.into())
                }
            },
        }

        // Guess address type
        let target_addr = read_address(&mut self.inner, address_type)
            .await
            .map_err(|e| {
                // print explicit error
                error!("{:#}", e);
                // then convert it to a reply
                ReplyError::AddressTypeNotSupported
            })?;

        self.target_addr = Some(target_addr);

        debug!("Request target is {}", self.target_addr.as_ref().unwrap());

        Ok(())
    }

    /// This function is public, it can be call manually on your own-willing
    /// if config flag has been turned off: `Config::dns_resolve == false`.
    pub async fn resolve_dns(&mut self) -> Result<()> {
        trace!("resolving dns");
        if let Some(target_addr) = self.target_addr.take() {
            // decide whether we have to resolve DNS or not
            self.target_addr = match target_addr {
                TargetAddr::Domain(_, _) => Some(target_addr.resolve_dns().await?),
                TargetAddr::Ip(_) => Some(target_addr),
            };
        }

        Ok(())
    }

    /// Connect to the target address that the client wants,
    /// then forward the data between them (client <=> target address).
    async fn execute_command(&mut self) -> Result<()> {
        // async-std's ToSocketAddrs doesn't supports external trait implementation
        // @see https://github.com/async-rs/async-std/issues/539
        let addr = self
            .target_addr
            .as_ref()
            .context("target_addr empty")?
            .to_socket_addrs()?
            .next()
            .context("unreachable")?;

        let fut = TcpStream::connect(addr);
        let limit = Duration::from_secs(self.config.request_timeout);

        // TCP connect with timeout, to avoid memory leak for connection that takes forever
        let outbound = match timeout(limit, fut).await {
            Ok(e) => match e {
                Ok(o) => o,
                Err(e) => match e.kind() {
                    // Match other TCP errors with ReplyError
                    io::ErrorKind::ConnectionRefused => {
                        return Err(ReplyError::ConnectionRefused.into())
                    }
                    io::ErrorKind::ConnectionAborted => {
                        return Err(ReplyError::ConnectionNotAllowed.into())
                    }
                    io::ErrorKind::ConnectionReset => {
                        return Err(ReplyError::ConnectionNotAllowed.into())
                    }
                    io::ErrorKind::NotConnected => {
                        return Err(ReplyError::NetworkUnreachable.into())
                    }
                    _ => return Err(e.into()), // #[error("General failure")] ?
                },
            },
            // Wrap timeout error in a proper ReplyError
            Err(_) => return Err(ReplyError::TtlExpired.into()),
        };

        debug!("Connected to remote destination");

        self.inner
            .write(&new_reply(
                &ReplyError::Succeeded,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            ))
            .await
            .context("Can't write successful reply")?;

        self.inner.flush().await.context("Can't flush the reply!")?;

        debug!("Wrote success");

        transfer(&mut self.inner, outbound).await
    }

    pub fn target_addr(&self) -> Option<&TargetAddr> {
        self.target_addr.as_ref()
    }

    pub fn auth(&self) -> &AuthenticationMethod {
        &self.auth
    }
}

/// Copy data between two peers
/// Using 2 different generators, because they could be different structs with same traits.
async fn transfer<I, O>(mut inbound: I, mut outbound: O) -> Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
        Ok(res) => info!("transfer closed ({}, {})", res.0, res.1),
        Err(err) => error!("transfer error: {:?}", err),
    };

    Ok(())
}

/// Allow us to read directly from the struct
impl<T> AsyncRead for Socks5Socket<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buf)
    }
}

/// Allow us to write directly into the struct
impl<T> AsyncWrite for Socks5Socket<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// Generate reply code according to the RFC.
fn new_reply(error: &ReplyError, sock_addr: SocketAddr) -> Vec<u8> {
    let (addr_type, mut ip_oct, mut port) = match sock_addr {
        SocketAddr::V4(sock) => (
            consts::SOCKS5_ADDR_TYPE_IPV4,
            sock.ip().octets().to_vec(),
            sock.port().to_ne_bytes().to_vec(),
        ),
        SocketAddr::V6(sock) => (
            consts::SOCKS5_ADDR_TYPE_IPV6,
            sock.ip().octets().to_vec(),
            sock.port().to_ne_bytes().to_vec(),
        ),
    };

    let mut reply = vec![
        consts::SOCKS5_VERSION,
        error.as_u8(), // transform the error into byte code
        0x00,          // reserved
        addr_type,     // address type (ipv4, v6, domain)
    ];
    reply.append(&mut ip_oct);
    reply.append(&mut port);

    return reply;
}

#[cfg(test)]
mod test {
    use crate::server::Socks5Server;
    use tokio_test::block_on;

    #[test]
    fn test_bind() {
        let f = async {
            let _server = Socks5Server::bind("127.0.0.1:1080").await.unwrap();
        };

        block_on(f);
    }
}
