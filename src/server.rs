use crate::read_exact;
use crate::util::target_addr::read_address;
use crate::{consts, AuthenticationMethod, ReplyError, Result, SocksError};
use anyhow::Context;
use async_std::{
    future,
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::Arc,
    task::{Context as AsyncContext, Poll},
};
use futures::{
    future::{Either, Future},
    stream::Stream,
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
};
use std::io;
use std::pin::Pin;

pub struct Config {
    request_timeout: u64,
    auth: Option<Arc<dyn Authentication>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            request_timeout: 10,
            auth: None,
        }
    }
}

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
    /// In seconds
    pub fn set_request_timeout(&mut self, n: u64) -> &mut Self {
        self.request_timeout = n;
        self
    }

    /// Enable authentication
    /// 'static lifetime for Authentication avoid us to use `dyn Authentication`
    /// and set the Arc before calling the function.
    pub fn set_authentication<T: Authentication + 'static>(&mut self, authentication: T) {
        self.auth = Some(Arc::new(authentication));
    }
}

/// Wrapper of TcpListener
/// Useful if you don't use any existing TcpListener's streams.
pub struct Socks5Server {
    listener: TcpListener,
    config: Arc<Config>,
}

impl Socks5Server {
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Socks5Server> {
        let listener = TcpListener::bind(&addr).await?;
        let config = Arc::new(Config::default());

        Ok(Socks5Server { listener, config })
    }

    /// Set a custom config
    pub fn set_config(&mut self, config: Config) {
        self.config = Arc::new(config);
    }

    pub fn incoming(&self) -> Incoming<'_> {
        Incoming(self)
    }
}

/// `Incoming` implements [`futures::stream::Stream`].
pub struct Incoming<'a>(&'a Socks5Server);

/// Iterator for each incoming stream connection
/// this wrapper will convert async_std TcpStream into Socks5Socket.
impl<'a> Stream for Incoming<'a> {
    type Item = Result<Socks5Socket<TcpStream>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut AsyncContext<'_>) -> Poll<Option<Self::Item>> {
        let fut = self.0.listener.accept();
        // have to pin the future, otherwise can't poll it
        futures::pin_mut!(fut);

        let (socket, peer_addr) = futures::ready!(fut.poll(cx))?;
        let local_addr = socket.local_addr()?;
        debug!(
            "incoming connection from peer {} @ {}",
            &peer_addr, &local_addr
        );

        // Wrap the TcpStream into Socks5Socket
        let socket = Socks5Socket::new(socket, self.0.config.clone());
        //        socket.write(&[4]);
        //        let mut socket = Socks5Socket::new(socket);
        //        let fut = socket.upgrade_to_socks5();
        //        futures::pin_mut!(fut);
        //
        //        debug!("upgrading to socks...");
        //        let socket = futures::ready!(fut.poll(cx))?;
        //        debug!("upgraded ok.");

        Poll::Ready(Some(Ok(socket)))
    }
}

/// Wrap every TcpStream and contains Socks5 protocol implementation.
pub struct Socks5Socket<T: AsyncRead + AsyncWrite + Unpin> {
    inner: T,
    config: Arc<Config>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Socks5Socket<T> {
    pub fn new(socket: T, config: Arc<Config>) -> Self {
        Socks5Socket {
            inner: socket,
            config,
        }
    }

    /// Process clients SOCKS requests
    /// This is the entry point where a whole request is processed.
    pub async fn upgrade_to_socks5(mut self) -> Result<Socks5Socket<T>> {
        //        info!("Connected client: {}", self.inner.peer_addr()?);

        // Handshake
        {
            let methods = self.get_methods().await?;

            self.can_accept_method(methods).await?;

            if self.config.auth.is_some() {
                self.authenticate().await?;
            }
        }

        match self.request().await {
            Ok(_) => {}
            Err(SocksError::ReplyError(e)) => {
                // If a reply error has been returned, we send it to the client
                self.reply(&e).await?;
                Err(e)? // propagate the error to end this connection's task
            }
            // if any other errors has been detected, we simply end connection's task
            Err(d) => return Err(d),
        };

        Ok(self)
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
        let is_supported;
        let method_supported;

        if self.config.auth.is_some() {
            method_supported = consts::SOCKS5_AUTH_METHOD_PASSWORD;
        } else {
            method_supported = consts::SOCKS5_AUTH_METHOD_NONE;
        }

        is_supported = client_methods.contains(&method_supported);

        if !is_supported {
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
    async fn authenticate(&mut self) -> Result<()> {
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

        // Return methods available
        Ok(())
    }

    /// Wrapper to principally cover ReplyError types for both functions read & execute request.
    async fn request(&mut self) -> Result<()> {
        let addr = self.read_request().await?;
        self.execute_request(addr).await?;

        Ok(())
    }

    async fn reply(&mut self, error: &ReplyError) -> Result<()> {
        let reply = &[
            consts::SOCKS5_VERSION,
            error.as_u8(), // transform the error into byte code
            0x00,          // reserved
            1,             // address type (ipv4, v6, domain)
            127,           // ip
            0,
            0,
            1,
            0, // port
            0,
        ];
        debug!("reply error to be written: {:?}", &reply);

        self.inner
            .write(reply)
            .await
            .context("Can't write the reply!")?;

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
    async fn read_request(&mut self) -> Result<SocketAddr> {
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

        if cmd != consts::SOCKS5_CMD_TCP_CONNECT {
            return Err(ReplyError::CommandNotSupported)?;
        }

        // Guess address type
        let addr = read_address(&mut self.inner, address_type)
            .await
            .map_err(|e| {
                // print explicit error
                error!("{:#}", e);
                // then convert it to a reply
                ReplyError::AddressTypeNotSupported
            })?;

        debug!("Request target is {}", addr);

        Ok(addr)
    }

    /// Connect to the target address that the client wants,
    /// then forward the data between them (client <=> target address).
    async fn execute_request(&mut self, addr: SocketAddr) -> Result<()> {
        // TCP connect with timeout, to avoid memory leak for connection that takes forever
        // TODO: timeout might not be appropriated in the case when we client wants to download a file
        //       (then the stream should last for more than 10s).
        //       Test by downloading a linux distro with curl & socks
        let outbound = match future::timeout(
            std::time::Duration::from_secs(self.config.request_timeout),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(e) => match e {
                Ok(o) => o,
                Err(e) => match e.kind() {
                    // Match other TCP errors with ReplyError
                    io::ErrorKind::ConnectionRefused => Err(ReplyError::ConnectionRefused)?,
                    io::ErrorKind::ConnectionAborted => Err(ReplyError::ConnectionNotAllowed)?,
                    io::ErrorKind::ConnectionReset => Err(ReplyError::ConnectionNotAllowed)?,
                    io::ErrorKind::NotConnected => Err(ReplyError::NetworkUnreachable)?,
                    _ => Err(e)?, // #[error("General failure")] ?
                },
            },
            // Wrap timeout error in a proper ReplyError
            Err(_) => Err(ReplyError::TtlExpired)?,
        };

        debug!("Connected to remote destination");

        // TODO: convert this to the real address
        self.inner
            .write_all(&[
                consts::SOCKS5_VERSION,
                consts::SOCKS5_REPLY_SUCCEEDED,
                0x00, // reserved
                1,    // address type (ipv4, v6, domain)
                127,  // ip
                0,
                0,
                1,
                0, // port
                0,
            ])
            .await
            .context("Can't write successful reply")?;

        trace!("Wrote success");

        transfer(&mut self.inner, outbound).await
    }
}

/// Copy data between two peers
/// Using 2 different generators, because they could be different structs with same traits.
async fn transfer<I, O>(mut inbound: I, outbound: O) -> Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    //    let (mut ri, mut wi) = (&inbound, &inbound);
    let (mut ri, mut wi) = futures::io::AsyncReadExt::split(&mut inbound);
    //    let (mut ro, mut wo) = (&outbound, &outbound);
    let (mut ro, mut wo) = futures::io::AsyncReadExt::split(outbound);

    // Exchange data
    // For some reasons, futures::future::select does not work with async_std::io::copy() 🤔
    let inbound_to_outbound = futures::io::copy(&mut ri, &mut wo);
    let outbound_to_inbound = futures::io::copy(&mut ro, &mut wi);

    // I've chosen `select` over `join` because the inbound (client) is more likely to leave the connection open for a while,
    // while it's not necessarily as the other part (outbound, aka remote server) has closed the communication.
    match futures::future::select(inbound_to_outbound, outbound_to_inbound).await {
        Either::Left((Ok(data), _)) => {
            info!("local closed -> remote target ({} bytes consumed)", data)
        }
        Either::Left((Err(err), _)) => {
            error!("local closed -> remote target with error {:?}", err,)
        }
        Either::Right((Ok(data), _)) => {
            info!("local <- remote target closed ({} bytes consumed)", data)
        }
        Either::Right((Err(err), _)) => {
            error!("local <- remote target closed with error {:?}", err,)
        }
    };

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::socks5::server::Socks5Server;

    #[test]
    fn test_bind() {
        //dza
        async {
            let server = Socks5Server::bind("127.0.0.1:1080").await.unwrap();
        };
    }
}
