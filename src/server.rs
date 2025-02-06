use crate::new_udp_header;
use crate::parse_udp_request;
use crate::read_exact;
use crate::ready;
use crate::util::stream::tcp_connect_with_timeout;
use crate::util::stream::ConnectError;
use crate::util::target_addr::AddrError;
use crate::util::target_addr::{read_address, TargetAddr};
use crate::Socks5Command;
use crate::UdpHeaderError;
use crate::{consts, AuthenticationMethod, ReplyError, SocksError};
use anyhow::Context;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::{SocketAddr, ToSocketAddrs as StdToSocketAddrs};
use std::ops::Deref;
use std::pin::Pin;
use std::string::FromUtf8Error;
use std::sync::Arc;
use std::task::{Context as AsyncContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs as AsyncToSocketAddrs};
use tokio::try_join;
use tokio_stream::Stream;

#[derive(thiserror::Error, Debug)]
pub enum SocksServerError {
    #[error("i/o error when {context}: {source}")]
    Io {
        source: io::Error,
        context: &'static str,
    },
    #[error("string error when {context}: {source}")]
    FromUtf8 {
        source: FromUtf8Error,
        context: &'static str,
    },
    #[error(transparent)]
    ConnectError(#[from] ConnectError),
    #[error(transparent)]
    UdpHeaderError(#[from] UdpHeaderError),
    #[error(transparent)]
    AddrError(#[from] AddrError),
    #[error("BUG: {0}")] // should be unreachable
    Bug(&'static str),
    #[error("Auth method unacceptable `{0:?}`.")]
    AuthMethodUnacceptable(Vec<u8>),
    #[error("Unsupported SOCKS version `{0}`.")]
    UnsupportedSocksVersion(u8),
    #[error("Unsupported SOCKS command `{0}`.")]
    UnknownCommand(u8),
    #[error("Unexpected garbage received on TCP stream used for UDP proxy keep-alive: `{0}`")]
    UnexpectedUdpControlGarbage(u8),
    #[error("Empty username received")]
    EmptyUsername,
    #[error("Empty password received")]
    EmptyPassword,
    #[error("Authentication rejected")]
    AuthenticationRejected,
    #[error("End of stream")]
    EOF,
}

impl SocksServerError {
    pub fn to_reply_error(&self) -> ReplyError {
        match self {
            SocksServerError::UnknownCommand(_) => ReplyError::CommandNotSupported,
            SocksServerError::AddrError(err) => err.to_reply_error(),
            _ => ReplyError::GeneralFailure,
        }
    }
}

trait ErrorContext<T> {
    fn err_when(self, context: &'static str) -> Result<T, SocksServerError>;
}

impl<T> ErrorContext<T> for Result<T, io::Error> {
    fn err_when(self, context: &'static str) -> Result<T, SocksServerError> {
        self.map_err(|source| SocksServerError::Io { source, context })
    }
}

impl<T> ErrorContext<T> for Result<T, FromUtf8Error> {
    fn err_when(self, context: &'static str) -> Result<T, SocksServerError> {
        self.map_err(|source| SocksServerError::FromUtf8 { source, context })
    }
}

#[derive(Clone)]
pub struct Config<A: Authentication = DenyAuthentication> {
    /// Timeout of the command request
    request_timeout: u64,
    /// Avoid useless roundtrips if we don't need the Authentication layer
    skip_auth: bool,
    /// Enable dns-resolving
    dns_resolve: bool,
    /// Enable command execution
    execute_command: bool,
    /// Enable UDP support
    allow_udp: bool,
    /// For some complex scenarios, we may want to either accept Username/Password configuration
    /// or IP Whitelisting, in case the client send only 1-2 auth methods (no auth) rather than 3 (with auth)
    allow_no_auth: bool,
    /// Contains the authentication trait to use the user against with
    auth: Option<Arc<A>>,
    /// Disables Nagle's algorithm for TCP
    nodelay: bool,
}

impl<A: Authentication> Default for Config<A> {
    fn default() -> Self {
        Config {
            request_timeout: 10,
            skip_auth: false,
            dns_resolve: true,
            execute_command: true,
            allow_udp: false,
            allow_no_auth: false,
            auth: None,
            nodelay: false,
        }
    }
}

/// Use this trait to handle a custom authentication on your end.
#[async_trait::async_trait]
pub trait Authentication: Send + Sync {
    type Item;

    async fn authenticate(&self, credentials: Option<(String, String)>) -> Option<Self::Item>;
}

async fn authenticate_callback<T: AsyncRead + AsyncWrite + Unpin, A: Authentication>(
    auth_callback: &A,
    auth: StandardAuthenticationStarted<T>,
) -> Result<(Socks5ServerProtocol<T, states::Authenticated>, A::Item), SocksServerError> {
    match auth {
        StandardAuthenticationStarted::NoAuthentication(auth) => {
            if let Some(credentials) = auth_callback.authenticate(None).await {
                Ok((auth.finish_auth(), credentials))
            } else {
                Err(SocksServerError::AuthenticationRejected)
            }
        }
        StandardAuthenticationStarted::PasswordAuthentication(auth) => {
            let (username, password, auth) = auth.read_username_password().await?;
            if let Some(credentials) = auth_callback.authenticate(Some((username, password))).await
            {
                Ok((auth.accept().await?.finish_auth(), credentials))
            } else {
                auth.reject().await?;
                Err(SocksServerError::AuthenticationRejected)
            }
        }
    }
}

/// Basic user/pass auth method provided.
pub struct SimpleUserPassword {
    pub username: String,
    pub password: String,
}

/// The struct returned when the user has successfully authenticated
pub struct AuthSucceeded {
    pub username: String,
}

/// This is an example to auth via simple credentials.
/// If the auth succeed, we return the username authenticated with, for further uses.
#[async_trait::async_trait]
impl Authentication for SimpleUserPassword {
    type Item = AuthSucceeded;

    async fn authenticate(&self, credentials: Option<(String, String)>) -> Option<Self::Item> {
        if let Some((username, password)) = credentials {
            // Client has supplied credentials
            if username == self.username && password == self.password {
                // Some() will allow the authentication and the credentials
                // will be forwarded to the socket
                Some(AuthSucceeded { username })
            } else {
                // Credentials incorrect, we deny the auth
                None
            }
        } else {
            // The client hasn't supplied any credentials, which only happens
            // when `Config::allow_no_auth()` is set as `true`
            None
        }
    }
}

/// This will simply return Option::None, which denies the authentication
#[derive(Copy, Clone, Default)]
pub struct DenyAuthentication {}

#[async_trait::async_trait]
impl Authentication for DenyAuthentication {
    type Item = ();

    async fn authenticate(&self, _credentials: Option<(String, String)>) -> Option<Self::Item> {
        None
    }
}

/// While this one will always allow the user in.
#[derive(Copy, Clone, Default)]
pub struct AcceptAuthentication {}

#[async_trait::async_trait]
impl Authentication for AcceptAuthentication {
    type Item = ();

    async fn authenticate(&self, _credentials: Option<(String, String)>) -> Option<Self::Item> {
        Some(())
    }
}

impl<A: Authentication> Config<A> {
    /// How much time it should wait until the request timeout.
    pub fn set_request_timeout(&mut self, n: u64) -> &mut Self {
        self.request_timeout = n;
        self
    }

    /// Skip the entire auth/handshake part, which means the server will directly wait for
    /// the command request.
    pub fn set_skip_auth(&mut self, value: bool) -> &mut Self {
        self.skip_auth = value;
        self.auth = None;
        self
    }

    /// Enable authentication
    /// 'static lifetime for Authentication avoid us to use `dyn Authentication`
    /// and set the Arc before calling the function.
    pub fn with_authentication<T: Authentication + 'static>(self, authentication: T) -> Config<T> {
        Config {
            request_timeout: self.request_timeout,
            skip_auth: self.skip_auth,
            dns_resolve: self.dns_resolve,
            execute_command: self.execute_command,
            allow_udp: self.allow_udp,
            allow_no_auth: self.allow_no_auth,
            auth: Some(Arc::new(authentication)),
            nodelay: self.nodelay,
        }
    }

    /// For some complex scenarios, we may want to either accept Username/Password configuration
    /// or IP Whitelisting, in case the client send only 2 auth methods rather than 3 (with auth)
    pub fn set_allow_no_auth(&mut self, value: bool) -> &mut Self {
        self.allow_no_auth = value;
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

    /// Set whether or not to allow udp traffic
    pub fn set_udp_support(&mut self, value: bool) -> &mut Self {
        self.allow_udp = value;
        self
    }
}

/// Wrapper of TcpListener
/// Useful if you don't use any existing TcpListener's streams.
#[deprecated(
    since = "0.11.0",
    note = "Use the new explicit API instead, see examples/server.rs"
)]
pub struct Socks5Server<A: Authentication = DenyAuthentication> {
    listener: TcpListener,
    config: Arc<Config<A>>,
}

#[allow(deprecated)]
impl<A: Authentication + Default> Socks5Server<A> {
    pub async fn bind<S: AsyncToSocketAddrs>(addr: S) -> io::Result<Self> {
        let listener = TcpListener::bind(&addr).await?;
        let config = Arc::new(Config::default());

        Ok(Socks5Server { listener, config })
    }
}

#[allow(deprecated)]
impl<A: Authentication> Socks5Server<A> {
    /// Set a custom config
    pub fn with_config<T: Authentication>(self, config: Config<T>) -> Socks5Server<T> {
        Socks5Server {
            listener: self.listener,
            config: Arc::new(config),
        }
    }

    /// Can loop on `incoming().next()` to iterate over incoming connections.
    pub fn incoming(&self) -> Incoming<'_, A> {
        Incoming(self, None)
    }
}

/// `Incoming` implements [`futures_core::stream::Stream`].
///
/// [`futures_core::stream::Stream`]: https://docs.rs/futures/0.3.30/futures/stream/trait.Stream.html
#[allow(deprecated)]
pub struct Incoming<'a, A: Authentication>(
    &'a Socks5Server<A>,
    Option<Pin<Box<dyn Future<Output = io::Result<(TcpStream, SocketAddr)>> + Send + Sync + 'a>>>,
);

/// Iterator for each incoming stream connection
/// this wrapper will convert async_std TcpStream into Socks5Socket.
#[allow(deprecated)]
impl<'a, A: Authentication> Stream for Incoming<'a, A> {
    type Item = Result<Socks5Socket<TcpStream, A>, SocksError>;

    /// this code is mainly borrowed from [`Incoming::poll_next()` of `TcpListener`][tcpListenerLink]
    ///
    /// [tcpListenerLink]: https://docs.rs/async-std/1.8.0/async_std/net/struct.TcpListener.html#method.incoming
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
#[deprecated(
    since = "0.11.0",
    note = "Use the new explicit API instead, see examples/server.rs"
)]
pub struct Socks5Socket<T: AsyncRead + AsyncWrite + Unpin, A: Authentication> {
    inner: T,
    config: Arc<Config<A>>,
    auth: AuthenticationMethod,
    target_addr: Option<TargetAddr>,
    cmd: Option<Socks5Command>,
    /// Socket address which will be used in the reply message.
    reply_ip: Option<IpAddr>,
    /// If the client has been authenticated, that's where we store his credentials
    /// to be accessed from the socket
    credentials: Option<A::Item>,
}

pub mod states {
    pub struct Opened;
    pub struct Authenticated;
    pub struct CommandRead;
}

pub struct Socks5ServerProtocol<T, S> {
    inner: T,
    _state: PhantomData<S>,
}

impl<T, S> Socks5ServerProtocol<T, S> {
    fn new(inner: T) -> Self {
        Socks5ServerProtocol {
            inner,
            _state: PhantomData,
        }
    }
}

impl<T> Socks5ServerProtocol<T, states::Opened> {
    /// Start handling the SOCKS5 protocol flow, wrapping a client socket.
    pub fn start(inner: T) -> Self {
        Self::new(inner)
    }
}

pub trait CheckResult {
    fn is_good(&self) -> bool;
}

impl CheckResult for bool {
    fn is_good(&self) -> bool {
        *self
    }
}

impl<T> CheckResult for Option<T> {
    fn is_good(&self) -> bool {
        self.is_some()
    }
}

impl<T, E> CheckResult for Result<T, E> {
    fn is_good(&self) -> bool {
        self.is_ok()
    }
}

impl<T> Socks5ServerProtocol<T, states::Authenticated> {
    /// Finish handling the authentication method-specific part of the protocol,
    /// returning back to the overall SOCKS5 flow.
    pub fn finish_auth<A: AuthMethodSuccessState<T>>(auth: A) -> Self {
        Self::new(auth.into_inner())
    }

    /// Wrap a socket in a SOCKS5 flow handler that's already marked as authenticated.
    ///
    /// This is not actually part of the official SOCKS5 protocol, but allows you to
    /// only use the post-authentication subset of it.
    pub fn skip_auth_this_is_not_rfc_compliant(inner: T) -> Self {
        Self::new(inner)
    }

    /// Handle the SOCKS5 auth negotiation supporting only the `NoAuthentication` method.
    pub async fn accept_no_auth(inner: T) -> Result<Self, SocksServerError>
    where
        T: AsyncWrite + AsyncRead + Unpin,
    {
        Ok(Socks5ServerProtocol::start(inner)
            .negotiate_auth(&[NoAuthentication])
            .await?
            .finish_auth())
    }

    /// Handle the SOCKS5 auth negotiation supporting only the `PasswordAuthentication` method,
    /// and verify the provided username and password using the provided closure.
    ///
    /// The closure can mutate state variables and/or return a result as `Option`/`Result`.
    pub async fn accept_password_auth<F, R>(
        inner: T,
        mut check: F,
    ) -> Result<(Self, R), SocksServerError>
    where
        T: AsyncWrite + AsyncRead + Unpin,
        F: FnMut(String, String) -> R,
        R: CheckResult,
    {
        let (user, pass, auth) = Socks5ServerProtocol::start(inner)
            .negotiate_auth(&[PasswordAuthentication])
            .await?
            .read_username_password()
            .await?;
        let check_result = check(user, pass);
        if check_result.is_good() {
            Ok((auth.accept().await?.finish_auth(), check_result))
        } else {
            auth.reject().await?;
            Err(SocksServerError::AuthenticationRejected)
        }
    }
}

/// A trait for the final successful state of an authentication method's implementation.
///
/// This allows `Socks5ServerProtocol<T, states::Authenticated>::finish_authentication` to
/// let the user continue with the protocol after the socket has been handed off to the
/// authentication method.
pub trait AuthMethodSuccessState<T> {
    fn into_inner(self) -> T;

    fn finish_auth(self) -> Socks5ServerProtocol<T, states::Authenticated>
    where
        Self: Sized,
    {
        Socks5ServerProtocol::finish_auth(self)
    }
}

/// A metadata trait for authentication methods, essentially binding an ID value
/// (as used in the method negotiation) to an actual implementation of the method.
///
/// Use blank structs for individual protocol implementations and
/// enums for sets of supported protocols (you'll need a matching enum for the `Impl`).
pub trait AuthMethod<T>: Copy {
    type StartingState;
    fn method_id(self) -> u8;
    fn new(self, inner: T) -> Self::StartingState;
}

pub struct NoAuthenticationImpl<T>(T);

impl<T> AuthMethodSuccessState<T> for NoAuthenticationImpl<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

/// The "NO AUTHENTICATION REQUIRED" auth method, ID 00h as specifed by RFC 1928.
///
/// As the dummy no-auth method, it only has one state. Once it's been negotiated,
/// you can immediately continue with `finish_authentication`.
///
/// Or not so immediately: if you want to use no-authentication with e.g. IP address
/// allowlisting or TLS client certificate auth for TLS-wrapped SOCKS5, this is your
/// opportunity to reject the no-authentication by dropping the connection!
#[derive(Debug, Clone, Copy)]
pub struct NoAuthentication;

impl<T> AuthMethod<T> for NoAuthentication {
    type StartingState = NoAuthenticationImpl<T>;

    fn method_id(self) -> u8 {
        0x00
    }

    fn new(self, inner: T) -> Self::StartingState {
        NoAuthenticationImpl(inner)
    }
}

mod password_states {
    pub struct Started;
    pub struct Received;
    pub struct Finished;
}

pub struct PasswordAuthenticationImpl<T, S> {
    inner: T,
    _state: PhantomData<S>,
}

pub type PasswordAuthenticationStarted<T> = PasswordAuthenticationImpl<T, password_states::Started>;

impl<T, S> PasswordAuthenticationImpl<T, S> {
    fn new(inner: T) -> Self {
        PasswordAuthenticationImpl {
            inner,
            _state: PhantomData,
        }
    }
}

impl<T: AsyncRead + Unpin> PasswordAuthenticationImpl<T, password_states::Started> {
    /// Handle the username and password sent by the client.
    pub async fn read_username_password(
        self,
    ) -> Result<
        (
            String,
            String,
            PasswordAuthenticationImpl<T, password_states::Received>,
        ),
        SocksServerError,
    > {
        let mut socket = self.inner;
        trace!("PasswordAuthenticationStarted: read_username_password()");
        let [version, user_len] = read_exact!(socket, [0u8; 2]).err_when("reading user len")?;
        debug!(
            "Auth: [version: {version}, user len: {len}]",
            version = version,
            len = user_len,
        );

        if user_len < 1 {
            return Err(SocksServerError::EmptyUsername);
        }

        let username =
            read_exact!(socket, vec![0u8; user_len as usize]).err_when("reading username")?;
        debug!("username bytes: {:?}", &username);

        let [pass_len] = read_exact!(socket, [0u8; 1]).err_when("reading password len")?;
        debug!("Auth: [pass len: {len}]", len = pass_len,);

        if pass_len < 1 {
            return Err(SocksServerError::EmptyPassword);
        }

        let password =
            read_exact!(socket, vec![0u8; pass_len as usize]).err_when("reading password")?;
        debug!("password bytes: {:?}", &password);

        let username = String::from_utf8(username).err_when("converting username")?;
        let password = String::from_utf8(password).err_when("converting password")?;

        Ok((username, password, PasswordAuthenticationImpl::new(socket)))
    }
}

impl<T: AsyncWrite + Unpin> PasswordAuthenticationImpl<T, password_states::Received> {
    /// Notify the client with a "SUCCEEDED" reply and proceed to finish the authentication.
    pub async fn accept(
        mut self,
    ) -> Result<PasswordAuthenticationImpl<T, password_states::Finished>, SocksServerError> {
        self.inner
            .write_all(&[1, consts::SOCKS5_REPLY_SUCCEEDED])
            .await
            .err_when("replying auth success")?;

        info!("Password authentication accepted.");
        Ok(PasswordAuthenticationImpl::new(self.inner))
    }

    /// Notify the client with a "NOT_ACCEPTABLE" reply and drop the socket.
    pub async fn reject(mut self) -> Result<(), SocksServerError> {
        self.inner
            .write_all(&[1, consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE])
            .await
            .err_when("replying with auth method not acceptable")?;

        info!("Password authentication rejected.");
        Ok(())
    }
}

impl<T> AuthMethodSuccessState<T> for PasswordAuthenticationImpl<T, password_states::Finished> {
    fn into_inner(self) -> T {
        self.inner
    }
}

/// The "USERNAME/PASSWORD" auth method, ID 02h as specified by RFC 1928.
#[derive(Debug, Clone, Copy)]
pub struct PasswordAuthentication;

impl<T> AuthMethod<T> for PasswordAuthentication {
    type StartingState = PasswordAuthenticationImpl<T, password_states::Started>;

    fn method_id(self) -> u8 {
        0x02
    }

    fn new(self, inner: T) -> Self::StartingState {
        PasswordAuthenticationImpl::new(inner)
    }
}

#[macro_export]
macro_rules! auth_method_enums {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $enum:ident / $(#[$state_enum_meta:meta])* $state_enum:ident<$state_enum_par:ident> {
            $($method:ident($state:ty)),+ $(,)?
        }
    ) => {
        $(#[$state_enum_meta])*
        $vis enum $state_enum<$state_enum_par> {
            $($method($state)),+
        }

        #[derive(Clone, Copy)]
        $(#[$enum_meta])*
        $vis enum $enum {
            $($method($method)),+
        }

        impl<T> AuthMethod<T> for $enum {
            type StartingState = $state_enum<T>;

            fn method_id(self) -> u8 {
                match self {
                    $($enum::$method(auth) => AuthMethod::<T>::method_id(auth)),+
                }
            }

            fn new(self, inner: T) -> Self::StartingState {
                match self {
                    $($enum::$method(auth) => $state_enum::$method(auth.new(inner))),+
                }
            }
        }
    };
}

auth_method_enums! {
    /// The combination of all authentication methods supported by this crate out of the box,
    /// as an enum appropriate for static dispatch.
    ///
    /// If you want to add your own custom methods, you can generate a similar enum using the `auth_method_enums` macro.
    pub enum StandardAuthentication / StandardAuthenticationStarted<T> {
        NoAuthentication(NoAuthenticationImpl<T>),
        PasswordAuthentication(PasswordAuthenticationImpl<T, password_states::Started>),
    }
}

impl StandardAuthentication {
    /// Return a slice containing either both supported methods or only `PasswordAuthentication`.
    pub fn allow_no_auth(allow: bool) -> &'static [StandardAuthentication] {
        if allow {
            &[
                // The order of authentication methods can be tested by clients in sequence,
                // so list more secure or preferred methods first
                StandardAuthentication::PasswordAuthentication(PasswordAuthentication),
                StandardAuthentication::NoAuthentication(NoAuthentication),
            ]
        } else {
            &[StandardAuthentication::PasswordAuthentication(
                PasswordAuthentication,
            )]
        }
    }
}

#[allow(deprecated)]
impl<T: AsyncRead + AsyncWrite + Unpin, A: Authentication> Socks5Socket<T, A> {
    pub fn new(socket: T, config: Arc<Config<A>>) -> Self {
        Socks5Socket {
            inner: socket,
            config,
            auth: AuthenticationMethod::None,
            target_addr: None,
            cmd: None,
            reply_ip: None,
            credentials: None,
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
    /// [1]: https://github.com/chromium/chromium/blob/bd2c7a8b65ec42d806277dd30f138a673dec233a/net/socket/socks5_client_socket.cc#L481
    /// [2]: https://github.com/curl/curl/blob/d15692ebbad5e9cfb871b0f7f51a73e43762cee2/lib/socks.c#L978
    pub fn set_reply_ip(&mut self, addr: IpAddr) {
        self.reply_ip = Some(addr);
    }

    /// Process clients SOCKS requests
    /// This is the entry point where a whole request is processed.
    pub async fn upgrade_to_socks5(mut self) -> Result<Socks5Socket<T, A>, SocksError> {
        trace!("upgrading to socks5...");

        // NOTE: this cannot be split in two without making self.inner an Option

        // Handshake
        let proto = match self.config.auth.as_ref() {
            _ if self.config.skip_auth => {
                debug!("skipping auth");
                Socks5ServerProtocol::skip_auth_this_is_not_rfc_compliant(self.inner)
            }
            None => Socks5ServerProtocol::start(self.inner)
                .negotiate_auth(&[NoAuthentication])
                .await?
                .finish_auth(),
            Some(auth_callback) => {
                let methods = StandardAuthentication::allow_no_auth(self.config.allow_no_auth);
                let auth = Socks5ServerProtocol::start(self.inner)
                    .negotiate_auth(methods)
                    .await?;
                let (proto, creds) = authenticate_callback(auth_callback.as_ref(), auth).await?;
                self.credentials = Some(creds);
                proto
            }
        };

        let (proto, cmd, target_addr) = {
            let triple = proto.read_command().await?;

            if self.config.dns_resolve {
                triple.resolve_dns().await?
            } else {
                debug!(
                    "Domain won't be resolved because `dns_resolve`'s config has been turned off."
                );
                triple
            }
        };

        match cmd {
            cmd if !self.config.execute_command => {
                self.cmd = Some(cmd);
                self.inner = proto.inner;
            }
            Socks5Command::TCPConnect => {
                self.inner = run_tcp_proxy(
                    proto,
                    &target_addr,
                    self.config.request_timeout,
                    self.config.nodelay,
                )
                .await?;
            }
            Socks5Command::UDPAssociate if self.config.allow_udp => {
                self.inner = run_udp_proxy(
                    proto,
                    &target_addr,
                    self.reply_ip.context("invalid reply ip")?,
                )
                .await?;
            }
            _ => {
                proto.reply_error(&ReplyError::CommandNotSupported).await?;
                return Err(ReplyError::CommandNotSupported.into());
            }
        };

        self.target_addr = Some(target_addr); /* legacy API leaves it exported */
        Ok(self)
    }

    /// Consumes the `Socks5Socket`, returning the wrapped stream.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// This function is public, it can be call manually on your own-willing
    /// if config flag has been turned off: `Config::dns_resolve == false`.
    pub async fn resolve_dns(&mut self) -> Result<(), SocksError> {
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

    pub fn target_addr(&self) -> Option<&TargetAddr> {
        self.target_addr.as_ref()
    }

    pub fn auth(&self) -> &AuthenticationMethod {
        &self.auth
    }

    pub fn cmd(&self) -> &Option<Socks5Command> {
        &self.cmd
    }

    /// Borrow the credentials of the user has authenticated with
    pub fn get_credentials(&self) -> Option<&<<A as Authentication>::Item as Deref>::Target>
    where
        <A as Authentication>::Item: Deref,
    {
        self.credentials.as_deref()
    }

    /// Get the credentials of the user has authenticated with
    pub fn take_credentials(&mut self) -> Option<A::Item> {
        self.credentials.take()
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Socks5ServerProtocol<T, states::Opened> {
    /// Negotiate an authentication method from a list of supported ones and initialize it.
    ///
    /// Internally, this reads the list of authentication methods provided by the client, and
    /// picks the first one for which there exists an implementation in `server_methods`.
    ///
    /// If none of the auth methods requested by the client are in `server_methods`,
    /// returns a `SocksServerError::AuthMethodUnacceptable`.
    pub async fn negotiate_auth<M: AuthMethod<T>>(
        mut self,
        server_methods: &[M],
    ) -> Result<M::StartingState, SocksServerError> {
        trace!("Socks5ServerProtocol: negotiate_auth()");
        let [version, methods_len] =
            read_exact!(self.inner, [0u8; 2]).err_when("reading methods")?;
        debug!(
            "Handshake headers: [version: {version}, methods len: {len}]",
            version = version,
            len = methods_len,
        );

        if version != consts::SOCKS5_VERSION {
            return Err(SocksServerError::UnsupportedSocksVersion(version));
        }

        // {METHODS available from the client}
        // eg. (non-auth) {0, 1}
        // eg. (auth)     {0, 1, 2}
        let methods =
            read_exact!(self.inner, vec![0u8; methods_len as usize]).err_when("reading methods")?;
        debug!("methods supported sent by the client: {:?}", &methods);

        // server_methods order matter!
        // the server could choose to prioritize methods
        for server_method in server_methods {
            for client_method_id in methods.iter() {
                if server_method.method_id() == *client_method_id {
                    debug!("Reply with method {}", *client_method_id);
                    self.inner
                        .write_all(&[consts::SOCKS5_VERSION, *client_method_id])
                        .await
                        .err_when("replying with auth method")?;
                    return Ok(server_method.new(self.inner));
                }
            }
        }

        debug!("No auth method supported by both client and server, reply with (0xff)");
        self.inner
            .write_all(&[
                consts::SOCKS5_VERSION,
                consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE,
            ])
            .await
            .err_when("replying with method not acceptable")?;
        Err(SocksServerError::AuthMethodUnacceptable(methods))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Socks5ServerProtocol<T, states::CommandRead> {
    /// Reply success to the client according to the RFC.
    /// This consumes the wrapper as after this message actual proxying should begin.
    pub async fn reply_success(mut self, sock_addr: SocketAddr) -> Result<T, SocksServerError> {
        self.inner
            .write(&new_reply(&ReplyError::Succeeded, sock_addr))
            .await
            .err_when("writing successful reply")?;

        self.inner.flush().await.err_when("flushing auth reply")?;

        debug!("Wrote success");
        Ok(self.inner)
    }

    /// Reply error to the client with the reply code according to the RFC.
    pub async fn reply_error(mut self, error: &ReplyError) -> Result<(), SocksServerError> {
        let reply = new_reply(error, "0.0.0.0:0".parse().unwrap());
        debug!("reply error to be written: {:?}", &reply);

        self.inner
            .write(&reply)
            .await
            .err_when("writing unsuccessful reply")?;

        self.inner.flush().await.err_when("flushing auth reply")?;

        Ok(())
    }
}

macro_rules! try_notify {
    ($proto:expr, $e:expr) => {
        match $e {
            Ok(res) => res,
            Err(err) => {
                if let Err(rep_err) = $proto.reply_error(&err.to_reply_error()).await {
                    error!(
                        "extra error while reporting an error to the client: {}",
                        rep_err
                    );
                }
                return Err(err.into());
            }
        }
    };
}

impl<T: AsyncRead + AsyncWrite + Unpin> Socks5ServerProtocol<T, states::Authenticated> {
    /// Decide to whether or not, accept the authentication method.
    /// Don't forget that the methods list sent by the client, contains one or more methods.
    ///
    /// # Request
    /// ```text
    ///          +----+-----+-------+------+----------+----------+
    ///          |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    ///          +----+-----+-------+------+----------+----------+
    ///          | 1  |  1  |   1   |  1   | Variable |    2     |
    ///          +----+-----+-------+------+----------+----------+
    /// ```
    ///
    /// It the request is correct, it should returns a ['SocketAddr'].
    ///
    pub async fn read_command(
        mut self,
    ) -> Result<
        (
            Socks5ServerProtocol<T, states::CommandRead>,
            Socks5Command,
            TargetAddr,
        ),
        SocksServerError,
    > {
        let [version, cmd, rsv, address_type] =
            read_exact!(self.inner, [0u8; 4]).err_when("reading command")?;
        debug!(
            "Request: [version: {version}, command: {cmd}, rev: {rsv}, address_type: {address_type}]",
            version = version,
            cmd = cmd,
            rsv = rsv,
            address_type = address_type,
        );

        if version != consts::SOCKS5_VERSION {
            return Err(SocksServerError::UnsupportedSocksVersion(version));
        }

        let mut proto = Socks5ServerProtocol::new(self.inner);

        // Guess address type
        let target_addr = try_notify!(proto, read_address(&mut proto.inner, address_type).await);

        debug!("Request target is {}", target_addr);

        let cmd = try_notify!(
            proto,
            Socks5Command::from_u8(cmd).ok_or(SocksServerError::UnknownCommand(cmd))
        );

        Ok((proto, cmd, target_addr))
    }
}

#[allow(async_fn_in_trait)]
pub trait DnsResolveHelper
where
    Self: Sized,
{
    async fn resolve_dns(self) -> Result<Self, SocksServerError>;
}

impl<T> DnsResolveHelper
    for (
        Socks5ServerProtocol<T, states::CommandRead>,
        Socks5Command,
        TargetAddr,
    )
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    async fn resolve_dns(self) -> Result<Self, SocksServerError> {
        let (proto, cmd, target_addr) = self;
        let resolved_addr = try_notify!(proto, target_addr.resolve_dns().await);
        Ok((proto, cmd, resolved_addr))
    }
}

/// Handle the connect command by running a TCP proxy until the connection is done.
pub async fn run_tcp_proxy<T: AsyncRead + AsyncWrite + Unpin>(
    proto: Socks5ServerProtocol<T, states::CommandRead>,
    addr: &TargetAddr,
    request_timeout_s: u64,
    nodelay: bool,
) -> Result<T, SocksServerError> {
    let addr = try_notify!(
        proto,
        addr.to_socket_addrs()
            .err_when("converting to socket addr")
            .and_then(|mut addrs| addrs.next().ok_or(SocksServerError::Bug("no socket addrs")))
    );

    // TCP connect with timeout, to avoid memory leak for connection that takes forever
    let outbound = match tcp_connect_with_timeout(addr, request_timeout_s).await {
        Ok(stream) => stream,
        Err(err) => {
            proto.reply_error(&err.to_reply_error()).await?;
            return Err(err.into());
        }
    };

    // Disable Nagle's algorithm if config specifies to do so.
    try_notify!(
        proto,
        outbound.set_nodelay(nodelay).err_when("setting nodelay")
    );

    debug!("Connected to remote destination");

    let mut inner = proto
        .reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
        .await?;

    transfer(&mut inner, outbound).await;
    Ok(inner)
}

/// Handle the associate command by running a UDP proxy until the connection is done.
pub async fn run_udp_proxy<T: AsyncRead + AsyncWrite + Unpin>(
    proto: Socks5ServerProtocol<T, states::CommandRead>,
    _addr: &TargetAddr,
    reply_ip: IpAddr,
) -> Result<T, SocksServerError> {
    // The DST.ADDR and DST.PORT fields contain the address and port that
    // the client expects to use to send UDP datagrams on for the
    // association. The server MAY use this information to limit access
    // to the association.
    // @see Page 6, https://datatracker.ietf.org/doc/html/rfc1928.
    //
    // We do NOT limit the access from the client currently in this implementation.

    // Listen with UDP6 socket, so the client can connect to it with either
    // IPv4 or IPv6.
    let peer_sock = try_notify!(
        proto,
        UdpSocket::bind("[::]:0")
            .await
            .err_when("binding udp socket")
    );

    let peer_addr = try_notify!(
        proto,
        peer_sock.local_addr().err_when("getting peer's local addr")
    );

    // Respect the pre-populated reply IP address.
    let mut inner = proto
        .reply_success(SocketAddr::new(reply_ip, peer_addr.port()))
        .await?;

    let udp_fut = transfer_udp(peer_sock);
    let tcp_fut = wait_on_tcp(&mut inner);
    match try_join!(udp_fut, tcp_fut) {
        Ok(_) => warn!("unreachable"),
        Err(SocksServerError::EOF) => debug!("EOF on controlling TCP stream, closed UDP proxy"),
        Err(err) => warn!("while UDP proxying: {err}"),
    }
    Ok(inner)
}

/// Wait until a TCP stream (that's not supposed to receive anything) closes.
///
/// This is intended for cancelling the `transfer_udp` task.
pub async fn wait_on_tcp<I>(stream: &mut I) -> Result<(), SocksServerError>
where
    I: AsyncRead + Unpin,
{
    let mut buf = [0; 1];
    match stream.read(&mut buf).await {
        Ok(0) => Err(SocksServerError::EOF),
        Ok(_) => Err(SocksServerError::UnexpectedUdpControlGarbage(buf[0])),
        Err(err) => Err(err).err_when("waiting on UDP control stream"),
    }
}

/// Run a bidirectional proxy between two streams.
/// Using 2 different generators, because they could be different structs with same traits.
pub async fn transfer<I, O>(mut inbound: I, mut outbound: O)
where
    I: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
        Ok(res) => info!("transfer closed ({}, {})", res.0, res.1),
        Err(err) => error!("transfer error: {:?}", err),
    };
}

async fn handle_udp_request(
    inbound: &UdpSocket,
    outbound: &UdpSocket,
) -> Result<(), SocksServerError> {
    let mut buf = vec![0u8; 0x10000];
    loop {
        let (size, client_addr) = inbound
            .recv_from(&mut buf)
            .await
            .err_when("udp receiving from")?;
        debug!("Server recieve udp from {}", client_addr);
        inbound
            .connect(client_addr)
            .await
            .err_when("connecting udp inbound")?;

        let (frag, target_addr, data) = parse_udp_request(&buf[..size]).await?;

        if frag != 0 {
            debug!("Discard UDP frag packets sliently.");
            return Ok(());
        }

        debug!("Server forward to packet to {}", target_addr);
        let mut target_addr = target_addr
            .resolve_dns()
            .await?
            .to_socket_addrs()
            .err_when("udp target to socket addrs")?
            .next()
            .ok_or(SocksServerError::Bug("no socket addrs"))?;

        target_addr.set_ip(match target_addr.ip() {
            std::net::IpAddr::V4(v4) => std::net::IpAddr::V6(v4.to_ipv6_mapped()),
            v6 @ std::net::IpAddr::V6(_) => v6,
        });
        outbound
            .send_to(data, target_addr)
            .await
            .err_when("udp sending to")?;
    }
}

async fn handle_udp_response(
    inbound: &UdpSocket,
    outbound: &UdpSocket,
) -> Result<(), SocksServerError> {
    let mut buf = vec![0u8; 0x10000];
    loop {
        let (size, remote_addr) = outbound
            .recv_from(&mut buf)
            .await
            .err_when("udp receiving from")?;
        debug!("Recieve packet from {}", remote_addr);

        let mut data = new_udp_header(remote_addr)?;
        data.extend_from_slice(&buf[..size]);
        inbound.send(&data).await.err_when("udp sending")?;
    }
}

/// Run a bidirectional UDP SOCKS proxy for a bound port.
pub async fn transfer_udp(inbound: UdpSocket) -> Result<(), SocksServerError> {
    let outbound = UdpSocket::bind("[::]:0")
        .await
        .err_when("binding udp socket")?;

    let req_fut = handle_udp_request(&inbound, &outbound);
    let res_fut = handle_udp_response(&inbound, &outbound);
    match try_join!(req_fut, res_fut) {
        Ok(_) => {}
        Err(error) => return Err(error),
    }

    Ok(())
}

// Fixes the issue "cannot borrow data in dereference of `Pin<&mut >` as mutable"
//
// cf. https://users.rust-lang.org/t/take-in-impl-future-cannot-borrow-data-in-a-dereference-of-pin/52042
#[allow(deprecated)]
impl<T, A: Authentication> Unpin for Socks5Socket<T, A> where T: AsyncRead + AsyncWrite + Unpin {}

/// Allow us to read directly from the struct
#[allow(deprecated)]
impl<T, A: Authentication> AsyncRead for Socks5Socket<T, A>
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
#[allow(deprecated)]
impl<T, A: Authentication> AsyncWrite for Socks5Socket<T, A>
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
            sock.port().to_be_bytes().to_vec(),
        ),
        SocketAddr::V6(sock) => (
            consts::SOCKS5_ADDR_TYPE_IPV6,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
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

    reply
}

#[cfg(test)]
#[allow(deprecated)]
mod test {
    use crate::server::Socks5Server;
    use tokio_test::block_on;

    use super::AcceptAuthentication;

    #[test]
    fn test_bind() {
        let f = async {
            let _server = Socks5Server::<AcceptAuthentication>::bind("127.0.0.1:1080")
                .await
                .unwrap();
        };

        block_on(f);
    }
}
