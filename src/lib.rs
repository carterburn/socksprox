use std::error::Error;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::{
    net::{TcpListener, TcpStream},
    task,
    time::timeout,
};

mod errors;
mod socks_msgs;

use errors::{SocksHandleError, SocksSetupError, SocksUserAuthError};
use socks_msgs::{
    ClientConnection, SocksAuthMethod, SocksCommand, SocksErrorReply, SocksErrorReplyCode,
    SocksReply, SocksRequest, SocksServerAuthResponse,
};

#[derive(Clone, Debug, PartialEq)]
pub struct SocksUser {
    pub username: String,
    password: String,
}
// Maybe some serde JSON for the username/password

impl SocksUser {
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }
}

impl TryFrom<&str> for SocksUser {
    /// Decodes a string with format username:password into a SocksUser.
    /// Of note, the username and password cannot contain the character ':'
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let userpass: Vec<&str> = value.split(':').collect();
        if userpass.len() != 2 {
            return Err("Invalid input string");
        }
        Ok(Self {
            username: userpass[0].to_string(),
            password: userpass[1].to_string(),
        })
    }
}

/// A super simple, feature-lacking async SOCKS5 server.
/// Currently only supports the CONNECT command (TCP) and limited authentication
/// (Username/Password). No authentication is also supported.
///
/// ## But Why
/// Why would you want to use this? You probably don't, better implementations exist. BUT if you
/// want a straightforward, easy-to-use SOCKS5 library, well, you found it. This can be used (along
/// with the provided binary) to quickly and easily deploy a SOCKS5 Server.
///
/// To use in your own binary, all you need is the tokio runtime. Using anyhow for errors is also
/// convienent to easily handle errors provided by the library. The main function for the binary
/// in it's nascent stages looked something like this:
///
/// ```no_run
/// use socksprox::Socks5Server;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let mut server = match Socks5Server::new("0.0.0.0", 4444, None, None).await {
///         Ok(s) => s,
///         Err(e) => { return Err(anyhow::anyhow!("Error starting server: {e}")); }
///     };
///
///     server.serve().await;
///
///     Ok(())
/// }
/// ```
pub struct Socks5Server {
    /// The Listener that will accept connections
    listener: TcpListener,

    /// Table of users for User/Pass authentication method; if None, no authentication will be
    /// supported
    user_table: Arc<Option<Vec<SocksUser>>>,

    /// Optional Duration for a connection timeout
    connection_timeout: Arc<Option<Duration>>,
}

impl Socks5Server {
    /// Create a new Socks5Server and start listening for incoming connections on the provided IP
    /// and port. An optional list of SocksUsers can be provided for Username/Password
    /// authentication. If a list is provided and a client requests Username/Password
    /// authentication, this list of users will be used in order to authenticate clients.
    /// Additionally, an optional timeout can be provided for connections to upstream servers. That
    /// is, if the connection is not made in the specified timeout, the connection will drop.
    ///
    /// To build a server with no authentication and no timeout:
    ///
    /// ```no_run
    /// # use socksprox::Socks5Server;
    /// let server = Socks5Server::new("127.0.0.1", 4444, None, None);
    /// ```
    ///
    /// To add user authentication for clients that request it:
    ///
    /// ```no_run
    /// # use socksprox::{Socks5Server, SocksUser};
    /// let users = vec![SocksUser::new("admin".to_string(), "password".to_string())];
    ///
    /// let server = Socks5Server::new("127.0.0.1", 4444, Some(users), None);
    /// ```
    ///
    /// Finally, to add an optional timeout (like 3 seconds):
    ///
    /// ```no_run
    /// # use socksprox::Socks5Server;
    /// # use std::time::Duration;
    /// let server = Socks5Server::new("127.0.0.1", 4444, None, Some(Duration::from_secs(3)));
    /// ```
    pub async fn new(
        ip: &str,
        port: u16,
        user_table: Option<Vec<SocksUser>>,
        connection_timeout: Option<Duration>,
    ) -> Result<Self, Box<dyn Error>> {
        log::info!("Listening on {ip}:{port}");
        Ok(Self {
            listener: TcpListener::bind((ip, port)).await?,
            user_table: Arc::new(user_table),
            connection_timeout: Arc::new(connection_timeout),
        })
    }

    /// Begin serving connections to clients asynchronously. When a client connects, it will be
    /// handled as a separate task. Until the connection is finished.
    ///
    /// Once, you have a server created with `Socks5Server::new()`, serving clients is as easy as:
    ///
    /// ```no_run
    /// # use socksprox::Socks5Server;
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()> {
    /// # let mut server = match Socks5Server::new("127.0.0.1", 4444, None, None).await {
    /// # Ok(s) => s,
    /// # Err(e) => { return Err(anyhow::anyhow!("Error: {e}"));}
    /// # };
    /// server.serve().await;
    /// # Ok(())
    /// # }
    ///
    /// ```
    pub async fn serve(&mut self) {
        log::info!("Serving clients...");

        while let Ok((client_stream, client_addr)) = self.listener.accept().await {
            log::info!("New connection from: {client_addr}");

            let users = self.user_table.clone();
            let timeout = self.connection_timeout.clone();
            let stream = Arc::new(Mutex::new(client_stream));

            // spawn new tokio task to handle the client
            task::spawn(async move {
                let mut client = SocksConnection::new(stream, client_addr, &users, timeout);
                match client.setup().await.map_err(|e| e.to_string()) {
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("Error initializing SOCKS5 with client: {client_addr}: {e:?}");

                        let _ = client.shutdown().await.map_err(|e| e.to_string());
                    }
                }

                // start handling the client once we have authenticated
                if let Err(err) = client.handle().await.map_err(|e| e.to_string()) {
                    log::warn!("Error handling the client...shutting down: {err:?}");
                    if let Err(e) = client.shutdown().await.map_err(|e| e.to_string()) {
                        log::warn!("Error closing TcpStream: {:?}", e);
                    }
                }
                log::info!("Shutting down client connection: {client_addr:?}");
                let _ = client.shutdown().await;
            });
        }
    }
}

struct SocksConnection<'a> {
    /// Stream for this client connection
    stream: Arc<Mutex<TcpStream>>,

    /// Addr of the client
    addr: SocketAddr,

    /// Optional Users (None indicates NO authentication will be supported)
    users: &'a Option<Vec<SocksUser>>,

    /// Connection timeout for this connection
    timeout: Arc<Option<Duration>>,

    /// Authentication Method chosen for this client
    auth: SocksAuthMethod,
}

impl<'a> SocksConnection<'a> {
    const SOCKS_VERSION: u8 = 0x05;

    fn new(
        stream: Arc<Mutex<TcpStream>>,
        addr: SocketAddr,
        users: &'a Option<Vec<SocksUser>>,
        timeout: Arc<Option<Duration>>,
    ) -> Self {
        Self {
            stream,
            addr,
            users,
            timeout,
            auth: SocksAuthMethod::NoAuth,
        }
    }

    async fn setup(&mut self) -> Result<(), Box<dyn Error>> {
        log::debug!("Setting up new connection with {:?}", self.addr);

        let client_init = ClientConnection::read_from(self.stream.clone()).await?;

        // pick the auth method (Server only supports No Authentication or User/Pass)
        self.auth = if self.users.is_some() && client_init.user_pass_supported() {
            // we can support this and the client requested it
            SocksAuthMethod::UserPass
        } else if client_init.no_auth_supported() {
            SocksAuthMethod::NoAuth
        } else {
            SocksAuthMethod::NoAcceptableMethods
        };

        log::info!("Server selecting {:?} for {}", self.auth, self.addr);

        self.authenticate().await?;

        Ok(())
    }

    /// Sends a ServerConnectionResponse and authenticates the client (if needed)
    async fn authenticate(&self) -> Result<(), Box<dyn Error>> {
        match self.auth {
            SocksAuthMethod::NoAuth => {
                let response = SocksServerAuthResponse::create(
                    Self::SOCKS_VERSION,
                    SocksAuthMethod::NoAuth as u8,
                );
                response.send(self.stream.clone()).await?;
                log::info!("Authenticated with NoAuth");
                Ok(())
            }
            SocksAuthMethod::UserPass => {
                // initial response that we accept UserPass auth
                let response = SocksServerAuthResponse::create(
                    Self::SOCKS_VERSION,
                    SocksAuthMethod::UserPass as u8,
                );
                response.send(self.stream.clone()).await?;

                let users = self.users.as_ref().unwrap();
                let auth_engine = UserAuthEngine::create(users, self.stream.clone());
                let user_authed = auth_engine.authenticate().await?;
                log::info!("Authenticated user: {}", user_authed.username);
                Ok(())
            }
            _ => {
                let response = SocksServerAuthResponse::create(
                    Self::SOCKS_VERSION,
                    SocksAuthMethod::NoAcceptableMethods as u8,
                );
                response.send(self.stream.clone()).await?;
                Err(SocksSetupError::UnsupportedAuthMethod)?
            }
        }
    }

    async fn shutdown(&self) -> tokio::io::Result<()> {
        self.stream.lock().await.shutdown().await
    }

    async fn handle(&self) -> Result<usize, Box<dyn Error>> {
        log::info!("Receiving client requests");

        // should match on the errors that this can give. because we need to send a reply no matter
        // what. send the reply here and then return a specific error.
        // just match on what the request gives. if you get an error, then send response and return
        // later if you have a bad socks command, handle that there
        let request = SocksRequest::read_from_stream(self.stream.clone()).await?;

        log::info!(
            "Request; Command: {:?}, Addr/Port: {:?}",
            request.command,
            request.address
        );

        match request.command {
            SocksCommand::Connect => {
                // make a connection to addr:port
                log::info!("Connecting to: {:?}", request.address);

                let to = self.timeout.unwrap_or(Duration::from_millis(500));
                let addr = request
                    .address
                    .get_resolved()
                    .ok_or(SocksHandleError::FailedHostLookup)?;

                let mut conn = match timeout(to, async move { TcpStream::connect(addr).await })
                    .await
                    .map_err(|_| SocksHandleError::FailedConnection)
                {
                    Ok(conn_res) => match conn_res {
                        Ok(conn) => conn,
                        Err(_e) => {
                            SocksErrorReply::send(
                                self.stream.clone(),
                                SocksErrorReplyCode::ConnectionRefused,
                            )
                            .await?;
                            return Err(SocksHandleError::FailedConnection)?;
                        }
                    },
                    Err(_e) => {
                        SocksErrorReply::send(
                            self.stream.clone(),
                            SocksErrorReplyCode::ConnectionRefused,
                        )
                        .await?;
                        return Err(SocksHandleError::FailedConnection)?;
                    }
                };

                log::info!("Connected to upstream");

                // send reply indicating success
                SocksReply::send(self.stream.clone()).await?;

                // copy the data!
                log::info!("Copying data");
                let mut stream_b = self.stream.lock().await;
                match tokio::io::copy_bidirectional(&mut *stream_b, &mut conn).await {
                    Err(_e) => Err(SocksHandleError::FailedRelay)?,
                    Ok((_cli_to_serv, serv_to_up)) => {
                        let _ = conn.shutdown().await;
                        Ok(serv_to_up as usize)
                    }
                }
            }
            SocksCommand::Bind => {
                SocksErrorReply::send(
                    self.stream.clone(),
                    SocksErrorReplyCode::CommandNotSupported,
                )
                .await?;
                Err(SocksHandleError::BindNotSupported)?
            }
            SocksCommand::UdpAssociate => {
                SocksErrorReply::send(
                    self.stream.clone(),
                    SocksErrorReplyCode::CommandNotSupported,
                )
                .await?;
                Err(SocksHandleError::UdpNotSupported)?
            }
        }
    }
}

/// Engine to authenticate using UserPass
struct UserAuthEngine<'a> {
    /// Users and passwords
    users: &'a Vec<SocksUser>,

    /// Stream to use for negotiating the authentication
    stream: Arc<Mutex<TcpStream>>,
}

impl<'a> UserAuthEngine<'a> {
    const USER_PASS_VERSION: u8 = 0x01;
    const USER_PASS_AUTH_SUCCESS: u8 = 0x00;
    const USER_PASS_AUTH_FAILED: u8 = 0x01;

    fn create(users: &'a Vec<SocksUser>, stream: Arc<Mutex<TcpStream>>) -> Self {
        Self { users, stream }
    }

    async fn authenticate(&self) -> Result<&'a SocksUser, Box<dyn Error>> {
        // get initial header of version and username length
        let mut initial_hdr = [0u8; 2];

        self.stream
            .lock()
            .await
            .read_exact(&mut initial_hdr)
            .await?;

        if initial_hdr[0] != Self::USER_PASS_VERSION {
            return Err(SocksUserAuthError::InvalidVersion)?;
        }

        // read username
        let username_len = initial_hdr[1] as usize;

        let mut username = vec![0u8; username_len];
        self.stream.lock().await.read_exact(&mut username).await?;

        // password length (read it all to guard against timing attacks on username finding)
        let mut password_len_buf = [0u8; 1];
        self.stream
            .lock()
            .await
            .read_exact(&mut password_len_buf)
            .await?;
        let password_len = password_len_buf[0] as usize;

        // read password
        let mut password = vec![0u8; password_len];
        self.stream.lock().await.read_exact(&mut password).await?;

        // see if we can find this SocksUser in users
        let client_creds = SocksUser::new(
            String::from_utf8_lossy(&username).to_string(),
            String::from_utf8_lossy(&password).to_string(),
        );

        match self.users.iter().position(|x| *x == client_creds) {
            Some(user) => {
                let response = SocksServerAuthResponse::create(
                    Self::USER_PASS_VERSION,
                    Self::USER_PASS_AUTH_SUCCESS,
                );
                response.send(self.stream.clone()).await?;
                Ok(&self.users[user])
            }
            None => {
                let response = SocksServerAuthResponse::create(
                    Self::USER_PASS_VERSION,
                    Self::USER_PASS_AUTH_FAILED,
                );
                response.send(self.stream.clone()).await?;
                Err(Box::new(SocksUserAuthError::FailedAuthentication))
            }
        }
    }
}
