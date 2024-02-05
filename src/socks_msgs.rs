use derive_try_from_primitive::TryFromPrimitive;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::Mutex;

use crate::errors::{SocksHandleError, SocksSetupError};

#[derive(Debug, Clone)]
pub struct ClientConnection {
    methods: Vec<SocksAuthMethod>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
/// Only supporting Socks5 for now
enum SocksVersion {
    Socks5 = 0x05,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocksAuthMethod {
    NoAuth = 0x00,
    Gssapi = 0x01,
    UserPass = 0x02,
    IanaAssigned = 0x03,
    Reserved = 0x80,
    NoAcceptableMethods = 0xFF,
}

impl TryFrom<u8> for SocksAuthMethod {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x00 => Self::NoAuth,
            0x01 => Self::Gssapi,
            0x02 => Self::UserPass,
            0x03..=0x7F => Self::IanaAssigned,
            0x80..=0xFE => Self::Reserved,
            _ => Self::NoAcceptableMethods,
        })
    }
}

impl ClientConnection {
    /// Reads from the stream and parses into a ClientConnection
    /// The message sent from the client is of the form:
    ///         +----+----------+----------+
    ///         |VER | NMETHODS | METHODS  |
    ///         +----+----------+----------+
    ///         | 1  |    1     | 1 to 255 |
    ///         +----+----------+----------+
    pub async fn read_from(stream: Arc<Mutex<TcpStream>>) -> Result<Self, Box<dyn Error>> {
        let mut initial_hdr = [0u8; 2];

        stream.lock().await.read_exact(&mut initial_hdr).await?;

        // check the version
        SocksVersion::try_from(initial_hdr[0])
            .or(Err(SocksSetupError::InvalidSocksVersion(initial_hdr[0])))?;

        let nmethods: usize = initial_hdr[1].into();

        // read initial_hdr[1] bytes from stream for the methods
        let mut methods = vec![0; nmethods];
        stream.lock().await.read_exact(&mut methods).await?;

        let methods: Vec<SocksAuthMethod> = methods
            .iter()
            .map(|method| {
                SocksAuthMethod::try_from(*method).or(Err(SocksSetupError::UnsupportedAuthMethod))
            })
            .collect::<Result<Vec<_>, _>>()?;

        if methods.len() != nmethods {
            return Err(SocksSetupError::MismatchedMethods)?;
        }

        Ok(Self { methods })
    }

    /// Returns true if one of the methods is UserPass
    pub fn user_pass_supported(&self) -> bool {
        self.methods.contains(&SocksAuthMethod::UserPass)
    }

    /// Returns true if one of the methods is NoAuth
    pub fn no_auth_supported(&self) -> bool {
        self.methods.contains(&SocksAuthMethod::NoAuth)
    }
}

/// A Reply to the client's initial request (Authentication choice and authentication
/// success/failure)
pub struct SocksServerAuthResponse {
    /// Version number (either SOCKS or Auth version)
    ver: u8,

    /// response code to send back
    code: u8,
}

impl SocksServerAuthResponse {
    pub fn create(ver: u8, code: u8) -> Self {
        Self { ver, code }
    }

    pub async fn send(&self, stream: Arc<Mutex<TcpStream>>) -> Result<(), Box<dyn Error>> {
        let packet = [self.ver, self.code];
        stream.lock().await.write_all(&packet).await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocksCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for SocksCommand {
    type Error = SocksHandleError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::UdpAssociate),
            _ => Err(SocksHandleError::InvalidCommandValue),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SocksAddressType {
    Ipv4 = 0x01,
    Domain = 0x03,
    Ipv6 = 0x04,
}

impl TryFrom<u8> for SocksAddressType {
    type Error = SocksHandleError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Ipv4),
            0x03 => Ok(Self::Domain),
            0x04 => Ok(Self::Ipv6),
            _ => Err(SocksHandleError::InvalidAddressType),
        }
    }
}

pub struct SocksAddress {
    /// Address type we have
    addr_type: SocksAddressType,

    /// Buffer to store the address (has to be variably sized)
    addr: Vec<u8>,

    /// Port for this address
    port: u16,

    /// Resolved after doing any lookups
    resolved: Option<SocketAddr>,
}

impl std::fmt::Debug for SocksAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.resolved)
    }
}

impl SocksAddress {
    pub fn get_resolved(&self) -> Option<SocketAddr> {
        self.resolved
    }

    async fn from_stream(
        raw_addr_type: u8,
        stream: Arc<Mutex<TcpStream>>,
    ) -> Result<Self, Box<dyn Error>> {
        let addr_type = SocksAddressType::try_from(raw_addr_type)?;

        let read_len = match addr_type {
            SocksAddressType::Ipv4 => 4,
            SocksAddressType::Ipv6 => 16,
            SocksAddressType::Domain => {
                // read a single byte from the stream to get the length of the Buffer
                let len = stream.lock().await.read_u8().await?;
                len as usize
            }
        };

        let mut buf = vec![0u8; read_len];
        stream.lock().await.read_exact(&mut buf).await?;

        let port = stream.lock().await.read_u16().await?;

        Ok(Self {
            addr_type,
            addr: buf,
            port,
            resolved: None,
        })
    }

    pub async fn resolve_socket_addr(&mut self) -> Result<SocketAddr, Box<dyn Error>> {
        let addr = match self.addr_type {
            SocksAddressType::Ipv4 => {
                // buf of 4 bytes should be in addr with the port
                let buf: [u8; 4] = self.addr[..].try_into()?;
                SocketAddr::from((buf, self.port))
            }
            SocksAddressType::Ipv6 => {
                let buf: [u8; 16] = self.addr[..].try_into()?;
                SocketAddr::from((buf, self.port))
            }
            SocksAddressType::Domain => {
                let addr_to_lookup = String::from_utf8(self.addr.clone())?;
                log::info!("Performing DNS lookup for {}", addr_to_lookup);
                let mut addr_it = lookup_host(format!("{}:{}", addr_to_lookup, self.port)).await?;
                addr_it.next().ok_or(SocksHandleError::FailedHostLookup)?
            }
        };
        self.resolved = Some(addr);
        Ok(addr)
    }
}

/// Struct defining a client's SOCKS Request
pub struct SocksRequest {
    /// Command
    pub command: SocksCommand,

    /// Address definition for the request
    pub address: SocksAddress,
}

impl SocksRequest {
    pub async fn read_from_stream(stream: Arc<Mutex<TcpStream>>) -> Result<Self, Box<dyn Error>> {
        // read the first 4 bytes from the stream for the ver, cmd, rsv, addr_type
        let mut header = [0u8; 4];
        stream.lock().await.read_exact(&mut header).await?;

        // verify version
        if header[0] != SocksVersion::Socks5 as u8 {
            return Err(SocksSetupError::InvalidSocksVersion(header[0]))?;
        }

        let command = SocksCommand::try_from(header[1])?;

        let mut address = SocksAddress::from_stream(header[3], stream).await?;
        // resolve a hostname as soon as possible
        let _ = address.resolve_socket_addr().await?;

        Ok(Self { command, address })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocksErrorReplyCode {
    Success = 0x00,
    #[allow(dead_code)]
    GeneralFailure = 0x01,
    #[allow(dead_code)]
    DeniedConnection = 0x02,
    #[allow(dead_code)]
    NetworkUnreachable = 0x03,
    #[allow(dead_code)]
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    #[allow(dead_code)]
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    #[allow(dead_code)]
    AddressTypeNotSupported = 0x08,
    #[allow(dead_code)]
    Unassigned = 0xFF,
}

pub struct SocksErrorReply;

impl SocksErrorReply {
    pub async fn send(
        stream: Arc<Mutex<TcpStream>>,
        code: SocksErrorReplyCode,
    ) -> Result<(), Box<dyn Error>> {
        let packet = [
            // version
            SocksVersion::Socks5 as u8,
            // error code
            code as u8,
            // reserved (must be 0)
            0x00,
            // addr type (IPv4)
            0x01,
            // 4 byte address
            0x00,
            0x00,
            0x00,
            0x00,
            // port number
            0x00,
            0x00,
        ];
        stream.lock().await.write_all(&packet).await?;
        Ok(())
    }
}

pub struct SocksReply;

impl SocksReply {
    pub async fn send(stream: Arc<Mutex<TcpStream>>) -> Result<(), Box<dyn Error>> {
        let packet = [
            // version
            SocksVersion::Socks5 as u8,
            // success code
            SocksErrorReplyCode::Success as u8,
            // reserved (must be 0)
            0x00,
            // addr type (IPv4)
            0x01,
            // 4 byte address
            0x00,
            0x00,
            0x00,
            0x00,
            // port number
            0x00,
            0x00,
        ];
        stream.lock().await.write_all(&packet).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task;

    async fn client_connect_and_send_async<'a>(addr: &str, packets: Vec<Vec<u8>>) {
        let addr = addr.to_string();
        task::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            for p in packets {
                client.write_all(&p[..]).await.unwrap();
            }
        });
    }

    async fn accept_client(addr: &str) -> TcpStream {
        let listener = TcpListener::bind(addr).await.unwrap();
        let (stream, _addr) = listener.accept().await.unwrap();
        stream
    }

    #[tokio::test]
    async fn client_connection_two_methods() {
        const TEST_ADDR: &str = "127.0.0.1:1111";
        let tests = vec![vec![0x05, 0x02, 0x00, 0x02]];
        client_connect_and_send_async(TEST_ADDR, tests).await;

        let stream = accept_client(TEST_ADDR).await;

        let cc = ClientConnection::read_from(Arc::new(Mutex::new(stream)))
            .await
            .unwrap();

        assert_eq!(
            cc.methods,
            vec![SocksAuthMethod::NoAuth, SocksAuthMethod::UserPass]
        );
    }

    #[tokio::test]
    async fn client_connection_mismatched_methods() {
        const TEST_ADDR: &str = "127.0.0.1:1112";
        //                                     --- should be another here
        //                                    V
        let tests = vec![vec![0x05, 0x02, 0x02]];
        client_connect_and_send_async(TEST_ADDR, tests).await;

        let stream = accept_client(TEST_ADDR).await;

        let cc = ClientConnection::read_from(Arc::new(Mutex::new(stream))).await;

        assert!(cc.is_err());
    }

    #[test]
    fn auth_method_try() {
        assert_eq!(
            SocksAuthMethod::try_from(0x00).unwrap(),
            SocksAuthMethod::NoAuth
        );
        assert_eq!(
            SocksAuthMethod::try_from(0x01).unwrap(),
            SocksAuthMethod::Gssapi
        );
        assert_eq!(
            SocksAuthMethod::try_from(0x02).unwrap(),
            SocksAuthMethod::UserPass
        );
        assert_eq!(
            SocksAuthMethod::try_from(0x03).unwrap(),
            SocksAuthMethod::IanaAssigned
        );
        assert_eq!(
            SocksAuthMethod::try_from(0x50).unwrap(),
            SocksAuthMethod::IanaAssigned
        );
        assert_eq!(
            SocksAuthMethod::try_from(0x7F).unwrap(),
            SocksAuthMethod::IanaAssigned
        );
        assert_eq!(
            SocksAuthMethod::try_from(0x80).unwrap(),
            SocksAuthMethod::Reserved
        );
        assert_eq!(
            SocksAuthMethod::try_from(0xF0).unwrap(),
            SocksAuthMethod::Reserved
        );
        assert_eq!(
            SocksAuthMethod::try_from(0xFE).unwrap(),
            SocksAuthMethod::Reserved
        );
        assert_eq!(
            SocksAuthMethod::try_from(0xFF).unwrap(),
            SocksAuthMethod::NoAcceptableMethods
        );
    }

    #[test]
    fn socks_command_try() {
        assert_eq!(SocksCommand::try_from(0x01).unwrap(), SocksCommand::Connect);
        assert_eq!(SocksCommand::try_from(0x02).unwrap(), SocksCommand::Bind);
        assert_eq!(
            SocksCommand::try_from(0x03).unwrap(),
            SocksCommand::UdpAssociate
        );

        assert_eq!(
            SocksCommand::try_from(0xFF),
            Err(SocksHandleError::InvalidCommandValue)
        );
    }

    #[test]
    fn socks_addr_type_try() {
        assert_eq!(
            SocksAddressType::try_from(0x01).unwrap(),
            SocksAddressType::Ipv4
        );
        assert_eq!(
            SocksAddressType::try_from(0x03).unwrap(),
            SocksAddressType::Domain
        );
        assert_eq!(
            SocksAddressType::try_from(0x04).unwrap(),
            SocksAddressType::Ipv6
        );

        assert_eq!(
            SocksAddressType::try_from(0x10),
            Err(SocksHandleError::InvalidAddressType)
        );
    }

    #[tokio::test]
    async fn server_initial_response() {
        const TEST_ADDR: &str = "127.0.0.1:1113";

        task::spawn(async {
            // connect to the listener and send a SocksServerAuthResponse
            let addr = TEST_ADDR.to_string();
            let client = TcpStream::connect(addr).await.unwrap();
            let resp = SocksServerAuthResponse::create(0x05, SocksAuthMethod::NoAuth as u8);
            resp.send(Arc::new(Mutex::new(client))).await.unwrap();
        });

        let mut stream = accept_client(TEST_ADDR).await;

        let mut res = [0u8; 2];
        stream.read_exact(&mut res).await.unwrap();

        // verify the packet
        assert_eq!(res[0], 0x05);
        assert_eq!(res[1], SocksAuthMethod::NoAuth as u8);
    }

    #[tokio::test]
    async fn test_resolve_address() {
        const TEST_ADDR: &str = "127.0.0.1:1114";

        // test each resolve type
        // 127.0.0.1 IPv4
        let ipv4 = vec![0x7f, 0x00, 0x00, 0x01, 0x12, 0x34];
        // ::1 IPv6
        let ipv6 = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x12, 0x34,
        ];
        let hostname = "localhost";
        let mut domain: Vec<u8> = vec![hostname.len() as u8];
        domain.extend(hostname.bytes());
        domain.extend(vec![0x12, 0x34].into_iter());

        let tests = vec![ipv4, ipv6, domain];

        client_connect_and_send_async(TEST_ADDR, tests).await;

        let stream = accept_client(TEST_ADDR).await;

        let stream = Arc::new(Mutex::new(stream));

        // receive the ipv4
        let mut ipv4_addr = SocksAddress::from_stream(SocksAddressType::Ipv4 as u8, stream.clone())
            .await
            .unwrap();

        // ipv6 was next
        let mut ipv6_addr = SocksAddress::from_stream(SocksAddressType::Ipv6 as u8, stream.clone())
            .await
            .unwrap();

        // domain after (will resolve to ::1 v6 ftw)
        let mut domain_addr =
            SocksAddress::from_stream(SocksAddressType::Domain as u8, stream.clone())
                .await
                .unwrap();

        assert!(ipv4_addr.resolved.is_none());
        assert!(ipv6_addr.resolved.is_none());
        assert!(domain_addr.resolved.is_none());

        // resolve them all
        let res4 = ipv4_addr.resolve_socket_addr().await.unwrap();
        let res6 = ipv6_addr.resolve_socket_addr().await.unwrap();
        let resd = domain_addr.resolve_socket_addr().await.unwrap();

        assert_eq!(res4.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(res4.port(), 0x1234);
        assert_eq!(res6.ip(), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(res6.port(), 0x1234);
        assert_eq!(resd.ip(), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(resd.port(), 0x1234);
    }

    #[tokio::test]
    async fn failed_lookup() {
        const TEST_ADDR: &str = "127.0.0.1:1115";

        let hostname = "notadomainnamethatexistsever.com";
        let mut domain: Vec<u8> = vec![hostname.len() as u8];
        domain.extend(hostname.bytes());
        domain.extend(vec![0x12, 0x34].into_iter());
        let tests = vec![domain];

        client_connect_and_send_async(TEST_ADDR, tests).await;

        let stream = Arc::new(Mutex::new(accept_client(TEST_ADDR).await));

        let mut domain_addr =
            SocksAddress::from_stream(SocksAddressType::Domain as u8, stream.clone())
                .await
                .unwrap();

        assert!(domain_addr.resolved.is_none());

        // resolve, should fail
        let resd = domain_addr.resolve_socket_addr().await;

        // sadly (sort of?), tokio's error will beat our own so it's tough to test;
        // just need to know that we did fail
        assert!(resd.is_err());
    }

    #[tokio::test]
    async fn good_socks_request() {
        const TEST_ADDR: &str = "127.0.0.1:1116";

        let tests = vec![vec![
            //   ver   cmd   rsv  adtyp         address            port
            0x05, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x12, 0x34,
        ]];
        client_connect_and_send_async(TEST_ADDR, tests).await;

        let stream = Arc::new(Mutex::new(accept_client(TEST_ADDR).await));

        let req = SocksRequest::read_from_stream(stream.clone())
            .await
            .unwrap();

        assert_eq!(req.command, SocksCommand::Connect);
        assert!(req.address.get_resolved().is_some());
        let res = req.address.get_resolved().unwrap();
        assert_eq!(res.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(res.port(), 0x1234);
    }

    #[tokio::test]
    async fn bad_socks_version_request() {
        const TEST_ADDR: &str = "127.0.0.1:1117";

        let tests = vec![vec![
            // ver   cmd   adtyp         address            port
            0x05, 0x01, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x12, 0x34,
        ]];
        // the packet above holds an invalid address type because the reserved field is "skipped"
        client_connect_and_send_async(TEST_ADDR, tests).await;

        let stream = Arc::new(Mutex::new(accept_client(TEST_ADDR).await));

        let req = SocksRequest::read_from_stream(stream.clone()).await;

        assert!(req.is_err());
    }
}
