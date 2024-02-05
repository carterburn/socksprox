use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum SocksSetupError {
    #[error("Invalid SOCKS Version; SOCKS5 is the only supported version")]
    InvalidSocksVersion(u8),

    #[error("Mismatched number of methods and provided methods")]
    MismatchedMethods,

    #[error("Unsupported authentication method")]
    UnsupportedAuthMethod,
}

#[derive(Error, Debug, PartialEq)]
pub enum SocksUserAuthError {
    #[error("Invalid Username/Password Authentication version")]
    InvalidVersion,

    #[error("Invalid username or password; Authentication failed")]
    FailedAuthentication,
}

#[derive(Error, Debug, PartialEq)]
pub enum SocksHandleError {
    #[error("Bind command not supported")]
    BindNotSupported,

    #[error("UDP Associate command not supported")]
    UdpNotSupported,

    #[error("Invalid command (CMD) for Socks Request")]
    InvalidCommandValue,

    #[error("Invalid address type for Socks Request")]
    InvalidAddressType,

    #[error("Failed looking up the hostname for a request")]
    FailedHostLookup,

    #[error("General error")]
    #[allow(dead_code)]
    GeneralFailure,

    #[error("Failed connection to upstream")]
    FailedConnection,

    #[error("Couldn't keep relaying the data")]
    FailedRelay,
}
