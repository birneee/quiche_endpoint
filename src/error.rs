use std::fmt::{Display, Formatter};
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    CloseByUser,
    IO(io::Error),
    Quiche(quiche::Error),
    UnknownConnID,
    InvalidConnID,
    InvalidAddrToken,
    QuicheRecvFailed(quiche::Error),
    InvalidHeader(quiche::Error),
}

impl From<quiche::Error> for Error {
    fn from(e: quiche::Error) -> Self {
        Error::Quiche(e)
    }
}


impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IO(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            _ => None
        }
    }
}