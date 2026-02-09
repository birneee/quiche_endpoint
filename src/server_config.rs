use crate::packet_queue::PacketQueue;
use crate::MAX_UDP_PAYLOAD;
use quiche::{Connection, ConnectionId, Header, PROTOCOL_VERSION};
use ring::hmac;
use ring::rand::SystemRandom;
use std::net::SocketAddr;

type SetupConnKeylogFunc = fn(&mut Connection);
type AcceptFunc<TAppData> = fn(&Connection) -> TAppData;
/// Generate a retry token.
/// This token should use cryptographic authentication on production systems.
type MintTokenFunc = fn(&Header, &SocketAddr) -> Vec<u8>;
/// Returns None if token is not valid.
/// Otherwise, returns the ODCID, representing the original destination ID the
/// client sent before a stateless retry.
type ValidateTokenFunc = for<'a> fn(&SocketAddr, &'a [u8]) -> Option<ConnectionId<'a>>;

/// Configuration that is required by `Endpoint` if acting as a server
pub struct ServerConfig<
    TAppData = (),
>
{
    /// if none no retry
    pub retry: Option<RetryConfig<MintTokenFunc, ValidateTokenFunc>>,
    pub out: [u8; MAX_UDP_PAYLOAD],
    pub setup_conn_keylog: Option<SetupConnKeylogFunc>,
    pub on_accept: AcceptFunc<TAppData>,
    pub client_config: quiche::Config,
    pub conn_id_seed: hmac::Key,
    /// packets to send which are not related to a connection
    pub(crate) packet_queue: PacketQueue,
}

pub struct RetryConfig<
    FMintToken = fn(&Header, &SocketAddr) -> Vec<u8>,
    FValidateToken = for<'a> fn(&SocketAddr, &'a [u8]) -> Option<ConnectionId<'a>>,
>
where
    FMintToken: Fn(&Header, &SocketAddr) -> Vec<u8>,
    for<'a> FValidateToken: Fn(&SocketAddr, &'a [u8]) -> Option<ConnectionId<'a>>,
{
    pub mint_token: FMintToken,
    pub validate_token: FValidateToken,
}

impl<TAppData> Default for ServerConfig<TAppData> where TAppData: Default {
    fn default() -> Self {
        Self {
            retry: None,
            out: [0; MAX_UDP_PAYLOAD],
            setup_conn_keylog: None,
            on_accept: |_| { TAppData::default() },
            client_config: quiche::Config::new(PROTOCOL_VERSION).unwrap(),
            conn_id_seed: hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new()).unwrap(),
            packet_queue: PacketQueue::new(),
        }
    }
}

impl <T> ServerConfig<T> {
    /// reset pending packets
    pub(crate) fn reset(&mut self) {
        self.packet_queue.clear();
    }

    pub fn new(accept_func: AcceptFunc<T>) -> Self {
        Self {
            retry: None,
            out: [0; MAX_UDP_PAYLOAD],
            setup_conn_keylog: None,
            on_accept: accept_func,
            client_config: quiche::Config::new(PROTOCOL_VERSION).unwrap(),
            conn_id_seed: hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new()).unwrap(),
            packet_queue: PacketQueue::new(),
        }
    }
}