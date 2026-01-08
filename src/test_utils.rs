use crate::{ClientId, Endpoint, EndpointConfig, Error, Result, ServerConfig};
use boring::asn1::Asn1Time;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private};
use boring::rsa::Rsa;
use boring::ssl::{SslContextBuilder, SslMethod};
use boring::x509::extension::SubjectAlternativeName;
use boring::x509::store::X509StoreBuilder;
use boring::x509::{X509NameBuilder, X509};
use quiche::{Config, RecvInfo, SendInfo, PROTOCOL_VERSION};
use std::net::SocketAddr;
use std::sync::OnceLock;

/// generate private and public key pair for testing
pub fn key_pair() -> &'static (PKey<Private>, X509) {
    static KEY_PAIR: OnceLock<(PKey<Private>, X509)> = OnceLock::new();
    KEY_PAIR.get_or_init(|| {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        // Build X.509 certificate
        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder.append_entry_by_text("CN", "localhost").unwrap();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_pubkey(&pkey).unwrap();

        builder.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref()).unwrap();
        builder.set_not_after(Asn1Time::days_from_now(365).unwrap().as_ref()).unwrap();

        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(san).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        (pkey, cert)
    })
}

/// convert send info to recv info
pub fn to_recv_info(si: SendInfo) -> RecvInfo {
    RecvInfo {
        from: si.from,
        to: si.to,
    }
}

pub fn default_server_config(key: &PKey<Private>, cert: &'static X509) -> ServerConfig {
    {
        let mut c = ServerConfig::default();
        c.client_config = {
            let mut c = Config::with_boring_ssl_ctx_builder(PROTOCOL_VERSION, {
                let mut b = SslContextBuilder::new(SslMethod::tls()).unwrap();
                b.set_private_key(key).unwrap();
                b.set_certificate(cert).unwrap();
                b
            }).unwrap();
            c.set_application_protos(&[b"proto1"]).unwrap();
            c.set_initial_max_streams_bidi(1);
            c.set_initial_max_stream_data_uni(1);
            c.set_initial_max_data(10_000);
            c.set_initial_max_stream_data_uni(10_000);
            c.set_initial_max_stream_data_bidi_local(10_000);
            c.set_initial_max_stream_data_bidi_remote(10_000);
            c.set_active_connection_id_limit(5);
            c.set_max_idle_timeout(1000);
            c
        };
        c
    }
}

pub fn default_client_config(cert: &'static X509) -> Config {
    let mut c = Config::with_boring_ssl_ctx_builder(PROTOCOL_VERSION, {
        let mut b = SslContextBuilder::new(SslMethod::tls()).unwrap();
        b.set_cert_store_builder({
            let mut b = X509StoreBuilder::new().unwrap();
            b.add_cert(cert.clone()).unwrap();
            b
        });
        b
    }).unwrap();
    c.set_application_protos(&[b"proto1"]).unwrap();
    c.set_initial_max_streams_bidi(1);
    c.set_initial_max_stream_data_uni(1);
    c.set_initial_max_data(10_000);
    c.set_initial_max_stream_data_uni(10_000);
    c.set_initial_max_stream_data_bidi_local(10_000);
    c.set_initial_max_stream_data_bidi_remote(10_000);
    c.verify_peer(true);
    c.set_active_connection_id_limit(5);
    c.set_max_idle_timeout(1000);
    c
}

/// similar to `quiche::testing::Pipe` but for Endpoints
pub struct Pipe {
    pub cert: &'static X509,
    pub client: Endpoint<(), ()>,
    pub server: Endpoint<(), ()>,
}

impl Pipe {
    /// create a pipe containing a server and client endpoint.
    pub fn new() -> Self {
        Self::with(
            None,
        )
    }

    pub fn with(config_server: Option<fn(&mut ServerConfig)>) -> Self {
        let (key, cert) = key_pair();
        let mut server_config = default_server_config(key, cert);
        if let Some(config_server) = config_server {
            config_server(&mut server_config)
        }
        Self {
            cert,
            client: Endpoint::new(None, EndpointConfig::default(), ()),
            server: Endpoint::new(Some(server_config), EndpointConfig::default(), ()),
        }
    }

    /// create a new connection on the client endpoint.
    /// this function does not generate outgoing packets.
    pub fn connect(&mut self) -> ClientId {
        self.connect_with(
            None,
            None,
        )
    }

    /// create a new connection on the client endpoint.
    /// this function does not generate outgoing packets.
    ///
    /// * `peer_addr` - None to use default server address
    /// * `client_config` - None to use default config
    pub fn connect_with(&mut self, peer_addr: Option<SocketAddr>, client_config: Option<&mut Config>) -> ClientId {
        let peer_addr = peer_addr.unwrap_or("127.0.0.1:9000".parse().unwrap());
        let mut default_client_config = default_client_config(self.cert);
        let mut client_config = client_config.unwrap_or(&mut default_client_config);

        self.client.connect(
            None,
            "127.0.0.1:8000".parse().unwrap(),
            peer_addr,
            &mut client_config,
            (),
            None,
            None,
        )
    }

    /// transfer as many packets from sender to receiver as currently available.
    /// return `Done` if nothing was sent.
    pub fn transfer(sender: &mut Endpoint<(), ()>, receiver: &mut Endpoint<(), ()>) -> Result<()> {
        let mut sent_something = false;
        let mut buf = [0u8; 1 << 16];
        loop {
            let ok = match sender.send_packets_out(&mut buf) {
                Ok(v) => v,
                Err(Error::Done) => {
                    return match sent_something {
                        true => Ok(()),
                        false => Err(Error::Done),
                    }
                }
                Err(e) => panic!("{:?}", e)
            };
            for r in receiver.recv_pkts(&mut buf[..ok.total], ok.segment_size, to_recv_info(ok.send_info)) {
                r.unwrap();
            }
            sent_something = true;
        }
    }

    /// exchange packets as long as packets are currently available
    pub fn advance(&mut self) {
        let mut client_done = false;
        let mut server_done = false;
        while !client_done || !server_done {
            match Self::transfer(&mut self.client, &mut self.server) {
                Ok(()) => client_done = false,
                Err(Error::Done) => client_done = true,
                Err(e) => panic!("{:?}", e)
            }
            match Self::transfer(&mut self.server, &mut self.client) {
                Ok(()) => server_done = false,
                Err(Error::Done) => server_done = true,
                Err(e) => panic!("{:?}", e)
            }
        }
    }

    /// Handshake all connections.
    /// This might advance other connections.
    pub fn handshake_all(&mut self) -> Result<()> {
        while !(
            self.client.conn_iter().all(|(_, c)| c.conn.is_established())
                && self.server.conn_iter().all(|(_, c)| c.conn.is_established())
        ) {
            Self::transfer(&mut self.client, &mut self.server)?;
            Self::transfer(&mut self.server, &mut self.client)?;
        }
        Ok(())
    }

    pub fn take(self) -> (Endpoint, Endpoint) {
        (self.client, self.server)
    }
}
