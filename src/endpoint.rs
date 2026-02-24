use crate::endpoint_config::EndpointConfig;
use crate::error::Error;
use crate::error::Error::{InvalidHeader, QuicheRecvFailed};
use crate::{generate_cid_and_reset_token, handle_path_events, server_config, setup_qlog, ClientId, ClientIdMap, Conn, ConnMap, Result, INSTANT_ZERO, MAX_UDP_PAYLOAD};
use log::{debug, error, trace, warn};
use quiche::{ConnectionId, Header, RecvInfo, SendInfo};
use ring::rand::{SecureRandom, SystemRandom};
use smallvec::SmallVec;
use std::net::SocketAddr;
use std::ops::Range;
use std::time::{Duration, Instant};

#[derive(Debug, Eq, PartialEq, Hash)]
pub enum RecvResult {
    VersionNegotiation,
    Retry,
    NewConnection(ClientId),
    /// true if migrated
    ForConnection(ClientId, bool),
}

pub struct Endpoint<TConnAppData = (), TAppData = ()> {
    config: EndpointConfig,
    server: Option<server_config::ServerConfig<TConnAppData>>,
    conn_ids: ClientIdMap,
    conns: ConnMap<TConnAppData>,
    rng: SystemRandom,
    app_data: TAppData,
    continue_write: bool,
}

/// Endpoint is an entity that can participate in a QUIC connection by
/// generating, receiving, and processing QUIC packets.
///
/// There are two types of endpoints in QUIC: client and server. Endpoint may
/// multiplex more QUIC connections.  Endpoint provides a high level API
/// to use the QUIC library.
/// > Inspired by tquic.
impl<TConnAppData, TAppData> Endpoint<TConnAppData, TAppData> {
    pub fn new(server: Option<server_config::ServerConfig<TConnAppData>>, config: EndpointConfig, app_data: TAppData) -> Self {
        Self {
            config,
            server,
            conn_ids: Default::default(),
            conns: Default::default(),
            rng: SystemRandom::new(),
            app_data,
            continue_write: false,
        }
    }

    /// create new client connection
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        &mut self,
        server_name: Option<&str>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        config: &mut quiche::Config,
        conn_app_data: TConnAppData,
        setup_conn_keylog: Option<fn(&mut quiche::Connection)>,
        session_file: Option<String>,
    ) -> ClientId {
        let scid = if !cfg!(feature = "fuzzing") {
            let mut conn_id = [0; quiche::MAX_CONN_ID_LEN];
            self.rng.fill(&mut conn_id[..]).unwrap();

            conn_id.to_vec()
        } else {
            // When fuzzing use an all zero connection ID.
            [0; quiche::MAX_CONN_ID_LEN].to_vec()
        };

        let scid = quiche::ConnectionId::from_ref(&scid);

        // Create a QUIC connection and initiate handshake.
        let mut conn = quiche::connect(
            server_name,
            &scid,
            local_addr,
            peer_addr,
            config,
        )
            .unwrap();

        if let Some(setup_conn_keylog) = setup_conn_keylog {
            setup_conn_keylog(&mut conn);
        }

        // Only bother with qlog if the user specified it.
        #[cfg(feature = "qlog")]
        setup_qlog(&mut conn, "client", &scid);

        if let Some(session_file) = session_file && let Ok(session) = std::fs::read(session_file) {
            conn.set_session(&session).ok();
        }

        let client_id = self.conns.vacant_key();
        let max_datagram_size = conn.max_send_udp_payload_size();
        self.conns.insert(Conn {
            client_id,
            conn,
            app_data: conn_app_data,
            max_datagram_size,
            loss_rate: 0.0,
            max_send_burst: MAX_UDP_PAYLOAD,
            setup_early_data: false,
            setup_established: false,
        });

        self.conn_ids.insert(scid.into_owned(), client_id);

        self.continue_write = true; // should send initial packet immediately, connection timeout is None initially
        client_id
    }

    /// similar to `recv`, but can process multiple packets
    pub fn recv_pkts(&mut self, buf: &mut [u8], segment_size: usize, ri: RecvInfo) -> SmallVec<Result<RecvResult>, 64> {
        let mut results = SmallVec::new();
        for segment in buf.chunks_mut(segment_size) {
            let r = self.recv(segment, ri);
            results.push(r);
        }
        results
    }

    /// Process an incoming UDP datagram.
    ///
    /// Incoming packets are classified on receipt. Packets can either be
    /// associated with an existing connection or for servers potentially create
    /// a new connection.
    /// See RFC 9000 Section 5.2 Matching Packets to Connections.
    /// > Inspired by tquic.
    pub fn recv(&mut self, buf: &mut [u8], info: RecvInfo) -> Result<RecvResult> {
        let pkt_buf = buf;
        // will be set if a new connection was created
        let mut new_connection = false;

        // Parse the QUIC packet's header.
        // Todo dont parse header twice
        let hdr = quiche::Header::from_slice(
            pkt_buf,
            quiche::MAX_CONN_ID_LEN,
        ).map_err(InvalidHeader)?;

        trace!("got packet {:?}", hdr);

        // Lookup a connection based on the packet's connection ID. If there
        // is no connection matching, create a new one.
        let (cid, conn) = if let Some(server) = self.server.as_mut() {
            let conn_id = if !cfg!(feature = "fuzzing") {
                let conn_id = ring::hmac::sign(&server.conn_id_seed, &hdr.dcid);
                let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                conn_id.to_vec().into()
            } else {
                // When fuzzing use an all zero connection ID.
                [0; quiche::MAX_CONN_ID_LEN].to_vec().into()
            };
            if !self.conn_ids.contains_key(&hdr.dcid) && !self.conn_ids.contains_key(&conn_id) {
                if hdr.ty != quiche::Type::Initial {
                    return Err(Error::UnknownConnID);
                }

                if !quiche::version_is_supported(hdr.version) {
                    self.queue_version_negotiation(&hdr, &info)?;
                    return Ok(RecvResult::VersionNegotiation);
                }

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                scid.copy_from_slice(&conn_id);

                let mut odcid = None;

                if let Some(retry) = &server.retry {
                    let validate_token = &retry.validate_token;

                    // Token is always present in Initial packets.
                    let token = hdr.token.as_ref().unwrap();

                    // Do stateless retry if the client didn't send a token.
                    if token.is_empty() {
                        self.queue_retry(&hdr, &info, &ConnectionId::from_ref(&scid))?;
                        return Ok(RecvResult::Retry);
                    }

                    odcid = validate_token(&info.from, token);

                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid.is_none() {
                        return Err(Error::InvalidAddrToken);
                    }

                    if scid.len() != hdr.dcid.len() {
                        return Err(Error::InvalidConnID);
                    }

                    // Reuse the source connection ID we sent in the Retry
                    // packet, instead of changing it again.
                    scid.copy_from_slice(&hdr.dcid);
                }

                let scid = quiche::ConnectionId::from_vec(scid.to_vec());

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                #[allow(unused_mut)]
                let mut conn = quiche::accept(
                    &scid,
                    odcid.as_ref(),
                    info.to,
                    info.from,
                    &mut server.client_config,
                )
                    .unwrap();

                if let Some(setup_conn_keylog) = &server.setup_conn_keylog {
                    setup_conn_keylog(&mut conn);
                }

                // Only bother with qlog if the user specified it.
                #[cfg(feature = "qlog")]
                setup_qlog(&mut conn, "server", &scid);

                let app_data = (server.on_accept)(&conn);

                let client_id = self.conns.vacant_key();
                let max_datagram_size = conn.max_send_udp_payload_size();
                self.conns.insert(Conn {
                    client_id,
                    conn,
                    app_data,
                    max_datagram_size,
                    loss_rate: 0.0,
                    max_send_burst: MAX_UDP_PAYLOAD,
                    setup_early_data: false,
                    setup_established: false,
                });
                self.continue_write = true;
                self.conn_ids.insert(scid.clone().into_owned(), client_id);
                new_connection = true;
                (client_id, self.conns.get_mut(client_id).unwrap())
            } else {
                let cid = match self.conn_ids.get(&hdr.dcid) {
                    Some(v) => v,

                    None => self.conn_ids.get(&conn_id).unwrap(),
                };

                (*cid, self.conns.get_mut(*cid).unwrap())
            }
        } else { // client
            if let Some(cid) = self.conn_ids.get(&hdr.dcid) {
                (*cid, self.conns.get_mut(*cid).unwrap())
            } else {
                return Err(Error::UnknownConnID);
            }
        };

        // Process potentially coalesced packets.
        let read = conn.conn.recv(pkt_buf, info).map_err(QuicheRecvFailed)?;
        self.continue_write = true;

        trace!("{}: processed {} bytes", info.to, read);

        // Handle path events.
        let migrated = handle_path_events(
            &mut conn.conn,
        );

        // Provides as many CIDs as possible.
        while conn.conn.scids_left() > 0 {
            let (scid, reset_token) = generate_cid_and_reset_token(&self.rng);

            if conn.conn
                .new_scid(&scid, reset_token, false)
                .is_err()
            {
                break;
            }
            self.conn_ids.insert(scid, conn.client_id);
        }

        // See whether source Connection IDs have been retired.
        while let Some(retired_scid) = conn.conn.retired_scid_next()
        {
            debug!(
                    "Retiring source CID {:?}",
                    retired_scid
                );
        }

        if !conn.setup_early_data && conn.conn.is_in_early_data() {
            conn.setup_early_data = true;
            conn.max_datagram_size = conn.conn.max_send_udp_payload_size();
        }
        if !conn.setup_established && conn.conn.is_established() {
            conn.setup_established = true;
            conn.max_datagram_size = conn.conn.max_send_udp_payload_size();
        }

        if new_connection {
            Ok(RecvResult::NewConnection(cid))
        } else {
            Ok(RecvResult::ForConnection(cid, migrated))
        }
    }

    /// Generate all outgoing QUIC packets to be sent on the UDP socket.
    /// continue_write is set if write < max_datagram_size or  total_write >= max_send_burst
    pub fn send_all<F>(&mut self, out: &mut [u8], mut send_to: F) where F: FnMut(&mut [u8], &SendInfo, usize) -> std::io::Result<()> {
        if let Some(server) = self.server.as_mut() {
            // send queued packets first
            while let Some((mut buf, send_info)) = server.packet_queue.pop_packet() {
                let len = buf.len();
                send_to(
                    buf.as_mut_slice(),
                    &send_info,
                    len,
                ).unwrap();
                server.packet_queue.push_buffer(buf);
            }
        }

        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        self.continue_write = false;
        for (_, client)in &mut self.conns {
            // Reduce max_send_burst by 25% if loss is increasing more than 0.1%.
            let loss_rate =
                client.conn.stats().lost as f64 / client.conn.stats().sent as f64;
            if loss_rate > client.loss_rate + 0.001 {
                client.max_send_burst = client.max_send_burst / 4 * 3;
                // Minimum bound of 10xMSS.
                client.max_send_burst =
                    client.max_send_burst.max(client.max_datagram_size * 10);
                client.loss_rate = loss_rate;
            }

            let max_datagram_size = client.conn.max_send_udp_payload_size();
            let quantum = if self.config.ignore_quantum {
                client.max_send_burst
            } else {
                client.conn.send_quantum().min(client.max_send_burst)
            };
            let max_send_burst = quantum /
                    max_datagram_size *
                    max_datagram_size;
            let mut total_write = 0;
            let mut dst_info = None;

            while total_write < max_send_burst {
                let (write, send_info) = match client
                    .conn
                    .send(&mut out[total_write..max_send_burst])
                {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        trace!("{} done writing", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!("{} send failed: {:?}", client.conn.trace_id(), e);

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                total_write += write;

                // Use the first packet time to send, not the last.
                let _ = dst_info.get_or_insert(send_info);

                if write < max_datagram_size {
                    self.continue_write = true;
                    break;
                }
            }

            if total_write == 0 || dst_info.is_none() {
                continue;
            }

            if let Err(e) = send_to(
                &mut out[..total_write],
                {
                    let i = dst_info.as_mut().unwrap();
                    if self.config.ignore_pacing {
                        i.at = INSTANT_ZERO;
                    }
                    i
                },
                max_datagram_size
            ) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    trace!("send() would block");
                    self.continue_write = true;
                    break;
                }

                panic!("send_to() failed: {e:?}");
            }

            trace!(
                "{} written {total_write} bytes with {dst_info:?}",
                client.conn.trace_id()
            );

            if total_write >= max_send_burst {
                trace!("{} pause writing", client.conn.trace_id(),);
                self.continue_write = true;
                break;
            }
        }
    }

    fn queue_version_negotiation(&mut self, hdr: &Header, recv_info: &RecvInfo) -> Result<()> {
        warn!("Doing version negotiation");
        let server = self.server.as_mut().unwrap();
        let mut buf = server.packet_queue.pop_buffer();

        let len =
            quiche::negotiate_version(&hdr.scid, &hdr.dcid, buf.as_mut_slice())
                .unwrap();
        buf.truncate(len);

        let send_info = SendInfo {
            from: recv_info.to,
            to: recv_info.from,
            at: Instant::now(),
        };

        server.packet_queue.push_packet(buf, send_info);

        Ok(())
    }

    fn queue_retry(&mut self, hdr: &Header, recv_info: &RecvInfo, new_scid: &ConnectionId) -> Result<()> {
        warn!("Doing stateless retry");
        let server = self.server.as_mut().unwrap();
        let mint_token = server.retry.as_mut().unwrap().mint_token;

        let mut buf = server.packet_queue.pop_buffer();

        let new_token = mint_token(hdr, &recv_info.from);

        let len = quiche::retry(
            &hdr.scid,
            &hdr.dcid,
            new_scid,
            &new_token,
            hdr.version,
            buf.as_mut_slice(),
        ).unwrap();

        buf.truncate(len);

        let send_info = SendInfo {
            from: recv_info.to,
            to: recv_info.from,
            at: Instant::now(),
        };

        server.packet_queue.push_packet(buf, send_info);

        Ok(())
    }

    /// Garbage collect closed connections.
    pub fn collect_garbage(&mut self, on_close: Option<fn(&Conn<TConnAppData>, &mut TAppData)>) {
        self.conns.retain(|_, ref mut c| {
            trace!("Collecting garbage");

            if !c.conn.is_closed() {
                return true; // retain
            }

            for id in c.conn.source_ids() {
                let id_owned = id.clone().into_owned();
                self.conn_ids.remove(&id_owned);
            }

            if let Some(on_close) = on_close {
                on_close(c, &mut self.app_data)
            }
            debug!("Garbage collect {}", c.conn.trace_id());

            false // remove
        });
    }

    /// Returns the amount of time until the next timeout event.
    ///
    /// Once the given duration has elapsed, the `on_timeout()` method should
    /// be called. A timeout of `None` means that the timer should be disarmed.
    pub fn timeout(&self) -> Option<Duration> {
        self.conns.iter().filter_map(|(_, c)| c.conn.timeout()).min()
    }

    /// Processes a timeout event.
    ///
    /// If no timeout has occurred it does nothing.
    pub fn on_timeout(&mut self) {
        trace!("on_timeout");
        self.conns.iter_mut().for_each(|(_, c)| {
            c.conn.on_timeout()
        });
        self.continue_write = true;
    }

    /// Returns true if `send_packets_out()` might still return packets.
    /// All packets must be sent before waiting for the next timeout.
    pub fn has_pending_sends(&self) -> bool {
        self.continue_write
    }

    pub fn conn(&self, cid: ClientId) -> Option<&Conn<TConnAppData>> {
        self.conns.get(cid)
    }

    /// This will mark the connection as `pending_send` because the caller might trigger sending
    /// packets, for example, by calling `stream_send`.
    fn _conn_mut<'a>(conns: &'a mut ConnMap<TConnAppData>, cid: ClientId, continue_write: &mut bool) -> Option<&'a mut Conn<TConnAppData>> {
        let c = conns.get_mut(cid)?;
        *continue_write = true;
        Some(c)
    }

    /// This will mark the connection as `pending_send` because the caller might trigger sending
    /// packets, for example, by calling `stream_send`.
    pub fn conn_mut(&mut self, cid: ClientId) -> Option<&mut Conn<TConnAppData>> {
        Self::_conn_mut(&mut self.conns, cid, &mut self.continue_write)
    }

    /// This will mark the connections as `pending_send` because the caller might trigger sending
    /// packets, for example, by calling `stream_send`.
    pub fn conn2_mut(&mut self, cid1: ClientId, cid2: ClientId) -> Option<(&mut Conn<TConnAppData>, &mut Conn<TConnAppData>)> {
        let (c1, c2) = self.conns.get2_mut(cid1, cid2)?;
        self.continue_write = true;
        Some((c1, c2))
    }

    /// This will mark the connection as `pending_send` because the caller might trigger sending
    /// packets, for example, by calling `stream_send`.
    /// Also returns the endpoints app data.
    pub fn conn_with_app_data_mut(&mut self, cid: ClientId) -> (Option<&mut Conn<TConnAppData>>, &mut TAppData) {
        (
            Self::_conn_mut(&mut self.conns, cid, &mut self.continue_write),
            &mut self.app_data
        )
    }

    /// This will mark the connections as `pending_send` because the caller might trigger sending
    /// packets, for example, by calling `stream_send`.
    /// Also returns the endpoints app data.
    #[allow(clippy::type_complexity)]
    pub fn conn2_with_app_data_mut(&mut self, cid1: ClientId, cid2: ClientId) -> (Option<(&mut Conn<TConnAppData>, &mut Conn<TConnAppData>)>, &mut TAppData) {
        let Some((c1, c2)) = self.conns.get2_mut(cid1, cid2) else { return (None, &mut self.app_data) };
        self.continue_write = true;
        (Some((c1, c2)), &mut self.app_data)
    }


    /// The number of QUIC connections managed by the endpoint.
    /// Draining are counted.
    /// Closed connections are counted until `collect_garbage`.
    pub fn num_conns(&self) -> usize {
        self.conns.len()
    }

    /// Iterate over all QUIC connections managed by the endpoint.
    /// Including draining connections.
    /// Including closed connections until `collect_garbage`.
    pub fn conn_iter(&self) -> slab::Iter<'_, Conn<TConnAppData>> {
        self.conns.iter()
    }

    /// Iterate over all connection indexes.
    /// Connection might be no longer available.
    /// `self.get_conn()` must always be chacked for `None`.
    /// The advantage of `conn_index_iter` over `conn_iter` is that it does not borrow.
    pub fn conn_index_iter(&self) -> Range<usize> {
        0..self.conns.capacity()
    }

    /// True if endpoint acts as a server
    pub fn is_server(&self) -> bool {
        self.server.is_some()
    }

    pub fn app_data(&self) -> &TAppData {
        &self.app_data
    }

    pub fn app_data_mut(&mut self) -> &mut TAppData {
        &mut self.app_data
    }

    /// Silently remove connection from endpoint.
    /// No close and no more other packets are sent for this connections.
    pub fn remove_conn(&mut self, cid: ClientId) {
        let conn = self.conns.remove(cid);

        for id in conn.conn.source_ids() {
            let id_owned = id.clone().into_owned();
            self.conn_ids.remove(&id_owned);
        }
    }

    pub fn take_app_data(self) -> TAppData {
        self.app_data
    }

    /// calls connection stream_send
    pub fn stream_send(&mut self, cid: ClientId, stream_id: u64, buf: &[u8], fin: bool) -> Result<usize> {
        self.conn_mut(cid)
            .ok_or(Error::UnknownConnID)?
            .conn.stream_send(stream_id, buf, fin)
            .map_err(Into::into)
    }

    /// calls connection stream_recv
    pub fn stream_recv(&mut self, cid: ClientId, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool)> {
        self.conn_mut(cid)
            .ok_or(Error::UnknownConnID)?
            .conn.stream_recv(stream_id, buf)
            .map_err(Into::into)
    }

    /// Remove all connections and pending packets
    pub fn reset(&mut self) {
        if let Some(server) = &mut self.server {
            server.reset();
        }
        self.conn_ids.clear();
        self.conns.clear();
        self.continue_write = false;
    }

    /// Return mut collection of connections and mut app_data
    pub fn mut_conns_and_app_data(&mut self) -> (&mut ConnMap<TConnAppData>, &mut TAppData) {
        self.continue_write = true;
        (&mut self.conns, &mut self.app_data)
    }

}
