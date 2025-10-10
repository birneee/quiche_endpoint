use crate::endpoint_config::EndpointConfig;
use crate::error::Error;
use crate::error::Error::{InvalidHeader, QuicheRecvFailed};
use crate::send_ok::SendOk;
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
    ForConnection(ClientId),
}

pub struct Endpoint<TConnAppData = (), TAppData = ()> {
    config: EndpointConfig<TConnAppData, TAppData>,
    server: Option<server_config::ServerConfig<TConnAppData>>,
    conn_ids: ClientIdMap,
    conns: ConnMap<TConnAppData>,
    rng: SystemRandom,
    app_data: TAppData,
    /// Number of connections that might have something to send.
    /// Number of connections hat have the field `pending_send` set.
    pending_send_conns: usize,
    /// The `ClientId` of QUIC connection to generate the next outgoing packet
    current_send_conn: usize,
    /// The destination addr to generate the next outgoing packet for.
    /// Must be reset to `None` if `current_send_conn` changes or all packets are sent on this path,
    /// and it should be continued with the next one.
    current_dst_addr: Option<SocketAddr>,
}

/// Endpoint is an entity that can participate in a QUIC connection by
/// generating, receiving, and processing QUIC packets.
///
/// There are two types of endpoints in QUIC: client and server. Endpoint may
/// multiplex more QUIC connections.  Endpoint provides a high level API
/// to use the QUIC library.
/// > Inspired by tquic.
impl<TConnAppData, TAppData> Endpoint<TConnAppData, TAppData> {
    pub fn new(server: Option<server_config::ServerConfig<TConnAppData>>, config: EndpointConfig<TConnAppData, TAppData>, app_data: TAppData) -> Self {
        Self {
            config,
            server,
            conn_ids: Default::default(),
            conns: Default::default(),
            rng: SystemRandom::new(),
            app_data,
            pending_send_conns: 0,
            current_send_conn: 0,
            current_dst_addr: None,
        }
    }

    /// create new client connection
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

        if let Some(session_file) = session_file {
            if let Ok(session) = std::fs::read(session_file) {
                conn.set_session(&session).ok();
            }
        }

        let client_id = self.conns.vacant_key();
        self.conns.insert(Conn {
            client_id,
            conn,
            app_data: conn_app_data,
            pending_send: true,
        });

        self.conn_ids.insert(scid.into_owned(), client_id);

        self.pending_send_conns += 1; // should send initial packet immediately, connection timeout is None initially
        client_id
    }

    /// similar to `recv`, but can process multiple packets
    pub fn recv_pkts(&mut self, buf: &mut [u8], segment_size: usize, ri: RecvInfo) -> SmallVec<Result<RecvResult>, 64> {
        let mut results = SmallVec::new();
        for segment in buf.chunks_mut(segment_size) {
            let r = self.recv(segment, ri);
            let _ = results.push(r);
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

        (self.config.on_recv_udp)(pkt_buf);

        // Parse the QUIC packet's header.
        // Todo dont parse header twice
        let hdr = quiche::Header::from_slice(
            pkt_buf,
            quiche::MAX_CONN_ID_LEN,
        ).map_err(|e| InvalidHeader(e))?;

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
                self.conns.insert(Conn {
                    client_id,
                    conn,
                    app_data,
                    pending_send: true,
                });
                self.pending_send_conns += 1;
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
        let read = conn.conn.recv(pkt_buf, info).map_err(|e| QuicheRecvFailed(e))?;
        if !conn.pending_send {
            conn.pending_send = true;
            self.pending_send_conns += 1;
        }

        trace!("{}: processed {} bytes", info.to, read);

        // Handle path events.
        handle_path_events(
            &mut conn.conn,
            self.config.on_migrate,
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
            (self.config.on_new_scid)(conn, &scid);
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

        (self.config.on_recv_quic)(self.conns.get_mut(cid).unwrap(), &mut self.app_data);
        if new_connection {
            Ok(RecvResult::NewConnection(cid))
        } else {
            Ok(RecvResult::ForConnection(cid))
        }
    }

    /// Generate a batch of outgoing QUIC packets to be sent on the UDP socket to the same destination.
    /// Returns `Err::Done` if no more packets are available.
    /// This function returns the same destination subsequently to optimize batched sending.
    /// Returns following values:
    ///  1. the total of bytes added to the `out`
    ///  2. the segment size (the least one might be smaller)
    ///  3. the send info
    pub fn send_packets_out(&mut self, out: &mut [u8]) -> Result<SendOk> {
        if let Some(server) = self.server.as_mut() {
            // send queued packets first
            while let Some((buf, send_info)) = server.packet_queue.pop_packet() {
                let len = buf.len();
                (&mut out[..len]).copy_from_slice(&buf);
                server.packet_queue.push_buffer(buf);
                return Ok(SendOk {
                    total: len,
                    segment_size: len,
                    send_info,
                    client_id: None,
                });
            }
        }

        let ok = 'conn: loop {
            if !self.has_pending_sends() {
                return Err(Error::Quiche(quiche::Error::Done));
            }
            let conn = match self.conns.get_mut(self.current_send_conn) {
                None => {
                    self.current_send_conn += 1;
                    if self.current_send_conn >= self.conns.capacity() {
                        self.current_send_conn = 0;
                    }
                    self.current_dst_addr = None;
                    continue;
                }
                Some(v) => v,
            };
            let quic_conn = &mut conn.conn;
            let max_datagram_size = quic_conn.max_send_udp_payload_size();
            debug_assert!(out.len() >= max_datagram_size);
            let mut total_write = 0;
            let mut dst_info: Option<quiche::SendInfo> = None;

            let quantum = if self.config.ignore_quantum {
                MAX_UDP_PAYLOAD
            } else {
                // using conn.send_quantum might perform worse
                quic_conn.send_quantum()
            };
            let max_send_burst = quantum.min(out.len()) / max_datagram_size * max_datagram_size;

            'packet: loop {
                let (write, mut send_info) = match quic_conn.send_on_path(&mut out[total_write..max_send_burst], None, self.current_dst_addr) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => {
                        match self.current_dst_addr {
                            None => {
                                trace!("{}: done writing", quic_conn.trace_id());
                                self.current_send_conn += 1; // next conn
                                conn.pending_send = false;
                                self.pending_send_conns -= 1;
                                debug_assert_eq!(total_write, 0);
                                continue 'conn;
                            }
                            Some(dst) => {
                                trace!("{}: None -> {}: done writing", quic_conn.trace_id(), dst);
                                self.current_dst_addr = None; // next path
                                if total_write == 0 {
                                    continue 'packet;
                                } else {
                                    break 'packet;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("{}: None -> {:?}: send failed: {:?}", quic_conn.trace_id(), self.current_dst_addr, e);
                        quic_conn.close(false, 0x1, b"fail").ok();
                        self.current_send_conn += 1; // next conn
                        continue 'conn;
                    }
                };
                match self.current_dst_addr {
                    None => {
                        self.current_dst_addr = Some(send_info.to);
                    }
                    Some(dst_addr) => {
                        debug_assert_eq!(dst_addr, send_info.to);
                    }
                }
                total_write += write;
                // Use the first packet time to send, not the last.
                if dst_info.is_none() {
                    if self.config.ignore_pacing {
                        send_info.at = INSTANT_ZERO;
                    }
                    dst_info = Some(send_info)
                }

                if write < max_datagram_size {
                    break 'packet;
                }

                if total_write >= max_send_burst {
                    break 'packet;
                }
            };
            debug_assert_ne!(total_write, 0);
            debug_assert_ne!(dst_info, None);
            break SendOk {
                total: total_write,
                segment_size: max_datagram_size,
                send_info: dst_info.unwrap(),
                client_id: Some(conn.client_id),
            };
        };
        Ok(ok)
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

        let new_token = mint_token(&hdr, &recv_info.from);

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
    pub fn collect_garbage(&mut self) {
        self.conns.retain(|_, ref mut c| {
            trace!("Collecting garbage");

            if !c.conn.is_closed() {
                return true; // retain
            }

            for id in c.conn.source_ids() {
                let id_owned = id.clone().into_owned();
                self.conn_ids.remove(&id_owned);
            }

            if c.pending_send {
                self.pending_send_conns -= 1;
            }

            (self.config.on_close)(c, &mut self.app_data);

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
            c.pending_send = true;
            c.conn.on_timeout()
        });
        self.pending_send_conns = self.conns.len();
    }

    /// Returns true if `send_packets_out()` might still return packets.
    /// All packets must be sent before waiting for the next timeout.
    pub fn has_pending_sends(&self) -> bool {
        if let Some(server) = &self.server {
            if server.packet_queue.packet_count() != 0 {
                return true;
            }
        }

        self.pending_send_conns != 0
    }

    pub fn conn(&self, cid: ClientId) -> Option<&Conn<TConnAppData>> {
        self.conns.get(cid)
    }

    /// This will mark the connection as `pending_send` because the caller might trigger sending
    /// packets, for example, by calling `stream_send`.
    fn _conn_mut<'a>(conns: &'a mut ConnMap<TConnAppData>, pending_send_conns: &mut usize, cid: ClientId) -> Option<&'a mut Conn<TConnAppData>> {
        let Some(c) = conns.get_mut(cid) else { return None };
        Self::_mark_pending_send(c, pending_send_conns);
        Some(c)
    }

    fn _mark_pending_send(c: &mut Conn<TConnAppData>, pending_send_conns: &mut usize) {
        if !c.pending_send {
            c.pending_send = true;
            *pending_send_conns += 1;
        }
    }

    /// This will mark the connection as `pending_send` because the caller might trigger sending
    /// packets, for example, by calling `stream_send`.
    pub fn conn_mut(&mut self, cid: ClientId) -> Option<&mut Conn<TConnAppData>> {
        Self::_conn_mut(&mut self.conns, &mut self.pending_send_conns, cid)
    }

    /// This will mark the connections as `pending_send` because the caller might trigger sending
    /// packets, for example, by calling `stream_send`.
    pub fn conn2_mut(&mut self, cid1: ClientId, cid2: ClientId) -> Option<(&mut Conn<TConnAppData>, &mut Conn<TConnAppData>)> {
        let Some((c1, c2)) = self.conns.get2_mut(cid1, cid2) else { return None };
        Self::_mark_pending_send(c1, &mut self.pending_send_conns);
        Self::_mark_pending_send(c2, &mut self.pending_send_conns);
        Some((c1, c2))
    }

    /// This will mark the connection as `pending_send` because the caller might trigger sending
    /// packets, for example, by calling `stream_send`.
    /// Also returns the endpoints app data.
    pub fn conn_with_app_data_mut(&mut self, cid: ClientId) -> (Option<&mut Conn<TConnAppData>>, &mut TAppData) {
        (
            Self::_conn_mut(&mut self.conns, &mut self.pending_send_conns, cid),
            &mut self.app_data
        )
    }

    /// This will mark the connections as `pending_send` because the caller might trigger sending
    /// packets, for example, by calling `stream_send`.
    /// Also returns the endpoints app data.
    pub fn conn2_with_app_data_mut(&mut self, cid1: ClientId, cid2: ClientId) -> (Option<(&mut Conn<TConnAppData>, &mut Conn<TConnAppData>)>, &mut TAppData) {
        let Some((c1, c2)) = self.conns.get2_mut(cid1, cid2) else { return (None, &mut self.app_data) };
        Self::_mark_pending_send(c1, &mut self.pending_send_conns);
        Self::_mark_pending_send(c2, &mut self.pending_send_conns);
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
}

#[cfg(test)]
mod tests {
    use crate::endpoint::RecvResult;
    use crate::server_config::RetryConfig;
    use crate::test_utils::{key_pair, server_config, to_recv_info, Pipe};
    use crate::ClientId;
    use quiche::{ConnectionId, Header, Type};
    use std::net::{SocketAddr, SocketAddrV4};

    #[test]
    fn version_negotiation() {
        let _ = env_logger::try_init();
        let mut p = Pipe::new();
        let _ = p.connect();
        let mut buf = [0u8; 1 << 16];
        let ok = p.client.send_packets_out(&mut buf).unwrap();
        assert_eq!(ok.total, 1200);
        assert_eq!(ok.num_packets(), 1);
        // modify version byte
        buf[1] = 0x73;
        for r in p.server.recv_pkts(&mut buf[..ok.total], ok.segment_size, to_recv_info(ok.send_info)) {
            assert!(r.is_ok());
            assert_eq!(r.unwrap(), RecvResult::VersionNegotiation);
        }
        let ok = p.server.send_packets_out(&mut buf).unwrap();
        assert_eq!(ok.num_packets(), 1);
        assert!(ok.client_id.is_none());
        let h = Header::from_slice(&mut buf[..ok.total], 20).unwrap();
        assert_eq!(h.ty, Type::VersionNegotiation);
    }

    #[test]
    fn handshake() {
        let _ = env_logger::try_init();
        let mut p = Pipe::new();
        let cid = p.connect();
        p.handshake_all().unwrap();
        assert!(p.client.conn(cid).unwrap().conn.is_established());
        assert!(p.server.conn(cid).unwrap().conn.is_established());
    }

    #[test]
    fn stream() {
        let _ = env_logger::try_init();
        const MESSAGE: &[u8] = b"hello";
        const STREAM_ID: u64 = 0;
        let mut p = Pipe::new();
        let cid = p.connect();
        p.handshake_all().unwrap();
        let client_conn = p.client.conn_mut(cid).unwrap();
        client_conn.conn.stream_send(STREAM_ID, MESSAGE, true).unwrap();
        p.advance();
        let mut buf = [0u8; 1 << 10];
        let server_conn = p.server.conn_mut(cid).unwrap();
        let (n, fin) = server_conn.conn.stream_recv(STREAM_ID, &mut buf).unwrap();
        assert_eq!(MESSAGE, &buf[..n]);
        assert_eq!(fin, true);
    }

    #[test]
    fn round_robin_conns() {
        let _ = env_logger::try_init();
        const NUM_ROUNDS: usize = 3;
        const NUM_CONNS: usize = 3;
        let mut buf = [0u8; 1 << 16];
        let mut p = Pipe::new();
        let addrs: Vec<SocketAddr> = (0..NUM_CONNS).map(|i| SocketAddr::V4(SocketAddrV4::new("127.0.0.1".parse().unwrap(), (9000 + i) as u16))).collect();
        let cids: Vec<ClientId> = addrs.as_slice().iter().map(|a| p.connect_with(*a)).collect();
        p.handshake_all().unwrap();
        for _ in 0..NUM_ROUNDS {
            p.advance(); // until nothing is to be sent
            // trigger in reverse order
            for &cid in &cids {
                let conn = &mut p.client.conn_mut(cid).unwrap().conn;
                conn.stream_send(0, b"hello", false).unwrap();
            }
            // expect send in original order
            for &cid in &cids {
                let ok = p.client.send_packets_out(&mut buf).unwrap();
                assert_eq!(cid, ok.client_id.unwrap());
            }
        }
    }

    #[test]
    fn round_robin_paths() {
        let _ = env_logger::try_init();
        const NUM_PATHS: usize = 3;
        let mut buf = [0u8; 1 << 16];
        let mut p = Pipe::new();
        let cid = p.connect();
        p.handshake_all().unwrap();
        let addrs: Vec<SocketAddr> = (0..NUM_PATHS).map(|i| SocketAddr::V4(SocketAddrV4::new("127.0.0.1".parse().unwrap(), (9000 + i) as u16))).collect();
        // create paths
        for &addr in &addrs {
            let conn = &mut p.client.conn_mut(cid).unwrap().conn;
            conn.probe_path("127.0.0.1:8000".parse().unwrap(), addr).unwrap();
            let ok = p.client.send_packets_out(&mut buf).unwrap();
            assert_eq!(ok.send_info.to, addr);
        }
        // trigger in reverse order
        for &addr in (&addrs).iter().rev() {
            let conn = &mut p.client.conn_mut(cid).unwrap().conn;
            conn.probe_path("127.0.0.1:8000".parse().unwrap(), addr).unwrap();
        }
        // expect send in original order
        for &addr in &addrs {
            let ok = p.client.send_packets_out(&mut buf).unwrap();
            assert_eq!(ok.send_info.to, addr);
        }
    }

    #[test]
    fn batch_send_and_recv() {
        let _ = env_logger::try_init();
        let mut p = Pipe::new();
        let cid = p.connect();
        p.handshake_all().unwrap();
        p.client.conn_mut(cid).unwrap().conn.stream_send(0, &[0u8; 9000], true).unwrap();
        let mut buf = [0u8; 1 << 16];
        let ok = p.client.send_packets_out(&mut buf).unwrap();
        assert_eq!(ok.num_packets(), 8);
        for r in p.server.recv_pkts(&mut buf[..ok.total], ok.segment_size, to_recv_info(ok.send_info)) {
            assert!(r.is_ok());
        }
        let (n, fin) = p.server.conn_mut(0).unwrap().conn.stream_recv(0, &mut buf).unwrap();
        assert_eq!(n, 9000);
        assert!(fin);
    }

    #[test]
    fn retry() {
        let _ = env_logger::try_init();
        let (key, cert) = key_pair();
        let server_config = {
            let mut c = server_config(key, cert);
            c.retry = Some(RetryConfig {
                mint_token: |hdr, _addr| { hdr.dcid.to_vec() },
                validate_token: |_addr, token| { Some(ConnectionId::from_ref(&token)) },
            });
            c
        };
        let mut p = Pipe::with_server_config(server_config, cert);
        p.connect();
        Pipe::transfer(&mut p.client, &mut p.server).unwrap();
        let mut buf = [0u8; 1 << 16];
        let ok = p.server.send_packets_out(&mut buf).unwrap();
        assert_eq!(ok.num_packets(), 1);
        assert!(ok.client_id.is_none());
        let h = Header::from_slice(&mut buf[..ok.total], 20).unwrap();
        assert_eq!(h.ty, Type::Retry);
        for r in p.client.recv_pkts(&mut buf[..ok.total], ok.segment_size, to_recv_info(ok.send_info)) {
            assert!(r.is_ok());
        }
        p.handshake_all().unwrap();
    }

    #[test]
    fn collect_carbage() {
        let _ = env_logger::try_init();
        let mut p = Pipe::new();
        let cid = p.connect();
        assert_eq!(p.client.num_conns(), 1);
        p.client.conn_mut(cid).unwrap().conn.close(true, 0, b"some reason").unwrap();
        assert_eq!(p.client.num_conns(), 1);
        p.client.collect_garbage();
        assert_eq!(p.client.num_conns(), 0);
    }
}