#[cfg(test)]
mod tests {
    use crate::endpoint::RecvResult;
    use crate::server_config::RetryConfig;
    use crate::test_utils::{to_recv_info, Pipe};
    use crate::{test_utils, ClientId, Error};
    use quiche::{ConnectionId, Header, Type};
    use std::net::{SocketAddr, SocketAddrV4};
    use crate::send_ok::SendOk;

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
        let cids: Vec<ClientId> = addrs.as_slice().iter().map(|a| p.connect_with(Some(*a), None)).collect();
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
        let mut p = Pipe::with(Some(|c| {
            c.retry = Some(RetryConfig {
                mint_token: |hdr, _addr| { hdr.dcid.to_vec() },
                validate_token: |_addr, token| { Some(ConnectionId::from_ref(&token)) },
            });
        }));
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
        p.client.collect_garbage(None);
        assert_eq!(p.client.num_conns(), 0);
    }

    #[test]
    fn pending_sends() {
        let _ = env_logger::try_init();
        let mut p = Pipe::new();
        let cid = p.connect();
        p.handshake_all().unwrap();
        p.advance();
        assert!(!p.client.has_pending_sends());
        p.client.conn(cid).unwrap();
        assert!(!p.client.has_pending_sends());
        p.client.conn_mut(cid).unwrap();
        assert!(p.client.has_pending_sends());
        p.advance();
        assert!(!p.client.has_pending_sends());
    }

    #[test]
    fn send_bursts() {
        let _ = env_logger::try_init();
        let mut p = Pipe::with(Some(|c| {
            c.client_config.set_initial_max_data(1_000_000);
            c.client_config.set_initial_max_stream_data_bidi_remote(1_000_000);
        }));
        const NUM_CONNS: usize = 3;
        let addrs: Vec<SocketAddr> = (0..NUM_CONNS).map(|i| SocketAddr::V4(SocketAddrV4::new("127.0.0.1".parse().unwrap(), (9000 + i) as u16))).collect();
        let mut client_config = {
            let mut c = test_utils::default_client_config(p.cert);
            c.set_initial_congestion_window_packets(100);
            c
        };
        let _cids: Vec<ClientId> = addrs.as_slice().iter().map(|a| p.connect_with(Some(*a), Some(&mut client_config))).collect();
        p.handshake_all().unwrap();
        let mut buf = [0u8; 1_000_000];
        const STREAM_DATA: usize = 100_000;
        for i in p.client.conn_index_iter() {
            let Some(conn) = p.client.conn_mut(i) else { continue };
            let n = conn.conn.stream_send(0, &buf[..STREAM_DATA], false).unwrap();
            assert_eq!(n, STREAM_DATA);
        }
        assert!(p.client.has_pending_sends());
        assert!(matches!(p.client.send_packets_out(&mut buf), Ok(SendOk{client_id: Some(0), ..})));
        assert!(p.client.has_pending_sends());
        assert!(matches!(p.client.send_packets_out(&mut buf), Ok(SendOk{client_id: Some(1), ..})));
        assert!(p.client.has_pending_sends());
        assert!(matches!(p.client.send_packets_out(&mut buf), Ok(SendOk{client_id: Some(2), ..})));
        assert!(p.client.has_pending_sends());
        assert!(matches!(p.client.send_packets_out(&mut buf), Err(Error::Done)));
        assert!(!p.client.has_pending_sends());
    }
}
