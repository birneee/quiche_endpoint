#[cfg(test)]
mod tests {
    use crate::quiche::{Header, SendInfo, Type};
    use crate::endpoint::RecvResult;
    use crate::test_utils::{to_recv_info, Pipe};

    #[test]
    fn version_negotiation() {
        struct SendRes {
            data: Vec<u8>,
            send_info: SendInfo,
            segment_size: usize,
        }
        let _ = env_logger::try_init();
        let mut p = Pipe::new();
        let _ = p.connect();
        let mut buf = [0u8; 1 << 16];
        let mut send_res = None;
        p.client.send_all(&mut buf, |b, i, s| {
            assert!(send_res.is_none());
            send_res = Some(SendRes {
                data: b.to_vec(),
                segment_size: s,
                send_info: *i,
            });
           Ok(())
        });
        let mut send_res = send_res.unwrap();
        assert_eq!(send_res.data.len(), 1200);
        // modify version byte
        send_res.data[1] = 0x73;
        for r in p.server.recv_pkts(send_res.data.as_mut_slice(), send_res.segment_size, to_recv_info(send_res.send_info)) {
            assert!(r.is_ok());
            assert_eq!(r.unwrap(), RecvResult::VersionNegotiation);
        }
        let mut send_res = None;
        p.server.send_all(&mut buf, |b, i, s| {
            assert!(send_res.is_none());
            send_res = Some(SendRes {
                data: b.to_vec(),
                segment_size: s,
                send_info: *i,
            });
            Ok(())
        });
        let mut send_res = send_res.unwrap();
        let h = Header::from_slice(send_res.data.as_mut_slice(), 20).unwrap();
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
        p.client.stream_send(0, 0, b"hello", false).unwrap();
        let mut buf = [0u8; 1<<16];
        p.client.send_all(&mut buf, |_,_,_|{ Ok(())} ); // this sets pending_sends because next package is shorter than max datagram size
        assert!(p.client.has_pending_sends());
        p.advance();
        assert!(!p.client.has_pending_sends());
    }
}
