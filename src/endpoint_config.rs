use quiche::ConnectionId;
use crate::{Conn, OnCloseFunc, OnRecvQuicFunc, OnRecvUdpFunc};

pub struct EndpointConfig<TConnAppData, TAppData> {
    pub on_close: OnCloseFunc<TConnAppData, TAppData>,
    pub ignore_pacing: bool,
    pub ignore_quantum: bool,
    pub on_recv_udp: OnRecvUdpFunc,
    /// executes on every received QUIC packet
    pub on_recv_quic: OnRecvQuicFunc<TConnAppData, TAppData>,
    pub on_migrate: fn(),
    pub on_new_scid: fn(&mut Conn<TConnAppData>, &ConnectionId<'static>),
}

impl<TConnAppData, TAppData> Default for EndpointConfig<TConnAppData, TAppData> {
    fn default() -> Self {
        Self {
            on_close: |_conn,_app_data| {},
            ignore_pacing: false,
            ignore_quantum: false,
            on_recv_udp: |_| {},
            on_recv_quic: |_,_,| {},
            on_migrate: || {},
            on_new_scid: |_,_| {},
        }
    }
}