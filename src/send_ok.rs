use crate::ClientId;
use quiche::SendInfo;

#[derive(Debug)]
pub struct SendOk {
    pub total: usize,
    pub segment_size: usize,
    pub send_info: SendInfo,
    pub client_id: Option<ClientId>,
}

impl SendOk {
    pub fn num_packets(&self) -> usize {
        self.total.div_ceil(self.segment_size)
    }
}
