use crate::ClientId;
use quiche::Connection;
use std::fmt;
use std::fmt::Formatter;

/// This wraps a `quiche::Connection` to add additional metadata.
/// tquic connections have a convenient context field for that.
pub struct Conn<TConnAppData> {
    pub client_id: ClientId,
    pub conn: Connection,
    pub app_data: TConnAppData,
    /// Tracks if the connection might send packets.
    /// The application should not wait for a timeout as long as packets are pending.
    pub(crate) pending_send: bool,
}

impl<TConnAppData: fmt::Debug> fmt::Debug for Conn<TConnAppData> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conn")
            .field("client_id", &self.client_id)
            .field("conn", &self.conn.trace_id())
            .field("app_data", &self.app_data)
            .finish()
    }
}
