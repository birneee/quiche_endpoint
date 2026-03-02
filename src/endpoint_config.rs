pub struct EndpointConfig {
    pub ignore_pacing: bool,
    pub ignore_quantum: bool,
    /// Qlog setup is called for every connection.
    /// By default a qlog file is creaded 
    /// if QLOGDIR environment variable is set.
    #[cfg(feature = "qlog")]
    pub setup_qlog: fn(&mut crate::quiche::Connection, &str, &crate::quiche::ConnectionId),
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            ignore_pacing: Default::default(),
            ignore_quantum: Default::default(),
            #[cfg(feature = "qlog")]
            setup_qlog: crate::default_setup_qlog
        }
    }
}
