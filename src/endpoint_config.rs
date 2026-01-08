pub struct EndpointConfig {
    pub ignore_pacing: bool,
    pub ignore_quantum: bool,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            ignore_pacing: false,
            ignore_quantum: false,
        }
    }
}
