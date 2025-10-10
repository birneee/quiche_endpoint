#![warn(unused_crate_dependencies)]
#![warn(unused_extern_crates)]
mod endpoint;
mod endpoint_config;
mod error;
mod packet_queue;
mod server_config;
mod conn;
#[cfg(test)]
mod test_utils;
mod send_ok;

pub use endpoint::Endpoint;
pub use endpoint_config::EndpointConfig;
pub use error::Error;
pub use error::Result;
/// reexport dependency
pub use quiche;
pub use server_config::ServerConfig;

pub use crate::conn::Conn;
use log::{error, info, warn};
use quiche::{Connection, ConnectionId};
use ring::rand::SecureRandom;
use rustc_hash::FxHashMap;
use slab::Slab;
use std::mem::MaybeUninit;
use std::time::Instant;

pub const MAX_UDP_PAYLOAD: usize = 65507;
pub const INSTANT_ZERO: Instant = unsafe { MaybeUninit::zeroed().assume_init() };
pub const INSTANT_MAX: Instant = unsafe{ 
    let mut u = MaybeUninit::<Instant>::uninit();
    u.as_mut_ptr().write_bytes(1u8, 1);
    u.assume_init()
};

/// An internal unique identifier for the QUIC connection
pub type ClientId = usize;

pub type ConnMap<TConnAppData> = Slab<Conn<TConnAppData>>;

pub type ClientIdMap = FxHashMap<ConnectionId<'static>, ClientId>;

type OnRecvUdpFunc = fn(&[u8]);
type OnRecvQuicFunc<TConnAppData, TAppData> = fn(&mut Conn<TConnAppData>, &mut TAppData);
type OnCloseFunc<TConnAppData, TAppData> = fn(&Conn<TConnAppData>, &mut TAppData);



// Handle path events.
fn handle_path_events(
    conn: &mut Connection,
    on_migrate: fn(),
) {
    while let Some(qe) = conn.path_event_next() {
        match qe {
            quiche::PathEvent::New(local_addr, peer_addr) => {
                if !conn.is_server() {
                    unreachable!()
                }
                info!(
                    "{} Seen new path ({}, {})",
                    conn.trace_id(),
                    local_addr,
                    peer_addr,
                );

                // Directly probe the new path.
                conn
                    .probe_path(local_addr, peer_addr)
                    .map_err(|e| error!("cannot probe: {}", e))
                    .ok();
            }

            quiche::PathEvent::Validated(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now validated",
                    conn.trace_id(),
                    local_addr,
                    peer_addr,
                );
                //TODO check if this is a good default
                if !conn.is_server() {
                    conn.migrate(local_addr, peer_addr).unwrap();
                    on_migrate();
                }
            }

            quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) failed validation",
                    conn.trace_id(),
                    local_addr,
                    peer_addr,
                );
            }

            quiche::PathEvent::Closed(local_addr, peer_addr) => {
                info!(
                    "{} Path ({}, {}) is now closed and unusable",
                    conn.trace_id(),
                    local_addr,
                    peer_addr,
                );
            }

            quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                info!(
                    "{} Peer reused cid seq {} (initially {:?}) on {:?}",
                    conn.trace_id(),
                    cid_seq,
                    old,
                    new,
                );
            }

            quiche::PathEvent::PeerMigrated(local_addr, peer_addr) => {
                if !conn.is_server() {
                    unreachable!();
                }
                info!(
                    "{} Connection migrated to ({}, {})",
                    conn.trace_id(),
                    local_addr,
                    peer_addr,
                );
            }
        }
    }
}

/// Generate a new pair of Source Connection ID and reset token.
/// TODO support different length
pub fn generate_cid_and_reset_token<T: SecureRandom>(
    rng: &T,
) -> (quiche::ConnectionId<'static>, u128) {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid).unwrap();
    let scid = scid.to_vec().into();
    let mut reset_token = [0; 16];
    rng.fill(&mut reset_token).unwrap();
    let reset_token = u128::from_be_bytes(reset_token);
    (scid, reset_token)
}

/// Enable qlog if QLOGDIR environment variable is set.
#[cfg(feature = "qlog")]
pub fn setup_qlog(conn: &mut Connection, role: &str, scid: &ConnectionId) {
    if let Some(dir) = std::env::var_os("QLOGDIR") {
        let id = format!("{:?}", scid);
        let writer = make_qlog_writer(&dir, role, &id);

        conn.set_qlog(
            std::boxed::Box::new(writer),
            format!("quiche-{} qlog", role),
            format!("quiche-{} qlog id={}", role, id),
        );
    }
}

/// Makes a buffered writer for a qlog.
pub fn make_qlog_writer(
    dir: &std::ffi::OsStr, role: &str, id: &str,
) -> std::io::BufWriter<std::fs::File> {
    let mut path = std::path::PathBuf::from(dir);
    let filename = format!("{role}-{id}.sqlog");
    path.push(filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),

        Err(e) => panic!(
            "Error creating qlog file attempted path was {:?}: {}",
            path, e
        ),
    }
}
