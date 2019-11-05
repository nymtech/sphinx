use crate::header::{create_header, Address, Delay, Host, SphinxHeader};
use crate::payload::create_enc_payload;

mod crypto;
mod header;
mod payload;

pub struct SphinxPacket {
    header: SphinxHeader,
    payload: Vec<u8>,
}

// TODO: a utility function to turn this into properly concatenated bytes
pub fn create_packet(message: Vec<u8>, route: &[Host]) -> SphinxPacket {
    let (header, shared_keys) = create_header(route);
    let enc_payload = create_enc_payload(message, shared_keys);
    SphinxPacket {
        header,
        payload: enc_payload,
    }
}

pub struct Hop {
    pub host: Host,
    pub delay: Delay,
}

// needs the processor's secret key somehow, figure out where this will come from
// the return value could also be a message, handle this
pub fn unwrap_layer(packet: SphinxPacket) -> (SphinxPacket, Hop) {
    (
        SphinxPacket {
            header: SphinxHeader {},
            payload: vec![],
        },
        Hop {
            host: Host {
                address: Address {},
                pub_key: curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]),
            },
            delay: Delay {},
        },
    )
}
