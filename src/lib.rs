#![feature(test)]
extern crate test;

use crate::header::header::{random_final_hop, random_forward_hop, MixNode, RouteElement};
use crate::header::keys;
use crate::header::routing::ROUTING_INFO_SIZE;

use constants::INTEGRITY_MAC_SIZE;

mod constants;
mod header;
mod payload;
mod utils;

pub struct SphinxPacket {
    header: header::SphinxHeader,
    payload: Vec<u8>,
}

pub fn create_packet(message: Vec<u8>, route: &[RouteElement]) -> SphinxPacket {
    let (header, payload_keys) = header::create(route);
    let payload = payload::create(message, payload_keys);
    SphinxPacket { header, payload }
}

// TODO: rethink
pub struct Hop {
    pub host: RouteElement,
    pub delay: f64,
}

// needs the processor's secret key somehow, figure out where this will come from
// the return value could also be a message, handle this
pub fn unwrap_layer(packet: SphinxPacket) -> (SphinxPacket, Hop) {
    (
        SphinxPacket {
            header: header::SphinxHeader {
                shared_secret: curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]),
                routing_info: header::routing::RoutingInfo {
                    enc_header: [0u8; ROUTING_INFO_SIZE],
                    header_integrity_hmac: [0u8; INTEGRITY_MAC_SIZE],
                },
            },
            payload: vec![],
        },
        Hop {
            host: RouteElement::ForwardHop(MixNode {
                address: header::header::address_fixture(),
                pub_key: curve25519_dalek::montgomery::MontgomeryPoint([0u8; 32]),
            }),
            delay: 0.0,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_create_header(b: &mut Bencher) {
        // 3 mixes and a destination
        let dummy_route = vec![
            random_forward_hop(),
            random_forward_hop(),
            random_forward_hop(),
            random_final_hop(),
        ];

        b.iter(|| {
            header::create(&dummy_route);
        });
    }

    #[bench]
    fn bench_generate_shared_secets(b: &mut Bencher) {
        // 3 mixes and a destination
        let dummy_route = vec![
            random_forward_hop(),
            random_forward_hop(),
            random_forward_hop(),
            random_final_hop(),
        ];

        let initial_secret = utils::crypto::generate_secret();

        b.iter(|| {
            header::keys::derive(&dummy_route, initial_secret);
        });
    }
}
