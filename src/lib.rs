//#![feature(test)]
//extern crate test;

use crate::header::header::{random_final_hop, random_forward_hop, MixNode, RouteElement};
use crate::header::keys;
use crate::header::routing::ROUTING_INFO_SIZE;
use constants::HEADER_INTEGRITY_MAC_SIZE;
use curve25519_dalek::scalar::Scalar;

mod constants;
mod header;
mod payload;
mod unwrap_payload;
mod utils;

pub struct SphinxPacket {
    header: header::SphinxHeader,
    payload: Vec<u8>,
}

pub fn create_packet(message: Vec<u8>, route: &[RouteElement]) -> SphinxPacket {
    let (header, payload_keys) = header::create(route);
    let destination = match route.last().expect("The route should not be empty") {
        RouteElement::FinalHop(destination) => destination,
        _ => panic!("The last route element must be a destination"),
    };
    let payload = payload::create(&message, payload_keys, destination.address);
    SphinxPacket { header, payload }
}

// TODO: rethink
pub struct Hop {
    pub host: RouteElement,
    pub delay: f64,
}

// needs the processor's secret key somehow, so far I'm just passing it
// the return value could also be a message, handle this
pub fn process_packet(packet: SphinxPacket, node_secret_key: Scalar) {
    //-> Result<(SphinxPacket, Hop), SphinxUnwrapError> {
    let shared_key =
        keys::KeyMaterial::compute_shared_key(packet.header.shared_secret, &node_secret_key);
    // TODO: we should have some list of 'seens shared_keys' for replay detection
    let routing_keys = keys::RoutingKeys::derive(shared_key);

    let tmp = header::process_header(packet.header, &routing_keys);
    // process the payload
    let unwrapped_payload =
        unwrap_payload::unwrap_payload(packet.payload, &routing_keys.payload_key);
    //Ok(())
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use test::Bencher;
//
//     //    #[bench]
//     //    fn bench_create_header(b: &mut Bencher) {
//     //        // 3 mixes and a destination
//     //        let dummy_route = vec![
//     //            random_forward_hop(),
//     //            random_forward_hop(),
//     //            random_forward_hop(),
//     //            random_final_hop(),
//     //        ];
//     //
//     //        b.iter(|| {
//     //            header::create(&dummy_route);
//     //        });
//     //    }
//
//     #[bench]
//     fn bench_generate_shared_secets(b: &mut Bencher) {
//         // 3 mixes and a destination
//         let dummy_route = vec![
//             random_forward_hop(),
//             random_forward_hop(),
//             random_forward_hop(),
//             random_final_hop(),
//         ];
//
//         let initial_secret = utils::crypto::generate_secret();
//
//         b.iter(|| {
//             header::keys::derive(&dummy_route, initial_secret);
//         });
//     }
// }

// test conclusion: chain is more than twice as fast as concat
//
//#[cfg(test)]
//mod tests {
//    use super::*;
//    use test::Bencher;
//
//    #[bench]
//    fn bench_concat(b: &mut test::Bencher) {
//        let foo: [u8; 32] = [
//            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
//            0, 1, 2,
//        ];
//        let bar: [u8; 16] = [0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5];
//        let baz: [u8; 48] = [
//            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
//            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
//        ];
//        b.iter(|| [foo.to_vec(), bar.to_vec(), baz.to_vec()].concat());
//    }
//
//    #[bench]
//    fn bench_chain(b: &mut test::Bencher) {
//        let foo: [u8; 32] = [
//            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
//            0, 1, 2,
//        ];
//        let bar: [u8; 16] = [0, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5];
//        let baz: [u8; 48] = [
//            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
//            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8,
//        ];
//        b.iter(|| {
//            let a: Vec<_> = foo
//                .iter()
//                .cloned()
//                .chain(bar.iter().cloned())
//                .chain(baz.iter().cloned())
//                .collect();
//        });
//    }
//}
