//#![feature(test)]
//extern crate test;

use curve25519_dalek::scalar::Scalar;

use crate::route::{Destination, Node, NodeAddressBytes};

mod constants;
mod header;
mod payload;
mod route;
mod utils;

pub struct SphinxPacket {
    header: header::SphinxHeader,
    payload: Vec<u8>,
}

pub fn create_packet(
    initial_secret: Scalar,
    message: Vec<u8>,
    route: &[Node],
    destination: &Destination,
) -> SphinxPacket {
    let (header, payload_keys) = header::create(initial_secret, route, destination);
    let payload = payload::create(&message, payload_keys, destination.address);
    SphinxPacket { header, payload }
}

// TODO: rethink
pub struct Hop {
    pub host: Node,
    pub delay: f64,
}

// needs the processor's secret key somehow, so far I'm just passing it
// the return value could also be a message, handle this
pub fn process_packet(
    packet: SphinxPacket,
    node_secret_key: Scalar,
) -> (SphinxPacket, NodeAddressBytes) {
    //-> Result<(SphinxPacket, Hop), SphinxUnwrapError> {
    // TODO: we should have some list of 'seens shared_keys' for replay detection, but this should be handeled by a mix node

    let unwrapped_header = match header::process_header(packet.header, node_secret_key) {
        Err(error) => panic!("Something went wrong in header unwrapping {:?}", error),
        Ok(unwrapped_header) => unwrapped_header,
    };
    let (new_header, next_hop_addr, payload_key) = unwrapped_header;

    // process the payload
    let new_payload = payload::unwrap::unwrap_payload(packet.payload, &payload_key);

    (
        SphinxPacket {
            header: new_header,
            payload: new_payload,
        },
        next_hop_addr,
    )
}

#[cfg(test)]
mod create_and_process_sphinx_packet {
    use crate::constants::{NODE_ADDRESS_LENGTH, SECURITY_PARAMETER};
    use crate::route::destination_fixture;
    use crate::utils::crypto;

    use super::*;

    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes() {
        let (node1_sk, node1_pk) = crypto::key_pair_fixture();
        let node1 = Node {
            address: [5u8; NODE_ADDRESS_LENGTH],
            pub_key: node1_pk,
        };
        let (node2_sk, node2_pk) = crypto::key_pair_fixture();
        let node2 = Node {
            address: [4u8; NODE_ADDRESS_LENGTH],
            pub_key: node2_pk,
        };
        let (node3_sk, node3_pk) = crypto::key_pair_fixture();
        let node3 = Node {
            address: [2u8; NODE_ADDRESS_LENGTH],
            pub_key: node3_pk,
        };
        let route = [node1, node2, node3];
        let destination = destination_fixture();
        let initial_secret = crypto::generate_secret();

        let message = vec![13u8, 16];
        let sphinx_packet = create_packet(initial_secret, message.clone(), &route, &destination);

        let (next_sphinx_packet_1, next_hop_addr1) = process_packet(sphinx_packet, node1_sk);
        assert_eq!([4u8; NODE_ADDRESS_LENGTH], next_hop_addr1);

        let (next_sphinx_packet_2, next_hop_addr2) = process_packet(next_sphinx_packet_1, node2_sk);
        assert_eq!([2u8; NODE_ADDRESS_LENGTH], next_hop_addr2);

        let (next_sphinx_packet_3, next_hop_addr3) = process_packet(next_sphinx_packet_2, node3_sk);
        assert_eq!(destination.address, next_hop_addr3);

        let zero_bytes = vec![0u8; SECURITY_PARAMETER];
        let expected_payload = [zero_bytes, destination.address.to_vec(), message].concat();
        assert_eq!(expected_payload, next_sphinx_packet_3.payload);
    }
}
//#[cfg(test)]
//mod test{
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
