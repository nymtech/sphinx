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

// andrew: if this is our public facing API, should we require users to pass an initial secret?
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

// needs the processor's secret key somehow, so far I'm just passing it
// the return value could also be a message, handle this
pub fn process_packet(
    packet: SphinxPacket,
    node_secret_key: Scalar,
) -> (SphinxPacket, NodeAddressBytes) {
    //-> Result<(SphinxPacket, Hop), SphinxUnwrapError> {
    // TODO: we should have some list of 'seen shared_keys' for replay detection, but this should be handled by a mix node

    let unwrapped_header = header::process_header(packet.header, node_secret_key).unwrap();
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

    #[test]
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
