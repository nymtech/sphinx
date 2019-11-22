extern crate sphinx;

use sphinx::create_packet;
use sphinx::process_packet;
use sphinx::route::destination_fixture;
use sphinx::utils::crypto;

const NODE_ADDRESS_LENGTH: usize = 32; // needs to be the same as what's in constants file.

#[cfg(test)]
mod create_and_process_sphinx_packet {
    use sphinx::route::Node;

    use super::*;

    #[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes() {
        let (node1_sk, node1_pk) = crypto::keygen();
        let node1 = Node::new([5u8; NODE_ADDRESS_LENGTH], node1_pk);
        let (node2_sk, node2_pk) = crypto::keygen();
        let node2 = Node {
            address: [4u8; NODE_ADDRESS_LENGTH],
            pub_key: node2_pk,
        };
        let (node3_sk, node3_pk) = crypto::keygen();
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

        let zero_bytes = vec![0u8; 16];
        let expected_payload = [zero_bytes, destination.address.to_vec(), message].concat();
        assert_eq!(expected_payload, next_sphinx_packet_3.payload);
    }
}
