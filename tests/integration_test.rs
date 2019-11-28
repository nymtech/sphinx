extern crate sphinx;

use sphinx::crypto;
use sphinx::header::delays;
use sphinx::route::{Destination, Node};
use sphinx::SphinxPacket;

const NODE_ADDRESS_LENGTH: usize = 32;
const DESTINATION_ADDRESS_LENGTH: usize = 32;
const IDENTIFIER_LENGTH: usize = 16;
const SECURITY_PARAMETER: usize = 16;

#[cfg(test)]
mod create_and_process_sphinx_packet {
    use super::*;
    use sphinx::ProcessedPacket;

    #[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes() {
        let (node1_sk, node1_pk) = crypto::keygen();
        let node1 = Node::new([5u8; NODE_ADDRESS_LENGTH], node1_pk);
        let (node2_sk, node2_pk) = crypto::keygen();
        let node2 = Node::new([4u8; NODE_ADDRESS_LENGTH], node2_pk);
        let (node3_sk, node3_pk) = crypto::keygen();
        let node3 = Node::new([2u8; NODE_ADDRESS_LENGTH], node3_pk);

        let route = [node1, node2, node3];
        let delays = delays::generate(route.len());
        let destination =
            Destination::new([3u8; DESTINATION_ADDRESS_LENGTH], [4u8; IDENTIFIER_LENGTH]);

        let message = vec![13u8, 16];
        let sphinx_packet = SphinxPacket::new(message.clone(), &route, &destination, &delays);

        let next_sphinx_packet_1 = match sphinx_packet.process(node1_sk) {
            ProcessedPacket::ProcessedPacketForwardHop(next_packet, next_hop_addr1, delay1) => {
                assert_eq!([4u8; NODE_ADDRESS_LENGTH], next_hop_addr1);
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(node2_sk) {
            ProcessedPacket::ProcessedPacketForwardHop(next_packet, next_hop_addr2, delay2) => {
                assert_eq!([2u8; NODE_ADDRESS_LENGTH], next_hop_addr2);
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(node3_sk) {
            ProcessedPacket::ProcessedPacketFinalHop(identifier, payload) => {
                let zero_bytes = vec![0u8; SECURITY_PARAMETER];
                let expected_payload = [zero_bytes, destination.address.to_vec(), message].concat();
                assert_eq!(expected_payload, payload.get_content());
            }
            _ => panic!(),
        };
    }
}

#[cfg(test)]
mod converting_sphinx_packet_to_and_from_bytes {
    use super::*;
    use sphinx::ProcessedPacket;

    #[test]
    fn it_is_possible_to_do_the_conversion_without_data_loss() {
        let (node1_sk, node1_pk) = crypto::keygen();
        let node1 = Node::new([5u8; NODE_ADDRESS_LENGTH], node1_pk);
        let (node2_sk, node2_pk) = crypto::keygen();
        let node2 = Node::new([4u8; NODE_ADDRESS_LENGTH], node2_pk);
        let (node3_sk, node3_pk) = crypto::keygen();
        let node3 = Node::new([2u8; NODE_ADDRESS_LENGTH], node3_pk);

        let route = [node1, node2, node3];
        let delays = delays::generate(route.len());
        let destination =
            Destination::new([3u8; DESTINATION_ADDRESS_LENGTH], [4u8; IDENTIFIER_LENGTH]);

        let message = vec![13u8, 16];
        let sphinx_packet = SphinxPacket::new(message.clone(), &route, &destination, &delays);

        let sphinx_packet_bytes = sphinx_packet.to_bytes();
        let recovered_packet = SphinxPacket::from_bytes(sphinx_packet_bytes).unwrap();

        let next_sphinx_packet_1 = match recovered_packet.process(node1_sk) {
            ProcessedPacket::ProcessedPacketForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!([4u8; NODE_ADDRESS_LENGTH], next_hop_address);
                assert_eq!(delays[0].get_value(), delay.get_value());
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(node2_sk) {
            ProcessedPacket::ProcessedPacketForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!([2u8; NODE_ADDRESS_LENGTH], next_hop_address);
                assert_eq!(delays[1].get_value(), delay.get_value());
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(node3_sk) {
            ProcessedPacket::ProcessedPacketFinalHop(identifier, payload) => {
                let zero_bytes = vec![0u8; SECURITY_PARAMETER];
                let expected_payload = [zero_bytes, destination.address.to_vec(), message].concat();
                assert_eq!(expected_payload, payload.get_content());
            }
            _ => panic!(),
        };
    }

    #[test]
    #[should_panic]
    fn it_panics_if_data_of_invalid_length_is_provided() {
        let (node1_sk, node1_pk) = crypto::keygen();
        let node1 = Node::new([5u8; NODE_ADDRESS_LENGTH], node1_pk);
        let (node2_sk, node2_pk) = crypto::keygen();
        let node2 = Node::new([4u8; NODE_ADDRESS_LENGTH], node2_pk);
        let (node3_sk, node3_pk) = crypto::keygen();
        let node3 = Node::new([2u8; NODE_ADDRESS_LENGTH], node3_pk);

        let route = [node1, node2, node3];
        let delays = delays::generate(route.len());
        let destination =
            Destination::new([3u8; DESTINATION_ADDRESS_LENGTH], [4u8; IDENTIFIER_LENGTH]);

        let message = vec![13u8, 16];
        let sphinx_packet = SphinxPacket::new(message.clone(), &route, &destination, &delays);

        let sphinx_packet_bytes = sphinx_packet.to_bytes()[..300].to_vec();
        let recovered_packet = SphinxPacket::from_bytes(sphinx_packet_bytes).unwrap();
    }
}
