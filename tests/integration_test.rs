// Copyright 2020 Nym Technologies SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate sphinx;

use sphinx::crypto;
use sphinx::header::delays;
use sphinx::route::{Destination, Node};
use sphinx::SphinxPacket;

// const PAYLOAD_SIZE: usize = 1024;

#[cfg(test)]
mod create_and_process_sphinx_packet {
    use std::time::Duration;

    use sphinx::constants::HKDF_SALT_SIZE;
    use sphinx::route::{DestinationAddressBytes, NodeAddressBytes};
    use sphinx::{
        constants::{
            DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH, PAYLOAD_SIZE,
            SECURITY_PARAMETER,
        },
        ProcessedPacket,
    };

    use super::*;

    #[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_without_surb() {
        let (node1_sk, node1_pk) = crypto::keygen();
        let node1 = Node::new(
            NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk, node2_pk) = crypto::keygen();
        let node2 = Node::new(
            NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk, node3_pk) = crypto::keygen();
        let node3 = Node::new(
            NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = delays::generate_from_average_duration(route.len(), average_delay);
        let hkdf_salt = vec![
            [1u8; HKDF_SALT_SIZE],
            [2u8; HKDF_SALT_SIZE],
            [3u8; HKDF_SALT_SIZE],
        ];
        let destination = Destination::new(
            DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
            [4u8; IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            SphinxPacket::new(message.clone(), &route, &destination, &delays, &hkdf_salt).unwrap();

        let next_sphinx_packet_1 = match sphinx_packet.process(&node1_sk).unwrap() {
            ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; PAYLOAD_SIZE - SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
}

#[cfg(test)]
mod converting_sphinx_packet_to_and_from_bytes {
    use std::time::Duration;

    use sphinx::constants::HKDF_SALT_SIZE;
    use sphinx::route::{DestinationAddressBytes, NodeAddressBytes};
    use sphinx::{
        constants::{
            DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH, PAYLOAD_SIZE,
            SECURITY_PARAMETER,
        },
        ProcessedPacket,
    };

    use super::*;

    #[test]
    fn it_is_possible_to_do_the_conversion_without_data_loss() {
        let (node1_sk, node1_pk) = crypto::keygen();
        let node1 = Node::new(
            NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk, node2_pk) = crypto::keygen();
        let node2 = Node::new(
            NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk, node3_pk) = crypto::keygen();
        let node3 = Node::new(
            NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = delays::generate_from_average_duration(route.len(), average_delay);
        let hkdf_salt = vec![
            [1u8; HKDF_SALT_SIZE],
            [2u8; HKDF_SALT_SIZE],
            [3u8; HKDF_SALT_SIZE],
        ];
        let destination = Destination::new(
            DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
            [4u8; IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            SphinxPacket::new(message.clone(), &route, &destination, &delays, &hkdf_salt).unwrap();

        let sphinx_packet_bytes = sphinx_packet.to_bytes();
        let recovered_packet = SphinxPacket::from_bytes(&sphinx_packet_bytes).unwrap();

        let next_sphinx_packet_1 = match recovered_packet.process(&node1_sk).unwrap() {
            ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            ProcessedPacket::ForwardHop(next_packet, next_hop_address, delay) => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; PAYLOAD_SIZE - SECURITY_PARAMETER - message.len() - 1];
                let expected_payload = [zero_bytes, message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }

    #[test]
    #[should_panic]
    fn it_panics_if_data_of_invalid_length_is_provided() {
        let (_, node1_pk) = crypto::keygen();
        let node1 = Node::new(
            NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (_, node2_pk) = crypto::keygen();
        let node2 = Node::new(
            NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (_, node3_pk) = crypto::keygen();
        let node3 = Node::new(
            NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = delays::generate_from_average_duration(route.len(), average_delay);
        let hkdf_salt = vec![
            [1u8; HKDF_SALT_SIZE],
            [2u8; HKDF_SALT_SIZE],
            [3u8; HKDF_SALT_SIZE],
        ];
        let destination = Destination::new(
            DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
            [4u8; IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            SphinxPacket::new(message, &route, &destination, &delays, &hkdf_salt).unwrap();

        let sphinx_packet_bytes = &sphinx_packet.to_bytes()[..300];
        SphinxPacket::from_bytes(&sphinx_packet_bytes).unwrap();
    }
}

#[cfg(test)]
mod create_and_process_surb {
    use std::time::Duration;

    use crypto::EphemeralSecret;
    use sphinx::constants::HKDF_SALT_SIZE;
    use sphinx::route::NodeAddressBytes;
    use sphinx::surb::{SURBMaterial, SURB};
    use sphinx::{
        constants::{NODE_ADDRESS_LENGTH, PAYLOAD_SIZE, SECURITY_PARAMETER},
        packet::builder::DEFAULT_PAYLOAD_SIZE,
        test_utils::fixtures::destination_fixture,
        ProcessedPacket,
    };

    use super::*;

    #[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes() {
        let (node1_sk, node1_pk) = crypto::keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk, node2_pk) = crypto::keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk, node3_pk) = crypto::keygen();
        let node3 = Node {
            address: NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = destination_fixture();
        let surb_initial_secret = EphemeralSecret::new();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));
        let surb_hkdf_salt = vec![
            [1u8; HKDF_SALT_SIZE],
            [2u8; HKDF_SALT_SIZE],
            [3u8; HKDF_SALT_SIZE],
        ];
        let pre_surb = SURB::new(
            surb_initial_secret,
            SURBMaterial::new(
                surb_route,
                surb_delays.clone(),
                surb_hkdf_salt,
                surb_destination,
            ),
        )
        .unwrap();

        let plaintext_message = vec![42u8; 160];
        let (surb_sphinx_packet, first_hop) =
            SURB::use_surb(pre_surb, &plaintext_message, DEFAULT_PAYLOAD_SIZE).unwrap();

        assert_eq!(
            first_hop,
            NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH])
        );

        let next_sphinx_packet_1 = match surb_sphinx_packet.process(&node1_sk).unwrap() {
            ProcessedPacket::ForwardHop(next_packet, next_hop_addr1, _delay1) => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
                    next_hop_addr1
                );
                assert_eq!(_delay1, surb_delays[0]);
                next_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap() {
            ProcessedPacket::ForwardHop(next_packet, next_hop_addr2, _delay2) => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
                    next_hop_addr2
                );
                assert_eq!(_delay2, surb_delays[1]);
                next_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap() {
            ProcessedPacket::FinalHop(_, _, payload) => {
                let zero_bytes = vec![0u8; SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; PAYLOAD_SIZE - SECURITY_PARAMETER - plaintext_message.len() - 1];
                let expected_payload =
                    [zero_bytes, plaintext_message, vec![1], additional_padding].concat();
                assert_eq!(expected_payload, payload.as_bytes());
            }
            _ => panic!(),
        };
    }
}

#[cfg(test)]
mod reusing_key {
    use std::time::Duration;

    use rand::Rng;

    use sphinx::constants::NODE_ADDRESS_LENGTH;
    use sphinx::route::NodeAddressBytes;
    use sphinx::test_utils::fixtures::destination_fixture;

    use super::*;

    #[test]
    fn reusing_the_same_shared_key_and_message_but_different_salt_gives_different_results() {
        let (_, node1_pk) = crypto::keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (_, node2_pk) = crypto::keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (_, node3_pk) = crypto::keygen();
        let node3 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };
        let route = [node1, node2, node3];
        let destination = destination_fixture();
        let average_delay = 1;
        let delays =
            delays::generate_from_average_duration(route.len(), Duration::from_secs(average_delay));
        let hkdf_salt1 = rand::thread_rng().gen::<[u8; 32]>();
        let hkdf_salt2 = rand::thread_rng().gen::<[u8; 32]>();
        let hkdf_salt3 = rand::thread_rng().gen::<[u8; 32]>();
        let hkdf_salts = [hkdf_salt1, hkdf_salt2, hkdf_salt3];

        let message = vec![13u8, 16];
        let sphinx_packet1 =
            SphinxPacket::new(message.clone(), &route, &destination, &delays, &hkdf_salts).unwrap();

        let new_hkdf_salt1 = rand::thread_rng().gen::<[u8; 32]>();
        let new_hkdf_salt2 = rand::thread_rng().gen::<[u8; 32]>();
        let new_hkdf_salt3 = rand::thread_rng().gen::<[u8; 32]>();
        let new_hkdf_salts: [[u8; 32]; 3] = [new_hkdf_salt1, new_hkdf_salt2, new_hkdf_salt3];

        let sphinx_packet2 =
            SphinxPacket::new(message, &route, &destination, &delays, &new_hkdf_salts).unwrap();

        assert_ne!(sphinx_packet1.to_bytes(), sphinx_packet2.to_bytes());
    }
}
