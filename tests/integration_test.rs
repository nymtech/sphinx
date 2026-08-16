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

extern crate sphinx_packet;

use sphinx_packet::header::delays;
use sphinx_packet::route::{Destination, Node};
use sphinx_packet::SphinxPacket;
use x25519_dalek::{PublicKey, StaticSecret};

// const PAYLOAD_SIZE: usize = 1024;

fn keygen() -> (StaticSecret, PublicKey) {
    let private_key = StaticSecret::random();
    let public_key = PublicKey::from(&private_key);
    (private_key, public_key)
}

#[cfg(test)]
mod create_and_process_sphinx_packet {
    use super::*;
    use sphinx_packet::constants::{
        DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH, PAYLOAD_SIZE,
        SECURITY_PARAMETER,
    };
    use sphinx_packet::packet::ProcessedPacketData;
    use sphinx_packet::route::{DestinationAddressBytes, NodeAddressBytes};
    use std::time::Duration;

    #[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes_without_surb() {
        let (node1_sk, node1_pk) = keygen();
        let node1 = Node::new(
            NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk, node2_pk) = keygen();
        let node2 = Node::new(
            NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk, node3_pk) = keygen();
        let node3 = Node::new(
            NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = delays::generate_from_average_duration(route.len(), average_delay);
        let destination = Destination::new(
            DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
            [4u8; IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();

        let next_sphinx_packet_1 = match sphinx_packet.process(&node1_sk).unwrap().data {
            ProcessedPacketData::ForwardHop {
                next_hop_packet,
                next_hop_address,
                delay: _,
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                next_hop_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap().data {
            ProcessedPacketData::ForwardHop {
                next_hop_packet,
                next_hop_address,
                delay: _,
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                next_hop_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap().data {
            ProcessedPacketData::FinalHop { payload, .. } => {
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
    use super::*;
    use sphinx_packet::constants::{
        DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH, PAYLOAD_SIZE,
        SECURITY_PARAMETER,
    };
    use sphinx_packet::packet::ProcessedPacketData;
    use sphinx_packet::route::{DestinationAddressBytes, NodeAddressBytes};
    use std::time::Duration;

    #[test]
    fn it_is_possible_to_do_the_conversion_without_data_loss() {
        let (node1_sk, node1_pk) = keygen();
        let node1 = Node::new(
            NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (node2_sk, node2_pk) = keygen();
        let node2 = Node::new(
            NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (node3_sk, node3_pk) = keygen();
        let node3 = Node::new(
            NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = delays::generate_from_average_duration(route.len(), average_delay);
        let destination = Destination::new(
            DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
            [4u8; IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet =
            SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();

        let sphinx_packet_bytes = sphinx_packet.to_bytes();
        let recovered_packet = SphinxPacket::from_bytes(&sphinx_packet_bytes).unwrap();

        let next_sphinx_packet_1 = match recovered_packet.process(&node1_sk).unwrap().data {
            ProcessedPacketData::ForwardHop {
                next_hop_packet,
                next_hop_address,
                delay,
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[0].to_nanos(), delay.to_nanos());
                next_hop_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap().data {
            ProcessedPacketData::ForwardHop {
                next_hop_packet,
                next_hop_address,
                delay,
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delays[1].to_nanos(), delay.to_nanos());
                next_hop_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap().data {
            ProcessedPacketData::FinalHop { payload, .. } => {
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
        let (_, node1_pk) = keygen();
        let node1 = Node::new(
            NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            node1_pk,
        );
        let (_, node2_pk) = keygen();
        let node2 = Node::new(
            NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            node2_pk,
        );
        let (_, node3_pk) = keygen();
        let node3 = Node::new(
            NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            node3_pk,
        );

        let route = [node1, node2, node3];
        let average_delay = Duration::from_secs_f64(1.0);
        let delays = delays::generate_from_average_duration(route.len(), average_delay);
        let destination = Destination::new(
            DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
            [4u8; IDENTIFIER_LENGTH],
        );

        let message = vec![13u8, 16];
        let sphinx_packet = SphinxPacket::new(message, &route, &destination, &delays).unwrap();

        let sphinx_packet_bytes = &sphinx_packet.to_bytes()[..300];
        SphinxPacket::from_bytes(sphinx_packet_bytes).unwrap();
    }
}

#[cfg(test)]
mod create_and_process_surb {
    use super::*;
    use sphinx_packet::constants::{DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH};
    use sphinx_packet::header::keys::KeyMaterial;
    use sphinx_packet::packet::ProcessedPacketData;
    use sphinx_packet::payload::key::derive_payload_key;
    use sphinx_packet::route::{DestinationAddressBytes, NodeAddressBytes};
    use sphinx_packet::surb::{SURBMaterial, SURB};
    use sphinx_packet::{
        constants::{NODE_ADDRESS_LENGTH, PAYLOAD_SIZE, SECURITY_PARAMETER},
        packet::builder::DEFAULT_PAYLOAD_SIZE,
    };
    use std::time::Duration;
    use x25519_dalek::StaticSecret;

    #[test]
    fn returns_the_correct_data_at_each_hop_for_route_of_3_mixnodes() {
        let (node1_sk, node1_pk) = keygen();
        let node1 = Node {
            address: NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
            pub_key: node1_pk,
        };
        let (node2_sk, node2_pk) = keygen();
        let node2 = Node {
            address: NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
            pub_key: node2_pk,
        };
        let (node3_sk, node3_pk) = keygen();
        let node3 = Node {
            address: NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
            pub_key: node3_pk,
        };

        let surb_route = vec![node1, node2, node3];
        let surb_destination = Destination {
            address: DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
            identifier: [4u8; IDENTIFIER_LENGTH],
        };
        let surb_initial_secret = StaticSecret::random();
        let surb_delays =
            delays::generate_from_average_duration(surb_route.len(), Duration::from_secs(3));

        // the SURB's creator (the eventual receiver of the reply) is the only party that ever
        // has both the route and the initial secret together, so it - and only it - can
        // re-derive every hop's payload key for itself in order to undo, layer by layer, what
        // each mix node added to the payload while relaying it back.
        //
        // SURBMaterial defaults to the current (seed-based) version, so hops derive their
        // payload key from the HKDF-expanded seed rather than using the legacy full key.
        let receiver_key_material = KeyMaterial::derive(&surb_route, &surb_initial_secret);
        let hop_payload_keys: Vec<_> = receiver_key_material
            .expanded_shared_secrets
            .iter()
            .map(|s| derive_payload_key(s.payload_key_seed()))
            .collect();

        let pre_surb = SURB::new(
            surb_initial_secret,
            SURBMaterial::new(surb_route, surb_delays.clone(), surb_destination),
        )
        .unwrap();

        let plaintext_message = vec![42u8; 160];
        let (surb_sphinx_packet, first_hop) =
            SURB::use_surb(pre_surb, &plaintext_message, DEFAULT_PAYLOAD_SIZE).unwrap();

        assert_eq!(
            first_hop,
            NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH])
        );

        let next_sphinx_packet_1 = match surb_sphinx_packet.process(&node1_sk).unwrap().data {
            ProcessedPacketData::ForwardHop {
                next_hop_packet,
                next_hop_address,
                delay,
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delay, surb_delays[0]);
                next_hop_packet
            }
            _ => panic!(),
        };

        let next_sphinx_packet_2 = match next_sphinx_packet_1.process(&node2_sk).unwrap().data {
            ProcessedPacketData::ForwardHop {
                next_hop_packet,
                next_hop_address,
                delay,
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                assert_eq!(delay, surb_delays[1]);
                next_hop_packet
            }
            _ => panic!(),
        };

        match next_sphinx_packet_2.process(&node3_sk).unwrap().data {
            ProcessedPacketData::FinalHop { payload, .. } => {
                // at this point `payload` has been through 3 hops, each of which *added* a layer
                // of encryption with its own key (node1's, then node2's, then node3's) on top of
                // the single innermost layer the SURB user added with node3's key (the last hop
                // in the route) - it is not yet the plaintext. Only the SURB's original creator,
                // who alone knows every hop's key, can undo this.
                //
                // undo the 3 hops' added layers, in the reverse order they were added
                let payload = payload
                    .add_encryption_layer(hop_payload_keys[2])
                    .unwrap()
                    .add_encryption_layer(hop_payload_keys[1])
                    .unwrap()
                    .add_encryption_layer(hop_payload_keys[0])
                    .unwrap();

                // and finally remove the SURB user's own innermost layer, which was added with
                // node3's (the last hop's) key
                let payload = payload.unwrap(hop_payload_keys[2]).unwrap();

                let zero_bytes = vec![0u8; SECURITY_PARAMETER];
                let additional_padding =
                    vec![0u8; PAYLOAD_SIZE - SECURITY_PARAMETER - plaintext_message.len() - 1];
                let expected_payload = [
                    zero_bytes,
                    plaintext_message.clone(),
                    vec![1],
                    additional_padding,
                ]
                .concat();
                assert_eq!(expected_payload, payload.as_bytes());
                assert_eq!(plaintext_message, payload.recover_plaintext().unwrap());
            }
            _ => panic!(),
        };
    }
}
