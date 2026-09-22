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

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]

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
    use sphinx_packet::constants::{
        DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH,
    };
    use sphinx_packet::packet::builder::DEFAULT_PAYLOAD_SIZE;
    use sphinx_packet::packet::{ProcessedPacket, ProcessedPacketData};
    use sphinx_packet::route::{DestinationAddressBytes, NodeAddressBytes, SURBIdentifier};
    use sphinx_packet::surb::{SURBMaterial, SurbReplyRecovery, SURB};
    use sphinx_packet::version::{PAYLOAD_KEYS_SEEDS_VERSION, SINGLE_SEED_SURB_VERSION};
    use std::time::Duration;

    fn node(address_byte: u8, pub_key: PublicKey) -> Node {
        Node::new(
            NodeAddressBytes::from_bytes([address_byte; NODE_ADDRESS_LENGTH]),
            pub_key,
        )
    }

    /// Processes `packet` as `node_sk`'s hop, asserting it is a forward hop towards `expected_next`.
    fn forward(packet: SphinxPacket, node_sk: &StaticSecret, expected_next: u8) -> SphinxPacket {
        match packet.process(node_sk).unwrap().data {
            ProcessedPacketData::ForwardHop {
                next_hop_packet,
                next_hop_address,
                ..
            } => {
                assert_eq!(
                    NodeAddressBytes::from_bytes([expected_next; NODE_ADDRESS_LENGTH]),
                    next_hop_address
                );
                next_hop_packet
            }
            ProcessedPacketData::FinalHop { .. } => panic!("expected a forward hop"),
        }
    }

    fn final_hop(packet: SphinxPacket, node_sk: &StaticSecret) -> ProcessedPacket {
        let processed = packet.process(node_sk).unwrap();
        assert!(
            matches!(processed.data, ProcessedPacketData::FinalHop { .. }),
            "expected the final hop"
        );
        processed
    }

    #[test]
    fn seeded_surb_reply_is_recovered_by_the_last_hop() {
        // legacy (259): mix, mix, gateway - the gateway is the final hop and gets the plaintext
        let (mix1_sk, mix1_pk) = keygen();
        let (mix2_sk, mix2_pk) = keygen();
        let (gateway_sk, gateway_pk) = keygen();
        let route = vec![node(1, mix1_pk), node(2, mix2_pk), node(3, gateway_pk)];
        let delays = delays::generate_from_average_duration(route.len(), Duration::from_millis(10));
        let destination = Destination::new(
            DestinationAddressBytes::from_bytes([9u8; DESTINATION_ADDRESS_LENGTH]),
            [0u8; IDENTIFIER_LENGTH],
        );

        let surb = SURBMaterial::new(route, delays, destination, PAYLOAD_KEYS_SEEDS_VERSION)
            .construct_SURB()
            .unwrap();
        assert_eq!(3, surb.materials_count());
        let surb = SURB::from_bytes(&surb.to_bytes()).unwrap();

        let message = vec![42u8; 160];
        let (packet, first_hop) = surb.use_surb(&message, DEFAULT_PAYLOAD_SIZE).unwrap();
        assert_eq!(
            NodeAddressBytes::from_bytes([1u8; NODE_ADDRESS_LENGTH]),
            first_hop
        );

        let packet = forward(packet, &mix1_sk, 2);
        let packet = forward(packet, &mix2_sk, 3);
        let processed = final_hop(packet, &gateway_sk);
        assert_eq!(PAYLOAD_KEYS_SEEDS_VERSION, processed.version);
        let ProcessedPacketData::FinalHop { payload, .. } = processed.data else {
            unreachable!()
        };
        assert_eq!(message, payload.recover_plaintext().unwrap());
    }

    #[test]
    fn single_seed_surb_reply_is_recovered_by_its_creator() {
        // new (260): mix, mix, gateway, recipient - the recipient is the final hop; the gateway
        // only ever sees a forward hop
        let (mix1_sk, mix1_pk) = keygen();
        let (mix2_sk, mix2_pk) = keygen();
        let (gateway_sk, gateway_pk) = keygen();
        let (recipient_sk, recipient_pk) = keygen();
        let route = vec![
            node(1, mix1_pk),
            node(2, mix2_pk),
            node(3, gateway_pk),
            node(4, recipient_pk),
        ];
        let delays = delays::generate_from_average_duration(route.len(), Duration::from_millis(10));
        let identifier: SURBIdentifier = [7u8; IDENTIFIER_LENGTH];
        let destination = Destination::new(
            DestinationAddressBytes::from_bytes([4u8; DESTINATION_ADDRESS_LENGTH]),
            identifier,
        );

        let (surb, recovery) =
            SURBMaterial::new(route, delays, destination, SINGLE_SEED_SURB_VERSION)
                .construct_recoverable_SURB()
                .unwrap();
        assert_eq!(1, surb.materials_count());
        assert_eq!(4, recovery.num_hops());
        assert_eq!(&identifier, recovery.identifier());

        // the SURB travels to the reply's sender as bytes, the recovery stays with the creator
        let surb = SURB::from_bytes(&surb.to_bytes()).unwrap();
        let recovery = SurbReplyRecovery::from_bytes(&recovery.to_bytes()).unwrap();

        let message = vec![42u8; 160];
        let (packet, first_hop) = surb.use_surb(&message, DEFAULT_PAYLOAD_SIZE).unwrap();
        assert_eq!(
            NodeAddressBytes::from_bytes([1u8; NODE_ADDRESS_LENGTH]),
            first_hop
        );

        let packet = forward(packet, &mix1_sk, 2);
        let packet = forward(packet, &mix2_sk, 3);
        let packet = forward(packet, &gateway_sk, 4);
        let processed = final_hop(packet, &recipient_sk);
        assert_eq!(SINGLE_SEED_SURB_VERSION, processed.version);
        let ProcessedPacketData::FinalHop {
            identifier: received_identifier,
            payload,
            ..
        } = processed.data
        else {
            unreachable!()
        };
        // the identifier is what the recipient looks the recovery material up by
        assert_eq!(identifier, received_identifier);
        assert_eq!(message, recovery.recover_plaintext(payload).unwrap());
    }

    #[test]
    fn single_seed_surb_reply_is_not_plaintext_at_the_final_hop_without_recovery() {
        let (mix_sk, mix_pk) = keygen();
        let (recipient_sk, recipient_pk) = keygen();
        let route = vec![node(1, mix_pk), node(2, recipient_pk)];
        let delays = delays::generate_from_average_duration(route.len(), Duration::from_millis(10));
        let destination = Destination::new(
            DestinationAddressBytes::from_bytes([2u8; DESTINATION_ADDRESS_LENGTH]),
            [7u8; IDENTIFIER_LENGTH],
        );
        let (surb, _recovery) =
            SURBMaterial::new(route, delays, destination, SINGLE_SEED_SURB_VERSION)
                .construct_recoverable_SURB()
                .unwrap();

        let (packet, _) = surb.use_surb(&[42u8; 160], DEFAULT_PAYLOAD_SIZE).unwrap();
        let packet = forward(packet, &mix_sk, 2);
        let ProcessedPacketData::FinalHop { payload, .. } = final_hop(packet, &recipient_sk).data
        else {
            unreachable!()
        };
        assert!(payload.recover_plaintext().is_err());
    }

    /// Relays `packet` through every forward hop in `hops` (hop `i` sits at address `i + 1`)
    /// and processes the final hop with `recipient_sk`, returning the delivered payload.
    fn deliver(
        packet: SphinxPacket,
        hops: &[&StaticSecret],
        recipient_sk: &StaticSecret,
    ) -> sphinx_packet::payload::Payload {
        let mut packet = packet;
        for (i, hop_sk) in hops.iter().enumerate() {
            packet = forward(packet, hop_sk, (i + 2) as u8);
        }
        match final_hop(packet, recipient_sk).data {
            ProcessedPacketData::FinalHop { payload, .. } => payload,
            ProcessedPacketData::ForwardHop { .. } => {
                unreachable!("final_hop already asserted a final hop")
            }
        }
    }

    #[test]
    fn single_seed_surb_reply_is_recovered_on_a_max_length_route() {
        use sphinx_packet::constants::MAX_PATH_LENGTH;

        // 3 mixes + gateway + recipient = MAX_PATH_LENGTH: the route 260 traffic will actually
        // use, and the one on which the final-hop header padding is smallest
        let (mix1_sk, mix1_pk) = keygen();
        let (mix2_sk, mix2_pk) = keygen();
        let (mix3_sk, mix3_pk) = keygen();
        let (gateway_sk, gateway_pk) = keygen();
        let (recipient_sk, recipient_pk) = keygen();
        let hops = [&mix1_sk, &mix2_sk, &mix3_sk, &gateway_sk];

        // two SURBs for the same route, so one's reply can be tried against the other's material
        let material = || {
            let route = vec![
                node(1, mix1_pk),
                node(2, mix2_pk),
                node(3, mix3_pk),
                node(4, gateway_pk),
                node(5, recipient_pk),
            ];
            assert_eq!(MAX_PATH_LENGTH, route.len());
            let delays =
                delays::generate_from_average_duration(route.len(), Duration::from_millis(10));
            let destination = Destination::new(
                DestinationAddressBytes::from_bytes([5u8; DESTINATION_ADDRESS_LENGTH]),
                [9u8; IDENTIFIER_LENGTH],
            );
            SURBMaterial::new(route, delays, destination, SINGLE_SEED_SURB_VERSION)
        };
        let (surb_a, recovery_a) = material().construct_recoverable_SURB().unwrap();
        let (surb_b, recovery_b) = material().construct_recoverable_SURB().unwrap();
        assert_eq!(1, surb_a.materials_count());
        assert_eq!(MAX_PATH_LENGTH, recovery_a.num_hops());
        assert_eq!(MAX_PATH_LENGTH, recovery_b.num_hops());
        // same identifier, different initial secrets - so different hop seeds
        assert_eq!(recovery_a.identifier(), recovery_b.identifier());
        assert_ne!(recovery_a.to_bytes(), recovery_b.to_bytes());

        let message = vec![42u8; 160];

        // a reply through A cannot be unsealed with B's material, and the mismatch is detected
        let (packet, _) = surb_a.use_surb(&message, DEFAULT_PAYLOAD_SIZE).unwrap();
        let sealed = deliver(packet, &hops, &recipient_sk);
        assert!(recovery_b.recover_plaintext(sealed).is_err());

        // a reply through B is recovered with B's material after a full-length transit
        let (packet, first_hop) = surb_b.use_surb(&message, DEFAULT_PAYLOAD_SIZE).unwrap();
        assert_eq!(
            NodeAddressBytes::from_bytes([1u8; NODE_ADDRESS_LENGTH]),
            first_hop
        );
        let sealed = deliver(packet, &hops, &recipient_sk);
        assert_eq!(message, recovery_b.recover_plaintext(sealed).unwrap());
    }
}
