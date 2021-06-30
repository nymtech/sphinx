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

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sphinx::constants::{
    DESTINATION_ADDRESS_LENGTH, HKDF_SALT_SIZE, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH,
    PAYLOAD_KEY_SIZE,
};
use sphinx::crypto::{keygen, EphemeralSecret};
use sphinx::header::keys::RoutingKeys;
use sphinx::header::{delays, keys, SphinxHeader};
use sphinx::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes};
use sphinx::SphinxPacket;
use std::time::Duration;

fn make_packet_copy(packet: &SphinxPacket) -> SphinxPacket {
    SphinxPacket::from_bytes(&packet.to_bytes()).unwrap()
}

// two of those can be run concurrently to perform credential verification
fn bench_new_no_surb(c: &mut Criterion) {
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
    let delays = delays::generate_from_average_duration(route.len(), Duration::from_millis(10));
    let destination = Destination::new(
        DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
        [4u8; IDENTIFIER_LENGTH],
    );

    let message = vec![13u8, 16];

    c.bench_function("sphinx creation", |b| {
        b.iter(|| {
            SphinxPacket::new(
                black_box(message.clone()),
                black_box(&route),
                black_box(&destination),
                black_box(&delays),
            )
            .unwrap()
        })
    });
}

fn bench_unwrap(c: &mut Criterion) {
    let (node1_sk, node1_pk) = keygen();
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
    let delays = delays::generate_from_average_duration(route.len(), Duration::from_millis(10));
    let destination = Destination::new(
        DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
        [4u8; IDENTIFIER_LENGTH],
    );

    let message = vec![13u8, 16];
    let packet = SphinxPacket::new(message, &route, &destination, &delays).unwrap();

    // technically it's not benching only unwrapping, but also "make_packet_copy"
    // but it's relatively small
    c.bench_function("sphinx unwrap", |b| {
        b.iter(|| {
            make_packet_copy(&packet)
                .process(black_box(&node1_sk))
                .unwrap()
        })
    });
}

fn bench_unwrap_key_reuse(c: &mut Criterion) {
    let (node1_sk, node1_pk) = keygen();
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
    let delays = delays::generate_from_average_duration(route.len(), Duration::from_millis(10));
    let destination = Destination::new(
        DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
        [4u8; IDENTIFIER_LENGTH],
    );
    let hkdf_salt = [
        [4u8; HKDF_SALT_SIZE],
        [1u8; HKDF_SALT_SIZE],
        [3u8; HKDF_SALT_SIZE],
    ];

    let initial_secret = EphemeralSecret::new();
    let key_material = keys::KeyMaterial::derive(&route, &initial_secret);
    let routing_keys = key_material.routing_keys;
    let initial_shared_secret = key_material.initial_shared_secret;

    let message = vec![13u8, 16];

    let packet = SphinxPacket::new_with_precomputed_keys(
        message,
        &route,
        &destination,
        &delays,
        &routing_keys,
        &initial_shared_secret,
    )
    .unwrap();
    let new_secret = SphinxHeader::blind_the_shared_secret(
        packet.header.shared_secret,
        routing_keys[0].blinding_factor,
    );

    c.bench_function("sphinx unwrap with routing keys reuse", |b| {
        b.iter(|| {
            make_packet_copy(&packet)
                .process_with_derived_keys(
                    black_box(&Some(new_secret)),
                    black_box(&routing_keys[0]),
                )
                .unwrap()
        })
    });
}

fn bench_create_packet_key_reuse(c: &mut Criterion) {
    let (node1_sk, node1_pk) = keygen();
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
    let delays = delays::generate_from_average_duration(route.len(), Duration::from_millis(10));
    let destination = Destination::new(
        DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
        [4u8; IDENTIFIER_LENGTH],
    );
    let hkdf_salt = [
        [4u8; HKDF_SALT_SIZE],
        [1u8; HKDF_SALT_SIZE],
        [3u8; HKDF_SALT_SIZE],
    ];

    let initial_secret = EphemeralSecret::new();
    let key_material = keys::KeyMaterial::derive(&route, &initial_secret);
    let routing_keys = key_material.routing_keys;
    let initial_shared_secret = key_material.initial_shared_secret;

    let message = vec![13u8, 16];

    c.bench_function("sphinx creation with routing key reuse", |b| {
        b.iter(|| {
            SphinxPacket::new_with_precomputed_keys(
                black_box(message.clone()),
                black_box(&route),
                black_box(&destination),
                black_box(&delays),
                black_box(&routing_keys),
                black_box(&initial_shared_secret),
            )
            .unwrap()
        })
    });
}

criterion_group!(
    sphinx,
    bench_new_no_surb,
    bench_unwrap,
    bench_create_packet_key_reuse,
    bench_unwrap_key_reuse,
);

criterion_main!(sphinx);
