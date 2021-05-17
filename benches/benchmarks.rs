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
};
use sphinx::crypto::{keygen, EphemeralSecret, SharedKey};
use sphinx::header::{delays, SphinxHeader};
use sphinx::packet::builder::DEFAULT_PAYLOAD_SIZE;
use sphinx::payload::Payload;
use sphinx::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes};
use sphinx::SphinxPacket;
use std::time::Duration;

fn make_packet_copy(packet: &SphinxPacket) -> SphinxPacket {
    SphinxPacket::from_bytes(&packet.to_bytes()).unwrap()
}

fn make_header_copy(header: &SphinxHeader) -> SphinxHeader {
    SphinxHeader::from_bytes(&header.to_bytes()).unwrap()
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

    let hkdf_salt = [
        [4u8; HKDF_SALT_SIZE],
        [1u8; HKDF_SALT_SIZE],
        [3u8; HKDF_SALT_SIZE],
    ];

    let message = vec![13u8, 16];

    c.bench_function("sphinx creation", |b| {
        b.iter(|| {
            SphinxPacket::new(
                black_box(message.clone()),
                black_box(&route),
                black_box(&destination),
                black_box(&delays),
                black_box(&hkdf_salt),
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
    let hkdf_salt = [
        [4u8; HKDF_SALT_SIZE],
        [1u8; HKDF_SALT_SIZE],
        [3u8; HKDF_SALT_SIZE],
    ];

    let message = vec![13u8, 16];
    let packet = SphinxPacket::new(message, &route, &destination, &delays, &hkdf_salt).unwrap();

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
    let initial_shared_secret = SharedKey::from(&initial_secret);
    let message = vec![13u8, 16];
    let (header, payload_keys) =
        SphinxHeader::new(&initial_secret, &route, &delays, &hkdf_salt, &destination);
    let payload = Payload::encapsulate_message(&message, &payload_keys, DEFAULT_PAYLOAD_SIZE);
    let payload = match payload {
        Ok(payload) => payload,
        Err(error) => panic!("Problem when encapsulating message: {:?}", error),
    };

    let packet = SphinxPacket { header, payload };
    let shared_key1 = node1_sk.diffie_hellman(&initial_shared_secret);

    c.bench_function("sphinx unwrap key reuse", |b| {
        b.iter(|| {
            make_packet_copy(&packet)
                .process_with_previously_derived_keys(
                    black_box(shared_key1),
                    black_box(Some(&hkdf_salt[0])),
                )
                .unwrap()
        })
    });
}

fn bench_unwrap_header(c: &mut Criterion) {
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
        [123u8; HKDF_SALT_SIZE],
        [236u8; HKDF_SALT_SIZE],
        [98u8; HKDF_SALT_SIZE],
    ];

    let initial_secret = EphemeralSecret::new();
    let (sphinx_header, _) =
        SphinxHeader::new(&initial_secret, &route, &delays, &hkdf_salt, &destination);

    c.bench_function("sphinx unwrap header", |b| {
        b.iter(|| {
            make_header_copy(&sphinx_header)
                .process(black_box(&node1_sk))
                .unwrap()
        })
    });
}

fn bench_unwrap_header_key_reuse(c: &mut Criterion) {
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
        [123u8; HKDF_SALT_SIZE],
        [236u8; HKDF_SALT_SIZE],
        [98u8; HKDF_SALT_SIZE],
    ];

    let initial_secret = EphemeralSecret::new();
    let (sphinx_header, _) =
        SphinxHeader::new(&initial_secret, &route, &delays, &hkdf_salt, &destination);

    let shared_key = node1_sk.diffie_hellman(&sphinx_header.shared_secret);

    c.bench_function("sphinx unwrap header with key reuse", |b| {
        b.iter(|| {
            make_header_copy(&sphinx_header)
                .process_with_previously_derived_keys(shared_key, Some(&hkdf_salt[0]))
                .unwrap()
        })
    });
}

criterion_group!(
    sphinx,
    bench_new_no_surb,
    bench_unwrap,
    bench_unwrap_key_reuse,
    bench_unwrap_header,
    bench_unwrap_header_key_reuse,
);

criterion_main!(sphinx);
