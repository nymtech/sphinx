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
use sphinx::crypto;
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
fn bench_create_new_packet_with_fresh_keys(c: &mut Criterion) {
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

    c.bench_function("sphinx creation using fresh keys", |b| {
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

fn bench_unwrap_with_fresh_keys(c: &mut Criterion) {
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
    c.bench_function("sphinx packet unwrap using fresh keys", |b| {
        b.iter(|| {
            make_packet_copy(&packet)
                .process(black_box(&node1_sk))
                .unwrap()
        })
    });
}

fn bench_create_packet_with_key_reuse(c: &mut Criterion) {
    let node1_pk_bytes: [u8; 32] = [
        96, 85, 39, 207, 33, 61, 106, 35, 99, 98, 193, 184, 10, 103, 161, 180, 199, 3, 114, 92, 90,
        245, 91, 135, 7, 195, 109, 48, 156, 59, 141, 83,
    ];
    let node2_pk_bytes: [u8; 32] = [
        34, 109, 116, 102, 45, 145, 189, 34, 236, 138, 142, 57, 141, 230, 94, 233, 0, 230, 230,
        121, 13, 195, 66, 209, 227, 217, 244, 170, 15, 15, 166, 38,
    ];
    let node3_pk_bytes: [u8; 32] = [
        164, 103, 20, 95, 51, 139, 88, 47, 250, 8, 226, 247, 244, 31, 146, 209, 146, 110, 78, 87,
        209, 104, 80, 245, 19, 63, 185, 198, 28, 175, 198, 87,
    ];

    let salt1: [u8; 32] = [
        157, 119, 175, 80, 29, 2, 228, 213, 134, 226, 222, 108, 204, 40, 53, 44, 83, 145, 117, 45,
        139, 234, 30, 39, 224, 196, 145, 165, 82, 183, 131, 238,
    ];
    let salt2: [u8; 32] = [
        130, 43, 117, 106, 227, 230, 203, 89, 191, 62, 96, 181, 228, 181, 51, 173, 91, 181, 155,
        72, 82, 17, 206, 223, 169, 68, 250, 110, 240, 43, 162, 61,
    ];
    let salt3: [u8; 32] = [
        191, 246, 173, 250, 231, 232, 191, 76, 77, 15, 5, 203, 13, 115, 136, 182, 18, 31, 34, 232,
        29, 109, 77, 50, 214, 168, 61, 44, 74, 251, 127, 144,
    ];

    let initital_shared_secret_bytes: [u8; 32] = [
        37, 196, 197, 122, 29, 47, 44, 45, 216, 119, 133, 224, 42, 14, 175, 211, 109, 141, 172,
        123, 182, 0, 252, 29, 136, 120, 140, 232, 87, 201, 230, 70,
    ];

    let shared_key1_bytes: [u8; 32] = [
        208, 232, 201, 166, 191, 135, 41, 153, 107, 45, 179, 119, 5, 219, 55, 72, 149, 2, 206, 140,
        29, 89, 177, 4, 159, 234, 171, 99, 34, 229, 70, 105,
    ];
    let shared_key2_bytes: [u8; 32] = [
        110, 116, 113, 237, 90, 11, 235, 200, 32, 16, 138, 245, 11, 151, 17, 126, 79, 167, 55, 63,
        85, 171, 131, 45, 252, 255, 25, 7, 135, 153, 96, 113,
    ];
    let shared_key3_bytes: [u8; 32] = [
        37, 250, 14, 151, 66, 29, 169, 137, 81, 14, 46, 115, 73, 176, 21, 251, 116, 59, 225, 39, 3,
        22, 217, 127, 45, 104, 53, 135, 212, 189, 10, 96,
    ];

    let node1 = Node::new(
        NodeAddressBytes::from_bytes([5u8; NODE_ADDRESS_LENGTH]),
        crypto::PublicKey::from(node1_pk_bytes),
    );
    let node2 = Node::new(
        NodeAddressBytes::from_bytes([4u8; NODE_ADDRESS_LENGTH]),
        crypto::PublicKey::from(node2_pk_bytes),
    );
    let node3 = Node::new(
        NodeAddressBytes::from_bytes([2u8; NODE_ADDRESS_LENGTH]),
        crypto::PublicKey::from(node3_pk_bytes),
    );
    let route = [node1, node2, node3];
    let delays = delays::generate_from_average_duration(route.len(), Duration::from_millis(10));
    let destination = Destination::new(
        DestinationAddressBytes::from_bytes([3u8; DESTINATION_ADDRESS_LENGTH]),
        [4u8; IDENTIFIER_LENGTH],
    );
    let hkdf_salt = [salt1, salt2, salt3];
    let message = vec![13u8, 16];
    let shared_key1: crypto::SharedKey = crypto::PublicKey::from(shared_key1_bytes);
    let shared_key2: crypto::SharedKey = crypto::PublicKey::from(shared_key2_bytes);
    let shared_key3: crypto::SharedKey = crypto::PublicKey::from(shared_key3_bytes);
    let shared_keys = vec![shared_key1, shared_key2, shared_key3];
    let initial_shared_secret: crypto::SharedKey =
        crypto::PublicKey::from(initital_shared_secret_bytes);

    c.bench_function("sphinx creation with precomputed shared keys", |b| {
        b.iter(|| {
            SphinxPacket::new_with_precomputed_keys(
                black_box(message.clone()),
                black_box(&route),
                black_box(&destination),
                black_box(&delays),
                black_box(&hkdf_salt),
                black_box(&shared_keys),
                black_box(&initial_shared_secret),
            )
            .unwrap()
        })
    });
}

fn bench_unwrap_packet_key_reuse(c: &mut Criterion) {
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

    c.bench_function("sphinx unwrap packet with precomputed shared keys", |b| {
        b.iter(|| {
            make_packet_copy(&packet)
                .process_with_previously_derived_keys(
                    black_box(shared_key1),
                    black_box(&hkdf_salt[0]),
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

    c.bench_function("sphinx unwrap header with fresh keys", |b| {
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

    c.bench_function("sphinx unwrap header with precomputed shared keys", |b| {
        b.iter(|| {
            make_header_copy(&sphinx_header)
                .process_with_previously_derived_keys(shared_key, &hkdf_salt[0])
                .unwrap()
        })
    });
}

criterion_group!(
    sphinx,
    bench_create_new_packet_with_fresh_keys,
    bench_unwrap_with_fresh_keys,
    bench_create_packet_with_key_reuse,
    bench_unwrap_packet_key_reuse,
    bench_unwrap_header,
    bench_unwrap_header_key_reuse,
);

criterion_main!(sphinx);
