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

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sphinx_packet::constants::{
    DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH,
};
use sphinx_packet::crypto::{keygen, EphemeralSecret};
use sphinx_packet::header::{delays, SphinxHeader};
use sphinx_packet::route::{Destination, DestinationAddressBytes, Node, NodeAddressBytes};
use sphinx_packet::SphinxPacket;
use std::time::Duration;
use sphinx_packet::payload::Payload;

struct PayloadBenchCase {
    payload_size: usize,
}

fn make_header_copy(header: &SphinxHeader) -> SphinxHeader {
    SphinxHeader::from_bytes(&header.to_bytes()).unwrap()
}

fn make_payload_copy(payload: Payload) -> Payload {
    Payload::from_bytes(&payload.into_bytes()).unwrap()
}

fn make_packet_copy(packet: &SphinxPacket) -> SphinxPacket {
    SphinxPacket::from_bytes(&packet.to_bytes()).unwrap()
}

fn bench_sphinx_header(c: &mut Criterion){
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


    c.bench_function("Sphinx Header Creation", |b| {
        b.iter(|| {
            SphinxHeader::new(&EphemeralSecret::new(), &route, &delays, &destination)
        })
    });

    let (header, _) = SphinxHeader::new(&EphemeralSecret::new(), &route, &delays, &destination);

    c.bench_function("Sphinx Header Processing", |b| {
        b.iter(|| {
            make_header_copy(&header).process(&node1_sk).unwrap()
        })
    });

}

fn bench_sphinx_payload(c: &mut Criterion){
    let case = PayloadBenchCase {
        payload_size: 1000,
    };

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

    let (_, payload_keys) = SphinxHeader::new(&EphemeralSecret::new(), &route, &delays, &destination);
    let message = vec![1u8, 16];

    c.bench_function("Sphinx Payload Creation", |b| {
        b.iter(|| {
            Payload::encapsulate_message(message.as_ref(), &payload_keys, case.payload_size).unwrap()
        })
    });

    let payload =
        Payload::encapsulate_message(message.as_ref(), &payload_keys, case.payload_size).unwrap();

    let payload_key = payload_keys.first().unwrap();
    c.bench_function("Sphinx Payload Processing", |b| {
        b.iter(|| {
            payload.clone().unwrap(&payload_key)
        })
    });
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

// criterion_group!(sphinx, bench_new_no_surb, bench_unwrap);
criterion_group!(sphinx, bench_sphinx_header, bench_sphinx_payload);
criterion_main!(sphinx);
