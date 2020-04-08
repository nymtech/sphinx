// Copyright 2020 Nym
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

#![feature(test)]

extern crate sphinx;
extern crate test;

use sphinx::crypto;
use sphinx::header::delays;
use sphinx::route::NodeAddressBytes;
use sphinx::route::{Destination, Node};
use sphinx::SphinxPacket;
use std::time::Duration;

const NODE_ADDRESS_LENGTH: usize = 32;
const DESTINATION_ADDRESS_LENGTH: usize = 32;
const IDENTIFIER_LENGTH: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;

    // two of those can be run concurrently to perform credential verification
    #[bench]
    fn bench_new(b: &mut Bencher) {
        let (_, node1_pk) = crypto::keygen();
        let node1 = Node::new(NodeAddressBytes([5u8; NODE_ADDRESS_LENGTH]), node1_pk);
        let (_, node2_pk) = crypto::keygen();
        let node2 = Node::new(NodeAddressBytes([4u8; NODE_ADDRESS_LENGTH]), node2_pk);
        let (_, node3_pk) = crypto::keygen();
        let node3 = Node::new(NodeAddressBytes([2u8; NODE_ADDRESS_LENGTH]), node3_pk);

        let route = [node1, node2, node3];
        let delays = delays::generate_from_average_duration(route.len(), Duration::from_millis(10));
        let destination =
            Destination::new([3u8; DESTINATION_ADDRESS_LENGTH], [4u8; IDENTIFIER_LENGTH]);

        let message = vec![13u8, 16];
        b.iter(|| {
            SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();
        })
    }

    #[bench]
    fn bench_unwrap(b: &mut Bencher) {
        let (node1_sk, node1_pk) = crypto::keygen();
        let node1 = Node::new(NodeAddressBytes([5u8; NODE_ADDRESS_LENGTH]), node1_pk);
        let (_, node2_pk) = crypto::keygen();
        let node2 = Node::new(NodeAddressBytes([4u8; NODE_ADDRESS_LENGTH]), node2_pk);
        let (_, node3_pk) = crypto::keygen();
        let node3 = Node::new(NodeAddressBytes([2u8; NODE_ADDRESS_LENGTH]), node3_pk);

        let route = [node1, node2, node3];
        let delays = delays::generate_from_average_duration(route.len(), Duration::from_millis(10));
        let destination =
            Destination::new([3u8; DESTINATION_ADDRESS_LENGTH], [4u8; IDENTIFIER_LENGTH]);

        let message = vec![13u8, 16];
        let packet = SphinxPacket::new(message.clone(), &route, &destination, &delays).unwrap();
        b.iter(|| {
            packet.clone().process(node1_sk).unwrap();
        })
    }
}
