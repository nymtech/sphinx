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

use crate::constants::{HEADER_INTEGRITY_MAC_SIZE, MAX_PATH_LENGTH, NODE_META_INFO_SIZE};
use crate::header::delays::Delay;
use crate::header::filler::Filler;
use crate::header::keys::RoutingKeys;
use crate::header::mac::HeaderIntegrityMac;
use crate::header::routing::destination::FinalRoutingInformation;
use crate::header::routing::nodes::{EncryptedRoutingInformation, RoutingInformation};
use crate::route::{Destination, Node, NodeAddressBytes};
use crate::{Error, ErrorKind, Result};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};

pub const TRUNCATED_ROUTING_INFO_SIZE: usize =
    ENCRYPTED_ROUTING_INFO_SIZE - (NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE);
pub const ENCRYPTED_ROUTING_INFO_SIZE: usize =
    (NODE_META_INFO_SIZE + HEADER_INTEGRITY_MAC_SIZE) * MAX_PATH_LENGTH;

pub mod destination;
pub mod nodes;

pub const FORWARD_HOP: RoutingFlag = 1;
pub const FINAL_HOP: RoutingFlag = 2;

pub type RoutingFlag = u8;

#[derive(Default)]
pub struct Version {
    major: u8,
    minor: u8,
    patch: u8,
}

impl Version {
    pub fn new() -> Self {
        Self {
            major: env!("CARGO_PKG_VERSION_MAJOR").to_string().parse().unwrap(),
            minor: env!("CARGO_PKG_VERSION_MINOR").to_string().parse().unwrap(),
            patch: env!("CARGO_PKG_VERSION_PATCH").to_string().parse().unwrap(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        vec![self.major, self.minor, self.patch]
    }
}

// the derivation is only required for the tests. please remove it in production
#[derive(Clone, Debug)]
pub struct EncapsulatedRoutingInformation {
    pub(crate) enc_routing_information: EncryptedRoutingInformation,
    pub(crate) integrity_mac: HeaderIntegrityMac,
}

impl EncapsulatedRoutingInformation {
    pub fn encapsulate(
        enc_routing_information: EncryptedRoutingInformation,
        integrity_mac: HeaderIntegrityMac,
    ) -> Self {
        Self {
            enc_routing_information,
            integrity_mac,
        }
    }

    pub fn new(
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
        routing_keys: &[RoutingKeys],
        filler: Filler,
    ) -> Self {
        Self::new_with_rng(route, destination, delays, routing_keys, filler, &mut OsRng)
    }

    pub fn new_with_rng<R: RngCore + CryptoRng>(
        route: &[Node],
        destination: &Destination,
        delays: &[Delay],
        routing_keys: &[RoutingKeys],
        filler: Filler,
        rng: &mut R,
    ) -> Self {
        assert_eq!(route.len(), routing_keys.len());
        assert_eq!(delays.len(), route.len());

        let final_keys = match routing_keys.last() {
            Some(k) => k,
            None => panic!("empty keys"),
        };

        let encapsulated_destination_routing_info =
            Self::for_final_hop(destination, final_keys, filler, route.len(), rng);

        Self::for_forward_hops(
            encapsulated_destination_routing_info,
            delays,
            route,
            routing_keys,
        )
    }

    fn for_final_hop<R: RngCore + CryptoRng>(
        dest: &Destination,
        routing_keys: &RoutingKeys,
        filler: Filler,
        route_len: usize,
        rng: &mut R,
    ) -> Self {
        // personal note: I like how this looks so much.
        FinalRoutingInformation::new(dest, route_len)
            .add_padding(route_len, rng) // add padding to obtain correct destination length
            .encrypt(routing_keys.stream_cipher_key, route_len) // encrypt with the key of final node (in our case service provider)
            .combine_with_filler(filler, route_len) // add filler to get header of correct length
            .encapsulate_with_mac(routing_keys.header_integrity_hmac_key) // combine the previous data with a MAC on the header (also calculated with the SPs key)
    }

    fn for_forward_hops(
        encapsulated_destination_routing_info: Self,
        delays: &[Delay],
        route: &[Node],               // [Mix0, Mix1, Mix2, ..., Mix_{v-1}, Mix_v]
        routing_keys: &[RoutingKeys], // [Keys0, Keys1, Keys2, ..., Keys_{v-1}, Keys_v]
    ) -> Self {
        route
            .iter()
            .skip(1) // we don't want the first element as person creating the packet knows the address of the first hop
            .map(|node| node.address.as_bytes()) // we only care about the address field
            .zip(
                // we need both route (i.e. address field) and corresponding keys of the PREVIOUS hop
                routing_keys.iter().take(routing_keys.len() - 1), // we don't want last element - it was already used to encrypt the destination
            )
            .zip(delays.iter().take(delays.len() - 1)) // no need for the delay for the final node
            .rev() // we are working from the 'inside'
            // we should be getting here
            // [(Mix_v, Keys_{v-1}, Delay_{v-1}), (Mix_{v-1}, Keys_{v-2}, Delay_{v-2}), ..., (Mix2, Keys1, Delay1), (Mix1, Keys0, Delay0)]
            .fold(
                // we start from the already created encrypted final routing info and mac for the destination
                // (encrypted with Keys_v)
                encapsulated_destination_routing_info,
                |next_hop_encapsulated_routing_information,
                 ((current_node_address, previous_node_routing_keys), delay)| {
                    RoutingInformation::new(
                        NodeAddressBytes::from_bytes(current_node_address),
                        delay.to_owned(),
                        next_hop_encapsulated_routing_information,
                    )
                    .encrypt(previous_node_routing_keys.stream_cipher_key)
                    .encapsulate_with_mac(previous_node_routing_keys.header_integrity_hmac_key)
                },
            )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.integrity_mac
            .as_bytes()
            .iter()
            .cloned()
            .chain(self.enc_routing_information.get_value_ref().iter().cloned())
            .collect()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_INTEGRITY_MAC_SIZE + ENCRYPTED_ROUTING_INFO_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidRouting,
                format!(
                    "tried to recover routing information using {} bytes, expected {}",
                    bytes.len(),
                    HEADER_INTEGRITY_MAC_SIZE + ENCRYPTED_ROUTING_INFO_SIZE
                ),
            ));
        }

        let mut integrity_mac_bytes = [0u8; HEADER_INTEGRITY_MAC_SIZE];
        let mut enc_routing_info_bytes = [0u8; ENCRYPTED_ROUTING_INFO_SIZE];

        // first bytes represent the mac
        integrity_mac_bytes.copy_from_slice(&bytes[..HEADER_INTEGRITY_MAC_SIZE]);
        // the rest are for the routing info
        enc_routing_info_bytes.copy_from_slice(
            &bytes[HEADER_INTEGRITY_MAC_SIZE
                ..HEADER_INTEGRITY_MAC_SIZE + ENCRYPTED_ROUTING_INFO_SIZE],
        );

        let integrity_mac = HeaderIntegrityMac::from_bytes(integrity_mac_bytes);
        let enc_routing_information =
            EncryptedRoutingInformation::from_bytes(enc_routing_info_bytes);

        Ok(EncapsulatedRoutingInformation {
            enc_routing_information,
            integrity_mac,
        })
    }
}

#[cfg(test)]
mod encapsulating_all_routing_information {
    use super::*;
    use crate::test_utils::{
        fixtures::{destination_fixture, filler_fixture, routing_keys_fixture},
        random_node,
    };

    #[test]
    #[should_panic]
    fn it_panics_if_route_is_longer_than_keys() {
        let route = [random_node(), random_node(), random_node()];
        let destination = destination_fixture();
        let delays = [
            Delay::new_from_nanos(10),
            Delay::new_from_nanos(20),
            Delay::new_from_nanos(30),
        ];
        let keys = [routing_keys_fixture(), routing_keys_fixture()];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &destination, &delays, &keys, filler);
    }

    #[test]
    #[should_panic]
    fn it_panics_if_keys_are_longer_than_route() {
        let route = [random_node(), random_node()];
        let destination = destination_fixture();
        let delays = [
            Delay::new_from_nanos(10),
            Delay::new_from_nanos(20),
            Delay::new_from_nanos(30),
        ];
        let keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &destination, &delays, &keys, filler);
    }

    #[test]
    #[should_panic]
    fn it_panics_if_empty_route_is_provided() {
        let route = vec![];
        let destination = destination_fixture();
        let delays = [
            Delay::new_from_nanos(10),
            Delay::new_from_nanos(20),
            Delay::new_from_nanos(30),
        ];
        let keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &destination, &delays, &keys, filler);
    }

    #[test]
    #[should_panic]
    fn it_panic_if_empty_keys_are_provided() {
        let route = [random_node(), random_node()];
        let destination = destination_fixture();
        let delays = [
            Delay::new_from_nanos(10),
            Delay::new_from_nanos(20),
            Delay::new_from_nanos(30),
        ];
        let keys = vec![];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &destination, &delays, &keys, filler);
    }
}

#[cfg(test)]
mod encapsulating_forward_routing_information {
    use super::*;
    use crate::test_utils::{
        fixtures::{destination_fixture, filler_fixture, routing_keys_fixture},
        random_node,
    };

    #[test]
    fn it_correctly_generates_sphinx_routing_information_for_route_of_length_3() {
        // this is basically loop unwrapping, but considering the complex logic behind it, it's warranted
        let route = [random_node(), random_node(), random_node()];
        let destination = destination_fixture();
        let delay0 = Delay::new_from_nanos(10);
        let delay1 = Delay::new_from_nanos(20);
        let delay2 = Delay::new_from_nanos(30);
        let delays = [delay0.clone(), delay1.clone(), delay2].to_vec();
        let routing_keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);
        let filler_copy = filler_fixture(route.len() - 1);
        assert_eq!(filler, filler_copy);

        let destination_routing_info = EncapsulatedRoutingInformation::for_final_hop(
            &destination,
            routing_keys.last().unwrap(),
            filler,
            route.len(),
            &mut OsRng,
        );

        let destination_routing_info_copy = destination_routing_info.clone();

        // sanity check to make sure our 'copy' worked
        assert_eq!(
            destination_routing_info
                .enc_routing_information
                .get_value_ref()
                .to_vec(),
            destination_routing_info_copy
                .enc_routing_information
                .get_value_ref()
                .to_vec()
        );
        assert_eq!(
            destination_routing_info.integrity_mac.as_bytes().to_vec(),
            destination_routing_info_copy
                .integrity_mac
                .as_bytes()
                .to_vec()
        );

        let routing_info = EncapsulatedRoutingInformation::for_forward_hops(
            destination_routing_info,
            &delays,
            &route,
            &routing_keys,
        );

        let layer_1_routing =
            RoutingInformation::new(route[2].address, delay1, destination_routing_info_copy)
                .encrypt(routing_keys[1].stream_cipher_key)
                .encapsulate_with_mac(routing_keys[1].header_integrity_hmac_key);

        // this is what first mix should receive
        let layer_0_routing = RoutingInformation::new(route[1].address, delay0, layer_1_routing)
            .encrypt(routing_keys[0].stream_cipher_key)
            .encapsulate_with_mac(routing_keys[0].header_integrity_hmac_key);

        assert_eq!(
            routing_info
                .enc_routing_information
                .get_value_ref()
                .to_vec(),
            layer_0_routing
                .enc_routing_information
                .get_value_ref()
                .to_vec()
        );
        assert_eq!(
            routing_info.integrity_mac.into_inner(),
            layer_0_routing.integrity_mac.into_inner()
        );
    }
    #[test]
    fn it_correctly_generates_sphinx_routing_information_for_route_of_max_length() {
        // this is basically loop unwrapping, but considering the complex iterator, it's warranted
        assert_eq!(5, MAX_PATH_LENGTH); // make sure we catch it if we decided to change the constant

        /* since we're using max path length we expect literally:
        n4 || m4 || n3 || m3 || n2 || m2 || n1 || m1 || d || i || p
        // so literally no filler!
        where:
        {n1, n2, ...} are node addresses
        {m1, m2, ...} are macs on previous layers
        d is destination address
        i is destination identifier
        p is destination padding
        */
        // TODO: IMPLEMENT SPHINX HEADER LAYER UNWRAPPING
        // HOWEVER! to test it, we need to first wrap function to unwrap header layer because each consecutive (ni, mi) pair is encrypted
    }
}

#[cfg(test)]
mod converting_encapsulated_routing_info_to_bytes {
    use super::*;
    use crate::test_utils::fixtures::encapsulated_routing_information_fixture;

    #[test]
    fn it_is_possible_to_convert_back_and_forth() {
        let encapsulated_routing_info = encapsulated_routing_information_fixture();
        let encapsulated_routing_info_bytes = encapsulated_routing_info.to_bytes();

        let recovered_routing_info =
            EncapsulatedRoutingInformation::from_bytes(&encapsulated_routing_info_bytes).unwrap();
        assert_eq!(
            encapsulated_routing_info
                .enc_routing_information
                .get_value_ref()
                .to_vec(),
            recovered_routing_info
                .enc_routing_information
                .get_value_ref()
                .to_vec()
        );

        assert_eq!(
            encapsulated_routing_info.integrity_mac.into_inner(),
            recovered_routing_info.integrity_mac.into_inner()
        );
    }
}
