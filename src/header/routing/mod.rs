use crate::constants::{
    DESTINATION_ADDRESS_LENGTH, FLAG_LENGTH, HEADER_INTEGRITY_MAC_SIZE, HOP_META_INFO_LENGTH,
    IDENTIFIER_LENGTH, MAX_PATH_LENGTH, SECURITY_PARAMETER,
};
use crate::header;
use crate::header::filler::Filler;
use crate::header::keys::RoutingKeys;
use crate::header::mac::HeaderIntegrityMac;
use crate::header::routing::destination::FinalRoutingInformation;
use crate::header::routing::nodes::{
    encrypted_routing_information_fixture, EncryptedRoutingInformation, RoutingInformation,
};
use crate::route::{Destination, Node};

pub const TRUNCATED_ROUTING_INFO_SIZE: usize =
    MAX_ENCRYPTED_ROUTING_INFO_SIZE - DESTINATION_ADDRESS_LENGTH - IDENTIFIER_LENGTH - FLAG_LENGTH;
pub const MAX_ENCRYPTED_ROUTING_INFO_SIZE: usize =
    (HOP_META_INFO_LENGTH + HEADER_INTEGRITY_MAC_SIZE) * MAX_PATH_LENGTH;

pub mod destination;
pub mod nodes;

pub const ROUTING_FLAG: u8 = 1;
pub const FINAL_FLAG: u8 = 2;

// the derivation is only required for the tests. please remove it in production
#[derive(Clone)]
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
        routing_keys: &[RoutingKeys],
        filler: Filler,
    ) -> Self {
        assert_eq!(route.len(), routing_keys.len());

        let final_keys = match routing_keys.last() {
            Some(k) => k,
            None => panic!("empty keys"),
        };

        let encapsulated_destination_routing_info =
            Self::for_destination(destination, final_keys, filler, route.len());

        Self::for_forward_hops(encapsulated_destination_routing_info, route, routing_keys)
    }

    fn for_destination(
        dest: &Destination,
        routing_keys: &RoutingKeys,
        filler: Filler,
        route_len: usize,
    ) -> Self {
        // personal note: I like how this looks so much.
        FinalRoutingInformation::new(dest, route_len)
            .add_padding(route_len) // add padding to obtain correct destination length
            .encrypt(routing_keys.stream_cipher_key, route_len) // encrypt with the key of final node (in our case service provider)
            .combine_with_filler(filler, route_len) // add filler to get header of correct length
            .encapsulate_with_mac(routing_keys.header_integrity_hmac_key) // combine the previous data with a MAC on the header (also calculated with the SPs key)
    }

    fn for_forward_hops(
        encapsulated_destination_routing_info: Self,
        route: &[Node],               // [Mix0, Mix1, Mix2, ..., Mix_{v-1}, Mix_v]
        routing_keys: &[RoutingKeys], // [Keys0, Keys1, Keys2, ..., Keys_{v-1}, Keys_v]
    ) -> Self {
        route
            .iter()
            .skip(1) // we don't want the first element as person creating the packet knows the address of the first hop
            .map(|node| node.address) // we only care about the address field
            .zip(
                // we need both route (i.e. address field) and corresponding keys of the PREVIOUS hop
                routing_keys.iter().take(routing_keys.len() - 1), // we don't want last element - it was already used to encrypt the destination
            )
            .rev() // we are working from the 'inside'
            // we should be getting here
            // [(Mix_v, Keys_{v-1}), (Mix_{v-1}, Keys_{v-2}), ..., (Mix2, Keys1), (Mix1, Keys0)]
            .fold(
                // we start from the already created encrypted final routing info and mac for the destination
                // (encrypted with Keys_v)
                encapsulated_destination_routing_info,
                |next_hop_encapsulated_routing_information,
                 (current_node_address, previous_node_routing_keys)| {
                    RoutingInformation::new(
                        current_node_address,
                        next_hop_encapsulated_routing_information,
                    )
                    .encrypt(previous_node_routing_keys.stream_cipher_key)
                    .encapsulate_with_mac(previous_node_routing_keys.header_integrity_hmac_key)
                },
            )
    }
}

// TODO: all tests were retrofitted to work with new code structure,
// they should be rewritten to work better with what we have now.

#[cfg(test)]
mod encapsulating_all_routing_information {
    use crate::header::filler::filler_fixture;
    use crate::header::keys::routing_keys_fixture;
    use crate::route::{destination_fixture, random_node};

    use super::*;

    #[test]
    #[should_panic]
    fn it_panics_if_route_is_longer_than_keys() {
        let route = [random_node(), random_node(), random_node()];
        let destination = destination_fixture();
        let keys = [routing_keys_fixture(), routing_keys_fixture()];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &destination, &keys, filler);
    }

    #[test]
    #[should_panic]
    fn it_panics_if_keys_are_longer_than_route() {
        let route = [random_node(), random_node()];
        let destination = destination_fixture();
        let keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &destination, &keys, filler);
    }

    #[test]
    #[should_panic]
    fn it_panics_if_empty_route_is_provided() {
        let route = vec![];
        let destination = destination_fixture();
        let keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &destination, &keys, filler);
    }

    #[test]
    #[should_panic]
    fn it_panic_if_empty_keys_are_provided() {
        let route = [random_node(), random_node()];
        let destination = destination_fixture();
        let keys = vec![];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &destination, &keys, filler);
    }
}

#[cfg(test)]
mod encapsulating_forward_routing_information {
    use crate::header::filler::filler_fixture;
    use crate::header::keys::routing_keys_fixture;
    use crate::route::{destination_fixture, random_node};

    use super::*;

    #[test]
    fn it_correctly_generates_sphinx_routing_information_for_route_of_length_3() {
        // this is basically loop unwrapping, but considering the complex logic behind it, it's warranted
        let route = [random_node(), random_node(), random_node()];
        let destination = destination_fixture();
        let routing_keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);
        let filler_copy = filler_fixture(route.len() - 1);
        assert_eq!(filler, filler_copy);

        let destination_routing_info = EncapsulatedRoutingInformation::for_destination(
            &destination,
            &routing_keys.last().unwrap(),
            filler,
            route.len(),
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
            destination_routing_info.integrity_mac.get_value_ref(),
            destination_routing_info_copy.integrity_mac.get_value_ref()
        );

        let routing_info = EncapsulatedRoutingInformation::for_forward_hops(
            destination_routing_info,
            &route,
            &routing_keys,
        );

        let layer_1_routing =
            RoutingInformation::new(route[2].address, destination_routing_info_copy)
                .encrypt(routing_keys[1].stream_cipher_key)
                .encapsulate_with_mac(routing_keys[1].header_integrity_hmac_key);

        // this is what first mix should receive
        let layer_0_routing = RoutingInformation::new(route[1].address, layer_1_routing)
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
            routing_info.integrity_mac.get_value(),
            layer_0_routing.integrity_mac.get_value()
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

#[allow(dead_code)]
pub fn encapsulated_routing_information_fixture() -> EncapsulatedRoutingInformation {
    EncapsulatedRoutingInformation {
        enc_routing_information: encrypted_routing_information_fixture(),
        integrity_mac: header::mac::header_integrity_mac_fixture(),
    }
}
