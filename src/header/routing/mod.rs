use crate::constants::{
    DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, MAX_PATH_LENGTH, SECURITY_PARAMETER,
};
use crate::header;
use crate::header::filler::Filler;
use crate::header::keys::RoutingKeys;
use crate::header::mac::HeaderIntegrityMac;
use crate::header::routing::destination::FinalRoutingInformation;
use crate::header::routing::nodes::{
    encrypted_routing_information_fixture, EncryptedRoutingInformation, RoutingInformation,
};
use crate::route::RouteElement;

pub const TRUNCATED_ROUTING_INFO_SIZE: usize =
    ENCRYPTED_ROUTING_INFO_SIZE - DESTINATION_ADDRESS_LENGTH - IDENTIFIER_LENGTH;
pub const ENCRYPTED_ROUTING_INFO_SIZE: usize = 3 * MAX_PATH_LENGTH * SECURITY_PARAMETER;

mod destination;
mod nodes;

#[derive(Debug)]
pub enum RoutingEncapsulationError {
    IsNotForwardHopError,
    IsNotFinalHopError,
    EmptyRouteError,
    EmptyKeysError,
    UnequalRouteAndKeysError,
}

// the derivation is only required for the tests. please remove it in production
#[derive(Clone)]
pub struct EncapsulatedRoutingInformation {
    enc_routing_information: EncryptedRoutingInformation,
    integrity_mac: HeaderIntegrityMac,
}

impl EncapsulatedRoutingInformation {
    pub fn new(
        route: &[RouteElement],
        routing_keys: &[RoutingKeys],
        filler: Filler,
    ) -> Result<Self, RoutingEncapsulationError> {
        if route.len() != routing_keys.len() {
            return Err(RoutingEncapsulationError::UnequalRouteAndKeysError);
        }
        let final_keys = match routing_keys.last() {
            Some(k) => k,
            None => return Err(RoutingEncapsulationError::EmptyKeysError),
        };
        let final_hop = match route.last() {
            Some(k) => k,
            None => return Err(RoutingEncapsulationError::EmptyRouteError),
        };

        // TODO: proper error wrapping for below
        let final_encapsulated_routing_info =
            Self::for_final_hop(final_hop, final_keys, filler, route.len()).unwrap();

        Ok(Self::for_forward_hops(
            final_encapsulated_routing_info,
            route,
            routing_keys,
        ))
    }

    fn for_final_hop(
        destination_hop: &RouteElement,
        routing_keys: &RoutingKeys,
        filler: Filler,
        route_len: usize,
    ) -> Result<Self, RoutingEncapsulationError> {
        let destination = match destination_hop {
            RouteElement::FinalHop(dest) => dest,
            _ => return Err(RoutingEncapsulationError::IsNotFinalHopError),
        };

        // personal note: I like how this looks so much.
        Ok(FinalRoutingInformation::new(destination, route_len)
            .add_padding(route_len)
            .encrypt(routing_keys.stream_cipher_key, route_len)
            .combine_with_filler(filler, route_len)
            .encapsulate_with_mac(routing_keys.header_integrity_hmac_key))
    }

    fn for_forward_hops(
        final_encapsulated_routing_info: Self,
        route: &[RouteElement],
        routing_keys: &[RoutingKeys],
    ) -> Self {
        route
            .iter()
            .take(route.len() - 1) // we don't want the last element as we already created header.routing information for it
            .zip(
                // we need both route (i.e. address field) and corresponding keys
                routing_keys.iter().take(routing_keys.len() - 1), // again, we don't want last element
            )
            .rev() // we from from the 'inside'
            .fold(
                final_encapsulated_routing_info, // we start from the already created encrypted final header.routing info and mac for the destination
                |next_encapsulated_routing_information,
                 (current_node_route_element, current_node_routing_keys)| {
                    RoutingInformation::new(
                        current_node_route_element,
                        next_encapsulated_routing_information,
                    )
                    .unwrap()
                    .encrypt(current_node_routing_keys.stream_cipher_key)
                    .encapsulate_with_mac(current_node_routing_keys.header_integrity_hmac_key)
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
    use crate::route::{random_final_hop, random_forward_hop};

    use super::*;

    #[test]
    #[should_panic]
    fn it_panics_if_route_is_longer_than_keys() {
        let route = [
            random_forward_hop(),
            random_forward_hop(),
            random_final_hop(),
        ];
        let keys = [routing_keys_fixture(), routing_keys_fixture()];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &keys, filler).unwrap();
    }

    #[test]
    #[should_panic]
    fn it_panics_if_keys_are_longer_than_route() {
        let route = [random_forward_hop(), random_final_hop()];
        let keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &keys, filler).unwrap();
    }

    #[test]
    #[should_panic]
    fn it_panics_if_empty_route_is_provided() {
        let route = vec![];
        let keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &keys, filler).unwrap();
    }

    #[test]
    #[should_panic]
    fn it_panic_if_empty_keys_are_provided() {
        let route = [random_forward_hop(), random_final_hop()];
        let keys = vec![];
        let filler = filler_fixture(route.len() - 1);

        EncapsulatedRoutingInformation::new(&route, &keys, filler).unwrap();
    }
}

#[cfg(test)]
mod encapsulating_forward_routing_information {
    use crate::header::filler::filler_fixture;
    use crate::header::keys::routing_keys_fixture;
    use crate::route::{random_final_hop, random_forward_hop};

    use super::*;

    #[test]
    fn it_correctly_generates_sphinx_routing_information_for_route_of_length_3() {
        // this is basically loop unwrapping, but considering the complex logic behind it, it's warranted
        let route = [
            random_forward_hop(),
            random_forward_hop(),
            random_final_hop(),
        ];
        let routing_keys = [
            routing_keys_fixture(),
            routing_keys_fixture(),
            routing_keys_fixture(),
        ];
        let filler = filler_fixture(route.len() - 1);
        let filler_copy = filler_fixture(route.len() - 1);
        assert_eq!(filler, filler_copy);

        let final_routing_info = EncapsulatedRoutingInformation::for_final_hop(
            &route.last().unwrap(),
            &routing_keys.last().unwrap(),
            filler,
            route.len(),
        )
        .unwrap();

        let final_routing_info_copy = final_routing_info.clone();

        // sanity check to make sure our 'copy' worked
        assert_eq!(
            final_routing_info
                .enc_routing_information
                .get_value_ref()
                .to_vec(),
            final_routing_info_copy
                .enc_routing_information
                .get_value_ref()
                .to_vec()
        );
        assert_eq!(
            final_routing_info.integrity_mac.get_value_ref(),
            final_routing_info_copy.integrity_mac.get_value_ref()
        );

        let routing_info = EncapsulatedRoutingInformation::for_forward_hops(
            final_routing_info,
            &route,
            &routing_keys,
        );

        let layer_1_routing = RoutingInformation::new(&route[1], final_routing_info_copy)
            .unwrap()
            .encrypt(routing_keys[1].stream_cipher_key)
            .encapsulate_with_mac(routing_keys[1].header_integrity_hmac_key);

        let layer_0_routing = RoutingInformation::new(&route[0], layer_1_routing)
            .unwrap()
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

        // TODO: IMPLEMENT SPHINX HEADER LAYER UNWRAPING
        // HOWEVER! to test it, we need to first wrap function to unwrap header layer because each consequtive (ni, mi) pair is encrypted
    }
}

pub fn encapsulated_routing_information_fixture() -> EncapsulatedRoutingInformation {
    EncapsulatedRoutingInformation {
        enc_routing_information: encrypted_routing_information_fixture(),
        integrity_mac: header::mac::header_integrity_mac_fixture(),
    }
}
