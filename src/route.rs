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

use crate::constants::{DESTINATION_ADDRESS_LENGTH, IDENTIFIER_LENGTH, NODE_ADDRESS_LENGTH};
use crate::crypto;
use crate::{Error, ErrorKind, Result};
use std::fmt::{self, Display, Formatter};

// in paper delta
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash)]
pub struct DestinationAddressBytes([u8; DESTINATION_ADDRESS_LENGTH]);

impl DestinationAddressBytes {
    pub fn to_base58_string(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    pub fn try_from_base58_string<S: Into<String>>(val: S) -> Result<Self> {
        let decoded = match bs58::decode(val.into()).into_vec() {
            Ok(decoded) => decoded,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::InvalidRouting,
                    format!("failed to decode destination from b58 string: {:?}", e),
                ))
            }
        };

        if decoded.len() != DESTINATION_ADDRESS_LENGTH {
            return Err(Error::new(
                ErrorKind::InvalidRouting,
                "decoded destination address has invalid length",
            ));
        }

        let mut address_bytes = [0; DESTINATION_ADDRESS_LENGTH];
        address_bytes.copy_from_slice(&decoded[..]);

        Ok(DestinationAddressBytes(address_bytes))
    }

    pub fn from_bytes(b: [u8; DESTINATION_ADDRESS_LENGTH]) -> Self {
        DestinationAddressBytes(b)
    }

    pub fn try_from_byte_slice(b: &[u8]) -> Result<Self> {
        if b.len() != DESTINATION_ADDRESS_LENGTH {
            return Err(Error::new(
                ErrorKind::InvalidRouting,
                "received bytes got invalid length",
            ));
        }

        let mut address_bytes = [0; DESTINATION_ADDRESS_LENGTH];
        address_bytes.copy_from_slice(&b);

        Ok(DestinationAddressBytes(address_bytes))
    }

    /// View this `DestinationAddressBytes` as an array of bytes.
    pub fn as_bytes(&self) -> &[u8; DESTINATION_ADDRESS_LENGTH] {
        &self.0
    }

    /// Convert this `DestinationAddressBytes` to an array of bytes.
    pub fn to_bytes(&self) -> [u8; DESTINATION_ADDRESS_LENGTH] {
        self.0
    }
}

impl Display for DestinationAddressBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "DestinationAddressBytes: {}", self.to_base58_string())
    }
}

// in paper nu
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash)]
pub struct NodeAddressBytes([u8; NODE_ADDRESS_LENGTH]);

impl NodeAddressBytes {
    pub fn to_base58_string(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    pub fn try_from_base58_string<S: Into<String>>(val: S) -> Result<Self> {
        let decoded = match bs58::decode(val.into()).into_vec() {
            Ok(decoded) => decoded,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::InvalidRouting,
                    format!("failed to decode node address from b58 string: {:?}", e),
                ))
            }
        };

        if decoded.len() != NODE_ADDRESS_LENGTH {
            return Err(Error::new(
                ErrorKind::InvalidRouting,
                "decoded node address has invalid length",
            ));
        }

        let mut address_bytes = [0; NODE_ADDRESS_LENGTH];
        address_bytes.copy_from_slice(&decoded[..]);

        Ok(NodeAddressBytes(address_bytes))
    }

    pub fn try_from_byte_slice(b: &[u8]) -> Result<Self> {
        if b.len() != NODE_ADDRESS_LENGTH {
            return Err(Error::new(
                ErrorKind::InvalidRouting,
                "received bytes got invalid length",
            ));
        }

        let mut address_bytes = [0; NODE_ADDRESS_LENGTH];
        address_bytes.copy_from_slice(&b);

        Ok(NodeAddressBytes(address_bytes))
    }

    pub fn from_bytes(b: [u8; NODE_ADDRESS_LENGTH]) -> Self {
        NodeAddressBytes(b)
    }

    /// View this `NodeAddressBytes` as an array of bytes.
    pub fn as_bytes(&self) -> &[u8; NODE_ADDRESS_LENGTH] {
        &self.0
    }

    /// Convert this `NodeAddressBytes` to an array of bytes.
    pub fn to_bytes(&self) -> [u8; NODE_ADDRESS_LENGTH] {
        self.0
    }
}

impl Display for NodeAddressBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "NodeAddressBytes: {}", self.to_base58_string())
    }
}

// in paper I
pub type SURBIdentifier = [u8; IDENTIFIER_LENGTH];

#[derive(Clone, Debug, PartialEq)]
pub struct Destination {
    // address in theory could be changed to a vec<u8> as it does not need to be strictly DESTINATION_ADDRESS_LENGTH long
    // but cannot be longer than that (assuming longest possible route)
    pub address: DestinationAddressBytes,
    pub identifier: SURBIdentifier,
}

impl Destination {
    pub fn new(address: DestinationAddressBytes, identifier: SURBIdentifier) -> Self {
        Self {
            address,
            identifier,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    pub address: NodeAddressBytes,
    pub pub_key: crypto::PublicKey,
}

impl Node {
    pub fn new(address: NodeAddressBytes, pub_key: crypto::PublicKey) -> Self {
        Self { address, pub_key }
    }
}

#[cfg(test)]
mod address_encoding {
    use super::*;

    #[test]
    fn it_is_possible_to_encode_and_decode_address() {
        let dummy_address = NodeAddressBytes([42u8; 32]);
        let dummy_address_str = dummy_address.to_base58_string();
        let recovered = NodeAddressBytes::try_from_base58_string(dummy_address_str).unwrap();
        assert_eq!(dummy_address, recovered)
    }
}
