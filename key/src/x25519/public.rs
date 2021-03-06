// Copyright 2020 Kodebox, Inc.
// This file is part of CodeChain.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use primitives::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sodiumoxide::crypto::kx::gen_keypair;
use sodiumoxide::crypto::scalarmult::{GroupElement, GROUPELEMENTBYTES};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Public(pub(crate) GroupElement);

impl Public {
    // This function is only for tests
    pub fn random() -> Self {
        let (publ, _) = gen_keypair();
        GroupElement::from_slice(publ.as_ref()).unwrap().into()
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        GroupElement::from_slice(slice).map(Self)
    }
}

impl From<GroupElement> for Public {
    fn from(k: GroupElement) -> Self {
        Public(k)
    }
}

impl AsRef<[u8]> for Public {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Encodable for Public {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append_single_value(&self.0.as_ref());
    }
}

impl Decodable for Public {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        let vec: Vec<u8> = rlp.as_val()?;
        let length = vec.len();
        if length == GROUPELEMENTBYTES {
            let mut array = [0; GROUPELEMENTBYTES];
            array.copy_from_slice(&vec[..GROUPELEMENTBYTES]);
            Ok(Public(GroupElement(array)))
        } else {
            Err(DecoderError::RlpInvalidLength {
                expected: GROUPELEMENTBYTES,
                got: length,
            })
        }
    }
}

impl Serialize for Public {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        let h256_pubkey = H256::from_slice(self.as_ref());
        h256_pubkey.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Public {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>, {
        let h256_pubkey = H256::deserialize(deserializer)?;
        Ok(Self::from_slice(h256_pubkey.as_ref()).expect("Bytes length was verified"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rlp::rlp_encode_and_decode_test;

    #[test]
    fn public_key_rlp() {
        rlp_encode_and_decode_test!(Public::from_slice(&[1; GROUPELEMENTBYTES]));
    }
}
