// Copyright 2018-2020 Kodebox, Inc.
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

use ccore::UnverifiedTransaction;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

#[derive(Debug, PartialEq)]
pub enum Message {
    Transactions(Vec<UnverifiedTransaction>),
}

impl Encodable for Message {
    fn rlp_append(&self, s: &mut RlpStream) {
        match &self {
            Message::Transactions(transactions) => {
                let uncompressed = {
                    let mut inner_list = RlpStream::new();
                    inner_list.append_list(transactions);
                    inner_list.out()
                };

                let compressed = {
                    // TODO: Cache the Encoder object
                    let mut snappy_encoder = snap::Encoder::new();
                    snappy_encoder.compress_vec(&uncompressed).expect("Compression always succeed")
                };

                s.append(&compressed)
            }
        };
    }
}

impl Decodable for Message {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        let compressed: Vec<u8> = rlp.as_val()?;
        let uncompressed = {
            // TODO: Cache the Decoder object
            let mut snappy_decoder = snap::Decoder::new();
            snappy_decoder.decompress_vec(&compressed).map_err(|err| {
                cwarn!(SYNC_TX, "Decompression failed with decoding a transactions: {}", err);
                DecoderError::Custom("Invalid compression format")
            })?
        };

        let uncompressed_rlp = Rlp::new(&uncompressed);
        Ok(Message::Transactions(uncompressed_rlp.as_list()?))
    }
}

#[cfg(test)]
mod tests {
    use ccore::UnverifiedTransaction;
    use ckey::{Ed25519Public as Public, Signature};
    use ctypes::transaction::{Action, Transaction};

    use super::Message;

    /// For a type that does not have PartialEq, uses Debug instead.
    fn assert_eq_by_debug<T: std::fmt::Debug>(a: &T, b: &T) {
        assert_eq!(format!("{:?}", a), format!("{:?}", b));
    }

    #[test]
    fn transactions_message_rlp() {
        let message = Message::Transactions(Vec::new());
        let encoded = rlp::encode(&message);
        let decoded: Message = rlp::decode(&encoded).unwrap();
        assert_eq_by_debug(&message, &decoded);
    }

    #[test]
    fn transactions_message_rlp_with_tx() {
        let tx = UnverifiedTransaction::new(
            Transaction {
                seq: 0,
                fee: 10,
                action: Action::Pay {
                    receiver: Public::random(),
                    quantity: 30,
                },
                network_id: "tc".into(),
            },
            Signature::default(),
            Public::random(),
        );

        let message = Message::Transactions(vec![tx]);
        let encoded = rlp::encode(&message);
        let decoded: Message = rlp::decode(&encoded).unwrap();
        assert_eq_by_debug(&message, &decoded);
    }
}
