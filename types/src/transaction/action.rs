// Copyright 2018-2020 Kodebox, Inc.
// This file is part of CodeChain.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::errors::SyntaxError;
use crate::transaction::{Approval, ShardTransaction, Validator};
use crate::{BlockNumber, CommonParams, ShardId};
use ccrypto::Blake;
use ckey::{verify, Address, NetworkId};
use primitives::{Bytes, H256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

#[derive(Clone, Copy)]
#[repr(u8)]
enum ActionTag {
    Pay = 0x02,
    ShardStore = 0x19,
    TransferCCS = 0x21,
    DelegateCCS = 0x22,
    Revoke = 0x23,
    SelfNominate = 0x24,
    ReportDoubleVote = 0x25,
    Redelegate = 0x26,
    UpdateValidators = 0x30,
    CloseTerm = 0x31,
    ReleaseJailed = 0x32,
    Jail = 0x33,
    IncreaseTermId = 0x34,
    ChangeNextValidators = 0x35,
    UpdateTermParams = 0x36,
    ChangeParams = 0xFF,
}

impl Encodable for ActionTag {
    fn rlp_append(&self, s: &mut RlpStream) {
        (*self as u8).rlp_append(s)
    }
}

impl Decodable for ActionTag {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let tag = rlp.as_val()?;
        match tag {
            0x02u8 => Ok(Self::Pay),
            0x19 => Ok(Self::ShardStore),
            0x21 => Ok(Self::TransferCCS),
            0x22 => Ok(Self::DelegateCCS),
            0x23 => Ok(Self::Revoke),
            0x24 => Ok(Self::SelfNominate),
            0x25 => Ok(Self::ReportDoubleVote),
            0x26 => Ok(Self::Redelegate),
            0x30 => Ok(Self::UpdateValidators),
            0x31 => Ok(Self::CloseTerm),
            0x32 => Ok(Self::ReleaseJailed),
            0x33 => Ok(Self::Jail),
            0x34 => Ok(Self::IncreaseTermId),
            0x35 => Ok(Self::ChangeNextValidators),
            0x36 => Ok(Self::UpdateTermParams),
            0xFF => Ok(Self::ChangeParams),
            _ => Err(DecoderError::Custom("Unexpected action prefix")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Pay {
        receiver: Address,
        /// Transferred quantity.
        quantity: u64,
    },
    ShardStore {
        network_id: NetworkId,
        shard_id: ShardId,
        content: String,
    },
    TransferCCS {
        address: Address,
        quantity: u64,
    },
    DelegateCCS {
        address: Address,
        quantity: u64,
    },
    Revoke {
        address: Address,
        quantity: u64,
    },
    Redelegate {
        prev_delegatee: Address,
        next_delegatee: Address,
        quantity: u64,
    },
    SelfNominate {
        deposit: u64,
        metadata: Bytes,
    },
    ChangeParams {
        metadata_seq: u64,
        params: Box<CommonParams>,
        approvals: Vec<Approval>,
    },
    ReportDoubleVote {
        message1: Bytes,
        message2: Bytes,
    },
    UpdateValidators {
        block_number: BlockNumber,
        validators: Vec<Validator>,
    },
    CloseTerm {
        block_number: BlockNumber,
        inactive_validators: Vec<Address>,
    },
    ReleaseJailed {
        block_number: BlockNumber,
        released_addresses: Vec<Address>,
    },
    Jail {
        block_number: BlockNumber,
        prisoners: Vec<Address>,
        custody_until: u64,
        kick_at: u64,
    },
    IncreaseTermId {
        block_number: BlockNumber,
    },
    ChangeNextValidators {
        block_number: BlockNumber,
        validators: Vec<Validator>,
    },
    UpdateTermParams {
        block_number: BlockNumber,
    },
}

impl Action {
    pub fn hash(&self) -> H256 {
        let rlp = self.rlp_bytes();
        Blake::blake(rlp)
    }

    pub fn shard_transaction(&self) -> Option<ShardTransaction> {
        match self {
            Action::ShardStore {
                ..
            } => self.clone().into(),
            _ => None,
        }
    }

    pub fn verify(&self) -> Result<(), SyntaxError> {
        Ok(())
    }

    pub fn verify_with_params(&self, common_params: &CommonParams) -> Result<(), SyntaxError> {
        if let Some(network_id) = self.network_id() {
            let system_network_id = common_params.network_id();
            if network_id != system_network_id {
                return Err(SyntaxError::InvalidNetworkId(network_id))
            }
        }

        match self {
            Action::TransferCCS {
                ..
            } => {}
            Action::DelegateCCS {
                ..
            } => {}
            Action::Revoke {
                ..
            } => {}
            Action::Redelegate {
                ..
            } => {}
            Action::SelfNominate {
                metadata,
                ..
            } => {
                if metadata.len() > common_params.max_candidate_metadata_size() {
                    return Err(SyntaxError::InvalidCustomAction(format!(
                        "Too long candidate metadata: the size limit is {}",
                        common_params.max_candidate_metadata_size()
                    )))
                }
            }
            Action::ChangeParams {
                metadata_seq,
                params,
                approvals,
            } => {
                params.verify_change(common_params).map_err(SyntaxError::InvalidCustomAction)?;
                let action = Action::ChangeParams {
                    metadata_seq: *metadata_seq,
                    params: params.clone(),
                    approvals: vec![],
                };
                let encoded_action = H256::blake(rlp::encode(&action));
                for approval in approvals {
                    if !verify(approval.signature(), &encoded_action, approval.signer_public()) {
                        return Err(SyntaxError::InvalidCustomAction(format!(
                            "Cannot decode the signature {:?} with public {:?} and the message {:?}",
                            approval.signature(),
                            approval.signer_public(),
                            &encoded_action,
                        )))
                    }
                }
            }
            Action::ReportDoubleVote {
                message1,
                message2,
            } => {
                if message1 == message2 {
                    return Err(SyntaxError::InvalidCustomAction(String::from("Messages are duplicated")))
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn network_id(&self) -> Option<NetworkId> {
        match self {
            Action::ShardStore {
                network_id,
                ..
            } => Some(*network_id),
            _ => None,
        }
    }
}

impl From<Action> for Option<ShardTransaction> {
    fn from(action: Action) -> Self {
        match action {
            Action::ShardStore {
                network_id,
                shard_id,
                content,
            } => Some(ShardTransaction::ShardStore {
                network_id,
                shard_id,
                content,
            }),
            _ => None,
        }
    }
}

impl Encodable for Action {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            Action::Pay {
                receiver,
                quantity,
            } => {
                s.begin_list(3);
                s.append(&ActionTag::Pay);
                s.append(receiver);
                s.append(quantity);
            }
            Action::ShardStore {
                shard_id,
                content,
                network_id,
            } => {
                s.begin_list(4);
                s.append(&ActionTag::ShardStore);
                s.append(network_id);
                s.append(shard_id);
                s.append(content);
            }
            Action::TransferCCS {
                address,
                quantity,
            } => {
                s.begin_list(3).append(&ActionTag::TransferCCS).append(address).append(quantity);
            }
            Action::DelegateCCS {
                address,
                quantity,
            } => {
                s.begin_list(3).append(&ActionTag::DelegateCCS).append(address).append(quantity);
            }
            Action::Revoke {
                address,
                quantity,
            } => {
                s.begin_list(3).append(&ActionTag::Revoke).append(address).append(quantity);
            }
            Action::Redelegate {
                prev_delegatee,
                next_delegatee,
                quantity,
            } => {
                s.begin_list(4)
                    .append(&ActionTag::Redelegate)
                    .append(prev_delegatee)
                    .append(next_delegatee)
                    .append(quantity);
            }
            Action::SelfNominate {
                deposit,
                metadata,
            } => {
                s.begin_list(3).append(&ActionTag::SelfNominate).append(deposit).append(metadata);
            }
            Action::ChangeParams {
                metadata_seq,
                params,
                approvals,
            } => {
                s.begin_list(3 + approvals.len())
                    .append(&ActionTag::ChangeParams)
                    .append(metadata_seq)
                    .append(&**params);
                for approval in approvals {
                    s.append(approval);
                }
            }
            Action::ReportDoubleVote {
                message1,
                message2,
            } => {
                s.begin_list(3).append(&ActionTag::ReportDoubleVote).append(message1).append(message2);
            }
            Action::UpdateValidators {
                block_number,
                validators,
            } => {
                let s = s.begin_list(validators.len() + 2).append(&ActionTag::UpdateValidators).append(block_number);
                for validator in validators {
                    s.append(validator);
                }
            }
            Action::CloseTerm {
                block_number,
                inactive_validators,
            } => {
                s.begin_list(inactive_validators.len() + 2).append(&ActionTag::CloseTerm).append(block_number);
                for validator in inactive_validators {
                    s.append(validator);
                }
            }
            Action::ReleaseJailed {
                block_number,
                released_addresses,
            } => {
                s.begin_list(2 + released_addresses.len()).append(&ActionTag::ReleaseJailed).append(block_number);
                for address in released_addresses {
                    s.append(address);
                }
            }
            Action::Jail {
                block_number,
                prisoners,
                custody_until,
                kick_at,
            } => {
                s.begin_list(4 + prisoners.len())
                    .append(&ActionTag::Jail)
                    .append(block_number)
                    .append(custody_until)
                    .append(kick_at);
                for validator in prisoners {
                    s.append(validator);
                }
            }
            Action::IncreaseTermId {
                block_number,
            } => {
                s.begin_list(2).append(&ActionTag::IncreaseTermId).append(block_number);
            }
            Action::ChangeNextValidators {
                block_number,
                validators,
            } => {
                s.begin_list(2 + validators.len()).append(&ActionTag::ChangeNextValidators).append(block_number);
                for validator in validators {
                    s.append(validator);
                }
            }
            Action::UpdateTermParams {
                block_number,
            } => {
                s.begin_list(2).append(&ActionTag::UpdateTermParams).append(block_number);
            }
        }
    }
}

impl Decodable for Action {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        match rlp.val_at(0)? {
            ActionTag::Pay => {
                let item_count = rlp.item_count()?;
                if item_count != 3 {
                    return Err(DecoderError::RlpIncorrectListLen {
                        got: item_count,
                        expected: 3,
                    })
                }
                Ok(Action::Pay {
                    receiver: rlp.val_at(1)?,
                    quantity: rlp.val_at(2)?,
                })
            }
            ActionTag::ShardStore => {
                let item_count = rlp.item_count()?;
                if item_count != 4 {
                    return Err(DecoderError::RlpIncorrectListLen {
                        got: item_count,
                        expected: 4,
                    })
                }
                Ok(Action::ShardStore {
                    network_id: rlp.val_at(1)?,
                    shard_id: rlp.val_at(2)?,
                    content: rlp.val_at(3)?,
                })
            }
            ActionTag::TransferCCS => {
                let item_count = rlp.item_count()?;
                if item_count != 3 {
                    return Err(DecoderError::RlpInvalidLength {
                        expected: 3,
                        got: item_count,
                    })
                }
                Ok(Action::TransferCCS {
                    address: rlp.val_at(1)?,
                    quantity: rlp.val_at(2)?,
                })
            }
            ActionTag::DelegateCCS => {
                let item_count = rlp.item_count()?;
                if item_count != 3 {
                    return Err(DecoderError::RlpInvalidLength {
                        expected: 3,
                        got: item_count,
                    })
                }
                Ok(Action::DelegateCCS {
                    address: rlp.val_at(1)?,
                    quantity: rlp.val_at(2)?,
                })
            }
            ActionTag::Revoke => {
                let item_count = rlp.item_count()?;
                if item_count != 3 {
                    return Err(DecoderError::RlpInvalidLength {
                        expected: 3,
                        got: item_count,
                    })
                }
                Ok(Action::Revoke {
                    address: rlp.val_at(1)?,
                    quantity: rlp.val_at(2)?,
                })
            }
            ActionTag::Redelegate => {
                let item_count = rlp.item_count()?;
                if item_count != 4 {
                    return Err(DecoderError::RlpInvalidLength {
                        expected: 4,
                        got: item_count,
                    })
                }
                Ok(Action::Redelegate {
                    prev_delegatee: rlp.val_at(1)?,
                    next_delegatee: rlp.val_at(2)?,
                    quantity: rlp.val_at(3)?,
                })
            }
            ActionTag::SelfNominate => {
                let item_count = rlp.item_count()?;
                if item_count != 3 {
                    return Err(DecoderError::RlpInvalidLength {
                        expected: 3,
                        got: item_count,
                    })
                }
                Ok(Action::SelfNominate {
                    deposit: rlp.val_at(1)?,
                    metadata: rlp.val_at(2)?,
                })
            }
            ActionTag::ChangeParams => {
                let item_count = rlp.item_count()?;
                if item_count < 4 {
                    return Err(DecoderError::RlpIncorrectListLen {
                        expected: 4,
                        got: item_count,
                    })
                }
                let metadata_seq = rlp.val_at(1)?;
                let params = Box::new(rlp.val_at(2)?);
                let approvals = (3..item_count).map(|i| rlp.val_at(i)).collect::<Result<_, _>>()?;
                Ok(Action::ChangeParams {
                    metadata_seq,
                    params,
                    approvals,
                })
            }
            ActionTag::ReportDoubleVote => {
                let item_count = rlp.item_count()?;
                if item_count != 3 {
                    return Err(DecoderError::RlpIncorrectListLen {
                        expected: 3,
                        got: item_count,
                    })
                }
                let message1 = rlp.val_at(1)?;
                let message2 = rlp.val_at(2)?;
                Ok(Action::ReportDoubleVote {
                    message1,
                    message2,
                })
            }
            ActionTag::UpdateValidators => {
                let item_count = rlp.item_count()?;
                if item_count < 2 {
                    return Err(DecoderError::RlpIncorrectListLen {
                        expected: 2,
                        got: item_count,
                    })
                }
                let block_number = rlp.val_at(1)?;
                let validators = rlp.iter().skip(2).map(|rlp| rlp.as_val()).collect::<Result<_, _>>()?;
                Ok(Action::UpdateValidators {
                    block_number,
                    validators,
                })
            }
            ActionTag::CloseTerm => {
                let item_count = rlp.item_count()?;
                if item_count < 2 {
                    return Err(DecoderError::RlpIncorrectListLen {
                        expected: 2,
                        got: item_count,
                    })
                }
                let block_number = rlp.val_at(1)?;
                let inactive_validators = rlp.iter().skip(2).map(|rlp| rlp.as_val()).collect::<Result<_, _>>()?;
                Ok(Action::CloseTerm {
                    block_number,
                    inactive_validators,
                })
            }
            ActionTag::ReleaseJailed => {
                let item_count = rlp.item_count()?;
                if item_count < 2 {
                    return Err(DecoderError::RlpIncorrectListLen {
                        expected: 2,
                        got: item_count,
                    })
                }
                let block_number = rlp.val_at(1)?;
                let released_addresses = rlp.iter().skip(2).map(|rlp| rlp.as_val()).collect::<Result<_, _>>()?;
                Ok(Action::ReleaseJailed {
                    block_number,
                    released_addresses,
                })
            }
            ActionTag::Jail => {
                let item_count = rlp.item_count()?;
                if item_count < 4 {
                    return Err(DecoderError::RlpIncorrectListLen {
                        expected: 4,
                        got: item_count,
                    })
                }
                let block_number = rlp.val_at(1)?;
                let custody_until = rlp.val_at(2)?;
                let kick_at = rlp.val_at(3)?;
                let prisoners = rlp.iter().skip(4).map(|rlp| rlp.as_val()).collect::<Result<_, _>>()?;
                Ok(Action::Jail {
                    block_number,
                    prisoners,
                    custody_until,
                    kick_at,
                })
            }
            ActionTag::IncreaseTermId => {
                let item_count = rlp.item_count()?;
                if item_count != 2 {
                    return Err(DecoderError::RlpIncorrectListLen {
                        expected: 2,
                        got: item_count,
                    })
                }
                let block_number = rlp.val_at(1)?;
                Ok(Action::IncreaseTermId {
                    block_number,
                })
            }
            ActionTag::ChangeNextValidators => {
                let item_count = rlp.item_count()?;
                if item_count < 2 {
                    return Err(DecoderError::RlpIncorrectListLen {
                        expected: 2,
                        got: item_count,
                    })
                }
                let block_number = rlp.val_at(1)?;
                let validators = rlp.iter().skip(2).map(|rlp| rlp.as_val()).collect::<Result<_, _>>()?;
                Ok(Action::ChangeNextValidators {
                    block_number,
                    validators,
                })
            }
            ActionTag::UpdateTermParams => {
                let item_count = rlp.item_count()?;
                if item_count != 2 {
                    return Err(DecoderError::RlpIncorrectListLen {
                        expected: 2,
                        got: item_count,
                    })
                }
                let block_number = rlp.val_at(1)?;
                Ok(Action::UpdateTermParams {
                    block_number,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ckey::{Ed25519Public as Public, Signature};
    use rlp::rlp_encode_and_decode_test;

    #[test]
    fn encode_and_decode_pay_action() {
        rlp_encode_and_decode_test!(Action::Pay {
            receiver: Address::random(),
            quantity: 300,
        });
    }

    #[test]
    fn rlp_of_change_params() {
        rlp_encode_and_decode_test!(Action::ChangeParams {
            metadata_seq: 3,
            params: CommonParams::default_for_test().into(),
            approvals: vec![
                Approval::new(Signature::random(), Public::random()),
                Approval::new(Signature::random(), Public::random()),
            ],
        });
    }

    #[test]
    fn rlp_of_update_validators() {
        rlp_encode_and_decode_test!(Action::UpdateValidators {
            block_number: 100,
            validators: vec![Validator::new(1, 2, Public::random()), Validator::new(3, 4, Public::random())],
        });
    }

    #[test]
    fn rlp_of_close_term() {
        rlp_encode_and_decode_test!(Action::CloseTerm {
            block_number: 37,
            inactive_validators: vec![],
        });
    }

    #[test]
    fn rlp_of_release_jailed() {
        rlp_encode_and_decode_test!(Action::ReleaseJailed {
            block_number: 37,
            released_addresses: vec![],
        });
    }

    #[test]
    fn rlp_of_jail() {
        rlp_encode_and_decode_test!(Action::Jail {
            block_number: 42,
            prisoners: vec![],
            custody_until: 17,
            kick_at: 31,
        });
    }

    #[test]
    fn rlp_of_increase_term_id() {
        rlp_encode_and_decode_test!(Action::IncreaseTermId {
            block_number: 39,
        });
    }

    #[test]
    fn rlp_of_change_next_validators() {
        rlp_encode_and_decode_test!(Action::ChangeNextValidators {
            block_number: 47,
            validators: vec![],
        });
    }

    #[test]
    fn rlp_of_update_term_params() {
        rlp_encode_and_decode_test!(Action::UpdateTermParams {
            block_number: 39,
        });
    }

    #[test]
    fn decode_fail_if_change_params_have_no_signatures() {
        let action = Action::ChangeParams {
            metadata_seq: 3,
            params: CommonParams::default_for_test().into(),
            approvals: vec![],
        };
        assert_eq!(
            Err(DecoderError::RlpIncorrectListLen {
                expected: 4,
                got: 3,
            }),
            Rlp::new(&rlp::encode(&action)).as_val::<Action>()
        );
    }
}
