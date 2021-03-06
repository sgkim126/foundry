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

use super::{ConsensusMessage, VoteStep};
use crate::consensus::BitSet;
use ckey::Signature;
use ctypes::transaction::Action;
use ctypes::BlockHash;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::collections::{BTreeMap, HashMap};
use std::iter::Iterator;

/// Storing all Proposals, Prevotes and Precommits.
#[derive(Debug)]
pub struct VoteCollector {
    votes: BTreeMap<VoteStep, StepCollector>,
}

#[derive(Debug, Default)]
struct StepCollector {
    voted: HashMap<usize, ConsensusMessage>,
    block_votes: HashMap<Option<BlockHash>, BTreeMap<usize, Signature>>,
    messages: Vec<ConsensusMessage>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct DoubleVote {
    author_index: usize,
    vote_one: ConsensusMessage,
    vote_two: ConsensusMessage,
}

impl DoubleVote {
    pub fn to_action(&self) -> Action {
        Action::ReportDoubleVote {
            message1: self.vote_one.rlp_bytes(),
            message2: self.vote_two.rlp_bytes(),
        }
    }
}

impl Encodable for DoubleVote {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2).append(&self.vote_one).append(&self.vote_two);
    }
}

impl Decodable for DoubleVote {
    fn decode(_rlp: &Rlp) -> Result<Self, DecoderError> {
        todo!()
    }
}

impl StepCollector {
    /// Some(true): a message is new
    /// Some(false): a message is duplicated
    /// Err(DoubleVote): a double vote
    fn insert(&mut self, message: ConsensusMessage) -> Result<bool, DoubleVote> {
        // Do nothing when message was seen.
        if self.messages.contains(&message) {
            return Ok(false)
        }
        self.messages.push(message.clone());
        if let Some(previous) = self.voted.insert(message.signer_index(), message.clone()) {
            // Bad validator sent a different message.
            Err(DoubleVote {
                author_index: message.signer_index(),
                vote_one: previous,
                vote_two: message,
            })
        } else {
            self.block_votes
                .entry(message.block_hash())
                .or_default()
                .insert(message.signer_index(), message.signature());
            Ok(true)
        }
    }

    /// Count all votes for the given block hash at this round.
    fn count_block(&self, block_hash: &Option<BlockHash>) -> BitSet {
        let mut result = BitSet::new();
        if let Some(votes) = self.block_votes.get(block_hash) {
            for index in votes.keys() {
                result.set(*index);
            }
        }
        result
    }

    /// Count all votes collected for the given round.
    fn count(&self) -> BitSet {
        let mut result = BitSet::new();
        for votes in self.block_votes.values() {
            for index in votes.keys() {
                assert!(!result.is_set(*index), "Cannot vote twice in a round");
                result.set(*index);
            }
        }
        result
    }
}

impl Default for VoteCollector {
    fn default() -> Self {
        let mut collector = BTreeMap::new();
        // Insert dummy entry to fulfill invariant: "only messages newer than the oldest are inserted".
        collector.insert(Default::default(), Default::default());
        VoteCollector {
            votes: collector,
        }
    }
}

impl VoteCollector {
    /// Insert vote if it is newer than the oldest one.
    pub fn collect(&mut self, message: ConsensusMessage) -> Result<bool, DoubleVote> {
        self.votes.entry(*message.round()).or_insert_with(Default::default).insert(message)
    }

    /// Checks if the message should be ignored.
    pub fn is_old_or_known(&self, message: &ConsensusMessage) -> bool {
        let is_known = self.votes.get(&message.round()).map_or(false, |c| c.messages.contains(message));
        if is_known {
            cdebug!(ENGINE, "Known message: {:?}.", message);
            return true
        }

        // The reason not using `message.round() <= oldest` is to allow precommit messages on Commit step.
        let is_old = self.votes.keys().next().map_or(true, |oldest| message.round() < oldest);
        if is_old {
            cdebug!(ENGINE, "Old message {:?}.", message);
            return true
        }

        false
    }

    /// Throws out messages older than message, leaves message as marker for the oldest.
    pub fn throw_out_old(&mut self, vote_round: &VoteStep) {
        let new_collector = self.votes.split_off(vote_round);
        assert!(!new_collector.is_empty());
        self.votes = new_collector;
    }

    /// Collects the signatures and the indices for the given round and hash.
    /// Returning indices is in ascending order, and signature and indices are matched with another.
    pub fn round_signatures_and_indices(
        &self,
        round: &VoteStep,
        block_hash: &BlockHash,
    ) -> (Vec<Signature>, Vec<usize>) {
        self.votes
            .get(round)
            .and_then(|c| c.block_votes.get(&Some(*block_hash)))
            .map(|votes| {
                let (indices, sigs) = votes.iter().unzip();
                (sigs, indices)
            })
            .unwrap_or_default()
    }

    /// Returns the first signature and the index of its signer for a given round and hash if exists.
    pub fn round_signature(&self, round: &VoteStep, block_hash: &BlockHash) -> Option<Signature> {
        self.votes
            .get(round)
            .and_then(|c| c.block_votes.get(&Some(*block_hash)))
            .and_then(|votes| votes.values().next().cloned())
    }

    /// Count votes which agree with the given message.
    pub fn aligned_votes(&self, message: &ConsensusMessage) -> BitSet {
        if let Some(votes) = self.votes.get(&message.round()) {
            votes.count_block(&message.block_hash())
        } else {
            Default::default()
        }
    }

    pub fn block_round_votes(&self, round: &VoteStep, block_hash: &Option<BlockHash>) -> BitSet {
        if let Some(votes) = self.votes.get(round) {
            votes.count_block(block_hash)
        } else {
            Default::default()
        }
    }

    /// Count all votes collected for a given round.
    pub fn round_votes(&self, vote_round: &VoteStep) -> BitSet {
        if let Some(votes) = self.votes.get(vote_round) {
            votes.count()
        } else {
            Default::default()
        }
    }

    pub fn get_block_hashes(&self, round: &VoteStep) -> Vec<BlockHash> {
        self.votes
            .get(round)
            .map(|c| c.block_votes.keys().cloned().filter_map(|x| x).collect())
            .unwrap_or_else(Vec::new)
    }

    pub fn has_votes_for(&self, round: &VoteStep, block_hash: BlockHash) -> bool {
        let votes = self
            .votes
            .get(round)
            .map(|c| c.block_votes.keys().cloned().filter_map(|x| x).collect())
            .unwrap_or_else(Vec::new);
        votes.into_iter().any(|vote_block_hash| vote_block_hash == block_hash)
    }

    pub fn get_all(&self) -> Vec<ConsensusMessage> {
        self.votes.iter().flat_map(|(_round, collector)| collector.messages.clone()).collect()
    }

    pub fn get_all_votes_in_round(&self, round: &VoteStep) -> Vec<ConsensusMessage> {
        self.votes.get(round).map(|c| c.messages.clone()).unwrap_or_default()
    }

    pub fn get_all_votes_and_indices_in_round(&self, round: &VoteStep) -> Vec<(usize, ConsensusMessage)> {
        self.votes.get(round).map(|c| c.voted.iter().map(|(k, v)| (*k, v.clone())).collect()).unwrap_or_default()
    }
}
