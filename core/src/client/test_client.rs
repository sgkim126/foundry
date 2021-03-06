// Copyright 2015-2017 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

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

use crate::block::{Block, ClosedBlock, OpenBlock};
use crate::blockchain_info::BlockChainInfo;
use crate::client::{
    AccountData, BlockChainClient, BlockChainTrait, BlockProducer, BlockStatus, ConsensusClient, EngineInfo,
    ImportBlock, ImportResult, MiningBlockChainClient, StateInfo, StateOrBlock, TermInfo,
};
use crate::consensus::EngineError;
use crate::db::{COL_STATE, NUM_COLUMNS};
use crate::encoded;
use crate::error::{BlockImportError, Error as GenericError};
use crate::miner::{Miner, MinerService, TransactionImportResult};
use crate::scheme::Scheme;
use crate::transaction::{LocalizedTransaction, PendingVerifiedTransactions, VerifiedTransaction};
use crate::types::{TransactionId, VerificationQueueInfo as QueueInfo};
use ccrypto::BLAKE_NULL_RLP;
use ckey::{
    Ed25519KeyPair as KeyPair, Ed25519Private as Private, Ed25519Public as Public, Generator, KeyPairTrait, NetworkId,
    PlatformAddress, Random,
};
use cstate::tests::helpers::empty_top_state_with_metadata;
use cstate::{FindDoubleVoteHandler, NextValidators, StateDB, TopLevelState};
use ctimer::{TimeoutHandler, TimerToken};
use ctypes::transaction::{Action, Transaction, Validator};
use ctypes::Header;
use ctypes::{BlockHash, BlockId, BlockNumber, CommonParams, Header as BlockHeader, SyncHeader, TxHash};
use kvdb::KeyValueDB;
use merkle_trie::skewed_merkle_root;
use parking_lot::RwLock;
use primitives::{u256_from_u128, BigEndianHash, Bytes, H256};
use rlp::{Encodable, Rlp, RlpStream};
use std::collections::HashMap;
use std::mem;
use std::ops::Range;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrder};
use std::sync::Arc;

/// Test client.
pub struct TestBlockChainClient {
    /// Blocks.
    pub blocks: RwLock<HashMap<BlockHash, Bytes>>,
    /// Mapping of numbers to hashes.
    pub numbers: RwLock<HashMap<usize, BlockHash>>,
    /// Genesis block hash.
    pub genesis_hash: BlockHash,
    /// Last block hash.
    pub last_hash: RwLock<BlockHash>,
    /// Extra data do set for each block
    pub extra_data: Bytes,
    /// Balances.
    pub balances: RwLock<HashMap<Public, u64>>,
    /// Seqs.
    pub seqs: RwLock<HashMap<Public, u64>>,
    /// Storage.
    pub storage: RwLock<HashMap<(Public, H256), H256>>,
    /// Block queue size.
    pub queue_size: AtomicUsize,
    /// Miner
    pub miner: Arc<Miner>,
    /// Scheme
    pub scheme: Scheme,
    /// Timestamp assigned to latest closed block
    pub latest_block_timestamp: RwLock<u64>,
    /// Pruning history size to report.
    pub history: RwLock<Option<u64>>,
    /// Term ID
    pub term_id: Option<u64>,
    /// Fixed validator keys
    pub validator_keys: RwLock<HashMap<Public, Private>>,
    /// Fixed validators
    pub validators: NextValidators,
}

impl Default for TestBlockChainClient {
    fn default() -> Self {
        TestBlockChainClient::new()
    }
}

impl TestBlockChainClient {
    /// Creates new test client.
    pub fn new() -> Self {
        Self::new_with_extra_data(Bytes::new())
    }

    /// Creates new test client with specified extra data for each block
    pub fn new_with_extra_data(extra_data: Bytes) -> Self {
        let db = Arc::new(kvdb_memorydb::create(NUM_COLUMNS.unwrap()));
        let scheme = Scheme::new_test();
        TestBlockChainClient::new_with_scheme_and_extra(scheme, extra_data, db)
    }

    /// Create test client with custom scheme.
    pub fn new_with_scheme(scheme: Scheme) -> Self {
        let db = Arc::new(kvdb_memorydb::create(NUM_COLUMNS.unwrap()));
        TestBlockChainClient::new_with_scheme_and_extra(scheme, Bytes::new(), db)
    }

    /// Create test client with custom scheme and extra data.
    pub fn new_with_scheme_and_extra(scheme: Scheme, extra_data: Bytes, db: Arc<dyn KeyValueDB>) -> Self {
        let genesis_block = scheme.genesis_block();
        let genesis_header = scheme.genesis_header();
        let genesis_hash = genesis_header.hash();

        let mut client = TestBlockChainClient {
            blocks: RwLock::new(HashMap::new()),
            numbers: RwLock::new(HashMap::new()),
            genesis_hash,
            extra_data,
            last_hash: RwLock::new(genesis_hash),
            balances: RwLock::new(HashMap::new()),
            seqs: RwLock::new(HashMap::new()),
            storage: RwLock::new(HashMap::new()),
            queue_size: AtomicUsize::new(0),
            miner: Arc::new(Miner::with_scheme_for_test(&scheme, db)),
            scheme,
            latest_block_timestamp: RwLock::new(10_000_000),
            history: RwLock::new(None),
            term_id: Some(1),
            validator_keys: RwLock::new(HashMap::new()),
            validators: vec![].into(),
        };

        // insert genesis hash.
        client.blocks.get_mut().insert(genesis_hash, genesis_block);
        client.numbers.get_mut().insert(0, genesis_hash);
        client
    }

    /// Set the balance of account `address` to `balance`.
    pub fn set_balance(&self, pubkey: Public, balance: u64) {
        self.balances.write().insert(pubkey, balance);
    }

    /// Set seq of account `address` to `seq`.
    pub fn set_seq(&self, pubkey: Public, seq: u64) {
        self.seqs.write().insert(pubkey, seq);
    }

    /// Set storage `position` to `value` for account `address`.
    pub fn set_storage(&self, pubkey: Public, position: H256, value: H256) {
        self.storage.write().insert((pubkey, position), value);
    }

    /// Set block queue size for testing
    pub fn set_queue_size(&self, size: usize) {
        self.queue_size.store(size, AtomicOrder::Relaxed);
    }

    /// Set timestamp assigned to latest closed block
    pub fn set_latest_block_timestamp(&self, ts: u64) {
        *self.latest_block_timestamp.write() = ts;
    }

    /// Add blocks to test client.
    pub fn add_blocks(&self, count: usize, transaction_length: usize) {
        let len = self.numbers.read().len();
        for n in len..(len + count) {
            self.add_block_with_author(None, n, transaction_length);
        }
    }
    /// Add a block to test client with designated author.
    pub fn add_block_with_author(&self, author: Option<Public>, n: usize, transaction_length: usize) -> BlockHash {
        let mut header = BlockHeader::new();
        header.set_parent_hash(*self.last_hash.read());
        header.set_number(n as BlockNumber);
        header.set_extra_data(self.extra_data.clone());
        if let Some(addr) = author {
            header.set_author(addr);
        }
        let mut transactions = Vec::with_capacity(transaction_length);
        for _ in 0..transaction_length {
            let keypair: KeyPair = Random.generate().unwrap();
            // Update seqs value
            self.seqs.write().insert(*keypair.public(), 0);
            let tx = Transaction {
                seq: 0,
                fee: 10,
                network_id: NetworkId::default(),
                action: Action::Pay {
                    receiver: Public::random(),
                    quantity: 0,
                },
            };
            let signed = VerifiedTransaction::new_with_sign(tx, keypair.private());
            transactions.push(signed);
        }
        header.set_transactions_root(skewed_merkle_root(BLAKE_NULL_RLP, transactions.iter().map(Encodable::rlp_bytes)));
        let mut rlp = RlpStream::new_list(3);
        rlp.append(&header);
        rlp.append_raw(&RlpStream::new_list(0).out(), 1); // evidences
        rlp.append_list(&transactions);
        self.import_block(rlp.as_raw().to_vec()).unwrap()
    }

    /// Make a bad block by setting invalid extra data.
    pub fn corrupt_block(&self, n: BlockNumber) {
        let block_id = n.into();
        let hash = self.block_hash(&block_id).unwrap();
        let mut header: BlockHeader = self.block_header(&block_id).unwrap().decode();
        header.set_extra_data(b"This extra data is way too long to be considered valid".to_vec());
        let mut rlp = RlpStream::new_list(3);
        rlp.append(&header);
        rlp.append_raw(&::rlp::NULL_RLP, 1);
        rlp.append_raw(&::rlp::NULL_RLP, 1);
        self.blocks.write().insert(hash, rlp.out());
    }

    /// Make a bad block by setting invalid parent hash.
    pub fn corrupt_block_parent(&self, n: BlockNumber) {
        let block_id = n.into();
        let hash = self.block_hash(&block_id).unwrap();
        let mut header: BlockHeader = self.block_header(&block_id).unwrap().decode();
        header.set_parent_hash(H256::from_uint(&u256_from_u128(42u128)).into());
        let mut rlp = RlpStream::new_list(3);
        rlp.append(&header);
        rlp.append_raw(&::rlp::NULL_RLP, 1);
        rlp.append_raw(&::rlp::NULL_RLP, 1);
        self.blocks.write().insert(hash, rlp.out());
    }

    /// TODO:
    pub fn block_hash_delta_minus(&mut self, delta: usize) -> BlockHash {
        let blocks_read = self.numbers.read();
        let index = blocks_read.len() - delta;
        blocks_read[&index]
    }

    fn block_hash(&self, id: &BlockId) -> Option<BlockHash> {
        match id {
            BlockId::Hash(hash) => Some(*hash),
            BlockId::Number(n) => self.numbers.read().get(&(*n as usize)).cloned(),
            BlockId::Earliest => self.numbers.read().get(&0).cloned(),
            BlockId::Latest => self.numbers.read().get(&(self.numbers.read().len() - 1)).cloned(),
            BlockId::ParentOfLatest => {
                let numbers = self.numbers.read();
                let len = numbers.len();
                if len < 2 {
                    None
                } else {
                    self.numbers.read().get(&(len - 2)).cloned()
                }
            }
        }
    }

    /// Inserts a transaction to miners mem pool.
    pub fn insert_transaction_to_pool(&self) -> TxHash {
        let keypair: KeyPair = Random.generate().unwrap();
        let tx = Transaction {
            seq: 0,
            fee: 10,
            network_id: NetworkId::default(),
            action: Action::Pay {
                receiver: Public::random(),
                quantity: 0,
            },
        };
        let signed = VerifiedTransaction::new_with_sign(tx, keypair.private());
        self.set_balance(signed.signer_public(), 10_000_000_000_000_000_000);
        let hash = signed.transaction().hash();
        let res = self.miner.import_external_transactions(self, vec![signed.into()]);
        let res = res.into_iter().next().unwrap().expect("Successful import");
        assert_eq!(res, TransactionImportResult::Current);
        hash
    }

    /// Set reported history size.
    pub fn set_history(&self, h: Option<u64>) {
        *self.history.write() = h;
    }

    /// Set validators which can be brought from state.
    pub fn set_random_validators(&mut self, count: usize) {
        let mut pubkeys: Vec<Public> = vec![];
        for _ in 0..count {
            let private = Private::random();
            let public = private.public_key();
            self.validator_keys.write().insert(public, private);
            pubkeys.push(public);
        }
        let fixed_validators: NextValidators =
            pubkeys.into_iter().map(|pubkey| Validator::new(0, 0, pubkey, 0, 0)).collect::<Vec<_>>().into();

        self.validators = fixed_validators;
    }

    pub fn get_validators(&self) -> &NextValidators {
        &self.validators
    }
}

pub fn get_temp_state_db() -> StateDB {
    let db = kvdb_memorydb::create(NUM_COLUMNS.unwrap_or(0));
    let journal_db = cdb::new_journaldb(Arc::new(db), cdb::Algorithm::Archive, COL_STATE);
    StateDB::new(journal_db)
}

impl BlockProducer for TestBlockChainClient {
    fn prepare_open_block(&self, _parent_block: BlockId, author: Public, extra_data: Bytes) -> OpenBlock {
        let engine = &*self.scheme.engine;
        let genesis_header = self.scheme.genesis_header();
        let db = get_temp_state_db();

        let mut open_block = OpenBlock::try_new(engine, db, &genesis_header, author, &[], extra_data)
            .expect("Opening block for tests will not fail.");
        // TODO [todr] Override timestamp for predictability (set_timestamp_now kind of sucks)
        open_block.set_timestamp(*self.latest_block_timestamp.read());
        open_block
    }
}

impl MiningBlockChainClient for TestBlockChainClient {}

impl AccountData for TestBlockChainClient {
    fn seq(&self, pubkey: &Public, id: BlockId) -> Option<u64> {
        match id {
            BlockId::Latest => Some(self.seqs.read().get(pubkey).cloned().unwrap_or(0)),
            BlockId::Hash(hash) if hash == *self.last_hash.read() => {
                Some(self.seqs.read().get(pubkey).cloned().unwrap_or(0))
            }
            _ => None,
        }
    }

    fn balance(&self, pubkey: &Public, state: StateOrBlock) -> Option<u64> {
        match state {
            StateOrBlock::Block(BlockId::Latest) | StateOrBlock::State(_) => {
                Some(self.balances.read().get(pubkey).cloned().unwrap_or(0))
            }
            StateOrBlock::Block(BlockId::Hash(hash)) if hash == *self.last_hash.read() => {
                Some(self.balances.read().get(pubkey).cloned().unwrap_or(0))
            }
            _ => None,
        }
    }
}

impl BlockChainTrait for TestBlockChainClient {
    fn chain_info(&self) -> BlockChainInfo {
        let number = self.blocks.read().len() as BlockNumber - 1;
        BlockChainInfo {
            genesis_hash: self.genesis_hash,
            best_block_hash: *self.last_hash.read(),
            best_proposal_block_hash: *self.last_hash.read(),
            best_block_number: number,
            best_block_timestamp: number,
        }
    }

    fn block_header(&self, id: &BlockId) -> Option<encoded::Header> {
        self.block_hash(id)
            .and_then(|hash| self.blocks.read().get(&hash).map(|r| Rlp::new(r).at(0).unwrap().as_raw().to_vec()))
            .map(encoded::Header::new)
    }

    fn best_block_header(&self) -> encoded::Header {
        self.block_header(&self.chain_info().best_block_hash.into()).expect("Best block always has header.")
    }

    fn best_header(&self) -> encoded::Header {
        unimplemented!()
    }

    fn best_proposal_header(&self) -> encoded::Header {
        unimplemented!()
    }

    fn block(&self, id: &BlockId) -> Option<encoded::Block> {
        self.block_hash(id).and_then(|hash| self.blocks.read().get(&hash).cloned()).map(encoded::Block::new)
    }

    fn transaction_block(&self, _id: &TransactionId) -> Option<BlockHash> {
        None // Simple default.
    }
}

impl ImportBlock for TestBlockChainClient {
    fn import_block(&self, b: Bytes) -> Result<BlockHash, BlockImportError> {
        let header = Rlp::new(&b).val_at::<BlockHeader>(0).unwrap();
        let h = header.hash();
        let number: usize = header.number() as usize;
        if number > self.blocks.read().len() {
            panic!("Unexpected block number. Expected {}, got {}", self.blocks.read().len(), number);
        }
        if number > 0 {
            let blocks = self.blocks.read();
            let parent = blocks
                .get(header.parent_hash())
                .unwrap_or_else(|| panic!("Unknown block parent {:?} for block {}", header.parent_hash(), number));
            let parent = Rlp::new(parent).val_at::<BlockHeader>(0).unwrap();
            assert_eq!(parent.number(), header.number() - 1, "Unexpected block parent");
        }
        let len = self.numbers.read().len();
        if number == len {
            let _ = mem::replace(&mut *self.last_hash.write(), h);
            self.blocks.write().insert(h, b);
            self.numbers.write().insert(number, h);
            let mut parent_hash = *header.parent_hash();
            if number > 0 {
                let mut n = number - 1;
                while n > 0 && self.numbers.read()[&n] != parent_hash {
                    *self.numbers.write().get_mut(&n).unwrap() = parent_hash;
                    n -= 1;
                    parent_hash =
                        *Rlp::new(&self.blocks.read()[&parent_hash]).val_at::<BlockHeader>(0).unwrap().parent_hash();
                }
            }
        } else {
            self.blocks.write().insert(h, b.to_vec());
        }
        Ok(h)
    }

    fn import_header(&self, _header: SyncHeader) -> Result<BlockHash, BlockImportError> {
        unimplemented!()
    }

    fn import_trusted_header(&self, _header: Header) -> Result<BlockHash, BlockImportError> {
        unimplemented!()
    }

    fn import_trusted_block(&self, _block: &Block) -> Result<BlockHash, BlockImportError> {
        unimplemented!()
    }

    fn force_update_best_block(&self, _hash: &BlockHash) {
        unimplemented!()
    }

    fn import_generated_block(&self, _block: &ClosedBlock) -> ImportResult {
        Ok(H256::default().into())
    }

    fn set_min_timer(&self) {}
}

impl BlockChainClient for TestBlockChainClient {
    fn queue_info(&self) -> QueueInfo {
        QueueInfo {
            verified_queue_size: self.queue_size.load(AtomicOrder::Relaxed),
            unverified_queue_size: 0,
            verifying_queue_size: 0,
            max_queue_size: 0,
            max_mem_use: 0,
            mem_used: 0,
        }
    }

    fn queue_own_transaction(&self, transaction: VerifiedTransaction) -> Result<(), GenericError> {
        self.miner.import_own_transaction(self, transaction)?;
        Ok(())
    }

    fn queue_transactions(&self, transactions: Vec<Bytes>) {
        // import right here
        let transactions = transactions.into_iter().filter_map(|bytes| Rlp::new(&bytes).as_val().ok()).collect();
        self.miner.import_external_transactions(self, transactions);
    }

    fn delete_all_pending_transactions(&self) {
        self.miner.delete_all_pending_transactions();
    }

    fn ready_transactions(&self, range: Range<u64>) -> PendingVerifiedTransactions {
        let size_limit = self
            .common_params(BlockId::Latest)
            .expect("Common params of the latest block always exists")
            .max_body_size();
        self.miner.ready_transactions(size_limit, range)
    }

    fn future_pending_transactions(&self, range: Range<u64>) -> PendingVerifiedTransactions {
        self.miner.future_pending_transactions(range)
    }

    fn count_pending_transactions(&self, range: Range<u64>) -> usize {
        self.miner.count_pending_transactions(range)
    }

    fn future_included_count_pending_transactions(&self, range: Range<u64>) -> usize {
        self.miner.future_included_count_pending_transactions(range)
    }

    fn is_pending_queue_empty(&self) -> bool {
        self.miner.num_pending_transactions() == 0
    }

    fn block_number(&self, _id: &BlockId) -> Option<BlockNumber> {
        unimplemented!()
    }

    fn block_body(&self, id: &BlockId) -> Option<encoded::Body> {
        self.block_hash(id).and_then(|hash| {
            self.blocks.read().get(&hash).map(|r| {
                let mut stream = RlpStream::new_list(2);
                let rlp = Rlp::new(r);
                stream.append_raw(rlp.at(1).unwrap().as_raw(), 1); // evidences
                stream.append_raw(rlp.at(2).unwrap().as_raw(), 1); // transactions
                encoded::Body::new(stream.out())
            })
        })
    }

    fn block_status(&self, id: &BlockId) -> BlockStatus {
        match id {
            BlockId::Number(number) if (*number as usize) < self.blocks.read().len() => BlockStatus::InChain,
            BlockId::Hash(ref hash) if self.blocks.read().get(hash).is_some() => BlockStatus::InChain,
            BlockId::Latest | BlockId::Earliest => BlockStatus::InChain,
            BlockId::ParentOfLatest => BlockStatus::InChain,
            _ => BlockStatus::Unknown,
        }
    }

    fn block_hash(&self, id: &BlockId) -> Option<BlockHash> {
        Self::block_hash(self, id)
    }

    fn transaction(&self, _id: &TransactionId) -> Option<LocalizedTransaction> {
        unimplemented!();
    }

    fn error_hint(&self, _hash: &TxHash) -> Option<String> {
        unimplemented!();
    }
}

impl TimeoutHandler for TestBlockChainClient {
    fn on_timeout(&self, _token: TimerToken) {}
}

impl FindDoubleVoteHandler for TestBlockChainClient {}

impl super::EngineClient for TestBlockChainClient {
    fn update_sealing(&self, parent_block: BlockId, allow_empty_block: bool) {
        self.miner.update_sealing(self, parent_block, allow_empty_block)
    }

    fn update_best_as_committed(&self, _block_hash: BlockHash) {}

    fn get_kvdb(&self) -> Arc<dyn KeyValueDB> {
        let db = kvdb_memorydb::create(NUM_COLUMNS.unwrap_or(0));
        Arc::new(db)
    }
}

impl EngineInfo for TestBlockChainClient {
    fn network_id(&self) -> NetworkId {
        self.scheme.genesis_params().network_id()
    }

    fn common_params(&self, _block_id: BlockId) -> Option<CommonParams> {
        Some(self.scheme.genesis_params())
    }

    fn metadata_seq(&self, _block_id: BlockId) -> Option<u64> {
        unimplemented!()
    }

    fn possible_authors(&self, _block_number: Option<u64>) -> Result<Option<Vec<PlatformAddress>>, EngineError> {
        unimplemented!()
    }

    fn validator_set(&self, _block_number: Option<u64>) -> Result<Option<ctypes::CompactValidatorSet>, EngineError> {
        unimplemented!()
    }
}

impl ConsensusClient for TestBlockChainClient {}

impl TermInfo for TestBlockChainClient {
    fn last_term_finished_block_num(&self, _id: BlockId) -> Option<BlockNumber> {
        None
    }

    fn current_term_id(&self, _id: BlockId) -> Option<u64> {
        self.term_id
    }

    fn term_common_params(&self, _id: BlockId) -> Option<CommonParams> {
        None
    }
}

impl StateInfo for TestBlockChainClient {
    fn state_at(&self, _id: BlockId) -> Option<TopLevelState> {
        let statedb = StateDB::new_with_memorydb();
        let mut top_state = empty_top_state_with_metadata(statedb, CommonParams::default_for_test());
        let _ = self.validators.save_to_state(&mut top_state);

        Some(top_state)
    }
}
