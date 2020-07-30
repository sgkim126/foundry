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

use super::block_info::BestBlockChanged;
use super::extras::TransactionAddress;
use crate::db::{self, CacheUpdatePolicy, Readable, Writable};
use crate::encoded;
use crate::views::BlockView;
use ctypes::{BlockHash, TransactionIndex, TxHash};
use kvdb::{DBTransaction, KeyValueDB};
use lru_cache::LruCache;
use parking_lot::{Mutex, RwLock};
use primitives::Bytes;
use rlp::RlpStream;
use rlp_compress::{blocks_swapper, compress, decompress};
use std::collections::HashMap;
use std::mem;
use std::sync::Arc;

const BODY_CACHE_SIZE: usize = 1000;

pub struct BodyDB {
    // block cache
    body_cache: Mutex<LruCache<BlockHash, Bytes>>,
    address_by_hash_cache: RwLock<HashMap<TxHash, TransactionAddress>>,
    pending_addresses_by_hash: RwLock<HashMap<TxHash, TransactionAddress>>,

    db: Arc<dyn KeyValueDB>,
}

impl BodyDB {
    /// Create new instance of blockchain from given Genesis.
    pub fn new(genesis: &BlockView<'_>, db: Arc<dyn KeyValueDB>) -> Self {
        let bdb = Self {
            body_cache: Mutex::new(LruCache::new(BODY_CACHE_SIZE)),
            address_by_hash_cache: RwLock::new(HashMap::new()),
            pending_addresses_by_hash: RwLock::new(HashMap::new()),

            db,
        };

        let genesis_hash = genesis.hash();
        if bdb.block_body(&genesis_hash).is_none() {
            let mut batch = DBTransaction::new();
            batch.put(db::COL_BODIES, &genesis_hash, &Self::block_to_body(genesis));

            bdb.db.write(batch).expect("Low level database error. Some issue with disk?");
        }

        bdb
    }

    /// Inserts the block body into backing cache database.
    /// Expects the body to be valid and already verified.
    /// If the body is already known, does nothing.
    pub fn insert_body(&self, batch: &mut DBTransaction, block: &BlockView<'_>) {
        let hash = block.hash();

        if self.is_known_body(&hash) {
            return
        }

        let compressed_body = compress(&Self::block_to_body(block), blocks_swapper());

        // store block in db
        batch.put(db::COL_BODIES, &hash, &compressed_body);
    }

    pub fn update_best_block(&self, batch: &mut DBTransaction, best_block_changed: &BestBlockChanged) {
        let mut pending_addresses_by_hash = self.pending_addresses_by_hash.write();
        batch.extend_with_cache(
            db::COL_EXTRA,
            &mut *pending_addresses_by_hash,
            self.new_transaction_address_entries(best_block_changed),
            CacheUpdatePolicy::Overwrite,
        );
    }

    /// Apply pending insertion updates
    pub fn commit(&self) {
        let mut address_by_hash_cache = self.address_by_hash_cache.write();
        let mut pending_addresses_by_hash = self.pending_addresses_by_hash.write();

        let new_txs_by_hash = mem::replace(&mut *pending_addresses_by_hash, HashMap::new());

        address_by_hash_cache.extend(new_txs_by_hash.into_iter());
    }

    /// This function returns modified transaction addresses.
    fn new_transaction_address_entries(
        &self,
        best_block_changed: &BestBlockChanged,
    ) -> HashMap<TxHash, TransactionAddress> {
        let block = match best_block_changed.best_block() {
            Some(block) => block,
            None => return HashMap::new(),
        };
        let tx_hashes = block.transaction_hashes();

        match best_block_changed {
            BestBlockChanged::CanonChainAppended {
                ..
            } => tx_hash_and_address_entries(best_block_changed.new_best_hash().unwrap(), tx_hashes).collect(),
            BestBlockChanged::None => HashMap::new(),
        }
    }

    /// Create a block body from a block.
    pub fn block_to_body(block: &BlockView<'_>) -> Bytes {
        let mut body = RlpStream::new_list(2);
        let rlp = block.rlp();
        body.append_raw(rlp.at(1).unwrap().as_raw(), 1); // evidences
        body.append_raw(rlp.at(2).unwrap().as_raw(), 1); // transactions
        body.out()
    }
}

/// Interface for querying block bodiess by hash and by number.
pub trait BodyProvider {
    /// Returns true if the given block is known
    /// (though not necessarily a part of the canon chain).
    fn is_known_body(&self, hash: &BlockHash) -> bool;

    /// Get the address of transaction with given hash.
    fn transaction_address(&self, hash: &TxHash) -> Option<TransactionAddress>;

    /// Get the block body (transactions).
    fn block_body(&self, hash: &BlockHash) -> Option<encoded::Body>;
}

impl BodyProvider for BodyDB {
    fn is_known_body(&self, hash: &BlockHash) -> bool {
        self.block_body(hash).is_some()
    }

    /// Get the address of transaction with given hash.
    fn transaction_address(&self, hash: &TxHash) -> Option<TransactionAddress> {
        let result = self.db.read_with_cache(db::COL_EXTRA, &mut *self.address_by_hash_cache.write(), hash)?;
        Some(result)
    }

    /// Get block body data
    fn block_body(&self, hash: &BlockHash) -> Option<encoded::Body> {
        // Check cache first
        {
            let mut lock = self.body_cache.lock();
            if let Some(v) = lock.get_mut(hash) {
                return Some(encoded::Body::new(v.clone()))
            }
        }

        // Read from DB and populate cache
        let compressed_body =
            self.db.get(db::COL_BODIES, hash).expect("Low level database error. Some issue with disk?")?;

        let raw_body = decompress(&compressed_body, blocks_swapper());
        let mut lock = self.body_cache.lock();
        lock.insert(*hash, raw_body.clone());

        Some(encoded::Body::new(raw_body))
    }
}

fn tx_hash_and_address_entries(
    block_hash: BlockHash,
    tx_hashes: impl IntoIterator<Item = TxHash>,
) -> impl Iterator<Item = (TxHash, TransactionAddress)> {
    tx_hashes.into_iter().enumerate().map(move |(index, tx_hash)| {
        (tx_hash, TransactionAddress {
            block_hash,
            index: index as TransactionIndex,
        })
    })
}
