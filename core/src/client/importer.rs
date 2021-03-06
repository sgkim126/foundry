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

use super::{BlockChainTrait, Client, ClientConfig};
use crate::block::{enact, Block, ClosedBlock, IsBlock};
use crate::blockchain::{BodyProvider, ChainUpdateResult, HeaderProvider};
use crate::client::EngineInfo;
use crate::consensus::CodeChainEngine;
use crate::error::Error;
use crate::miner::{Miner, MinerService};
use crate::service::ClientIoMessage;
use crate::verification::queue::{BlockQueue, HeaderQueue};
use crate::verification::{PreverifiedBlock, Verifier};
use crate::views::{BlockView, HeaderView};
use cio::IoChannel;
use ctypes::header::{Header, Seal};
use ctypes::{BlockHash, BlockId, SyncHeader};
use kvdb::DBTransaction;
use parking_lot::{Mutex, MutexGuard};
use rlp::Encodable;
use std::borrow::Borrow;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::{ops::Deref, sync::Arc};

pub struct Importer {
    /// Lock used during block import
    pub import_lock: Mutex<()>, // FIXME Maybe wrap the whole `Importer` instead?

    /// Used to verify blocks
    pub verifier: Verifier,

    /// Queue containing pending blocks
    pub block_queue: BlockQueue,

    /// Queue containing pending headers
    pub header_queue: HeaderQueue,

    /// Handles block sealing
    miner: Arc<Miner>,

    /// CodeChain engine to be used during import
    pub engine: Arc<dyn CodeChainEngine>,
}

impl Importer {
    pub fn try_new(
        config: &ClientConfig,
        engine: Arc<dyn CodeChainEngine>,
        message_channel: IoChannel<ClientIoMessage>,
        miner: Arc<Miner>,
    ) -> Result<Importer, Error> {
        let block_queue = BlockQueue::new(&config.queue, engine.clone(), message_channel.clone());

        let header_queue = HeaderQueue::new(&config.queue, engine.clone(), message_channel);

        Ok(Importer {
            import_lock: Mutex::new(()),
            verifier: Verifier,
            block_queue,
            header_queue,
            miner,
            engine,
        })
    }

    /// This is triggered by a message coming from a block queue when the block is ready for insertion
    pub fn import_verified_blocks(&self, client: &Client) -> usize {
        let (imported_blocks, update_results, invalid_blocks, imported, is_empty) = {
            const MAX_BLOCKS_TO_IMPORT: usize = 1_000;
            let mut imported_blocks = Vec::with_capacity(MAX_BLOCKS_TO_IMPORT);
            let mut invalid_blocks = HashSet::new();
            let mut update_results = Vec::with_capacity(MAX_BLOCKS_TO_IMPORT);

            let import_lock = self.import_lock.lock();
            let blocks = self.block_queue.drain(MAX_BLOCKS_TO_IMPORT);
            if blocks.is_empty() {
                return 0
            }

            {
                let headers: Vec<_> =
                    blocks.iter().map(|block| VerifiedHeader::from_verified_block(&block.header)).collect();
                self.import_verified_headers(headers, client, &import_lock);
            }

            for block in blocks {
                let header = &block.header;
                ctrace!(CLIENT, "Importing block {}", header.number());
                let is_invalid = invalid_blocks.contains(header.parent_hash());
                if is_invalid {
                    invalid_blocks.insert(header.hash());
                    continue
                }
                if let Ok(closed_block) = self.check_and_close_block(&block, client) {
                    imported_blocks.push(header.hash());
                    let update_result = self.commit_block(&closed_block, &header, &block.bytes, client);
                    update_results.push(update_result);
                } else {
                    invalid_blocks.insert(header.hash());
                }
            }

            let imported = imported_blocks.len();
            let invalid_blocks = invalid_blocks.into_iter().collect::<Vec<_>>();

            if !invalid_blocks.is_empty() {
                self.block_queue.mark_as_bad(&invalid_blocks);
            }
            let is_empty = self.block_queue.mark_as_good(&imported_blocks);
            (imported_blocks, update_results, invalid_blocks, imported, is_empty)
        };

        {
            if !imported_blocks.is_empty() {
                if !is_empty {
                    ctrace!(CLIENT, "Call new_blocks even though block verification queue is not empty");
                }
                let enacted = self.extract_enacted(update_results);
                self.miner.chain_new_blocks(client, &imported_blocks, &invalid_blocks, &enacted);
                client.new_blocks(&imported_blocks, &invalid_blocks, &enacted);
            }
        }

        client.db().flush().expect("DB flush failed.");
        imported
    }

    pub fn extract_enacted(&self, update_results: Vec<ChainUpdateResult>) -> Vec<BlockHash> {
        let set = update_results.into_iter().fold(HashSet::new(), |mut set, result| {
            set.extend(result.enacted);
            set
        });
        Vec::from_iter(set)
    }

    // NOTE: the header of the block passed here is not necessarily sealed, as
    // it is for reconstructing the state transition.
    //
    // The header passed is from the original block data and is sealed.
    pub fn commit_block<B>(&self, block: &B, header: &Header, block_data: &[u8], client: &Client) -> ChainUpdateResult
    where
        B: IsBlock, {
        let hash = header.hash();
        let number = header.number();

        let chain = client.block_chain();

        // Commit results
        let invoices = block.invoices().to_owned();

        assert_eq!(hash, BlockView::new(block_data).header_view().hash());

        let mut batch = DBTransaction::new();

        block.state().journal_under(&mut batch, number).expect("DB commit failed");
        let update_result = chain.insert_block(&mut batch, block_data, invoices, self.engine.borrow());

        // Final commit to the DB
        client.db().write_buffered(batch);
        chain.commit();

        if hash == chain.best_block_hash() {
            let mut state_db = client.state_db().write();
            let state = block.state();
            state_db.override_state(&state);
        }

        update_result
    }

    fn check_and_close_block(&self, block: &PreverifiedBlock, client: &Client) -> Result<ClosedBlock, ()> {
        let engine = &*self.engine;
        let header = &block.header;

        let chain = client.block_chain();

        // Check if parent is in chain
        let parent = chain.block_header(header.parent_hash()).ok_or_else(|| {
            cwarn!(
                CLIENT,
                "Block import failed for #{} ({}): Parent not found ({}) ",
                header.number(),
                header.hash(),
                header.parent_hash()
            );
        })?;

        chain.block_body(header.parent_hash()).ok_or_else(|| {
            cerror!(
                CLIENT,
                "Block import failed for #{} ({}): Parent block not found ({}) ",
                header.number(),
                header.hash(),
                parent.hash()
            );
        })?;

        let common_params = client.common_params(parent.hash().into()).unwrap();

        // Verify Block Family
        self.verifier.verify_block_family(&block.bytes, header, &parent, engine, &common_params).map_err(|e| {
            cwarn!(
                CLIENT,
                "Stage 3 block verification failed for #{} ({})\nError: {:?}",
                header.number(),
                header.hash(),
                e
            );
        })?;

        self.verifier.verify_block_external(header, engine).map_err(|e| {
            cwarn!(
                CLIENT,
                "Stage 4 block verification failed for #{} ({})\nError: {:?}",
                header.number(),
                header.hash(),
                e
            );
        })?;

        // Enact Verified Block
        let db = client.state_db().read().clone(&parent.state_root());

        let enact_result = enact(&block.header, &block.evidences, &block.transactions, engine, client, db, &parent);
        let closed_block = enact_result.map_err(|e| {
            cwarn!(CLIENT, "Block import failed for #{} ({})\nError: {:?}", header.number(), header.hash(), e);
        })?;

        // Final Verification
        self.verifier.verify_block_final(header, closed_block.block().header()).map_err(|e| {
            cwarn!(
                CLIENT,
                "Stage 5 block verification failed for #{} ({})\nError: {:?}",
                header.number(),
                header.hash(),
                e
            );
        })?;

        Ok(closed_block)
    }

    /// This is triggered by a message coming from a header queue when the header is ready for insertion
    pub fn import_verified_headers_from_queue(&self, client: &Client) -> usize {
        const MAX_HEADERS_TO_IMPORT: usize = 1_000;
        let lock = self.import_lock.lock();
        let headers = self.header_queue.drain(MAX_HEADERS_TO_IMPORT);
        self.import_verified_headers(
            headers.iter().map(|sync_header| VerifiedHeader::from_sync(sync_header)),
            client,
            &lock,
        )
    }

    pub fn import_verified_headers<'a>(
        &'a self,
        headers: impl IntoIterator<Item = VerifiedHeader<'a>>,
        client: &Client,
        _importer_lock: &MutexGuard<'_, ()>,
    ) -> usize {
        let prev_best_proposal_header_hash = client.block_chain().best_proposal_header().hash();

        let mut bad = HashSet::new();
        let mut imported = Vec::new();
        let mut update_results = Vec::new();

        for header in headers {
            let hash = header.hash();
            ctrace!(CLIENT, "Importing header {}-{:?}", header.number(), hash);

            if bad.contains(&hash) || bad.contains(header.parent_hash()) {
                cinfo!(CLIENT, "Bad header detected : {}", hash);
                bad.insert(hash);
                continue
            }

            let parent_header = client
                .block_header(&(*header.parent_hash()).into())
                .unwrap_or_else(|| panic!("Parent of importing header must exist {:?}", header.parent_hash()))
                .decode();
            let grand_parent = if header.number() <= 1 {
                None
            } else {
                let grand_parent = client
                    .block_header(&(*parent_header.parent_hash()).into())
                    .unwrap_or_else(|| panic!("Grand parent of importing header must exist {:?}", header.parent_hash()))
                    .decode();
                Some(grand_parent)
            };
            if client.block_header(&BlockId::Hash(hash)).is_some() {
                // Do nothing if the header is already imported
            } else if self.check_header(&header, &parent_header, grand_parent.as_ref()) {
                imported.push(hash);
                update_results.push(self.commit_header(&header, client));
            } else {
                bad.insert(hash);
            }
        }

        self.header_queue.mark_as_bad(&bad.drain().collect::<Vec<_>>());
        let enacted = self.extract_enacted(update_results);

        let new_best_proposal_header_hash = client.block_chain().best_proposal_header().hash();
        let best_proposal_header_changed = if prev_best_proposal_header_hash != new_best_proposal_header_hash {
            Some(new_best_proposal_header_hash)
        } else {
            None
        };

        client.new_headers(&imported, &enacted, best_proposal_header_changed);

        client.db().flush().expect("DB flush failed.");

        imported.len()
    }

    pub fn import_trusted_header<'a>(&'a self, header: &'a Header, client: &Client, _importer_lock: &MutexGuard<()>) {
        let hash = header.hash();
        ctrace!(CLIENT, "Importing trusted header #{}-{:?}", header.number(), hash);

        {
            let chain = client.block_chain();
            let mut batch = DBTransaction::new();
            chain.insert_floating_header(&mut batch, &HeaderView::new(&header.rlp_bytes()));
            client.db().write_buffered(batch);
            chain.commit();
        }
        client.new_headers(&[hash], &[], None);

        client.db().flush().expect("DB flush failed.");
    }

    pub fn import_trusted_block<'a>(&'a self, block: &'a Block, client: &Client, importer_lock: &MutexGuard<()>) {
        let header = &block.header;
        let hash = header.hash();
        ctrace!(CLIENT, "Importing trusted block #{}-{:?}", header.number(), hash);

        self.import_trusted_header(header, client, importer_lock);
        {
            let chain = client.block_chain();
            let mut batch = DBTransaction::new();
            chain.insert_floating_block(&mut batch, &block.rlp_bytes(&Seal::With));
            client.db().write_buffered(batch);
            chain.commit();
        }
        self.miner.chain_new_blocks(client, &[hash], &[], &[]);
        client.new_blocks(&[hash], &[], &[]);

        client.db().flush().expect("DB flush failed.");
    }

    pub fn force_update_best_block(&self, hash: &BlockHash, client: &Client) {
        let chain = client.block_chain();
        let mut batch = DBTransaction::new();
        chain.force_update_best_block(&mut batch, hash);
        client.db().write_buffered(batch);
        chain.commit();

        client.db().flush().expect("DB flush failed.");
    }

    /// grand_parent === None only when parent is genesis
    fn check_header(&self, header: &VerifiedHeader, parent: &Header, grand_parent: Option<&Header>) -> bool {
        // FIXME: self.verifier.verify_block_family
        if let Err(e) = self.engine.verify_block_family(header, &parent) {
            cwarn!(
                CLIENT,
                "Stage 3 block verification failed for #{} ({})\nError: {:?}",
                header.number(),
                header.hash(),
                e
            );
            return false
        };

        if let VerifiedHeader::FromSync(sync_header) = header {
            if let Err(e) = self.engine.verify_header_family(sync_header, &parent, grand_parent) {
                cwarn!(
                    CLIENT,
                    "Stage 3 header verification failed for #{} ({})\nError: {:?}",
                    header.number(),
                    header.hash(),
                    e
                );
                return false
            };
        }
        true
    }

    fn commit_header(&self, header: &Header, client: &Client) -> ChainUpdateResult {
        let chain = client.block_chain();

        let mut batch = DBTransaction::new();
        let update_result =
            chain.insert_header(&mut batch, &HeaderView::new(&header.rlp_bytes()), self.engine.borrow());
        client.db().write_buffered(batch);
        chain.commit();

        update_result
    }
}

pub enum VerifiedHeader<'a> {
    FromSync(&'a SyncHeader),
    Generated(&'a Header),
    FromVerifiedBlock(&'a Header),
}

impl<'a> VerifiedHeader<'a> {
    pub fn from_sync(sync_header: &'a SyncHeader) -> Self {
        VerifiedHeader::FromSync(sync_header)
    }

    pub fn from_generated(generated_header: &'a Header) -> Self {
        VerifiedHeader::Generated(generated_header)
    }

    pub fn from_verified_block(header: &'a Header) -> Self {
        VerifiedHeader::FromVerifiedBlock(header)
    }
}

impl<'a> Deref for VerifiedHeader<'a> {
    type Target = Header;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::FromSync(sync_header) => sync_header,
            Self::Generated(header) => header,
            Self::FromVerifiedBlock(header) => header,
        }
    }
}
