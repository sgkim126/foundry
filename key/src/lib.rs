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

extern crate codechain_crypto as crypto;
#[macro_use]
extern crate serde_derive;

mod ed25519;
mod error;
mod keypair;
mod network;
mod password;
mod platform_address;
mod random;
mod x25519;

pub use crate::ed25519::{
    sign, verify, KeyPair as Ed25519KeyPair, Private as Ed25519Private, Public as Ed25519Public, Signature,
    SIGNATURE_LENGTH,
};
pub use crate::error::Error;
pub use crate::keypair::KeyPair as KeyPairTrait;
pub use crate::network::NetworkId;
pub use crate::password::Password;
pub use crate::platform_address::PlatformAddress;
pub use crate::random::Random;
pub use crate::x25519::{exchange, KeyPair as X25519KeyPair, Private as X25519Private, Public as X25519Public};
use primitives::H256;
pub use rustc_serialize::hex;

/// 32 bytes long signable message
pub type Message = H256;
pub type SharedSecret = H256;

/// Uninstantiatable error type for infallible generators.
#[derive(Debug)]
pub enum Void {}

/// Generates new keypair.
pub trait Generator<KP: KeyPairTrait> {
    type Error;

    /// Should be called to generate new keypair.
    fn generate(&mut self) -> Result<KP, Self::Error>;
}
