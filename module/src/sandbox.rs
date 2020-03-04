// Copyright 2020 Kodebox, Inc.
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

use crate::link::Linkable;
use linkme::distributed_slice;
use std::fmt::Debug;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

type Result<'a, T> = std::result::Result<T, Error<'a>>;

#[distributed_slice]
pub static SANDBOXERS: [fn() -> Arc<dyn Sandboxer>] = [..];

/// An entity that can sandbox modules of types it supports.
///
/// A `Sandboxer` is thread-safe.
pub trait Sandboxer: Send + Sync {
    /// Returns the identifier string for this provider.
    fn id(&self) -> &'static str;

    /// Returns a list of module types that can be loaded by this `Sandboxer`.
    fn supported_module_types(&self) -> &'static [&'static str];

    /// Loads the module in the given `path` into a [`Sandbox`] and pass the given
    /// `init` and `exports` to the module for initialization.
    ///
    /// The corresponding module must have been imported into the module repository
    /// configured for the current Foundry host. That is why this method accepts a `path`
    /// to identify a module.
    ///
    /// [`Sandbox`]: ./trait.Sandbox.html
    fn load(&self, path: &dyn AsRef<Path>, init: &[u8], exports: &[(&str, &[u8])]) -> Result<Arc<dyn Sandbox>>;
}

/// A sandbox instance hosting an instantiated module.
pub trait Sandbox: Linkable {
    /// Returns the `Sandboxer` for this sandbox.
    fn sandboxer(&self) -> Arc<dyn Sandboxer>;
}

#[derive(Debug, Error)]
pub enum Error<'a> {
    /// The module identified by the given `path` is not in the module repository.
    #[error("Could not find the specified module: {path:?}")]
    ModuleNotFound {
        path: &'a Path,
    },

    /// The module identified by the given `path` is not supported by the provider.
    #[error("The module is not supported: type '{ty:?}' at '{path:?}'")]
    UnsupportedModuleType {
        /// The identifier of the subject module.
        path: &'a Path,
        /// The type of the subject module.
        ty: String,
    },
}