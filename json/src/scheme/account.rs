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

use crate::uint::Uint;

/// Scheme account.
#[derive(Debug, PartialEq, Deserialize)]
pub struct Account {
    /// Balance.
    pub balance: Option<Uint>,
    /// Seq.
    pub seq: Option<Uint>,
}

impl Account {
    /// Returns true if account does not have seq and balance
    pub fn is_empty(&self) -> bool {
        self.balance.is_none() && self.seq.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::Account;

    #[test]
    fn account_deserialization() {
        let s = r#"{
            "balance": "1",
            "seq": "0"
        }"#;
        let deserialized: Account = serde_json::from_str(s).unwrap();
        assert!(!deserialized.is_empty());
        assert_eq!(deserialized.balance, Some(1.into()));
        assert_eq!(deserialized.seq, Some(0.into()));
    }
}
