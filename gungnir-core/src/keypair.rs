/*
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

use crate::{AssociatedData, SignatureAlgorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Keypair {
	pub ad: AssociatedData,
	pub keys: Vec<KeySlot>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeySlot {
	/// The signature algorithm this key uses.
	pub algorithm: SignatureAlgorithm,
	/// The public key of this keypair.
	pub public_key: Vec<u8>,
	/// The private key of this keypair;
	/// if this does not exist, it indicates this is *someone else's* keypair,
	/// to be used for verification.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub private_key: Option<Vec<u8>>,
}
