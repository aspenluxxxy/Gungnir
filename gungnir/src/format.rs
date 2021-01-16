/*
	This Source Code Form is subject to the terms of the Mozilla Public
	License, v. 2.0. If a copy of the MPL was not distributed with this
	file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

pub mod ad;
pub mod algorithm;
pub mod keypair;
pub mod signature;

pub use ad::AssociatedData;
pub use algorithm::{HashAlgorithm, SignatureAlgorithm};
use deku::prelude::*;
pub use keypair::{KeySlot, Keypair};
pub use signature::SignatureSlot;

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(magic = b"GUNGNIR\x2A")]
pub struct GungnirSignature {
	#[deku(endian = "little")]
	pub version: u8,
	pub hash_algorithm: HashAlgorithm,
	#[deku(endian = "little", update = "self.signatures.len()")]
	pub signature_amt: u8,
	#[deku(count = "signature_amt")]
	pub signatures: Vec<SignatureSlot>,
}
