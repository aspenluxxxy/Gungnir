/*
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

pub mod algorithm;
pub mod slot;

pub use crate::{
	algorithm::{HashAlgorithm, SignatureAlgorithm},
	slot::SignatureSlot,
};
pub use deku;
use deku::prelude::*;

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(magic = b"GUNGNIR")]
pub struct GungnirSignature {
	#[deku(endian = "little")]
	pub version: u8,
	pub hash_algorithm: HashAlgorithm,
	#[deku(endian = "little", update = "self.signatures.len()")]
	pub signature_amt: u8,
	#[deku(count = "signature_amt")]
	pub signatures: Vec<SignatureSlot>,
}
