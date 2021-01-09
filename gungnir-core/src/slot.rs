/*
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

use crate::SignatureAlgorithm;
use deku::prelude::*;

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
pub struct SignatureSlot {
	pub algorithm: SignatureAlgorithm,
	#[deku(endian = "little")]
	pub public_key_digest: [u8; 32],
	#[deku(endian = "little", update = "self.signature.len()")]
	pub signature_len: usize,
	#[deku(endian = "little", count = "signature_len")]
	pub signature: Vec<u8>,
}
