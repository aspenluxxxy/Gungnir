/*
	This Source Code Form is subject to the terms of the Mozilla Public
	License, v. 2.0. If a copy of the MPL was not distributed with this
	file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

use deku::prelude::*;
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq, DekuRead, DekuWrite, Serialize, Deserialize)]
#[deku(type = "u8", endian = "little")]
pub enum SignatureAlgorithm {
	/// The Ed25519 signature algorithm.
	/// For more info, see https://ed25519.cr.yp.to/
	#[deku(id = "0x01")]
	Ed25519 = 1,
	/// The Falcon post-quantum signature algorithm (Falcon-512 variant).
	/// For more info, see https://falcon-sign.info/
	#[deku(id = "0x02")]
	Falcon512 = 2,
	/// The Falcon post-quantum signature algorithm (Falcon-1024 variant).
	/// For more info, see https://falcon-sign.info/
	#[deku(id = "0x03")]
	Falcon1024 = 3,
}

impl SignatureAlgorithm {
	/// The current default primary signature algorithm, Ed25519
	pub const fn default_primary() -> Self {
		SignatureAlgorithm::Ed25519
	}

	/// The current default secondary signature algorithm, Falcon-512
	pub const fn default_secondary() -> Self {
		SignatureAlgorithm::Falcon512
	}
}

#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Eq, PartialEq, DekuRead, DekuWrite, Serialize, Deserialize)]
#[deku(type = "u8", endian = "little")]
pub enum HashAlgorithm {
	/// The BLAKE3 hash function.
	/// For more info, see https://github.com/BLAKE3-team/BLAKE3
	#[deku(id = "0x01")]
	Blake3 = 1,
	/// The SHA-2 hash function, with a 384-bit output./// The current default primary signature algorithm, Ed25519
	/// For more info, see https://en.wikipedia.org/wiki/SHA-2
	#[deku(id = "0x02")]
	Sha2_384 = 2,
	/// The SHA-2 hash function, with a 512-bit output.
	/// For more info, see https://en.wikipedia.org/wiki/SHA-2
	#[deku(id = "0x03")]
	Sha2_512 = 3,
	/// The SHA-3 hash function, with a 384-bit output.
	/// For more info, see https://en.wikipedia.org/wiki/SHA-3
	#[deku(id = "0x04")]
	Sha3_384 = 4,
	/// The SHA-3 hash function, with a 512-bit output.
	/// For more info, see https://en.wikipedia.org/wiki/SHA-3
	#[deku(id = "0x05")]
	Sha3_512 = 5,
}

impl HashAlgorithm {
	/// Returns the length of a hash this algorithm produces in bytes.
	pub fn hash_len(&self) -> usize {
		match *self {
			HashAlgorithm::Blake3 => 32,
			HashAlgorithm::Sha2_384 => 48,
			HashAlgorithm::Sha2_512 => 64,
			HashAlgorithm::Sha3_384 => 48,
			HashAlgorithm::Sha3_512 => 64,
		}
	}
}

impl Default for HashAlgorithm {
	fn default() -> Self {
		HashAlgorithm::Blake3
	}
}
