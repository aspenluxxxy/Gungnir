/*
	This Source Code Form is subject to the terms of the Mozilla Public
	License, v. 2.0. If a copy of the MPL was not distributed with this
	file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

use crate::format::HashAlgorithm;
use digest::{Digest, DynDigest};
use std::convert::AsRef;

pub struct Hasher(Box<dyn DynDigest>);

impl Hasher {
	pub fn update<R: AsRef<[u8]>>(&mut self, data: R) {
		self.0.update(data.as_ref());
	}

	pub fn finish(self) -> Vec<u8> {
		self.0.finalize().to_vec()
	}
}

impl From<HashAlgorithm> for Hasher {
	fn from(algo: HashAlgorithm) -> Self {
		match algo {
			HashAlgorithm::Blake3 => Hasher(Box::new(blake3::Hasher::new())),
			HashAlgorithm::Sha2_384 => Hasher(Box::new(sha2::Sha384::new())),
			HashAlgorithm::Sha2_512 => Hasher(Box::new(sha2::Sha512::new())),
			HashAlgorithm::Sha3_384 => Hasher(Box::new(sha3::Sha3_384::new())),
			HashAlgorithm::Sha3_512 => Hasher(Box::new(sha3::Sha3_512::new())),
			_ => unimplemented!(),
		}
	}
}
