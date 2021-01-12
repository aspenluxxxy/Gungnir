/*
  Copyright (C) 2021 aspen

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 3 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program; if not, write to the Free Software Foundation,
  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

use digest::{Digest, DynDigest};
use gungnir_core::HashAlgorithm;
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
