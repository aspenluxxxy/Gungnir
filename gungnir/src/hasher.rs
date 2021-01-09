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

use gungnir_core::HashAlgorithm;
use sha2::Digest;
use std::convert::AsRef;

pub enum Hasher {
	Blake3(Box<blake3::Hasher>),
	Sha2_384(Box<sha2::Sha384>),
	Sha2_512(Box<sha2::Sha512>),
	Sha3_384(Box<sha3::Sha3_384>),
	Sha3_512(Box<sha3::Sha3_512>),
}

impl Hasher {
	pub fn update<R: AsRef<[u8]>>(&mut self, data: R) {
		self.update_impl(data.as_ref())
	}

	#[doc(hidden)]
	fn update_impl(&mut self, data: &[u8]) {
		match self {
			Hasher::Blake3(hasher) => {
				hasher.update(data);
			}
			Hasher::Sha2_384(hasher) => hasher.update(data),
			Hasher::Sha2_512(hasher) => hasher.update(data),
			Hasher::Sha3_384(hasher) => hasher.update(data),
			Hasher::Sha3_512(hasher) => hasher.update(data),
		}
	}

	pub fn finish(&mut self) -> Vec<u8> {
		match self {
			Hasher::Blake3(hasher) => hasher.finalize_reset().to_vec(),
			Hasher::Sha2_384(hasher) => hasher.finalize_reset().to_vec(),
			Hasher::Sha2_512(hasher) => hasher.finalize_reset().to_vec(),
			Hasher::Sha3_384(hasher) => hasher.finalize_reset().to_vec(),
			Hasher::Sha3_512(hasher) => hasher.finalize_reset().to_vec(),
		}
	}
}

impl From<HashAlgorithm> for Hasher {
	fn from(algo: HashAlgorithm) -> Self {
		match algo {
			HashAlgorithm::Blake3 => Hasher::Blake3(Box::new(blake3::Hasher::new())),
			HashAlgorithm::Sha2_384 => Hasher::Sha2_384(Box::new(sha2::Sha384::new())),
			HashAlgorithm::Sha2_512 => Hasher::Sha2_512(Box::new(sha2::Sha512::new())),
			HashAlgorithm::Sha3_384 => Hasher::Sha3_384(Box::new(sha3::Sha3_384::new())),
			HashAlgorithm::Sha3_512 => Hasher::Sha3_512(Box::new(sha3::Sha3_512::new())),
			_ => unimplemented!(),
		}
	}
}
