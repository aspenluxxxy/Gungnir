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

use ed25519_dalek::{ed25519::signature::Signature, Signer, Verifier};
use gungnir_core::{SignatureAlgorithm, SignatureSlot};
use pqcrypto::{
	prelude::*,
	sign::{falcon1024, falcon512},
};

pub enum Keypair {
	Ed25519 {
		public: Box<ed25519_dalek::PublicKey>,
		private: Option<Box<ed25519_dalek::SecretKey>>,
	},
	Falcon512 {
		public: Box<falcon512::PublicKey>,
		private: Option<Box<falcon512::SecretKey>>,
	},
	Falcon1024 {
		public: Box<falcon1024::PublicKey>,
		private: Option<Box<falcon1024::SecretKey>>,
	},
}

impl Keypair {
	pub fn new(algo: SignatureAlgorithm) -> Self {
		match algo {
			SignatureAlgorithm::Ed25519 => {
				let kp = ed25519_dalek::Keypair::generate(&mut rand::thread_rng());
				Self::Ed25519 {
					public: Box::new(kp.public),
					private: Some(Box::new(kp.secret)),
				}
			}
			SignatureAlgorithm::Falcon512 => {
				let (pub_key, priv_key) = falcon512::keypair();
				Self::Falcon512 {
					public: Box::new(pub_key),
					private: Some(Box::new(priv_key)),
				}
			}
			SignatureAlgorithm::Falcon1024 => {
				let (pub_key, priv_key) = falcon1024::keypair();
				Self::Falcon1024 {
					public: Box::new(pub_key),
					private: Some(Box::new(priv_key)),
				}
			}
			_ => unimplemented!(),
		}
	}

	pub fn sign(&self, data: &[u8]) -> crate::Result<SignatureSlot> {
		let (algorithm, public_key_digest, signature) = match self {
			Keypair::Ed25519 {
				public, private, ..
			} => private
				.as_ref()
				.map_or(Err(crate::Error::NoPrivateKey), |secret| {
					let keypair = ed25519_dalek::Keypair {
						public: ed25519_dalek::PublicKey::from_bytes(public.as_bytes())
							.map_err(|e| crate::Error::InvalidKey(e.to_string()))?,
						secret: ed25519_dalek::SecretKey::from_bytes(secret.as_bytes())
							.map_err(|e| crate::Error::InvalidKey(e.to_string()))?,
					};

					let signature = keypair.sign(data).to_bytes().to_vec();
					Ok((
						SignatureAlgorithm::Ed25519,
						*blake3::hash(public.as_bytes()).as_bytes(),
						signature,
					))
				})?,
			Keypair::Falcon512 { public, private } => {
				private
					.as_ref()
					.map_or(Err(crate::Error::NoPrivateKey), |secret| {
						let signature = falcon512::sign(data, &*secret).as_bytes().to_vec();
						Ok((
							SignatureAlgorithm::Falcon512,
							*blake3::hash(public.as_bytes()).as_bytes(),
							signature,
						))
					})?
			}
			Keypair::Falcon1024 { public, private } => {
				private
					.as_ref()
					.map_or(Err(crate::Error::NoPrivateKey), |secret| {
						let signature = falcon1024::sign(data, &*secret).as_bytes().to_vec();
						Ok((
							SignatureAlgorithm::Falcon1024,
							*blake3::hash(public.as_bytes()).as_bytes(),
							signature,
						))
					})?
			}
		};

		Ok(SignatureSlot {
			algorithm,
			public_key_digest,
			signature_len: signature.len(),
			signature,
		})
	}

	pub fn verify(&self, data: &[u8], signature: &[u8]) -> crate::Result<bool> {
		Ok(match self {
			Keypair::Ed25519 { public, .. } => public
				.verify(
					data,
					&ed25519_dalek::Signature::from_bytes(signature)
						.map_err(|e| crate::Error::InvalidKey(e.to_string()))?,
				)
				.is_ok(),
			Keypair::Falcon512 { public, .. } => falcon512::verify_detached_signature(
				&falcon512::DetachedSignature::from_bytes(signature)
					.map_err(|e| crate::Error::InvalidSignature(e.to_string()))?,
				data,
				&**public,
			)
			.is_ok(),
			Keypair::Falcon1024 { public, .. } => falcon1024::verify_detached_signature(
				&falcon1024::DetachedSignature::from_bytes(signature)
					.map_err(|e| crate::Error::InvalidKey(e.to_string()))?,
				data,
				&**public,
			)
			.is_ok(),
		})
	}
}
