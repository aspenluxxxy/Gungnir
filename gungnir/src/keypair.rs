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

use pqcrypto::sign::{falcon1024, falcon512};
use zeroize::Zeroize;

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

impl Zeroize for Keypair {
	fn zeroize(&mut self) {
		match self {
			Keypair::Ed25519 { public, private } => {
				let public: &mut ed25519_dalek::PublicKey = public.as_mut();
				*public = unsafe { core::mem::zeroed() };
				if let Some(private) = private {
					let private: &mut ed25519_dalek::SecretKey = private.as_mut();
					*private = unsafe { core::mem::zeroed() };
				}
			}
			Keypair::Falcon512 { public, private } => {
				let public: &mut falcon512::PublicKey = public.as_mut();
				*public = unsafe { core::mem::zeroed() };
				if let Some(private) = private {
					let private: &mut falcon512::SecretKey = private.as_mut();
					*private = unsafe { core::mem::zeroed() };
				}
			}
			Keypair::Falcon1024 { public, private } => {
				let public: &mut falcon1024::PublicKey = public.as_mut();
				*public = unsafe { core::mem::zeroed() };
				if let Some(private) = private {
					let private: &mut falcon1024::SecretKey = private.as_mut();
					*private = unsafe { core::mem::zeroed() };
				}
			}
		}
	}
}
