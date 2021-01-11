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

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
	#[error("invalid key: {0}")]
	InvalidKey(String),
	#[error("invalid signature: {0}")]
	InvalidSignature(String),
	#[error("keypair does not contain private key")]
	NoPrivateKey,
}
