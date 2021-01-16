/*
	This Source Code Form is subject to the terms of the Mozilla Public
	License, v. 2.0. If a copy of the MPL was not distributed with this
	file, You can obtain one at http://mozilla.org/MPL/2.0/.
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
