/*
	This Source Code Form is subject to the terms of the Mozilla Public
	License, v. 2.0. If a copy of the MPL was not distributed with this
	file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

pub mod error;
pub mod format;
pub mod hasher;
pub mod keypair;
pub mod reader;

pub use error::Error;
pub use gungnir_core as core;

pub type Result<T> = std::result::Result<T, Error>;
