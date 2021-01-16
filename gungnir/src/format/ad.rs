/*
	This Source Code Form is subject to the terms of the Mozilla Public
	License, v. 2.0. If a copy of the MPL was not distributed with this
	file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

use serde::{Deserialize, Serialize};

/// The associated identity data of a key's owner
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssociatedData {
	/// The name (real name or pseudonym) of the keyowner
	#[serde(skip_serializing_if = "Option::is_none")]
	pub name: Option<String>,
	/// The preferred pronouns of the keyowner
	#[serde(skip_serializing_if = "Option::is_none")]
	pub pronouns: Option<String>,
	/// The email of the keyowner
	#[serde(skip_serializing_if = "Option::is_none")]
	pub email: Option<String>,
	/// A comment left by the keyowner.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub comment: Option<String>,
}
