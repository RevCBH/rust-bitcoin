//! Handshake transaction covenants

use std::io;

use consensus::encode::ReadExt;
use consensus::{encode, Decodable, Encodable};

use crate::consensus::encode::{serialize, deserialize};
// use hashes::Hash;

/// Handshake covenant types
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, FromPrimitive, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum CovenantType {
    /// NONE
    None = 0,
    /// CLAIM
    Claim = 1,
    /// OPEN
    Open = 2,
    /// BID
    Bid = 3,
    /// REVEAL
    Reveal = 4,
    /// REDEEM
    Redeem = 5,
    /// REGISTER
    Register = 6,
    /// Update
    Update = 7,
    /// Renew
    Renew = 8,
    /// Transfer
    Transfer = 9,
    /// Finalize
    Finalize = 10,
    /// Revoke
    Revoke = 11,
}

impl Encodable for CovenantType {
    fn consensus_encode<W: io::Write>(&self, writer: W) -> Result<usize, io::Error> {
        let value: u8 = *self as u8;
        return Ok(value.consensus_encode(writer)?);
    }
}

impl Decodable for CovenantType {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let value = d.read_u8()?;
        return num::FromPrimitive::from_u8(value).ok_or(encode::Error::InvalidCovenant(value));
    }
}

/// A serializable covenant
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Covenant {
    /// The covenant type
    pub covenant_type: CovenantType,
    /// The covenant items
    pub items: Vec<Vec<u8>>,
}

impl Default for Covenant {
    fn default() -> Self {
        Covenant {
            covenant_type: CovenantType::None,
            items: vec![],
        }
    }
}

impl_consensus_encoding!(Covenant, covenant_type, items);

pub mod typed {
    //! typed covenants

    use crate::{NameHash, BlindHash};

    /// typed Bid covenant
    pub struct Bid {
        /// name_hash
        pub name_hash: NameHash,

        /// height
        pub height: u32,

        /// name
        pub name: String,

        /// hash of the blind + nonce
        pub blind_hash: BlindHash,
    }

    /// typed None covenant
    pub struct None{}
}

impl Covenant {
    /// as_bid
    pub fn as_bid(&self) -> Result<typed::Bid, encode::Error> {
        if self.covenant_type != CovenantType::Bid {
            return Err(encode::Error::InvalidCovenant(self.covenant_type as u8));
        }

        // prepend the lenght as a varint so we can use the default deserialize
        let name_bytes = serialize(&self.items[2]);

        Ok(typed::Bid {
            name_hash: deserialize(self.items[0].as_slice())?,
            // name_hash: String::from_str("").unwrap(),
            height: deserialize(self.items[1].as_slice())?,
            name: deserialize(&name_bytes)?,
            // name: String::from_str("").unwrap(),
            // hash: deserialize(self.items[3].as_slice())?,
            blind_hash: deserialize(self.items[3].as_slice())?
        })
    }

    /// as_none
    pub fn as_none(&self) -> Result<typed::None, encode::Error> {
        if self.covenant_type != CovenantType::None {
            return Err(encode::Error::InvalidCovenant(self.covenant_type as u8));
        }

        Ok(typed::None{})
    }
}
