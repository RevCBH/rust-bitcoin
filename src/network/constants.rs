// Rust Handshake Library
// Written in 2021 by
//   Bennett Hoffman <benn.hoffman@gmail.com>
//
// Based on the Rust Bitcoin Library by Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Network constants
//!
//! This module provides various constants relating to the Handshake network
//! protocol, such as protocol versioning and magic header bytes.
//!
//! The [`Network`][1] type implements the [`Decodable`][2] and
//! [`Encodable`][3] traits and encodes the magic bytes of the given
//! network
//!
//! [1]: enum.Network.html
//! [2]: ../../consensus/encode/trait.Decodable.html
//! [3]: ../../consensus/encode/trait.Encodable.html
//!
//! # Example: encoding a network's magic bytes
//!
//! ```rust
//! use handshake::network::constants::Network;
//! use handshake::consensus::encode::serialize;
//!
//! let network = Network::Handshake;
//! let bytes = serialize(&network.magic());
//!
//! assert_eq!(&bytes[..], &[0xF9, 0xBE, 0xB4, 0xD9]);
//! ```

use core::{convert::From, fmt, ops};
use std::sync::RwLock;

use consensus::encode::{self, Decodable, Encodable};
use io;

use super::ACTIVE_NETWORK;

/// Version of the protocol as appearing in network message headers
/// This constant is used to signal to other peers which features you support.
/// Increasing it implies that your software also supports every feature prior to this version.
/// Doing so without support may lead to you incorrectly banning other peers or other peers banning you.
/// These are the features required for each version:
/// 70016 - Support receiving `wtxidrelay` message between `version` and `verack` message
/// 70015 - Support receiving invalid compact blocks from a peer without banning them
/// 70014 - Support compact block messages `sendcmpct`, `cmpctblock`, `getblocktxn` and `blocktxn`
/// 70013 - Support `feefilter` message
/// 70012 - Support `sendheaders` message and announce new blocks via headers rather than inv
/// 70011 - Support NODE_BLOOM service flag and don't support bloom filter messages if it is not set
/// 70002 - Support `reject` message
/// 70001 - Support bloom filter messages `filterload`, `filterclear` `filteradd`, `merkleblock` and FILTERED_BLOCK inventory type
/// 60002 - Support `mempool` message
/// 60001 - Support `pong` message and nonce in `ping` message
// TODO - correct this for handshake
pub const PROTOCOL_VERSION: u32 = 3;

user_enum! {
    /// The cryptocurrency to act on
    #[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
    pub enum Network {
        /// Classic Handshake
        Mainnet <-> "mainnet",
        /// Handshake's testnet
        Testnet <-> "testnet",
        /// Handshake's signet
        Simnet <-> "simnet",
        /// Handshake's regtest
        Regtest <-> "regtest"
    }
}

impl Default for Network {
    fn default() -> Self {
        let inner =
            |x: &RwLock<Network>| x.read().map(|x| x.clone()).ok().unwrap_or(Network::Regtest);

        ACTIVE_NETWORK
            .try_get()
            .map(inner)
            .unwrap_or(Network::Regtest)
    }
}

impl Network {
    /// Creates a `Network` from the magic bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use handshake::network::constants::Network;
    ///
    /// assert_eq!(Some(Network::Mainnet), Network::from_magic(0x5B6EF2D3));
    /// assert_eq!(None, Network::from_magic(0xFFFFFFFF));
    /// ```
    pub fn from_magic(magic: u32) -> Option<Network> {
        // Note: any new entries here must be added to `magic` below
        match magic {
            0x5B6EF2D3 => Some(Network::Mainnet),
            0xB1520DD2 => Some(Network::Testnet),
            0x0E648EDC => Some(Network::Simnet),
            0xAE3895CF => Some(Network::Regtest),
            _ => None,
        }
    }

    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    ///
    /// # Examples
    ///
    /// ```rust
    /// use handshake::network::constants::Network;
    ///
    /// let network = Network::Mainnet;
    /// assert_eq!(network.magic(), 0x5B6EF2D3);
    /// ```
    pub fn magic(self) -> u32 {
        // Note: any new entries here must be added to `from_magic` above
        match self {
            Network::Mainnet => 0x5B6EF2D3,
            Network::Testnet => 0xB1520DD2,
            Network::Simnet => 0x0E648EDC,
            Network::Regtest => 0xAE3895CF,
        }
    }
}

/// Flags to indicate which network services a node supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceFlags(u64);

// TODO - revise for handshake
impl ServiceFlags {
    /// NONE means no services supported.
    pub const NONE: ServiceFlags = ServiceFlags(0);

    /// NETWORK means that the node is capable of serving the complete block chain. It is currently
    /// set by all Bitcoin Core non pruned nodes, and is unset by SPV clients or other light
    /// clients.
    pub const NETWORK: ServiceFlags = ServiceFlags(1 << 0);

    /// GETUTXO means the node is capable of responding to the getutxo protocol request.  Bitcoin
    /// Core does not support this but a patch set called Bitcoin XT does.
    /// See BIP 64 for details on how this is implemented.
    pub const GETUTXO: ServiceFlags = ServiceFlags(1 << 1);

    /// BLOOM means the node is capable and willing to handle bloom-filtered connections.  Bitcoin
    /// Core nodes used to support this by default, without advertising this bit, but no longer do
    /// as of protocol version 70011 (= NO_BLOOM_VERSION)
    pub const BLOOM: ServiceFlags = ServiceFlags(1 << 2);

    /// WITNESS indicates that a node can be asked for blocks and transactions including witness
    /// data.
    pub const WITNESS: ServiceFlags = ServiceFlags(1 << 3);

    /// COMPACT_FILTERS means the node will service basic block filter requests.
    /// See BIP157 and BIP158 for details on how this is implemented.
    pub const COMPACT_FILTERS: ServiceFlags = ServiceFlags(1 << 6);

    /// NETWORK_LIMITED means the same as NODE_NETWORK with the limitation of only serving the last
    /// 288 (2 day) blocks.
    /// See BIP159 for details on how this is implemented.
    pub const NETWORK_LIMITED: ServiceFlags = ServiceFlags(1 << 10);

    // NOTE: When adding new flags, remember to update the Display impl accordingly.

    /// Add [ServiceFlags] together.
    ///
    /// Returns itself.
    pub fn add(&mut self, other: ServiceFlags) -> ServiceFlags {
        self.0 |= other.0;
        *self
    }

    /// Remove [ServiceFlags] from this.
    ///
    /// Returns itself.
    pub fn remove(&mut self, other: ServiceFlags) -> ServiceFlags {
        self.0 ^= other.0;
        *self
    }

    /// Check whether [ServiceFlags] are included in this one.
    pub fn has(self, flags: ServiceFlags) -> bool {
        (self.0 | flags.0) == self.0
    }

    /// Get the integer representation of this [ServiceFlags].
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::LowerHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl fmt::Display for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut flags = *self;
        if flags == ServiceFlags::NONE {
            return write!(f, "ServiceFlags(NONE)");
        }
        let mut first = true;
        macro_rules! write_flag {
            ($f:ident) => {
                if flags.has(ServiceFlags::$f) {
                    if !first {
                        write!(f, "|")?;
                    }
                    first = false;
                    write!(f, stringify!($f))?;
                    flags.remove(ServiceFlags::$f);
                }
            };
        }
        write!(f, "ServiceFlags(")?;
        write_flag!(NETWORK);
        write_flag!(GETUTXO);
        write_flag!(BLOOM);
        write_flag!(WITNESS);
        write_flag!(COMPACT_FILTERS);
        write_flag!(NETWORK_LIMITED);
        // If there are unknown flags left, we append them in hex.
        if flags != ServiceFlags::NONE {
            if !first {
                write!(f, "|")?;
            }
            write!(f, "0x{:x}", flags)?;
        }
        write!(f, ")")
    }
}

impl From<u64> for ServiceFlags {
    fn from(f: u64) -> Self {
        ServiceFlags(f)
    }
}

impl Into<u64> for ServiceFlags {
    fn into(self) -> u64 {
        self.0
    }
}

impl ops::BitOr for ServiceFlags {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl ops::BitOrAssign for ServiceFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.add(rhs);
    }
}

impl ops::BitXor for ServiceFlags {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self {
        self.remove(rhs)
    }
}

impl ops::BitXorAssign for ServiceFlags {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.remove(rhs);
    }
}

impl Encodable for ServiceFlags {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        self.0.consensus_encode(&mut s)
    }
}

impl Decodable for ServiceFlags {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        Ok(ServiceFlags(Decodable::consensus_decode(&mut d)?))
    }
}

#[cfg(test)]
mod tests {
    use super::{Network, ServiceFlags};
    use consensus::encode::{deserialize, serialize};

    #[test]
    fn serialize_test() {
        assert_eq!(
            serialize(&Network::Mainnet.magic()),
            &[0xd3, 0xf2, 0x6e, 0x5b]
        );
        assert_eq!(
            serialize(&Network::Testnet.magic()),
            &[0xd2, 0x0d, 0x52, 0xb1]
        );
        assert_eq!(
            serialize(&Network::Simnet.magic()),
            &[0xdc, 0x8e, 0x64, 0x0e]
        );
        assert_eq!(
            serialize(&Network::Regtest.magic()),
            &[0xcf, 0x95, 0x38, 0xae]
        );

        assert_eq!(
            deserialize(&[0xd3, 0xf2, 0x6e, 0x5b]).ok(),
            Some(Network::Mainnet.magic())
        );
        assert_eq!(
            deserialize(&[0xd2, 0x0d, 0x52, 0xb1]).ok(),
            Some(Network::Testnet.magic())
        );
        assert_eq!(
            deserialize(&[0xdc, 0x8e, 0x64, 0x0e]).ok(),
            Some(Network::Simnet.magic())
        );
        assert_eq!(
            deserialize(&[0xcf, 0x95, 0x38, 0xae]).ok(),
            Some(Network::Regtest.magic())
        );
    }

    #[test]
    fn string_test() {
        assert_eq!(Network::Mainnet.to_string(), "mainnet");
        assert_eq!(Network::Testnet.to_string(), "testnet");
        assert_eq!(Network::Regtest.to_string(), "regtest");
        assert_eq!(Network::Simnet.to_string(), "simnet");

        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
        assert_eq!("simnet".parse::<Network>().unwrap(), Network::Simnet);
        assert!("fakenet".parse::<Network>().is_err());
    }

    #[test]
    fn service_flags_test() {
        let all = [
            ServiceFlags::NETWORK,
            ServiceFlags::GETUTXO,
            ServiceFlags::BLOOM,
            ServiceFlags::WITNESS,
            ServiceFlags::COMPACT_FILTERS,
            ServiceFlags::NETWORK_LIMITED,
        ];

        let mut flags = ServiceFlags::NONE;
        for f in all.iter() {
            assert!(!flags.has(*f));
        }

        flags |= ServiceFlags::WITNESS;
        assert_eq!(flags, ServiceFlags::WITNESS);

        let mut flags2 = flags | ServiceFlags::GETUTXO;
        for f in all.iter() {
            assert_eq!(
                flags2.has(*f),
                *f == ServiceFlags::WITNESS || *f == ServiceFlags::GETUTXO
            );
        }

        flags2 ^= ServiceFlags::WITNESS;
        assert_eq!(flags2, ServiceFlags::GETUTXO);

        flags2 |= ServiceFlags::COMPACT_FILTERS;
        flags2 ^= ServiceFlags::GETUTXO;
        assert_eq!(flags2, ServiceFlags::COMPACT_FILTERS);

        // Test formatting.
        assert_eq!("ServiceFlags(NONE)", ServiceFlags::NONE.to_string());
        assert_eq!("ServiceFlags(WITNESS)", ServiceFlags::WITNESS.to_string());
        let flag = ServiceFlags::WITNESS | ServiceFlags::BLOOM | ServiceFlags::NETWORK;
        assert_eq!("ServiceFlags(NETWORK|BLOOM|WITNESS)", flag.to_string());
        let flag = ServiceFlags::WITNESS | 0xf0.into();
        assert_eq!(
            "ServiceFlags(WITNESS|COMPACT_FILTERS|0xb0)",
            flag.to_string()
        );
    }
}
