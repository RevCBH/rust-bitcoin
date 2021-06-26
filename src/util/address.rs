// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Addresses
//!
//! Support for ordinary base58 Bitcoin addresses and private keys
//!
//! # Example: creating a new address from a randomly-generated key pair
//!
//! ```rust
//!
//! use handshake::network::constants::Network;
//! use handshake::util::address::Address;
//! use handshake::util::ecdsa;
//! use handshake::secp256k1::Secp256k1;
//! use handshake::secp256k1::rand::thread_rng;
//!
//! // Generate random key pair
//! let s = Secp256k1::new();
//! let public_key = ecdsa::PublicKey::new(s.generate_keypair(&mut thread_rng()).1);
//!
//! // Generate pay-to-pubkey-hash address
//! let address = Address::p2pkh(&public_key, Network::Bitcoin);
//! ```

use core::fmt;
use core::str::FromStr;
use std::error;

use bech32;
use blockdata::script;
use consensus::{encode, Decodable, Encodable};
use hash_types::{WPubkeyHash, WScriptHash};
use hashes::Hash;
use network::constants::Network;
use util::ecdsa;

use crate::consensus::ReadExt;

/// Address error.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum Error {
    /// The address wasn't Bech32
    Bech32Required,
    /// Bech32 encoding error
    Bech32(bech32::Error),
    /// The bech32 payload was empty
    EmptyBech32Payload,
    /// Script version must be 0 to 16 inclusive
    InvalidWitnessVersion(u8),
    /// The witness program must be between 2 and 40 bytes in length.
    InvalidWitnessProgramLength(usize),
    /// A v0 witness program must be either of length 20 or 32.
    InvalidSegwitV0ProgramLength(usize),
    /// An uncompressed pubkey was used where it is not allowed.
    UncompressedPubkey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Bech32Required => write!(f, "the address wasn't bech32"),
            Error::Bech32(ref e) => write!(f, "bech32: {}", e),
            Error::EmptyBech32Payload => write!(f, "the bech32 payload was empty"),
            Error::InvalidWitnessVersion(v) => write!(f, "invalid witness script version: {}", v),
            Error::InvalidWitnessProgramLength(l) => write!(
                f,
                "the witness program must be between 2 and 40 bytes in length: length={}",
                l,
            ),
            Error::InvalidSegwitV0ProgramLength(l) => write!(
                f,
                "a v0 witness program must be either of length 20 or 32 bytes: length={}",
                l,
            ),
            Error::UncompressedPubkey => {
                write!(f, "an uncompressed pubkey was used where it is not allowed",)
            }
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Bech32(ref e) => Some(e),
            _ => None,
        }
    }
}

#[doc(hidden)]
impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Error {
        Error::Bech32(e)
    }
}

/// The different types of addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressType {
    /// pay-to-witness-pubkey-hash
    P2wpkh,
    /// pay-to-witness-script-hash
    P2wsh,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            AddressType::P2wpkh => "p2wpkh",
            AddressType::P2wsh => "p2wsh",
        })
    }
}

impl FromStr for AddressType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2wpkh" => Ok(AddressType::P2wpkh),
            "p2wsh" => Ok(AddressType::P2wsh),
            _ => Err(()),
        }
    }
}

/// The method used to produce an address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Payload {
    /// Segwit addresses
    WitnessProgram {
        /// The witness program version
        version: bech32::u5,
        /// The witness program
        program: Vec<u8>,
    },
}

impl Default for Payload {
    fn default() -> Self {
        return Payload::WitnessProgram {
            version: Default::default(),
            program: Default::default(),
        };
    }
}

impl Payload {
    /// Get a [Payload] from an output script (scriptPubkey).
    pub fn from_script(script: &script::Script) -> Option<Payload> {
        Some(if script.is_witness_program() {
            // We can unwrap the u5 check and assume script length
            // because [Script::is_witness_program] makes sure of this.
            Payload::WitnessProgram {
                version: {
                    // Since we passed the [is_witness_program] check,
                    // the first byte is either 0x00 or 0x50 + version.
                    let mut verop = script.as_bytes()[0];
                    if verop > 0x50 {
                        verop -= 0x50;
                    }
                    bech32::u5::try_from_u8(verop).expect("checked before")
                },
                program: script.as_bytes()[2..].to_vec(),
            }
        } else {
            return None;
        })
    }

    /// Generates a script pubkey spending to this [Payload].
    pub fn script_pubkey(&self) -> script::Script {
        match *self {
            Payload::WitnessProgram {
                version: ver,
                program: ref prog,
            } => script::Script::new_witness_program(ver, prog),
        }
    }

    /// The size of the payload in bytes
    pub fn size_in_bytes(&self) -> usize {
        match *self {
            Payload::WitnessProgram {
                version: _,
                program: ref prog,
            } => return 1 + prog.len(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
/// A Bitcoin address
pub struct Address {
    /// The type of the address
    pub payload: Payload,
    /// The network on which this address is usable
    pub network: Network,
}
serde_string_impl!(Address, "a Bitcoin address");

impl Encodable for Address {
    fn consensus_encode<W: std::io::Write>(&self, mut writer: W) -> Result<usize, std::io::Error> {
        match &self.payload {
            Payload::WitnessProgram { version, program } => {
                let len = writer.write(&[version.to_u8(), program.len() as u8])?;
                return Ok(len + writer.write(program.as_slice())?);
            }
        }
    }
}

impl Decodable for Address {
    fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version_byte = d.read_u8()?;
        let version = bech32::u5::try_from_u8(version_byte)
            .or(Err(encode::Error::ParseFailed("invalid version byte")))?;

        let size = d.read_u8()?;
        if size < 2 || size > 40 {
            return Err(encode::Error::ParseFailed("invalid program size"));
        }
        let mut hash = vec![0_u8; size as usize];
        d.read(hash.as_mut_slice())?;

        return Ok(Address {
            payload: Payload::WitnessProgram {
                version,
                program: hash,
            },
            network: Default::default(),
        });
    }
}

impl Address {
    /// Create a witness pay to public key address from a public key
    /// This is the native segwit address type for an output redeemable with a single signature
    ///
    /// Will only return an Error when an uncompressed public key is provided.
    pub fn p2wpkh(pk: &ecdsa::PublicKey, network: Network) -> Result<Address, Error> {
        if !pk.compressed {
            return Err(Error::UncompressedPubkey);
        }

        let mut hash_engine = WPubkeyHash::engine();
        pk.write_into(&mut hash_engine)
            .expect("engines don't error");

        Ok(Address {
            network: network,
            payload: Payload::WitnessProgram {
                version: bech32::u5::try_from_u8(0).expect("0<32"),
                program: WPubkeyHash::from_engine(hash_engine)[..].to_vec(),
            },
        })
    }

    /// Create a witness pay to script hash address
    pub fn p2wsh(script: &script::Script, network: Network) -> Address {
        Address {
            network: network,
            payload: Payload::WitnessProgram {
                version: bech32::u5::try_from_u8(0).expect("0<32"),
                program: WScriptHash::hash(&script[..])[..].to_vec(),
            },
        }
    }

    /// Get the address type of the address.
    /// None if unknown or non-standard.
    pub fn address_type(&self) -> Option<AddressType> {
        match self.payload {
            Payload::WitnessProgram {
                version: ver,
                program: ref prog,
            } => {
                // BIP-141 p2wpkh or p2wsh addresses.
                match ver.to_u8() {
                    0 => match prog.len() {
                        20 => Some(AddressType::P2wpkh),
                        32 => Some(AddressType::P2wsh),
                        _ => None,
                    },
                    _ => None,
                }
            }
        }
    }

    /// Check whether or not the address is following Bitcoin
    /// standardness rules.
    ///
    /// Segwit addresses with unassigned witness versions or non-standard
    /// program sizes are considered non-standard.
    pub fn is_standard(&self) -> bool {
        self.address_type().is_some()
    }

    /// Get an [Address] from an output script (scriptPubkey).
    pub fn from_script(script: &script::Script, network: Network) -> Option<Address> {
        Some(Address {
            payload: Payload::from_script(script)?,
            network: network,
        })
    }

    /// Generates a script pubkey spending to this address
    pub fn script_pubkey(&self) -> script::Script {
        self.payload.script_pubkey()
    }

    /// Creates a URI string *handshake:address* optimized to be encoded in QR codes.
    ///
    /// If the address is bech32, both the schema and the address become uppercase.
    ///
    /// Quoting BIP 173 "inside QR codes uppercase SHOULD be used, as those permit the use of
    /// alphanumeric mode, which is 45% more compact than the normal byte mode."
    pub fn to_qr_uri(&self) -> String {
        let schema = match self.payload {
            Payload::WitnessProgram { .. } => "HANDSHAKE",
        };
        format!("{}:{:#}", schema, self)
    }
}

// Alternate formatting `{:#}` is used to return uppercase version of bech32 addresses which should
// be used in QR codes, see [Address::to_qr_uri]
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.payload {
            Payload::WitnessProgram {
                version: ver,
                program: ref prog,
            } => {
                let hrp = match self.network {
                    Network::Mainnet => "hs",
                    Network::Testnet => "ts",
                    Network::Simnet => "ss",
                    Network::Regtest => "rs",
                };
                let bech_ver = if ver.to_u8() > 0 {
                    bech32::Variant::Bech32m
                } else {
                    bech32::Variant::Bech32
                };
                let mut upper_writer;
                let writer = if fmt.alternate() {
                    upper_writer = UpperWriter(fmt);
                    &mut upper_writer as &mut dyn fmt::Write
                } else {
                    fmt as &mut dyn fmt::Write
                };
                let mut bech32_writer = bech32::Bech32Writer::new(hrp, bech_ver, writer)?;
                bech32::WriteBase32::write_u5(&mut bech32_writer, ver)?;
                bech32::ToBase32::write_base32(&prog, &mut bech32_writer)
            }
        }
    }
}

struct UpperWriter<W: fmt::Write>(W);

impl<W: fmt::Write> fmt::Write for UpperWriter<W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            self.0.write_char(c.to_ascii_uppercase())?;
        }
        Ok(())
    }
}

/// Extract the bech32 prefix.
/// Returns the same slice when no prefix is found.
fn find_bech32_prefix(bech32: &str) -> &str {
    // Split at the last occurrence of the separator character '1'.
    match bech32.rfind('1') {
        None => bech32,
        Some(sep) => bech32.split_at(sep).0,
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Address, Error> {
        // try bech32
        let bech32_network = match find_bech32_prefix(s) {
            // note that upper or lowercase is allowed but NOT mixed case
            "hs" | "HS" => Some(Network::Mainnet),
            "ts" | "TS" => Some(Network::Testnet),
            "ss" | "SS" => Some(Network::Simnet),
            "rs" | "RS" => Some(Network::Regtest),
            _ => None,
        };
        if let Some(network) = bech32_network {
            // decode as bech32
            let (_, payload, variant) = bech32::decode(s)?;
            if payload.is_empty() {
                return Err(Error::EmptyBech32Payload);
            }

            // Get the script version and program (converted from 5-bit to 8-bit)
            let (version, program): (bech32::u5, Vec<u8>) = {
                let (v, p5) = payload.split_at(1);
                (v[0], bech32::FromBase32::from_base32(p5)?)
            };

            // Generic segwit checks.
            if version.to_u8() > 16 {
                return Err(Error::InvalidWitnessVersion(version.to_u8()));
            }
            if program.len() < 2 || program.len() > 40 {
                return Err(Error::InvalidWitnessProgramLength(program.len()));
            }

            // Specific segwit v0 check.
            if version.to_u8() == 0 && (program.len() != 20 && program.len() != 32) {
                return Err(Error::InvalidSegwitV0ProgramLength(program.len()));
            }

            // Bech32 encoding check
            if (version.to_u8() > 0 && variant != bech32::Variant::Bech32m)
                || (version.to_u8() == 0 && variant != bech32::Variant::Bech32)
            {
                return Err(Error::InvalidWitnessVersion(version.to_u8()));
            }

            return Ok(Address {
                payload: Payload::WitnessProgram {
                    version: version,
                    program: program,
                },
                network: network,
            });
        }

        return Err(Error::Bech32Required);
    }
}

impl ::std::fmt::Debug for Address {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use hashes::hex::{FromHex, ToHex};

    use blockdata::script::Script;
    use network::constants::Network::Mainnet;
    use util::ecdsa::PublicKey;

    use super::*;

    macro_rules! hex (($hex:expr) => (Vec::from_hex($hex).unwrap()));
    macro_rules! hex_key (($hex:expr) => (PublicKey::from_slice(&hex!($hex)).unwrap()));
    macro_rules! hex_script (($hex:expr) => (Script::from(hex!($hex))));
    // macro_rules! hex_pubkeyhash (($hex:expr) => (PubkeyHash::from_hex(&$hex).unwrap()));
    // macro_rules! hex_scripthash (($hex:expr) => (ScriptHash::from_hex($hex).unwrap()));

    fn roundtrips(addr: &Address) {
        assert_eq!(
            Address::from_str(&addr.to_string()).unwrap(),
            *addr,
            "string round-trip failed for {}",
            addr,
        );
        assert_eq!(
            Address::from_script(&addr.script_pubkey(), addr.network).as_ref(),
            Some(addr),
            "script round-trip failed for {}",
            addr,
        );
        //TODO: add serde roundtrip after no-strason PR
    }

    #[test]
    fn test_p2wpkh() {
        // stolen from Bitcoin transaction: b3c8c2b6cfc335abbcb2c7823a8453f55d64b2b5125a9a61e8737230cdb8ce20
        let mut key =
            hex_key!("033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc");
        let addr = Address::p2wpkh(&key, Mainnet).unwrap();
        assert_eq!(
            &addr.to_string(),
            "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw"
        );
        assert_eq!(addr.address_type(), Some(AddressType::P2wpkh));
        roundtrips(&addr);

        // Test uncompressed pubkey
        key.compressed = false;
        assert_eq!(
            Address::p2wpkh(&key, Mainnet),
            Err(Error::UncompressedPubkey)
        );
    }

    #[test]
    fn test_p2wsh() {
        // stolen from Bitcoin transaction 5df912fda4becb1c29e928bec8d64d93e9ba8efa9b5b405bd683c86fd2c65667
        let script = hex_script!("52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae");
        let addr = Address::p2wsh(&script, Mainnet);
        assert_eq!(
            &addr.to_string(),
            "hs1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxs5tf0qk"
        );
        assert_eq!(addr.address_type(), Some(AddressType::P2wsh));
        roundtrips(&addr);
    }

    #[test]
    fn test_non_existent_segwit_version() {
        let version = 13;
        // 40-byte program
        let program = hex!(
            "654f6ea368e0acdfd92976b7c2103a1b26313f430654f6ea368e0acdfd92976b7c2103a1b26313f4"
        );
        let addr = Address {
            payload: Payload::WitnessProgram {
                version: bech32::u5::try_from_u8(version).expect("0<32"),
                program: program,
            },
            network: Network::Mainnet,
        };
        roundtrips(&addr);
    }

    #[test]
    fn test_bip173_350_vectors() {
        // Test vectors valid under both BIP-173 and BIP-350
        let valid_vectors = [
            ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
            // ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
            // ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"),
            // ("BC1SW50QGDZ25J", "6002751e"),
            // ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323"),
            // ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
            // ("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
            // ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        ];
        for vector in &valid_vectors {
            let addr: Address = vector.0.parse().unwrap();
            assert_eq!(&addr.script_pubkey().as_bytes().to_hex(), vector.1);
            roundtrips(&addr);
        }

        let invalid_vectors = [
            // // 1. BIP-350 test vectors
            // // Invalid human-readable part
            "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
            // // Invalid checksums (Bech32 instead of Bech32m):
            // "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
            // "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
            // "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
            // "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
            // "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
            // // Invalid character in checksum
            // "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
            // // Invalid witness version
            // "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
            // // Invalid program length (1 byte)
            // "bc1pw5dgrnzv",
            // // Invalid program length (41 bytes)
            // "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
            // // Invalid program length for witness version 0 (per BIP141)
            // "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            // // Mixed case
            // "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
            // // zero padding of more than 4 bits
            // "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
            // // Non-zero padding in 8-to-5 conversion
            // "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
            // // Empty data section
            // "bc1gmk9yu",
            // // 2. BIP-173 test vectors
            // // Invalid human-readable part
            // "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
            // // Invalid checksum
            // "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            // // Invalid witness version
            // "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            // // Invalid program length
            // "bc1rw5uspcuh",
            // // Invalid program length
            // "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            // // Invalid program length for witness version 0 (per BIP141)
            // "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            // // Mixed case
            // "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            // // zero padding of more than 4 bits
            // "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
            // // Non-zero padding in 8-to-5 conversion
            // "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
            // // Final test for empty data section is the same as above in BIP-350

            // // 3. BIP-173 valid test vectors obsolete by BIP-350
            // "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
            // "BC1SW50QA3JX3S",
            // "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
        ];
        for vector in &invalid_vectors {
            assert!(vector.parse::<Address>().is_err());
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_json_serialize() {
        use serde_json;

        let addr = Address::from_str("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("76a914162c5ea71c0b23f5b9022ef047c4a86470a5b07088ac")
        );

        let addr = Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("a914162c5ea71c0b23f5b9022ef047c4a86470a5b07087")
        );

        let addr =
            Address::from_str("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7")
                .unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String(
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_owned()
            )
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
        );

        let addr = Address::from_str("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl").unwrap();
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(
            json,
            serde_json::Value::String("bcrt1q2nfxmhd4n3c8834pj72xagvyr9gl57n5r94fsl".to_owned())
        );
        let into: Address = serde_json::from_value(json).unwrap();
        assert_eq!(addr.to_string(), into.to_string());
        assert_eq!(
            into.script_pubkey(),
            hex_script!("001454d26dddb59c7073c6a197946ea1841951fa7a74")
        );
    }

    #[test]
    fn test_qr_string() {
        for el in [
            "hs1qqzlmrc6phwz2drwshstcr30vuhjacv5z0u2x9l",
            "hs1qktkqg2474ue26l3w22rqlgqm0d980szelepvhm",
        ]
        .iter()
        {
            let addr = Address::from_str(el).unwrap();
            assert_eq!(
                addr.to_qr_uri(),
                format!("HANDSHAKE:{}", el.to_ascii_uppercase())
            );
        }
    }
}
