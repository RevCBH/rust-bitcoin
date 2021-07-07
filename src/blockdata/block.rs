// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! Bitcoin Block
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use core::fmt;
use std::io::Write;

use blockdata::constants::{max_target, WITNESS_SCALE_FACTOR};
use blockdata::transaction::Transaction;
use consensus::encode::Encodable;
use hash_types::{BlockHash, NameTreeMerkleNode, TxMerkleNode, WitnessMerkleNode, Wtxid};
use hashes::Hash;
use network::constants::Network;
use util;
use util::hash::handshake_merkle_root;
use util::uint::Uint256;
use util::Error::{BlockBadProofOfWork, BlockBadTarget};
use VarInt;

use super::hashes::{blake2b512, sha3};

struct BlockSubheader {
    // Subheader
    /// The extra nonce ... TODO explain
    pub extra_nonce: [u8; 24],
    /// The root hash of the reserved name tree
    pub reserved_root: NameTreeMerkleNode,
    /// The root hash of the witness tree
    pub witness_root: WitnessMerkleNode,
    /// The root hash of the merkle tree of transactions in the block
    pub merkle_root: TxMerkleNode,

    /// The protocol version. Should always be 0.
    pub version: i32,
    /// The target value below which the blockhash must lie, encoded as a
    /// a float (with well-defined rounding, of course)
    pub bits: u32,
}

impl_consensus_encoding!(
    BlockSubheader,
    extra_nonce,
    reserved_root,
    witness_root,
    merkle_root,
    version,
    bits
);

/// A block header, which contains all the block's information except
/// the actual transactions
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BlockHeader {
    // Preheader
    /// The nonce, selected to obtain a low enough blockhash
    pub nonce: u32,
    /// The timestamp of the block, as claimed by the miner
    pub time: u64,
    /// Reference to the previous block in the chain
    pub prev_blockhash: BlockHash,
    /// The root hash of the name tree
    pub tree_root: NameTreeMerkleNode,

    // Subheader
    /// The extra nonce ... TODO explain
    pub extra_nonce: [u8; 24],
    /// The root hash of the reserved name tree
    pub reserved_root: NameTreeMerkleNode,
    /// The root hash of the witness tree
    pub witness_root: WitnessMerkleNode,
    /// The root hash of the merkle tree of transactions in the block
    pub merkle_root: TxMerkleNode,

    /// The protocol version. Should always be 0.
    pub version: i32,
    /// The target value below which the blockhash must lie, encoded as a
    /// a float (with well-defined rounding, of course)
    pub bits: u32,

    // Mask
    /// The mask ... TODO explain
    pub mask: [u8; 32],
}

impl_consensus_encoding!(
    BlockHeader,
    nonce,
    time,
    prev_blockhash,
    tree_root,
    extra_nonce,
    reserved_root,
    witness_root,
    merkle_root,
    version,
    bits,
    mask
);

impl BlockSubheader {
    fn hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.consensus_encode(&mut engine)
            .expect("engines don't error");
        BlockHash::from_engine(engine)
    }
}

impl BlockHeader {
    /// Return the block hash.
    pub fn block_hash(&self) -> BlockHash {
        let prehead = self.preheader_hash_bytes();
        let left = blake2b512::digest(&prehead);
        let right = sha3::multi(vec![&prehead, &self.padding(8)]);

        let mut engine = BlockHash::engine();
        engine.write(left.as_slice()).expect("engines don't error");
        engine
            .write(self.padding(32).as_slice())
            .expect("engines don't error");
        engine.write(right.as_slice()).expect("engines don't error");
        let mut hash_vec = BlockHash::from_engine(engine).to_vec();

        for i in 0..32 {
            hash_vec[i] ^= self.mask[i];
        }

        BlockHash::from_slice(hash_vec.as_slice()).expect("hash from vec failed")
    }

    fn preheader_hash_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        self.nonce
            .consensus_encode(&mut result)
            .expect("Vec don't error");
        self.time
            .consensus_encode(&mut result)
            .expect("Vec don't error");
        result
            .write(self.padding(20).as_slice())
            .expect("Vec don't error");
        self.prev_blockhash
            .consensus_encode(&mut result)
            .expect("Vec don't error");
        self.tree_root
            .consensus_encode(&mut result)
            .expect("Vec don't error");
        self.commit_hash()
            .consensus_encode(&mut result)
            .expect("Vec don't error");

        if result.len() != 128 {
            panic!("Invalid number of prehead hash bytes: {}", result.len());
        }

        return result;
    }

    fn subheader(&self) -> BlockSubheader {
        BlockSubheader {
            bits: self.bits,
            extra_nonce: self.extra_nonce,
            merkle_root: self.merkle_root,
            reserved_root: self.reserved_root,
            version: self.version,
            witness_root: self.witness_root,
        }
    }

    fn commit_hash(&self) -> hashes::blake2b::Hash {
        let mut engine: hashes::blake2b::HashEngine = hashes::blake2b::Hash::engine();
        self.subheader()
            .hash()
            .consensus_encode(&mut engine)
            .expect("engines don't error");
        self.mask_hash()
            .consensus_encode(&mut engine)
            .expect("engines don't error");
        return hashes::blake2b::Hash::from_engine(engine);
    }

    fn mask_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.prev_blockhash
            .consensus_encode(&mut engine)
            .expect("engines don't error");
        self.mask
            .consensus_encode(&mut engine)
            .expect("engines don't error");
        BlockHash::from_engine(engine)
    }

    fn padding(&self, size: usize) -> Vec<u8> {
        let mut pad: Vec<u8> = vec![0; size];
        let prev_blockhash = self.prev_blockhash.to_vec();
        let tree_root = self.tree_root.to_vec();
        for i in 0..size {
            pad[i] = prev_blockhash[i % 32] ^ tree_root[i % 32];
        }

        return pad;
    }

    /// Computes the target [0, T] that a blockhash must land in to be valid
    pub fn target(&self) -> Uint256 {
        Self::u256_from_compact_target(self.bits)
    }

    /// Computes the target value in [`Uint256`] format, from a compact representation.
    ///
    /// [`Uint256`]: ../../util/uint/struct.Uint256.html
    ///
    /// ```
    /// use bitcoin::blockdata::block::BlockHeader;
    ///
    /// assert_eq!(0x1d00ffff,
    ///     BlockHeader::compact_target_from_u256(
    ///         &BlockHeader::u256_from_compact_target(0x1d00ffff)
    ///     )
    /// );
    /// ```
    pub fn u256_from_compact_target(bits: u32) -> Uint256 {
        // This is a floating-point "compact" encoding originally used by
        // OpenSSL, which satoshi put into consensus code, so we're stuck
        // with it. The exponent needs to have 3 subtracted from it, hence
        // this goofy decoding code:
        let (mant, expt) = {
            let unshifted_expt = bits >> 24;
            if unshifted_expt <= 3 {
                ((bits & 0xFFFFFF) >> (8 * (3 - unshifted_expt as usize)), 0)
            } else {
                (bits & 0xFFFFFF, 8 * ((bits >> 24) - 3))
            }
        };

        // The mantissa is signed but may not be negative
        if mant > 0x7FFFFF {
            Default::default()
        } else {
            Uint256::from_u64(mant as u64).unwrap() << (expt as usize)
        }
    }

    /// Computes the target value in float format from Uint256 format.
    pub fn compact_target_from_u256(value: &Uint256) -> u32 {
        let mut size = (value.bits() + 7) / 8;
        let mut compact = if size <= 3 {
            (value.low_u64() << (8 * (3 - size))) as u32
        } else {
            let bn = *value >> (8 * (size - 3));
            bn.low_u32()
        };

        if (compact & 0x00800000) != 0 {
            compact >>= 8;
            size += 1;
        }

        compact | (size << 24) as u32
    }

    /// Compute the popular "difficulty" measure for mining
    pub fn difficulty(&self, network: Network) -> u64 {
        (max_target(network) / self.target()).low_u64()
    }

    /// Checks that the proof-of-work for the block is valid, returning the block hash.
    /// TODO - fix byte ordering
    pub fn validate_pow(&self, required_target: &Uint256) -> Result<BlockHash, util::Error> {
        let target = &self.target();
        if target != required_target {
            return Err(BlockBadTarget);
        }
        let block_hash = self.block_hash();
        let mut ret = [0u64; 4];
        util::endian::bytes_to_u64_slice_le(block_hash.as_inner(), &mut ret);
        let hash = &Uint256(ret);
        if hash <= target {
            Ok(block_hash)
        } else {
            Err(BlockBadProofOfWork)
        }
    }

    /// Returns the total work of the block
    pub fn work(&self) -> Uint256 {
        // 2**256 / (target + 1) == ~target / (target+1) + 1    (eqn shamelessly stolen from bitcoind)
        let mut ret = !self.target();
        let mut ret1 = self.target();
        ret1.increment();
        ret = ret / ret1;
        ret.increment();
        ret
    }
}

/// A Bitcoin block, which is a collection of transactions with an attached
/// proof of work.
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Block {
    /// The block header
    pub header: BlockHeader,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>,
}

impl_consensus_encoding!(Block, header, txdata);

impl Block {
    /// Return the block hash.
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// check if merkle root of header matches merkle root of the transaction list
    pub fn check_merkle_root(&self) -> bool {
        self.header.merkle_root == self.merkle_root()
    }

    /// check if witness commitment in coinbase is matching the transaction list
    pub fn check_witness_commitment(&self) -> bool {
        if !self.txdata.is_empty() {
            let coinbase = &self.txdata[0];
            if coinbase.is_coin_base() {
                return self.header.witness_root == self.witness_root();
            }
        }
        false
    }

    /// Calculate the transaction merkle root.
    pub fn merkle_root(&self) -> TxMerkleNode {
        let hashes = self.txdata.iter().map(|obj| obj.txid().as_hash());
        handshake_merkle_root(hashes).into()
    }

    /// Merkle root of transactions hashed for witness
    pub fn witness_root(&self) -> WitnessMerkleNode {
        let hashes = self.txdata.iter().enumerate().map(|(i, t)| {
            if i == 0 {
                // Replace the first hash with zeroes.
                Wtxid::default().as_hash()
            } else {
                t.wtxid().as_hash()
            }
        });
        handshake_merkle_root(hashes).into()
    }

    /// Get the size of the block
    pub fn get_size(&self) -> usize {
        // The size of the header + the size of the varint with the tx count + the txs themselves
        let base_size = 80 + VarInt(self.txdata.len() as u64).len();
        let txs_size: usize = self.txdata.iter().map(Transaction::get_size).sum();
        base_size + txs_size
    }

    /// Get the weight of the block
    pub fn get_weight(&self) -> usize {
        let base_weight = WITNESS_SCALE_FACTOR * (80 + VarInt(self.txdata.len() as u64).len());
        let txs_weight: usize = self.txdata.iter().map(Transaction::get_weight).sum();
        base_weight + txs_weight
    }

    /// Get the coinbase transaction, if one is present.
    pub fn coinbase(&self) -> Option<&Transaction> {
        self.txdata.first()
    }

    /// Get the block height as encoded into the coinbase.
    /// Returns [Err<Bip34Error::NotPresent>] if not present.
    ///
    /// see "Coinbase transactions" at https://hsd-dev.org/guides/protocol.html
    #[deprecated(
        since = "0.1.0",
        note = "Handshake doesn't have script sig, so technically can't implement BIP34"
    )]
    pub fn bip34_block_height(&self) -> Result<u32, Bip34Error> {
        return self
            .coinbase()
            .map(|cb| cb.lock_time)
            .ok_or(Bip34Error::NotPresent);
    }
}

/// An error when looking up a BIP34 block height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bip34Error {
    /// The block does not support BIP34 yet.
    Unsupported,
    /// No push was present where the BIP34 push was expected.
    NotPresent,
    /// The BIP34 push was larger than 8 bytes.
    UnexpectedPush(Vec<u8>),
}

impl fmt::Display for Bip34Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Bip34Error::Unsupported => write!(f, "block doesn't support BIP34"),
            Bip34Error::NotPresent => write!(f, "BIP34 push not present in block's coinbase"),
            Bip34Error::UnexpectedPush(ref p) => {
                write!(f, "unexpected byte push of > 8 bytes: {:?}", p)
            }
        }
    }
}

impl ::std::error::Error for Bip34Error {}

#[cfg(test)]
mod tests {
    use blockdata::block::{Block, BlockHeader};
    use consensus::encode::deserialize;
    use hashes::hex::{FromHex, ToHex};
    use util::uint::Uint256;
    use util::Error::{BlockBadProofOfWork, BlockBadTarget};

    use crate::{fixture_hex, fixture_json};

    #[test]
    fn test_header_hash() {
        const EXPECTED_HASH: &str =
            "000000000000000004579eb1e48fd35ad3d02b6065fad0c9067763ce15c59455";
        let block_header: BlockHeader =
            fixture_hex(format!("block_header_{}.hex", EXPECTED_HASH).as_str()).unwrap();

        assert_eq!(block_header.block_hash().to_hex(), EXPECTED_HASH);
    }

    #[test]
    fn test_deserialize_genesis() {
        let block_hex = "\
        00000000\
        7641385e00000000\
        0000000000000000000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000\
        000000000000000000000000000000000000000000000000\
        0000000000000000000000000000000000000000000000000000000000000000\
        1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351\
        8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15\
        00000000\
        ffff001c\
        0000000000000000000000000000000000000000000000000000000000000000\
        0100000000010000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff01d04c5777000000000014f0237ae2e8f860f7d79124fc513f012e5aaa8d23000000000000042050b8937fc5def08f9f3cbda7e5f08c706edb80aba5880c000000000000000000202d5de58609d4970fb548f85ad07a87db40e054e34cc81c951ca995a58f674db72010d748eda1b9c67b94d3244e0211677618a9b4b329e896ad90431f9f48034bad20e2c0299a1e466773516655f09a64b1e16b2579530de6c4a59ce5654dea45180f";

        let block: Block = deserialize(&Vec::<u8>::from_hex(block_hex).unwrap()).unwrap();
        assert_eq!(
            block.header.nonce, 0,
            "invalid nonce: {}",
            block.header.nonce
        );
        assert_eq!(
            block.header.time.to_hex(),
            "5e384176",
            "invalid time: {}",
            block.header.time.to_hex()
        );
        assert_eq!(
            block.header.prev_blockhash.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            block.header.tree_root.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            block.header.extra_nonce.to_hex(),
            "000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            block.header.reserved_root.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            block.header.witness_root.to_hex(),
            "1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351"
        );
        assert_eq!(
            block.header.merkle_root.to_hex(),
            "8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15"
        );
        assert_eq!(
            block.header.version, 0,
            "invalid version: {}",
            block.header.version
        );
        assert_eq!(
            block.header.bits.to_hex(),
            "1c00ffff",
            "invalid bits: {}",
            block.header.bits.to_hex()
        );
        assert_eq!(
            block.header.mask.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000000",
            "invalid mask: {}",
            block.header.mask.to_hex()
        );
        assert_eq!(block.txdata.len(), 1);
        let tx = &block.txdata[0];
        assert_eq!(
            tx.txid().to_hex(),
            "9553240e6f711271cfccf9407c9348996e61cb3bd39adbc2ec258ff940ff22c6",
            "invalid tx[0].id: {}",
            tx.txid().to_hex()
        );
    }

    #[test]
    fn test_deserialize_large_block() {
        let block: Block = fixture_hex("bigblock.hex").unwrap();

        assert_eq!(
            block.header.block_hash().to_hex(),
            "000000000000000004579eb1e48fd35ad3d02b6065fad0c9067763ce15c59455"
        );

        assert_eq!(
            block.header.prev_blockhash.to_hex(),
            "00000000000000006d355e74ace77f831f4831b3d8f618f40ef21f19050584db",
            "invalid block hash: {}",
            block.header.prev_blockhash.to_hex()
        );

        let tx_hashes: Vec<String> = fixture_json("bigblock_tx_hashes.json").unwrap();
        assert_eq!(block.txdata.len(), tx_hashes.len());
        // TODO - fix byte ordering
        // assert_eq!(
        //     block.header.validate_pow(&block.header.target()).unwrap(),
        //     block.block_hash()
        // );

        for i in 0..tx_hashes.len() {
            let tx = &block.txdata[i];
            assert_eq!(
                tx.txid().to_hex(),
                tx_hashes[i],
                "incorrect hash for tx #{}",
                i
            );
        }
    }

    #[test]
    fn test_coinbase_and_bip34() {
        // mainnet block 75,125
        let block: Block = fixture_hex("bigblock.hex").unwrap();

        let cb_txid = "160af1e9305a83fc396d6d992caf4854a5f44f3493e30e06e80cd0cfe877db1c";
        assert_eq!(block.coinbase().unwrap().txid().to_string(), cb_txid);
        assert_eq!(block.bip34_block_height(), Ok(75_125));
    }

    #[test]
    fn validate_pow_test() {
        let some_header = Vec::from_hex("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b").unwrap();
        let some_header: BlockHeader =
            deserialize(&some_header).expect("Can't deserialize correct block header");
        assert_eq!(
            some_header.validate_pow(&some_header.target()).unwrap(),
            some_header.block_hash()
        );

        // test with zero target
        match some_header.validate_pow(&Uint256::default()) {
            Err(BlockBadTarget) => (),
            _ => assert!(false),
        }

        // test with modified header
        let mut invalid_header: BlockHeader = some_header.clone();
        invalid_header.version = invalid_header.version + 1;
        match invalid_header.validate_pow(&invalid_header.target()) {
            Err(BlockBadProofOfWork) => (),
            _ => assert!(false),
        }
    }

    #[test]
    fn compact_roundrtip_test() {
        let header: BlockHeader = fixture_hex(
            "block_header_000000000000000004579eb1e48fd35ad3d02b6065fad0c9067763ce15c59455.hex",
        )
        .unwrap();

        assert_eq!(
            header.bits,
            BlockHeader::compact_target_from_u256(&header.target())
        );
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use super::Block;
    use consensus::{deserialize, Encodable};
    use hashes::hex::FromHex;
    use test::{black_box, Bencher};
    use EmptyWrite;

    const SOME_BLOCK: &'static str = "000000202aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d7490600000000000010bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e5503bd5750d4061a4ed90a700f010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff3603da1b0e00045503bd5704c7dd8a0d0ced13bb5785010800000000000a636b706f6f6c122f4e696e6a61506f6f6c2f5345475749542fffffffff02b4e5a212000000001976a914876fbb82ec05caa6af7a3b5e5a983aae6c6cc6d688ac0000000000000000266a24aa21a9edf91c46b49eb8a29089980f02ee6b57e7d63d33b18b4fddac2bcd7db2a3983704012000000000000000000000000000000000000000000000000000000000000000000000000001000000017e4f81175332a733e26d4ba4e29f53f67b7a5d7c2adebb276e447ca71d130b55000000006b483045022100cac809cd1a3d9ad5d5e31a84e2e1d8ec5542841e4d14c6b52e8b38cbe1ff1728022064470b7fb0c2efeccb2e84bfa36ec5f9e434c84b1101c00f7ee32f726371b7410121020e62280798b6b8c37f068df0915b0865b63fabc401c2457cbc3ef96887dd3647ffffffff02ca2f780c000000001976a914c6b5545b3592cb477d709896fa705592c9b6113a88ac663b2a06000000001976a914e7c1345fc8f87c68170b3aa798a956c2fe6a9eff88ac0000000001000000011e99f5a785e677e017d36b50aa4fd10010ffd039f38f42f447ca8895250e121f01000000d90047304402200d3d296ad641a281dd5c0d68b9ab0d1ad5f7052bec148c1fb81fb1ba69181ec502201a372bb16fb8e054ee9bef41e300d292153830f841a4db0ab7f7407f6581b9bc01473044022002584f313ae990236b6bebb82fbbb006a2b02a448dd5c93434428991eae960d60220491d67d2660c4dde19025cf86e5164a559e2c79c3b98b40e146fab974acd24690147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a9140ffdcf96700455074292a821c74922e8652993998788997bc60000000017a9148ce5408cfeaddb7ccb2545ded41ef478109454848700000000010000000113100b09e6a78d63ec4850654ab0f68806de29710b09172eddfef730652b155501000000da00473044022015389408e3446a3f36a05060e0e4a3c8b92ff3901ba2511aa944ec91a537a1cb022045a33b6ec47605b1718ed2e753263e54918edbf6126508ff039621fb928d28a001483045022100bb952fde81f216f7063575c0bb2bedc050ce08c96d9b437ea922f5eb98c882da02201b7cbf3a2f94ea4c5eb7f0df3af2ebcafa8705af7f410ab5d3d4bac13d6bc6120147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a914d3db9a20312c3ab896a316eb108dbd01e47e17d687e0ba7ac60000000017a9148ce5408cfeaddb7ccb2545ded41ef47810945484870000000001000000016e3cca1599cde54878e2f27f434df69df0afd1f313cb6e38c08d3ffb57f97a6c01000000da0048304502210095623b70ec3194fa4037a1c1106c2580caedc390e25e5b330bbeb3111e8184bc02205ae973c4a4454be2a3a03beb66297143c1044a3c4743742c5cdd1d516a1ad3040147304402202f3d6d89996f5b42773dd6ebaf367f1af1f3a95c7c7b487ec040131c40f4a4a30220524ffbb0b563f37b3eb1341228f792e8f84111b7c4a9f49cdd998e052ee42efa0147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a9141ade6b95896dde8ec4dee9e59af8849d3797348e8728af7ac60000000017a9148ce5408cfeaddb7ccb2545ded41ef47810945484870000000001000000011d9dc3a5df9b5b2eeb2bd11a2db243be9e8cc23e2f180bf317d32a499904c15501000000db00483045022100ebbd1c9a8ce626edbb1a7881df81e872ef8c6424feda36faa8a5745157400c6a02206eb463bc8acd5ea06a289e86115e1daae0c2cf10d9cbbd199e1311170d5543ef01483045022100809411a917dc8cf4f3a777f0388fdea6de06243ef7691e500c60abd1c7f19ae602205255d2b1191d8adedb77b814ccb66471eb8486cb4ff8727824254ee5589f176b0147522102632178d046673c9729d828cfee388e121f497707f810c131e0d3fc0fe0bd66d62103a0951ec7d3a9da9de171617026442fcd30f34d66100fab539853b43f508787d452aeffffffff0240420f000000000017a914759a49c772347be81c49517f9e1e6def6a88d4dd87800b85c60000000017a9148ce5408cfeaddb7ccb2545ded41ef47810945484870000000001000000018c51902affd8e5247dfcc2e5d0528a3815f53c8b6d2c200ff290b2b2b486d7704f0000006a47304402201be0d485f6a3ce871be80064c593c5327b3fd7e450f05ab7fae38385bc40cfbe02206e2a6c9970b5d1d10207892376733757486634fce4f352e772149c486857612101210350c33bc9a790c9495195761577b34912a949b73d5bc5ae5343f5ba08b33220ccffffffff0110270000000000001976a9142ab1c62710a7bdfdb4bb6394bbedc58b32b4d5a388ac0000000001000000018c51902affd8e5247dfcc2e5d0528a3815f53c8b6d2c200ff290b2b2b486d7704e0000006b483045022100ccc8c0ac90bdb0402842aec91830c765cdead7a728552a6a34de7d13a6dab28e02206c96f8640cf3444054e9632b197be30598a09c3d5defcd95750bdb922a60d64801210350c33bc9a790c9495195761577b34912a949b73d5bc5ae5343f5ba08b33220ccffffffff0110270000000000001976a9142ab1c62710a7bdfdb4bb6394bbedc58b32b4d5a388ac0000000001000000011b436669c06cbf3442e21a2fe3edc20cd3cf13c358c53234bc4d88bfd8c4bd2a000000006a47304402204a63410ee13db52c7609ab08e25b7fe3c608cc21cc1755ad13460685eb55193202204cd1ea80c06a81571119be0b8cccd96ef7cdd90f62c1fe2d538622feb08e22ba0121024baa8b67cc9ed8a97d90895e3716b25469b67cb26d3324d7aff213f507764765ffffffff010000000000000000306a2e516d64523365345261445653324d436a736e536171734a5753324465655446624238354541794a4d5843784c7934000000000100000001be4a95ed36316cada5118b1982e4cb4a07f93e7a4153e227466f1cb0776de995000000006b483045022100a22d5251deea0470806bab817013d675a63cd52218d6e477ab0c9d601d018b7f022042121b46afcdcd0c66f189398212b66085e88c6973ae560f1810c13e55e2bee40121024baa8b67cc9ed8a97d90895e3716b25469b67cb26d3324d7aff213f507764765ffffffff010000000000000000306a2e516d57484d57504e5248515872504c7338554c586b4d483746745356413675366b5a6b4a4e3851796e4e583751340000000001000000016c061a65b49edec21acdbc22f97dc853aa872302aeef13fabf0bf6807de1b8bd010000006b483045022100dd80381f2d158b4dad7f98d2d97317c533fb36e737542473feb05fa74d0b73bb02207097d4331196069167e525b61d132532292fd75cc039a5839c04c2545d427e2b0121035e9a597df8b417bef66811882a2844604fc591c427f642628f0fef46be19a4c9feffffff0280a4bf07000000001976a914573b9106e16ee0b5c143dc40f0724f77dd0e282088ac9533b22c000000001976a9149c4da607efb1d759d33da71778bc6cafa56acb5988acd31b0e0001000000017dae20994b69b28534e5b22f3d7c50f9d7541348cbf6f43fcc654263ebaf8f68000000006b483045022100a85300eb94b24b044877d0b0d61e08e16dbc82ec7d69c723a8a45519f95c35b002203d78376e6bee31b455c097557af7fe4d6b620bc74269e9a75e2aad2b545abddb012103b0d08aba2a5ac6cf2788fda941c386040e35e49d3a57d2aefb16c0438fb98acbfeffffff022222305f000000001976a914cfda30dd836b596db6a9c230c45ae2179107f04888ac80a4bf07000000001976a91442dfcf5823aacb185844e663873c35fb98bfd21b88acd31b0e000100000002ad3e85e4af30678a330f8941ed7a9ca17cd0236368d238cac4e9ff09c466fed1020000006b483045022100d1196c48a0392e09592f1b96b4aec32ab0cecb6fd17b1d0c85ab3250a2fe45d9022059217c82f684fcdecdbe660a2077ea956dfbbb964d2648bc1e8ae0f0fe565449012103b64e32e5f62e03701428fb1e3151e9a57f149c67708f6164a235c8199fe17cc2ffffffff34f0a71c1c2cd610522e9c18c67931cded5e9647d4419c49b99715e2a0795f3d020000006a4730440220316e81d8242abf3c5f885d200feca12c3adb63cf2cd4dc74602f7b8b0cba50340220210d525758df77ccdca6908311c1895275e07bbb29b45963a19252acde55873f012103b64e32e5f62e03701428fb1e3151e9a57f149c67708f6164a235c8199fe17cc2ffffffff0510270000000000001976a914449d2394dde057bc199f23fb8aa2e400f344611788ac10270000000000001976a914449d2394dde057bc199f23fb8aa2e400f344611788aca0860100000000001976a91413d35ad337dd80a055757e5ea0a45b59fee3060c88ac70110100000000001976a91413d35ad337dd80a055757e5ea0a45b59fee3060c88ac0000000000000000026a000000000001000000018e33fecc2ddbd86c5ea919f7bd5a5acf8a09f3e0cdaaaf4f08c5ef095161ef1100000000fdfe0000483045022100d2489b225d39b7d8b6767a6928c8029a2a1297c08fdf00d683ba0c1987e7d7000220176cb66c8a243806bb7421f658325a69a51c82c0c3314e37f2400f33626390210148304502210096cfa57662a545830d0e29610becd41ea031e256339913718ce18dbb1a27bdb00220482911c851d15adcd37097dff99a9ff1f97d953bcebc528835118f447412553e014c695221028d9889862b29430278c084b5c4090b7b807b31e047bcd212ebc2c4e43fc0e3c52103160949a7c8c81f2c25d7763f57eb1cb407d867c5b7c290331bd2dc4b1182c6d32103fbef3b60914bda9173765902013a251ec89450c75d0b5a96a143db1dabf98d9553aeffffffff0220e8891c0100000017a914d996715e081c50f8f6b1b4e7fb6ca214f9924fdf87809698000000000017a9145611d812263f32960228cb5f85329bce4770a218870000000001000000017720507dcbe6c69f652b0c0ce19406f482372d1a8abc05d45fb7acf97fb80eec00000000fdfe00004830450221009821d8e117de44b1202c829c0f5063997acf007cf9b561c6fb8d1212cddb6c40022010ff5067b0d9d4eca2da0ceb876e9a16f1a2142da866d3042a7bae8968813e8001483045022100dea759d14a8a1c5da5f3dcc5509871aaa2c1e3be03752c1b858d80fa4227163702205183d70cc28dcb6df9b037714c8b6442ef84e0ddce07711a30c731e9f0925090014c695221028d70ea66fe7a7def282df7b2b498007e5072933e42c18f63ce85975dcbcf1a8821037e8f842b1e47e21d88002c5aab2559212a4c2c9dbe5ef5347f2a29afd0510ec1210251259cb9fd4f6206488408286e4475c9c9fe887e57a3e32ae4da222778a2aedf53aeffffffff023380cb020000000017a9143b5a7e85b22656a34d43187ac8dd09acd7109d2487809698000000000017a914b9b4b555f594a34deec3ad61d5c5f3738b17ee158700000000";

    #[bench]
    pub fn bench_block_serialize(bh: &mut Bencher) {
        let raw_block = Vec::from_hex(SOME_BLOCK).unwrap();

        let block: Block = deserialize(&raw_block).unwrap();

        let mut data = Vec::with_capacity(raw_block.len());

        bh.iter(|| {
            let result = block.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_block_serialize_logic(bh: &mut Bencher) {
        let raw_block = Vec::from_hex(SOME_BLOCK).unwrap();

        let block: Block = deserialize(&raw_block).unwrap();

        bh.iter(|| {
            let size = block.consensus_encode(&mut EmptyWrite);
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_block_deserialize(bh: &mut Bencher) {
        let raw_block = Vec::from_hex(SOME_BLOCK).unwrap();

        bh.iter(|| {
            let block: Block = deserialize(&raw_block).unwrap();
            black_box(&block);
        });
    }
}
