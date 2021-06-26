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

//! Blockdata constants
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction
//!

use core::default::Default;
use std::str::FromStr;

use blockdata::block::{Block, BlockHeader};
use blockdata::transaction::Transaction;
use hash_types::WitnessMerkleNode;
use hashes::blake2b;
use network::constants::Network;
use util::uint::Uint256;

use crate::{Address, OutPoint, TxIn, TxOut};

/// The maximum allowable sequence number
pub const MAX_SEQUENCE: u32 = 0xFFFFFFFF;
/// How many satoshis are in "one bitcoin"
pub const COIN_VALUE: u64 = 100_000_000;
/// How many seconds between blocks we expect on average
pub const TARGET_BLOCK_SPACING: u32 = 600;
/// How many blocks between diffchanges
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges
pub const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;
/// The maximum allowed weight for a block, see BIP 141 (network rule)
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;
/// The factor that non-witness serialization data is multiplied by during weight calculation
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;

/// In Bitcoind this is insanely described as ~((u256)0 >> 32)
pub fn max_target(_: Network) -> Uint256 {
    Uint256::from_u64(0xFFFF).unwrap() << 208
}

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub fn max_money(_: Network) -> u64 {
    21_000_000 * COIN_VALUE
}

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block
fn handshake_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 0,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };

    let witness = vec![
        WitnessMerkleNode::from_str(
            "50b8937fc5def08f9f3cbda7e5f08c706edb80aba5880c000000000000000000",
        )
        .unwrap()
        .to_vec(),
        WitnessMerkleNode::from_str(
            "2d5de58609d4970fb548f85ad07a87db40e054e34cc81c951ca995a58f674db7",
        )
        .unwrap()
        .to_vec(),
        WitnessMerkleNode::from_str(
            "10d748eda1b9c67b94d3244e0211677618a9b4b329e896ad90431f9f48034bad",
        )
        .unwrap()
        .to_vec(),
        WitnessMerkleNode::from_str(
            "e2c0299a1e466773516655f09a64b1e16b2579530de6c4a59ce5654dea45180f",
        )
        .unwrap()
        .to_vec(),
    ];

    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        sequence: MAX_SEQUENCE,
        witness,
    });

    let address = Address::from_str("hs1q7q3h4chglps004u3yn79z0cp9ed24rfr5ka9n5").unwrap();

    ret.output.push(TxOut {
        value: 2002210000,
        address,
        covenant: Default::default(),
    });
    // Inputs
    // let in_script = script::Builder::new()
    //     .push_scriptint(486604799)
    //     .push_scriptint(4)
    //     .push_slice(b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")
    //     .into_script();
    // ret.input.push(TxIn {
    //     previous_output: OutPoint::null(),
    //     script_sig: in_script,
    //     sequence: MAX_SEQUENCE,
    //     witness: vec![],
    // });

    // // Outputs
    // let out_script = script::Builder::new()
    //     .push_slice(&Vec::from_hex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f").unwrap())
    //     .push_opcode(opcodes::all::OP_CHECKSIG)
    //     .into_script();
    // ret.output.push(TxOut {
    //     value: 50 * COIN_VALUE,
    //     script_pubkey: out_script,
    // });

    // end
    ret
}

/// Constructs and returns the genesis block
pub fn genesis_block(network: Network) -> Block {
    let decoded_tx = handshake_genesis_tx();
    let decoded_txs = vec![decoded_tx];
    let hash: blake2b::Hash = decoded_txs[0].txid().into();
    let merkle_root = hash.into();
    let witness_root = WitnessMerkleNode::from_str(
        "1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351",
    )
    .unwrap();

    match network {
        Network::Mainnet => Block {
            header: BlockHeader {
                version: 0,
                prev_blockhash: Default::default(),
                merkle_root,
                witness_root,
                tree_root: Default::default(),
                reserved_root: Default::default(),
                time: 1580745078,
                bits: 0x1c00ffff,
                nonce: Default::default(),
                extra_nonce: Default::default(),
                mask: Default::default(),
            },
            txdata: decoded_txs,
        },
        Network::Testnet => Block {
            header: BlockHeader {
                version: 0,
                prev_blockhash: Default::default(),
                merkle_root,
                witness_root,
                tree_root: Default::default(),
                reserved_root: Default::default(),
                time: 1580745079,
                bits: 0x1d00ffff,
                nonce: 0x00000000,
                extra_nonce: Default::default(),
                mask: Default::default(),
            },
            txdata: decoded_txs,
        },
        Network::Simnet => Block {
            header: BlockHeader {
                version: 0,
                prev_blockhash: Default::default(),
                merkle_root,
                witness_root,
                tree_root: Default::default(),
                reserved_root: Default::default(),
                time: 1580745081,
                bits: 0x207fffff,
                nonce: 0x00000000,
                extra_nonce: Default::default(),
                mask: Default::default(),
            },
            txdata: decoded_txs,
        },
        Network::Regtest => Block {
            header: BlockHeader {
                version: 0,
                prev_blockhash: Default::default(),
                merkle_root,
                witness_root,
                tree_root: Default::default(),
                reserved_root: Default::default(),
                time: 1580745080,
                bits: 0x207fffff,
                nonce: 0x00000000,
                extra_nonce: Default::default(),
                mask: Default::default(),
            },
            txdata: decoded_txs,
        },
    }
}

#[cfg(test)]
mod test {
    use core::default::Default;

    use blockdata::constants::genesis_block;
    use network::constants::Network;

    // #[test]
    // fn mainnet_genesis_first_transaction() {
    //     let gen = bitcoin_genesis_tx();

    //     assert_eq!(gen.version, 1);
    //     assert_eq!(gen.input.len(), 1);
    //     assert_eq!(gen.input[0].previous_output.txid, Default::default());
    //     assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
    //     assert_eq!(serialize(&gen.input[0].script_sig),
    //                Vec::from_hex("4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap());

    //     assert_eq!(gen.input[0].sequence, MAX_SEQUENCE);
    //     assert_eq!(gen.output.len(), 1);
    //     assert_eq!(serialize(&gen.output[0].script_pubkey),
    //                Vec::from_hex("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap());
    //     assert_eq!(gen.output[0].value, 50 * COIN_VALUE);
    //     assert_eq!(gen.lock_time, 0);

    //     assert_eq!(
    //         format!("{:x}", gen.wtxid()),
    //         "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string()
    //     );
    // }
    #[test]
    fn mainnet_genesis_full_block() {
        let gen = genesis_block(Network::Mainnet);

        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(
            format!("{:x}", gen.header.merkle_root),
            "8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15".to_string()
        );
        assert_eq!(gen.header.time, 1580745078);
        assert_eq!(gen.header.bits, 0x1c00ffff);
        assert_eq!(gen.header.nonce, 0x00000000);
        assert_eq!(
            format!("{:x}", gen.header.block_hash()),
            "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0".to_string()
        );
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(
            format!("{:x}", gen.header.merkle_root),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string()
        );
        assert_eq!(gen.header.time, 1296688602);
        assert_eq!(gen.header.bits, 0x1d00ffff);
        assert_eq!(gen.header.nonce, 414098458);
        assert_eq!(
            format!("{:x}", gen.header.block_hash()),
            "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943".to_string()
        );
    }

    #[test]
    fn signet_genesis_full_block() {
        let gen = genesis_block(Network::Simnet);
        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(
            format!("{:x}", gen.header.merkle_root),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".to_string()
        );
        assert_eq!(gen.header.time, 1598918400);
        assert_eq!(gen.header.bits, 0x1e0377ae);
        assert_eq!(gen.header.nonce, 52613770);
        assert_eq!(
            format!("{:x}", gen.header.block_hash()),
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6".to_string()
        );
    }
}
