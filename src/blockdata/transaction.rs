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

//! Bitcoin Transaction
//!
//! A transaction describes a transfer of money. It consumes previously-unspent
//! transaction outputs and produces new ones, satisfying the condition to spend
//! the old outputs (typically a digital signature with a specific key must be
//! provided) and defining the condition to spend the new ones. The use of digital
//! signatures ensures that coins cannot be spent by unauthorized parties.
//!
//! This module provides the structures and functions needed to support transactions.
//!

use core::{default::Default, fmt, str};
use io;
use std::error;

use hashes::hex::FromHex;
use hashes::{self, blake2b, Hash};

use blake2::digest::{Update, VariableOutput};
use blockdata::constants::WITNESS_SCALE_FACTOR;
use blockdata::covenant::Covenant;
use blockdata::script::Script;
use consensus::encode::MAX_VEC_SIZE;
use consensus::{encode, Decodable, Encodable};
use hash_types::{SigHash, Txid, Wtxid};
use util::endian;
use Address;
use VarInt;

/// A reference to a transaction output
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct OutPoint {
    /// The referenced transaction's txid
    pub txid: Txid,
    /// The index of the referenced output in its transaction's vout
    pub vout: u32,
}
serde_struct_human_string_impl!(OutPoint, "an OutPoint", txid, vout);

impl OutPoint {
    /// Create a new [OutPoint].
    #[inline]
    pub fn new(txid: Txid, vout: u32) -> OutPoint {
        OutPoint {
            txid: txid,
            vout: vout,
        }
    }

    /// Creates a "null" `OutPoint`.
    ///
    /// This value is used for coinbase transactions because they don't have
    /// any previous outputs.
    #[inline]
    pub fn null() -> OutPoint {
        OutPoint {
            txid: Default::default(),
            vout: u32::max_value(),
        }
    }

    /// Checks if an `OutPoint` is "null".
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::blockdata::constants::genesis_block;
    /// use bitcoin::network::constants::Network;
    ///
    /// let block = genesis_block(Network::Mainnet);
    /// let tx = &block.txdata[0];
    ///
    /// // Coinbase transactions don't have any previous output.
    /// assert_eq!(tx.input[0].previous_output.is_null(), true);
    /// ```
    #[inline]
    pub fn is_null(&self) -> bool {
        *self == OutPoint::null()
    }
}

impl Default for OutPoint {
    fn default() -> Self {
        OutPoint::null()
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// An error in parsing an OutPoint.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ParseOutPointError {
    /// Error in TXID part.
    Txid(hashes::hex::Error),
    /// Error in vout part.
    Vout(::core::num::ParseIntError),
    /// Error in general format.
    Format,
    /// Size exceeds max.
    TooLong,
    /// Vout part is not strictly numeric without leading zeroes.
    VoutNotCanonical,
}

impl fmt::Display for ParseOutPointError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseOutPointError::Txid(ref e) => write!(f, "error parsing TXID: {}", e),
            ParseOutPointError::Vout(ref e) => write!(f, "error parsing vout: {}", e),
            ParseOutPointError::Format => write!(f, "OutPoint not in <txid>:<vout> format"),
            ParseOutPointError::TooLong => write!(f, "vout should be at most 10 digits"),
            ParseOutPointError::VoutNotCanonical => {
                write!(f, "no leading zeroes or + allowed in vout part")
            }
        }
    }
}

impl error::Error for ParseOutPointError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            ParseOutPointError::Txid(ref e) => Some(e),
            ParseOutPointError::Vout(ref e) => Some(e),
            _ => None,
        }
    }
}

/// Parses a string-encoded transaction index (vout).
/// It does not permit leading zeroes or non-digit characters.
fn parse_vout(s: &str) -> Result<u32, ParseOutPointError> {
    if s.len() > 1 {
        let first = s.chars().next().unwrap();
        if first == '0' || first == '+' {
            return Err(ParseOutPointError::VoutNotCanonical);
        }
    }
    Ok(s.parse().map_err(ParseOutPointError::Vout)?)
}

impl ::core::str::FromStr for OutPoint {
    type Err = ParseOutPointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 75 {
            // 64 + 1 + 10
            return Err(ParseOutPointError::TooLong);
        }
        let find = s.find(':');
        if find == None || find != s.rfind(':') {
            return Err(ParseOutPointError::Format);
        }
        let colon = find.unwrap();
        if colon == 0 || colon == s.len() - 1 {
            return Err(ParseOutPointError::Format);
        }
        Ok(OutPoint {
            txid: Txid::from_hex(&s[..colon]).map_err(ParseOutPointError::Txid)?,
            vout: parse_vout(&s[colon + 1..])?,
        })
    }
}

/// A transaction input, which defines old coins to be consumed
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxIn {
    /// The reference to the previous output that is being used an an input
    pub previous_output: OutPoint,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behaviour cannot be enforced.
    pub sequence: u32,
    /// Witness data: an array of byte-arrays.
    /// Note that this field is *not* (de)serialized with the rest of the TxIn in
    /// Encodable/Decodable, as it is (de)serialized at the end of the full
    /// Transaction. It *is* (de)serialized with the rest of the TxIn in other
    /// (de)serialization routines.
    pub witness: Vec<Vec<u8>>,
}

impl Default for TxIn {
    fn default() -> TxIn {
        TxIn {
            previous_output: OutPoint::default(),
            sequence: u32::max_value(),
            witness: Vec::new(),
        }
    }
}
/// A transaction output, which defines new coins to be created from old ones.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxOut {
    /// The value of the output, in satoshis
    pub value: u64,
    /// The script which must satisfy for the output to be spent
    pub address: Address,
    /// The transaction covenant
    pub covenant: Covenant,
}

// This is used as a "null txout" in consensus signing code
impl Default for TxOut {
    fn default() -> TxOut {
        TxOut {
            value: 0xffffffffffffffff,
            address: Default::default(),
            covenant: Default::default(),
        }
    }
}

// impl_consensus_encoding!(TxOut, value, address, covenant);

/// A Bitcoin transaction, which describes an authenticated movement of coins.
///
/// If any inputs have nonempty witnesses, the entire transaction is serialized
/// in the post-BIP141 Segwit format which includes a list of witnesses. If all
/// inputs have empty witnesses, the transaction is serialized in the pre-BIP141
/// format.
///
/// There is one major exception to this: to avoid deserialization ambiguity,
/// if the transaction has no inputs, it is serialized in the BIP141 style. Be
/// aware that this differs from the transaction format in PSBT, which _never_
/// uses BIP141. (Ordinarily there is no conflict, since in PSBT transactions
/// are always unsigned and therefore their inputs have empty witnesses.)
///
/// The specific ambiguity is that Segwit uses the flag bytes `0001` where an old
/// serializer would read the number of transaction inputs. The old serializer
/// would interpret this as "no inputs, one output", which means the transaction
/// is invalid, and simply reject it. Segwit further specifies that this encoding
/// should *only* be used when some input has a nonempty witness; that is,
/// witness-less transactions should be encoded in the traditional format.
///
/// However, in protocols where transactions may legitimately have 0 inputs, e.g.
/// when parties are cooperatively funding a transaction, the "00 means Segwit"
/// heuristic does not work. Since Segwit requires such a transaction be encoded
/// in the original transaction format (since it has no inputs and therefore
/// no input witnesses), a traditionally encoded transaction may have the `0001`
/// Segwit flag in it, which confuses most Segwit parsers including the one in
/// Bitcoin Core.
///
/// We therefore deviate from the spec by always using the Segwit witness encoding
/// for 0-input transactions, which results in unambiguously parseable transactions.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Transaction {
    /// The protocol version, is currently expected to be 1 or 2 (BIP 68).
    pub version: i32,
    /// Block number before which this transaction is valid, or 0 for
    /// valid immediately.
    pub lock_time: u32,
    /// List of inputs
    pub input: Vec<TxIn>,
    /// List of outputs
    pub output: Vec<TxOut>,
}

impl Transaction {
    /// Computes a "normalized TXID" which does not include any signatures.
    /// This gives a way to identify a transaction that is "the same" as
    /// another in the sense of having same inputs and outputs.
    pub fn ntxid(&self) -> blake2b::Hash {
        let cloned_tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self
                .input
                .iter()
                .map(|txin| TxIn {
                    witness: vec![],
                    ..*txin
                })
                .collect(),
            output: self.output.clone(),
        };
        cloned_tx.txid().into()
    }

    /// Computes the txid. For non-segwit transactions this will be identical
    /// to the output of `wtxid()`, but for segwit transactions,
    /// this will give the correct txid (not including witnesses) while `wtxid`
    /// will also hash witnesses.
    pub fn txid(&self) -> Txid {
        let mut enc = Txid::engine();
        self.version.consensus_encode(&mut enc).unwrap();
        self.input.consensus_encode(&mut enc).unwrap();
        self.output.consensus_encode(&mut enc).unwrap();
        self.lock_time.consensus_encode(&mut enc).unwrap();
        Txid::from_engine(enc)
    }

    /// Computes SegWit-version of the transaction id (wtxid). For transaction with the witness
    /// data this hash includes witness, for pre-witness transaction it is equal to the normal
    /// value returned by txid() function.
    pub fn wtxid(&self) -> Wtxid {
        // from algorithm from hsd/lib/primitives/tx.js
        // Get sizes
        fn get_witness_size(i: &TxIn) -> usize {
            let mut sz = size_var_int(i.witness.len());
            for w in i.witness.iter() {
                sz += size_var_int(w.len()) + w.len();
            }
            return sz;
        }

        fn get_covenant_size(c: &Covenant) -> usize {
            let mut sz = 1 + size_var_int(c.items.len());

            for i in c.items.iter() {
                sz += size_var_int(i.len()) + i.len();
            }

            return sz;
        }

        let mut base: usize = 4;
        let mut witness: usize = 0;

        base += size_var_int(self.input.len());
        for i in self.input.iter() {
            base += 40;
            witness += get_witness_size(i);
        }

        base += size_var_int(self.output.len());
        for o in self.output.iter() {
            base +=
                8 + 1 + /* 1+ */ o.address.payload.size_in_bytes() + get_covenant_size(&o.covenant);
        }

        base += 4;

        // Compute hashes
        // This has an extra 0x00 and 0x01 byte before the data

        // 0 0 0 0 0 1 1 166 236 66
        // should be
        // 0 0 0 0 1 166 236 66
        let raw = encode::serialize(self);

        // Normal data
        let ndata = raw.get(0..base).unwrap();

        // Witness data
        let wdata = raw.get(base..(base + witness)).unwrap();

        let mut final_blake = blake2::VarBlake2b::new(32).expect("creating blake");
        let mut part_blake = blake2::VarBlake2b::new(32).expect("creating blake");

        part_blake.update(ndata);
        part_blake.finalize_variable_reset(|res| final_blake.update(res));

        part_blake.update(wdata);
        part_blake.finalize_variable_reset(|res| final_blake.update(res));

        let mut hash_bytes: Vec<u8> = vec![0; 32];
        final_blake.finalize_variable(|res| hash_bytes.copy_from_slice(res));

        return Wtxid::consensus_decode(hash_bytes.as_slice()).unwrap();
    }

    /// Encodes the signing data from which a signature hash for a given input index with a given
    /// sighash flag can be computed.  To actually produce a scriptSig, this hash needs to be run
    /// through an ECDSA signer, the SigHashType appended to the resulting sig, and a script
    /// written around this, but this is the general (and hard) part.
    ///
    /// The `sighash_type` supports arbitrary `u32` value, instead of just [`SigHashType`],
    /// because internally 4 bytes are being hashed, even though only lowest byte
    /// is appended to signature in a transaction.
    ///
    /// *Warning* This does NOT attempt to support OP_CODESEPARATOR. In general this would require
    /// evaluating `script_pubkey` to determine which separators get evaluated and which don't,
    /// which we don't have the information to determine.
    ///
    /// # Panics
    /// Panics if `input_index` is greater than or equal to `self.input.len()`
    pub fn encode_signing_data_to<Write: io::Write, U: Into<u32>>(
        &self,
        mut writer: Write,
        input_index: usize,
        _script_pubkey: &Script, // TODO - remove
        sighash_type: U,
    ) -> Result<(), encode::Error> {
        let sighash_type: u32 = sighash_type.into();
        assert!(input_index < self.input.len()); // Panic on OOB

        let (sighash, anyone_can_pay) =
            SigHashType::from_u32_consensus(sighash_type).split_anyonecanpay_flag();

        // Special-case sighash_single bug because this is easy enough.
        if sighash == SigHashType::Single && input_index >= self.output.len() {
            writer.write_all(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])?;
            return Ok(());
        }

        // Build tx to sign
        let mut tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: vec![],
            output: vec![],
        };
        // Add all inputs necessary..
        if anyone_can_pay {
            tx.input = vec![TxIn {
                previous_output: self.input[input_index].previous_output,
                sequence: self.input[input_index].sequence,
                witness: vec![],
            }];
        } else {
            tx.input = Vec::with_capacity(self.input.len());
            for (n, input) in self.input.iter().enumerate() {
                tx.input.push(TxIn {
                    previous_output: input.previous_output,
                    sequence: if n != input_index
                        && (sighash == SigHashType::Single || sighash == SigHashType::None)
                    {
                        0
                    } else {
                        input.sequence
                    },
                    witness: vec![],
                });
            }
        }
        // ..then all outputs
        tx.output = match sighash {
            SigHashType::All => self.output.clone(),
            SigHashType::Single => {
                let output_iter = self
                    .output
                    .iter()
                    .take(input_index + 1) // sign all outputs up to and including this one, but erase
                    .enumerate() // all of them except for this one
                    .map(|(n, out)| {
                        if n == input_index {
                            out.clone()
                        } else {
                            TxOut::default()
                        }
                    });
                output_iter.collect()
            }
            SigHashType::None => vec![],
            _ => unreachable!(),
        };
        // hash the result
        tx.consensus_encode(&mut writer)?;
        let sighash_arr = endian::u32_to_array_le(sighash_type);
        sighash_arr.consensus_encode(&mut writer)?;
        Ok(())
    }

    /// Computes a signature hash for a given input index with a given sighash flag.
    /// To actually produce a scriptSig, this hash needs to be run through an
    /// ECDSA signer, the SigHashType appended to the resulting sig, and a
    /// script written around this, but this is the general (and hard) part.
    ///
    /// *Warning* This does NOT attempt to support OP_CODESEPARATOR. In general
    /// this would require evaluating `script_pubkey` to determine which separators
    /// get evaluated and which don't, which we don't have the information to
    /// determine.
    ///
    /// # Panics
    /// Panics if `input_index` is greater than or equal to `self.input.len()`
    ///
    pub fn signature_hash(
        &self,
        input_index: usize,
        script_pubkey: &Script,
        sighash_u32: u32,
    ) -> SigHash {
        let mut engine = SigHash::engine();
        self.encode_signing_data_to(&mut engine, input_index, script_pubkey, sighash_u32)
            .expect("engines don't error");
        SigHash::from_engine(engine)
    }

    /// Gets the "weight" of this transaction, as defined by BIP141. For transactions with an empty
    /// witness, this is simply the consensus-serialized size times 4. For transactions with a
    /// witness, this is the non-witness consensus-serialized size multiplied by 3 plus the
    /// with-witness consensus-serialized size.
    #[inline]
    pub fn get_weight(&self) -> usize {
        self.get_scaled_size(WITNESS_SCALE_FACTOR)
    }

    /// Gets the regular byte-wise consensus-serialized size of this transaction.
    #[inline]
    pub fn get_size(&self) -> usize {
        self.get_scaled_size(1)
    }

    /// Internal utility function for get_{size,weight}
    fn get_scaled_size(&self, scale_factor: usize) -> usize {
        let mut input_weight = 0;
        let mut inputs_with_witnesses = 0;
        for input in &self.input {
            input_weight += scale_factor * (32 + 4 + 4); // outpoint (32+4) + nSequence
            if !input.witness.is_empty() {
                inputs_with_witnesses += 1;
                input_weight += VarInt(input.witness.len() as u64).len();
                for elem in &input.witness {
                    input_weight += VarInt(elem.len() as u64).len() + elem.len();
                }
            }
        }

        let mut output_size = 0;
        for output in &self.output {
            output_size += 8 + // value
                output.address.payload.size_in_bytes();
        }
        let non_input_size =
        // version:
        4 +
        // count varints:
        VarInt(self.input.len() as u64).len() +
        VarInt(self.output.len() as u64).len() +
        output_size +
        // lock_time
        4;
        if inputs_with_witnesses == 0 {
            non_input_size * scale_factor + input_weight
        } else {
            non_input_size * scale_factor + input_weight + self.input.len() - inputs_with_witnesses
                + 2
        }
    }

    /// Is this a coin base transaction?
    pub fn is_coin_base(&self) -> bool {
        self.input.len() == 1 && self.input[0].previous_output.is_null()
    }

    /// Returns `true` if the transaction itself opted in to be BIP-125-replaceable (RBF). This
    /// **does not** cover the case where a transaction becomes replaceable due to ancestors being
    /// RBF.
    pub fn is_explicitly_rbf(&self) -> bool {
        self.input
            .iter()
            .any(|input| input.sequence < (0xffffffff - 1))
    }
}

fn size_var_int(n: usize) -> usize {
    if n < 0xfd {
        return 1;
    }

    if n <= 0xffff {
        return 3;
    }

    if n <= 0xffffffff {
        return 5;
    }

    return 9;
}

impl_consensus_encoding!(TxOut, value, address, covenant);

impl Encodable for OutPoint {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let len = self.txid.consensus_encode(&mut s)?;
        Ok(len + self.vout.consensus_encode(s)?)
    }
}
impl Decodable for OutPoint {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        Ok(OutPoint {
            txid: Decodable::consensus_decode(&mut d)?,
            vout: Decodable::consensus_decode(d)?,
        })
    }
}

impl Encodable for TxIn {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.previous_output.consensus_encode(&mut s)?;
        len += self.sequence.consensus_encode(s)?;
        Ok(len)
    }
}
impl Decodable for TxIn {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        Ok(TxIn {
            previous_output: Decodable::consensus_decode(&mut d)?,
            sequence: Decodable::consensus_decode(&mut d)?,
            witness: vec![],
        })
    }
}

impl Encodable for Transaction {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.input.consensus_encode(&mut s)?;
        len += self.output.consensus_encode(&mut s)?;
        len += self.lock_time.consensus_encode(&mut s)?;
        for input in &self.input {
            len += input.witness.consensus_encode(&mut s)?;
        }
        Ok(len)
    }
}

impl Decodable for Transaction {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        let mut d = d.take(MAX_VEC_SIZE as u64);
        let version = i32::consensus_decode(&mut d)?;
        let mut input = Vec::<TxIn>::consensus_decode(&mut d)?;
        let output = Vec::<TxOut>::consensus_decode(&mut d)?;
        let lock_time = u32::consensus_decode(&mut d)?;

        for i in input.iter_mut() {
            i.witness = Vec::<Vec<u8>>::consensus_decode(&mut d)?;
        }

        return Ok(Transaction {
            version,
            input,
            output,
            lock_time,
        });
    }
}

/// This type is consensus valid but an input including it would prevent the transaction from
/// being relayed on today's Bitcoin network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonStandardSigHashType;

impl fmt::Display for NonStandardSigHashType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Non standard sighash type")
    }
}

impl error::Error for NonStandardSigHashType {}

/// Hashtype of an input's signature, encoded in the last byte of the signature
/// Fixed values so they can be casted as integer types for encoding
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum SigHashType {
    /// 0x1: Sign all outputs
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,
    /// 0x81: Sign all outputs but only this input
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means)
    SinglePlusAnyoneCanPay = 0x83,
}
serde_string_impl!(SigHashType, "a SigHashType data");

impl fmt::Display for SigHashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SigHashType::All => "SIGHASH_ALL",
            SigHashType::None => "SIGHASH_NONE",
            SigHashType::Single => "SIGHASH_SINGLE",
            SigHashType::AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            SigHashType::NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            SigHashType::SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for SigHashType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.as_ref() {
            "SIGHASH_ALL" => Ok(SigHashType::All),
            "SIGHASH_NONE" => Ok(SigHashType::None),
            "SIGHASH_SINGLE" => Ok(SigHashType::Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(SigHashType::AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(SigHashType::NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(SigHashType::SinglePlusAnyoneCanPay),
            _ => Err("can't recognize SIGHASH string".to_string()),
        }
    }
}

impl SigHashType {
    /// Break the sighash flag into the "real" sighash flag and the ANYONECANPAY boolean
    pub(crate) fn split_anyonecanpay_flag(self) -> (SigHashType, bool) {
        match self {
            SigHashType::All => (SigHashType::All, false),
            SigHashType::None => (SigHashType::None, false),
            SigHashType::Single => (SigHashType::Single, false),
            SigHashType::AllPlusAnyoneCanPay => (SigHashType::All, true),
            SigHashType::NonePlusAnyoneCanPay => (SigHashType::None, true),
            SigHashType::SinglePlusAnyoneCanPay => (SigHashType::Single, true),
        }
    }

    /// Reads a 4-byte uint32 as a sighash type.
    #[deprecated(
        since = "0.26.1",
        note = "please use `from_u32_consensus` or `from_u32_standard` instead"
    )]
    pub fn from_u32(n: u32) -> SigHashType {
        Self::from_u32_consensus(n)
    }

    /// Reads a 4-byte uint32 as a sighash type.
    ///
    /// **Note**: this replicates consensus behaviour, for current standardness rules correctness
    /// you probably want [Self::from_u32_standard].
    pub fn from_u32_consensus(n: u32) -> SigHashType {
        // In Bitcoin Core, the SignatureHash function will mask the (int32) value with
        // 0x1f to (apparently) deactivate ACP when checking for SINGLE and NONE bits.
        // We however want to be matching also against on ACP-masked ALL, SINGLE, and NONE.
        // So here we re-activate ACP.
        let mask = 0x1f | 0x80;
        match n & mask {
            // "real" sighashes
            0x01 => SigHashType::All,
            0x02 => SigHashType::None,
            0x03 => SigHashType::Single,
            0x81 => SigHashType::AllPlusAnyoneCanPay,
            0x82 => SigHashType::NonePlusAnyoneCanPay,
            0x83 => SigHashType::SinglePlusAnyoneCanPay,
            // catchalls
            x if x & 0x80 == 0x80 => SigHashType::AllPlusAnyoneCanPay,
            _ => SigHashType::All,
        }
    }

    /// Read a 4-byte uint32 as a standard sighash type, returning an error if the type
    /// is non standard.
    pub fn from_u32_standard(n: u32) -> Result<SigHashType, NonStandardSigHashType> {
        match n {
            // Standard sighashes, see https://github.com/bitcoin/bitcoin/blob/b805dbb0b9c90dadef0424e5b3bf86ac308e103e/src/script/interpreter.cpp#L189-L198
            0x01 => Ok(SigHashType::All),
            0x02 => Ok(SigHashType::None),
            0x03 => Ok(SigHashType::Single),
            0x81 => Ok(SigHashType::AllPlusAnyoneCanPay),
            0x82 => Ok(SigHashType::NonePlusAnyoneCanPay),
            0x83 => Ok(SigHashType::SinglePlusAnyoneCanPay),
            _ => Err(NonStandardSigHashType),
        }
    }

    /// Converts to a u32
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

impl From<SigHashType> for u32 {
    fn from(t: SigHashType) -> u32 {
        t.as_u32()
    }
}

#[cfg(test)]
mod tests {
    use crate::blockdata::covenant::CovenantType;

    use super::{NonStandardSigHashType, OutPoint, ParseOutPointError, Transaction, TxIn};

    use consensus::encode::deserialize;
    use core::str::FromStr;

    use hashes::hex::FromHex;

    use hash_types::*;
    use SigHashType;

    #[test]
    fn test_outpoint() {
        assert_eq!(
            OutPoint::from_str("i don't care"),
            Err(ParseOutPointError::Format)
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:1:1"
            ),
            Err(ParseOutPointError::Format)
        );
        assert_eq!(
            OutPoint::from_str("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:"),
            Err(ParseOutPointError::Format)
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:11111111111"
            ),
            Err(ParseOutPointError::TooLong)
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:01"
            ),
            Err(ParseOutPointError::VoutNotCanonical)
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:+42"
            ),
            Err(ParseOutPointError::VoutNotCanonical)
        );
        assert_eq!(
            OutPoint::from_str("i don't care:1"),
            Err(ParseOutPointError::Txid(
                Txid::from_hex("i don't care").unwrap_err()
            ))
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945X:1"
            ),
            Err(ParseOutPointError::Txid(
                Txid::from_hex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c945X")
                    .unwrap_err()
            ))
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:lol"
            ),
            Err(ParseOutPointError::Vout(u32::from_str("lol").unwrap_err()))
        );

        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:42"
            ),
            Ok(OutPoint {
                txid: Txid::from_hex(
                    "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                )
                .unwrap(),
                vout: 42,
            })
        );
        assert_eq!(
            OutPoint::from_str(
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456:0"
            ),
            Ok(OutPoint {
                txid: Txid::from_hex(
                    "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
                )
                .unwrap(),
                vout: 0,
            })
        );
    }

    // #[test]
    // fn test_txin() {
    //     let txin: Result<TxIn, _> = deserialize(&Vec::from_hex("a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff").unwrap());
    //     assert!(txin.is_ok());
    // }

    #[test]
    fn test_txin_default() {
        let txin = TxIn::default();
        assert_eq!(txin.previous_output, OutPoint::default());
        assert_eq!(txin.sequence, 0xFFFFFFFF);
        assert_eq!(txin.previous_output, OutPoint::default());
        assert_eq!(txin.witness.len(), 0 as usize);
    }

    #[test]
    fn test_is_coinbase() {
        use blockdata::constants;
        use network::constants::Network;

        let genesis = constants::genesis_block(Network::Mainnet);
        assert!(genesis.txdata[0].is_coin_base());
        let tx_bytes = Vec::from_hex("00000000025ca2d52c92df1a8ddc5d84d635d4aa1e0874ad5e65a3047b64ea0cb7b614125000000000ffffffff44ffdf14e1c8bb77085910473213623dbfbb18562768993b7a86fa1ed3bdae7c01000000ffffffff0240420f00000000000014755bf96f2528248e99cded686b363a7f87db24580502201b918b30b5bd20c2dd7ab997e1c7bd24a885171c05e36350e0dbf063d91a4e8d047a1e0000346037ab070000000014c4f60ccb49e54d3c9da93883a2a67a7965e2de9b0000000000000241ed495dc64c4a71a0ba93d48e5ab899cf92b74e267b0d2447efa4bbbba3b3d3fa2d54754a91032cbd62e019a7992d2dc4d121a67ee05b99a29e8866fdc635d55601210364532e53f57edc342612a00c7d85c3181ab4baedf14da62bc02a426184d0d6fb02416b156cb895400b9306bdc63cd24f163d49b52576c2c76a6b3e4de8a8e0ddd2b81d286634b5dc4aac18cb04777118fc9fcd796b3535e9d918c90734461e3d3a6b012103d5c9043309ed2a9797ace401cd303021760f4eb16afb4a8edf8037ccb6854324").unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        assert!(!tx.is_coin_base());
    }

    #[test]
    fn test_parse_bid_tx() {
        let tx_hex = "0000000001114e4941ae49258401c50f550f056cd651c55b5ad565aa21f631a6951361a72533000000ffffffff0200e1f50500000000001438cddf428feb39a2b82ce37d707d7703807d7167030420d23bc69b71103fec25dc0ca6917a868288efb36b572f787a43a4d87b0a7da50404852201000a73746f726d737461636b20379c9f03b0b750093745abb418b05c09d8975357950e1b05ae6725aa23bb2b931e2f675f000000000014e54e9b67ae179d9f5310c7c6359e9c873cc31a6200000000000002419243e14c6542a0d04b2aaf53d06e45505c8f1680dd7970c6fa3a9e23ae99e97f7304a5d28f01055c472b1c36cdc3c85145d71948836a04ab1ef123a30ac6c1ab0121025c2ad4529da5169c8bce21e171574e6df222f81edf7fa4ceb5128ac9ebc750b0";
        let tx_bytes = Vec::from_hex(tx_hex).unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        assert!(!tx.is_coin_base());
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);

        assert_eq!(tx.output[0].covenant.covenant_type, CovenantType::Bid);
        assert_eq!(tx.output[0].covenant.items.len(), 4);
        assert_eq!(tx.output[0].value, 100000000);
        let mut addr = tx.output[0].address.clone();
        addr.network = crate::network::constants::Network::Mainnet;
        assert_eq!(
            addr.to_string(),
            "hs1q8rxa7s50avu69wpvud7hqlthqwq86ut8gln4k5"
        );

        let bid = tx.output[0].covenant.as_bid().unwrap();
        assert_eq!(
            bid.name_hash.to_string(),
            "d23bc69b71103fec25dc0ca6917a868288efb36b572f787a43a4d87b0a7da504"
        );
        assert_eq!(bid.height, 74373);
        assert_eq!(bid.name, "stormstack");
        assert_eq!(
            bid.blind_hash.to_string(),
            "379c9f03b0b750093745abb418b05c09d8975357950e1b05ae6725aa23bb2b93"
        );

        assert_eq!(tx.output[1].covenant.covenant_type, CovenantType::None);
        tx.output[1].covenant.as_none().unwrap();
    }

    #[test]
    fn test_segwit_transaction() {
        let tx_bytes = Vec::from_hex(
            "0000000001a6ec4245ef8c42d0602d1ec76961988719b8e72d97b7d073e2c4a8917da2\
            c65903000000ffffffff0280b2e60e00000000001487fbc22a3fe31e5a43d0252ae8fcb\
            b1cf931f9b703042071963d50fce3cf452a38675dd1ba610ab8c3274de8d5b40fdd62ed\
            1c7535b503042624000009627265657a746563682034614a11d9f02700640b3a55cde31\
            c428047a241c7e2247ce52aab0119cf7d0148072dc9000000000014d59f37ad0af29fce\
            7f6ea32d5226633d1e6a001400000000000002412f0e58a7f3a0310cfb016253478a9fa\
            8ab3bbbfff179fd72441f547942ffaad62217309d38ebb7fea5f04beff89e935a7d53a8\
            b1d84c08d6ceb1f67960e6695f0121023c6b2d479f020528b857082a547725f8e69debb\
            440beed8b183cff8475b14b14",
        )
        .unwrap();
        let tx: Result<Transaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        // All these tests aren't really needed because if they fail, the hash check at the end
        // will also fail. But these will show you where the failure is so I'll leave them in.
        assert_eq!(realtx.version, 0);
        assert_eq!(realtx.input.len(), 1);
        // In particular this one is easy to get backward -- in bitcoin hashes are encoded
        // as little-endian 256-bit numbers rather than as data strings.
        let _expected_prev_output_txid = format!("{:x}", realtx.input[0].previous_output.txid);
        assert_eq!(
            format!("{:x}", realtx.input[0].previous_output.txid),
            "a6ec4245ef8c42d0602d1ec76961988719b8e72d97b7d073e2c4a8917da2c659".to_string()
        );
        assert_eq!(realtx.input[0].previous_output.vout, 3);
        assert_eq!(realtx.output.len(), 2);
        assert_eq!(realtx.lock_time, 0);

        assert_eq!(
            format!("{:x}", realtx.txid()),
            "4cddf15bef61400728ba15356418200c6247f53ad173d06c4fd928023083f84b".to_string()
        );
        assert_eq!(
            format!("{:x}", realtx.wtxid()),
            "a50125d022b455e6d8f7a2ae49c7088897c9de4b4ee6e41a4036d15af158c78f".to_string()
        );
        assert_eq!(realtx.get_weight(), 535);
        // assert_eq!(realtx.get_size(), tx_bytes.len());
    }

    #[test]
    fn test_transaction_version() {
        let tx_bytes = Vec::from_hex("00000000010000000000000000000000000000000000000000000000000000000000000000ffffffff94e30c0901b848377700000000001400bfb1e341bb84a68dd0bc1781c5ece5e5dc328200001027000003066632706f6f6c084dee1b281be020dc080000000000000000").unwrap();
        let tx: Result<Transaction, _> = deserialize(&tx_bytes);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        assert_eq!(realtx.version, 0);
    }

    #[test]
    fn test_txid() {
        // tx from hsd
        let tx_bytes = Vec::from_hex(
            "0000000001a6ec4245ef8c42d0602d1ec76961988719b8e72d97b7d073e2c4a8917da2c65903000000ff\
            ffffff0280b2e60e00000000001487fbc22a3fe31e5a43d0252ae8fcbb1cf931f9b703042071963d50fce\
            3cf452a38675dd1ba610ab8c3274de8d5b40fdd62ed1c7535b503042624000009627265657a7465636820\
            34614a11d9f02700640b3a55cde31c428047a241c7e2247ce52aab0119cf7d0148072dc9000000000014d\
            59f37ad0af29fce7f6ea32d5226633d1e6a001400000000000002412f0e58a7f3a0310cfb016253478a9f\
            a8ab3bbbfff179fd72441f547942ffaad62217309d38ebb7fea5f04beff89e935a7d53a8b1d84c08d6ceb\
            1f67960e6695f0121023c6b2d479f020528b857082a547725f8e69debb440beed8b183cff8475b14b14",
        )
        .unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        assert_eq!(
            format!("{:x}", tx.txid()),
            "4cddf15bef61400728ba15356418200c6247f53ad173d06c4fd928023083f84b"
        );
        assert_eq!(
            format!("{:x}", tx.wtxid()),
            "a50125d022b455e6d8f7a2ae49c7088897c9de4b4ee6e41a4036d15af158c78f"
        );
        assert_eq!(tx.get_weight(), 535);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_txn_encode_decode() {
        let tx_bytes = Vec::from_hex("0000000001114e4941ae49258401c50f550f056cd651c55b5ad565aa21f631a6951361a72533000000ffffffff0200e1f50500000000001438cddf428feb39a2b82ce37d707d7703807d7167030420d23bc69b71103fec25dc0ca6917a868288efb36b572f787a43a4d87b0a7da50404852201000a73746f726d737461636b20379c9f03b0b750093745abb418b05c09d8975357950e1b05ae6725aa23bb2b931e2f675f000000000014e54e9b67ae179d9f5310c7c6359e9c873cc31a6200000000000002419243e14c6542a0d04b2aaf53d06e45505c8f1680dd7970c6fa3a9e23ae99e97f7304a5d28f01055c472b1c36cdc3c85145d71948836a04ab1ef123a30ac6c1ab0121025c2ad4529da5169c8bce21e171574e6df222f81edf7fa4ceb5128ac9ebc750b0").unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();
        serde_round_trip!(tx);
    }

    #[test]
    fn test_sighashtype_fromstr_display() {
        let sighashtypes = vec![
            ("SIGHASH_ALL", SigHashType::All),
            ("SIGHASH_NONE", SigHashType::None),
            ("SIGHASH_SINGLE", SigHashType::Single),
            (
                "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
                SigHashType::AllPlusAnyoneCanPay,
            ),
            (
                "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
                SigHashType::NonePlusAnyoneCanPay,
            ),
            (
                "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
                SigHashType::SinglePlusAnyoneCanPay,
            ),
        ];
        for (s, sht) in sighashtypes {
            assert_eq!(sht.to_string(), s);
            assert_eq!(SigHashType::from_str(s).unwrap(), sht);
        }
        let sht_mistakes = vec![
            "SIGHASH_ALL | SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |SIGHASH_ANYONECANPAY",
            "SIGHASH_SINGLE| SIGHASH_ANYONECANPAY",
            "SIGHASH_ALL SIGHASH_ANYONECANPAY",
            "SIGHASH_NONE |",
            "SIGHASH_SIGNLE",
            "sighash_none",
            "Sighash_none",
            "SigHash_None",
            "SigHash_NONE",
        ];
        for s in sht_mistakes {
            assert_eq!(
                SigHashType::from_str(s).unwrap_err(),
                "can't recognize SIGHASH string"
            );
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_sighashtype_standard() {
        let nonstandard_hashtype = 0x04;
        // This type is not well defined, by consensus it becomes ALL
        assert_eq!(
            SigHashType::from_u32(nonstandard_hashtype),
            SigHashType::All
        );
        assert_eq!(
            SigHashType::from_u32_consensus(nonstandard_hashtype),
            SigHashType::All
        );
        // But it's policy-invalid to use it!
        assert_eq!(
            SigHashType::from_u32_standard(nonstandard_hashtype),
            Err(NonStandardSigHashType)
        );
    }

    // TODO - test for handshake
    // #[test]
    // #[cfg(feature="bitcoinconsensus")]
    // fn test_transaction_verify () {
    //     use hashes::hex::FromHex;
    //     use std::collections::HashMap;
    //     use blockdata::script;
    //     // a random recent segwit transaction from blockchain using both old and segwit inputs
    //     let mut spending: Transaction = deserialize(Vec::from_hex("020000000001031cfbc8f54fbfa4a33a30068841371f80dbfe166211242213188428f437445c91000000006a47304402206fbcec8d2d2e740d824d3d36cc345b37d9f65d665a99f5bd5c9e8d42270a03a8022013959632492332200c2908459547bf8dbf97c65ab1a28dec377d6f1d41d3d63e012103d7279dfb90ce17fe139ba60a7c41ddf605b25e1c07a4ddcb9dfef4e7d6710f48feffffff476222484f5e35b3f0e43f65fc76e21d8be7818dd6a989c160b1e5039b7835fc00000000171600140914414d3c94af70ac7e25407b0689e0baa10c77feffffffa83d954a62568bbc99cc644c62eb7383d7c2a2563041a0aeb891a6a4055895570000000017160014795d04cc2d4f31480d9a3710993fbd80d04301dffeffffff06fef72f000000000017a91476fd7035cd26f1a32a5ab979e056713aac25796887a5000f00000000001976a914b8332d502a529571c6af4be66399cd33379071c588ac3fda0500000000001976a914fc1d692f8de10ae33295f090bea5fe49527d975c88ac522e1b00000000001976a914808406b54d1044c429ac54c0e189b0d8061667e088ac6eb68501000000001976a914dfab6085f3a8fb3e6710206a5a959313c5618f4d88acbba20000000000001976a914eb3026552d7e3f3073457d0bee5d4757de48160d88ac0002483045022100bee24b63212939d33d513e767bc79300051f7a0d433c3fcf1e0e3bf03b9eb1d70220588dc45a9ce3a939103b4459ce47500b64e23ab118dfc03c9caa7d6bfc32b9c601210354fd80328da0f9ae6eef2b3a81f74f9a6f66761fadf96f1d1d22b1fd6845876402483045022100e29c7e3a5efc10da6269e5fc20b6a1cb8beb92130cc52c67e46ef40aaa5cac5f0220644dd1b049727d991aece98a105563416e10a5ac4221abac7d16931842d5c322012103960b87412d6e169f30e12106bdf70122aabb9eb61f455518322a18b920a4dfa887d30700")
    //         .unwrap().as_slice()).unwrap();
    //     let spent1: Transaction = deserialize(Vec::from_hex("020000000001040aacd2c49f5f3c0968cfa8caf9d5761436d95385252e3abb4de8f5dcf8a582f20000000017160014bcadb2baea98af0d9a902e53a7e9adff43b191e9feffffff96cd3c93cac3db114aafe753122bd7d1afa5aa4155ae04b3256344ecca69d72001000000171600141d9984579ceb5c67ebfbfb47124f056662fe7adbfeffffffc878dd74d3a44072eae6178bb94b9253177db1a5aaa6d068eb0e4db7631762e20000000017160014df2a48cdc53dae1aba7aa71cb1f9de089d75aac3feffffffe49f99275bc8363f5f593f4eec371c51f62c34ff11cc6d8d778787d340d6896c0100000017160014229b3b297a0587e03375ab4174ef56eeb0968735feffffff03360d0f00000000001976a9149f44b06f6ee92ddbc4686f71afe528c09727a5c788ac24281b00000000001976a9140277b4f68ff20307a2a9f9b4487a38b501eb955888ac227c0000000000001976a9148020cd422f55eef8747a9d418f5441030f7c9c7788ac0247304402204aa3bd9682f9a8e101505f6358aacd1749ecf53a62b8370b97d59243b3d6984f02200384ad449870b0e6e89c92505880411285ecd41cf11e7439b973f13bad97e53901210205b392ffcb83124b1c7ce6dd594688198ef600d34500a7f3552d67947bbe392802473044022033dfd8d190a4ae36b9f60999b217c775b96eb10dee3a1ff50fb6a75325719106022005872e4e36d194e49ced2ebcf8bb9d843d842e7b7e0eb042f4028396088d292f012103c9d7cbf369410b090480de2aa15c6c73d91b9ffa7d88b90724614b70be41e98e0247304402207d952de9e59e4684efed069797e3e2d993e9f98ec8a9ccd599de43005fe3f713022076d190cc93d9513fc061b1ba565afac574e02027c9efbfa1d7b71ab8dbb21e0501210313ad44bc030cc6cb111798c2bf3d2139418d751c1e79ec4e837ce360cc03b97a024730440220029e75edb5e9413eb98d684d62a077b17fa5b7cc19349c1e8cc6c4733b7b7452022048d4b9cae594f03741029ff841e35996ef233701c1ea9aa55c301362ea2e2f68012103590657108a72feb8dc1dec022cf6a230bb23dc7aaa52f4032384853b9f8388baf9d20700")
    //         .unwrap().as_slice()).unwrap();
    //     let spent2: Transaction = deserialize(Vec::from_hex("0200000000010166c3d39490dc827a2594c7b17b7d37445e1f4b372179649cd2ce4475e3641bbb0100000017160014e69aa750e9bff1aca1e32e57328b641b611fc817fdffffff01e87c5d010000000017a914f3890da1b99e44cd3d52f7bcea6a1351658ea7be87024830450221009eb97597953dc288de30060ba02d4e91b2bde1af2ecf679c7f5ab5989549aa8002202a98f8c3bd1a5a31c0d72950dd6e2e3870c6c5819a6c3db740e91ebbbc5ef4800121023f3d3b8e74b807e32217dea2c75c8d0bd46b8665b3a2d9b3cb310959de52a09bc9d20700")
    //         .unwrap().as_slice()).unwrap();
    //     let spent3: Transaction = deserialize(Vec::from_hex("01000000027a1120a30cef95422638e8dab9dedf720ec614b1b21e451a4957a5969afb869d000000006a47304402200ecc318a829a6cad4aa9db152adbf09b0cd2de36f47b53f5dade3bc7ef086ca702205722cda7404edd6012eedd79b2d6f24c0a0c657df1a442d0a2166614fb164a4701210372f4b97b34e9c408741cd1fc97bcc7ffdda6941213ccfde1cb4075c0f17aab06ffffffffc23b43e5a18e5a66087c0d5e64d58e8e21fcf83ce3f5e4f7ecb902b0e80a7fb6010000006b483045022100f10076a0ea4b4cf8816ed27a1065883efca230933bf2ff81d5db6258691ff75202206b001ef87624e76244377f57f0c84bc5127d0dd3f6e0ef28b276f176badb223a01210309a3a61776afd39de4ed29b622cd399d99ecd942909c36a8696cfd22fc5b5a1affffffff0200127a000000000017a914f895e1dd9b29cb228e9b06a15204e3b57feaf7cc8769311d09000000001976a9144d00da12aaa51849d2583ae64525d4a06cd70fde88ac00000000")
    //         .unwrap().as_slice()).unwrap();

    //     let mut spent = HashMap::new();
    //     spent.insert(spent1.txid(), spent1);
    //     spent.insert(spent2.txid(), spent2);
    //     spent.insert(spent3.txid(), spent3);
    //     let mut spent2 = spent.clone();
    //     let mut spent3 = spent.clone();

    //     spending.verify(|point: &OutPoint| {
    //         if let Some(tx) = spent.remove(&point.txid) {
    //             return tx.output.get(point.vout as usize).cloned();
    //         }
    //         None
    //     }).unwrap();

    //     // test that we fail with repeated use of same input
    //     let mut double_spending = spending.clone();
    //     let re_use = double_spending.input[0].clone();
    //     double_spending.input.push (re_use);

    //     assert!(double_spending.verify(|point: &OutPoint| {
    //         if let Some(tx) = spent2.remove(&point.txid) {
    //             return tx.output.get(point.vout as usize).cloned();
    //         }
    //         None
    //     }).is_err());

    //     // test that we get a failure if we corrupt a signature
    //     spending.input[1].witness[0][10] = 42;
    //     match spending.verify(|point: &OutPoint| {
    //         if let Some(tx) = spent3.remove(&point.txid) {
    //             return tx.output.get(point.vout as usize).cloned();
    //         }
    //         None
    //     }).err().unwrap() {
    //         script::Error::BitcoinConsensus(_) => {},
    //         _ => panic!("Wrong error type"),
    //     }
    // }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use super::Transaction;
    use consensus::{deserialize, Encodable};
    use hashes::hex::FromHex;
    use test::{black_box, Bencher};
    use EmptyWrite;

    const SOME_TX: &'static str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

    #[bench]
    pub fn bench_transaction_get_size(bh: &mut Bencher) {
        let raw_tx = Vec::from_hex(SOME_TX).unwrap();

        let mut tx: Transaction = deserialize(&raw_tx).unwrap();

        bh.iter(|| {
            black_box(black_box(&mut tx).get_size());
        });
    }

    #[bench]
    pub fn bench_transaction_serialize(bh: &mut Bencher) {
        let raw_tx = Vec::from_hex(SOME_TX).unwrap();
        let tx: Transaction = deserialize(&raw_tx).unwrap();

        let mut data = Vec::with_capacity(raw_tx.len());

        bh.iter(|| {
            let result = tx.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_transaction_serialize_logic(bh: &mut Bencher) {
        let raw_tx = Vec::from_hex(SOME_TX).unwrap();
        let tx: Transaction = deserialize(&raw_tx).unwrap();

        bh.iter(|| {
            let size = tx.consensus_encode(&mut EmptyWrite);
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_transaction_deserialize(bh: &mut Bencher) {
        let raw_tx = Vec::from_hex(SOME_TX).unwrap();

        bh.iter(|| {
            let tx: Transaction = deserialize(&raw_tx).unwrap();
            black_box(&tx);
        });
    }
}
