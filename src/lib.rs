// Miniscript
// Written in 2019 by
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

//! Miniscript and Output Descriptors
//!
//! # Introduction
//! ## Bitcoin Script
//!
//! In Bitcoin, spending policies are defined and enforced by means of a
//! stack-based programming language known as Bitcoin Script. While this
//! language appears to be designed with tractable analysis in mind (e.g.
//! there are no looping or jumping constructions), in practice this is
//! extremely difficult. As a result, typical wallet software supports only
//! a small set of script templates, cannot interoperate with other similar
//! software, and each wallet contains independently written ad-hoc manually
//! verified code to handle these templates. Users who require more complex
//! spending policies, or who want to combine signing infrastructure which
//! was not explicitly designed to work together, are simply out of luck.
//!
//! ## Miniscript
//!
//! Miniscript is an alternative to Bitcoin Script which eliminates these
//! problems. It can be efficiently and simply encoded as Script to ensure
//! that it works on the Bitcoin blockchain, but its design is very different.
//! Essentially, a Miniscript is a monotone function (tree of ANDs, ORs and
//! thresholds) of signature requirements, hash preimage requirements, and
//! timelocks.
//!
//! A [full description of Miniscript is available here](http://bitcoin.sipa.be/miniscript/miniscript.html).
//!
//! Miniscript also admits a more human-readable encoding.
//!
//! ## Output Descriptors
//!
//! While spending policies in Bitcoin are entirely defined by Script; there
//! are multiple ways of embedding these Scripts in transaction outputs; for
//! example, P2SH or Segwit v0. These different embeddings are expressed by
//! *Output Descriptors*, [which are described here](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)
//!
//! # Examples
//!
//! ## Deriving an address from a descriptor
//!
//! ```rust
//! extern crate bitcoin;
//! extern crate miniscript;
//!
//! use std::str::FromStr;
//!
//! fn main() {
//!     let desc = miniscript::Descriptor::<
//!         bitcoin::PublicKey,
//!     >::from_str("\
//!         sh(wsh(or_d(\
//!             c:pk(020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261),\
//!             c:pk(020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261)\
//!         )))\
//!     ").unwrap();
//!
//!     // Derive the P2SH address
//!     assert_eq!(
//!         desc.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
//!         "32aAVauGwencZwisuvd3anhhhQhNZQPyHv"
//!     );
//!
//!     // Estimate the satisfaction cost
//!     assert_eq!(desc.max_satisfaction_weight(), 293);
//! }
//! ```
//!
//!
#![cfg_attr(all(test, feature = "unstable"), feature(test))]
pub extern crate bitcoin;
#[cfg(feature = "serde")]
pub extern crate serde;
#[cfg(all(test, feature = "unstable"))]
extern crate test;

#[macro_use]
#[cfg(test)]
mod macros;

pub mod descriptor;
pub mod expression;
pub mod miniscript;
pub mod policy;
pub mod psbt;

use std::str::FromStr;
use std::{cmp, error, fmt, hash, str};

use bitcoin::blockdata::{opcodes, script};
use bitcoin::hashes::{hash160, sha256, Hash};
use bitcoin::util::bip32;
use bitcoin::util::base58;
use bitcoin::secp256k1;

pub use descriptor::{Descriptor, SatisfiedConstraints};
pub use miniscript::decode::Terminal;
pub use miniscript::satisfy::{BitcoinSig, Satisfier};
pub use miniscript::Miniscript;

///Public key trait which can be converted to Hash type
pub trait MiniscriptKey:
    Clone + Eq + Ord + str::FromStr + fmt::Debug + fmt::Display + hash::Hash
{
    type Hash: Clone + Eq + Ord + str::FromStr + fmt::Display + fmt::Debug + hash::Hash;

    ///Converts an object to PublicHash
    fn to_pubkeyhash(&self) -> Self::Hash;
}

impl MiniscriptKey for bitcoin::PublicKey {
    type Hash = hash160::Hash;

    fn to_pubkeyhash(&self) -> Self::Hash {
        let mut engine = hash160::Hash::engine();
        self.write_into(&mut engine);
        hash160::Hash::from_engine(engine)
    }
}

impl MiniscriptKey for String {
    type Hash = String;

    fn to_pubkeyhash(&self) -> Self::Hash {
        format!("{}", &self)
    }
}

#[derive(Eq, Clone, Debug)]
pub struct MiniscriptExtendedKey {
    master_fingerprint: Option<String>,
    master_derivation: Option<bip32::DerivationPath>,
    xpub: bip32::ExtendedPubKey,
    path: bip32::DerivationPath,
    final_index: DerivationIndex,
}

impl MiniscriptExtendedKey {
    fn derived_pubkey(&self) -> bitcoin::PublicKey {
        self.xpub.derive_pub(&secp256k1::Secp256k1::new(), &self.path).unwrap().public_key
    }
}

impl fmt::Display for MiniscriptExtendedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref fingerprint) = self.master_fingerprint {
            write!(f, "[{}", fingerprint)?;
            if let Some(ref path) = self.master_derivation {
                write!(f, "{}", &path.to_string()[1..])?;
            }
            write!(f, "]")?;
        }

        write!(f, "{}{}{}", self.xpub, &self.path.to_string()[1..], self.final_index)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DerivationIndex {
    Fixed,
    Normal,
    Hardened,
}

impl fmt::Display for DerivationIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let chars = match *self {
            Self::Fixed => "",
            Self::Normal => "/*",
            Self::Hardened => "/*'",
        };

        write!(f, "{}", chars)
    }
}

impl str::FromStr for MiniscriptExtendedKey {
    type Err = String;

    fn from_str(inp: &str) -> Result<MiniscriptExtendedKey, Self::Err> {
        let len = inp.len();

        let (master_fingerprint, master_derivation, offset) = match inp.starts_with("[") {
            false => (None, Ok(None), 0),
            true => {
                let master_fingerprint = &inp[1..9];
                let close_bracket_index = &inp[9..].find("]").unwrap(); // required
                let path = match *close_bracket_index > 0 {
                    true => bip32::DerivationPath::from_str(&format!("m{}", &inp[9..9 + *close_bracket_index])), 
                    false => Ok(bip32::DerivationPath::from(vec![])),
                };

                (Some(master_fingerprint.into()), path.and_then(|x| Ok(Some(x))), 9 + *close_bracket_index + 1)
            }
        };

        let (xpub_range, offset) = match &inp[offset..].find("/") {
            Some(index) => (offset..offset + *index, offset + *index),
            None => (offset..len, len),
        };
        let xpub = bip32::ExtendedPubKey::from_str(&inp[xpub_range]);

        let (path, final_index, offset) = match &inp[offset..].starts_with("/") {
            false => (Ok(bip32::DerivationPath::from(vec![])), DerivationIndex::Fixed, offset),
            true => {
                let (all, skip) = match &inp[len - 2..len] {
                    "/*" => (DerivationIndex::Normal, 2),
                    "*'" => (DerivationIndex::Hardened, 3), // TODO: only allowed for xprv
                    _ => (DerivationIndex::Fixed, 0)
                };

                (bip32::DerivationPath::from_str(&format!("m{}", &inp[offset..len - skip])), all, len)
            }
        };

        // TODO: errors
        Ok(MiniscriptExtendedKey {
            master_fingerprint,
            master_derivation: master_derivation.unwrap(),
            xpub: xpub.unwrap(),
            path: path.unwrap(),
            final_index,
        })
    }
}

impl MiniscriptKey for MiniscriptExtendedKey {
    type Hash = hash160::Hash;

    // TODO: will probably need a derivation index
    fn to_pubkeyhash(&self) -> Self::Hash {
        self.derived_pubkey().to_pubkeyhash()
    }
}

impl Ord for MiniscriptExtendedKey {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.derived_pubkey().cmp(&other.derived_pubkey())
    }
}

impl PartialOrd for MiniscriptExtendedKey {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.derived_pubkey().cmp(&other.derived_pubkey()))
    }
}

impl PartialEq for MiniscriptExtendedKey {
    fn eq(&self, other: &Self) -> bool {
        self.derived_pubkey() == other.derived_pubkey()
    }
}

impl hash::Hash for MiniscriptExtendedKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        format!("{}", self).hash(state);
    }
}

/// Trait describing public key types which can be converted to bitcoin pubkeys
pub trait ToPublicKey: MiniscriptKey {
    /// Converts an object to a public key
    fn to_public_key(&self) -> bitcoin::PublicKey;

    /// Computes the size of a public key when serialized in a script,
    /// including the length bytes
    fn serialized_len(&self) -> usize {
        if self.to_public_key().compressed {
            34
        } else {
            66
        }
    }

    /// Converts a hashed version of the public key to a `hash160` hash.
    ///
    /// This method must be consistent with `to_public_key`, in the sense
    /// that calling `MiniscriptKey::to_pubkeyhash` followed by this function
    /// should give the same result as calling `to_public_key` and hashing
    /// the result directly.
    fn hash_to_hash160(hash: &<Self as MiniscriptKey>::Hash) -> hash160::Hash;
}

impl ToPublicKey for bitcoin::PublicKey {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        *self
    }

    fn hash_to_hash160(hash: &hash160::Hash) -> hash160::Hash {
        *hash
    }
}

impl ToPublicKey for MiniscriptExtendedKey {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        self.derived_pubkey()
    }

    fn hash_to_hash160(hash: &hash160::Hash) -> hash160::Hash {
        *hash
    }
}

/// Dummy key which de/serializes to the empty string; useful sometimes for testing
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub struct DummyKey;

impl str::FromStr for DummyKey {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<DummyKey, &'static str> {
        if x.is_empty() {
            Ok(DummyKey)
        } else {
            Err("non empty dummy key")
        }
    }
}

impl MiniscriptKey for DummyKey {
    type Hash = DummyKeyHash;

    fn to_pubkeyhash(&self) -> Self::Hash {
        DummyKeyHash
    }
}

impl hash::Hash for DummyKey {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        "DummyKey".hash(state);
    }
}

impl fmt::Display for DummyKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

impl ToPublicKey for DummyKey {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        bitcoin::PublicKey::from_str(
            "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352",
        )
        .unwrap()
    }

    fn hash_to_hash160(_: &DummyKeyHash) -> hash160::Hash {
        hash160::Hash::from_str("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31").unwrap()
    }
}

/// Dummy keyhash which de/serializes to the empty string; useful sometimes for testing
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub struct DummyKeyHash;

impl str::FromStr for DummyKeyHash {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<DummyKeyHash, &'static str> {
        if x.is_empty() {
            Ok(DummyKeyHash)
        } else {
            Err("non empty dummy key")
        }
    }
}

impl fmt::Display for DummyKeyHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

impl hash::Hash for DummyKeyHash {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        "DummyKeyHash".hash(state);
    }
}

/// Miniscript

#[derive(Debug)]
pub enum Error {
    /// Opcode appeared which is not part of the script subset
    InvalidOpcode(opcodes::All),
    /// Some opcode occurred followed by `OP_VERIFY` when it had
    /// a `VERIFY` version that should have been used instead
    NonMinimalVerify(miniscript::lex::Token),
    /// Push was illegal in some context
    InvalidPush(Vec<u8>),
    /// PSBT-related error
    Psbt(psbt::Error),
    /// rust-bitcoin script error
    Script(script::Error),
    /// A `CHECKMULTISIG` opcode was preceded by a number > 20
    CmsTooManyKeys(u32),
    /// Encountered unprintable character in descriptor
    Unprintable(u8),
    /// expected character while parsing descriptor; didn't find one
    ExpectedChar(char),
    /// While parsing backward, hit beginning of script
    UnexpectedStart,
    /// Got something we were not expecting
    Unexpected(String),
    /// Name of a fragment contained `:` multiple times
    MultiColon(String),
    /// Name of a fragment contained `@` multiple times
    MultiAt(String),
    /// Name of a fragment contained `@` but we were not parsing an OR
    AtOutsideOr(String),
    /// Fragment was an `and_v(_, true)` which should be written as `t:`
    NonCanonicalTrue,
    /// Fragment was an `or_i(_, false)` or `or_i(false,_)` which should be written as `u:` or `l:`
    NonCanonicalFalse,
    /// Encountered a `l:0` which is syntactically equal to `u:0` except stupid
    LikelyFalse,
    /// Encountered a wrapping character that we don't recognize
    UnknownWrapper(char),
    /// Parsed a miniscript and the result was not of type T
    NonTopLevel(String),
    /// Parsed a miniscript but there were more script opcodes after it
    Trailing(String),
    /// Failed to parse a push as a public key
    BadPubkey(bitcoin::util::key::Error),
    /// Could not satisfy a script (fragment) because of a missing hash preimage
    MissingHash(sha256::Hash),
    /// Could not satisfy a script (fragment) because of a missing signature
    MissingSig(bitcoin::PublicKey),
    /// Could not satisfy, relative locktime not met
    RelativeLocktimeNotMet(u32),
    /// Could not satisfy, absolute locktime not met
    AbsoluteLocktimeNotMet(u32),
    /// General failure to satisfy
    CouldNotSatisfy,
    /// Typechecking failed
    TypeCheck(String),
    ///General error in creating descriptor
    BadDescriptor,
    ///Forward-secp related errors
    Secp(bitcoin::secp256k1::Error),
    #[cfg(feature = "compiler")]
    ///Compiler related errors
    CompilerError(policy::compiler::CompilerError),
    ///Interpreter related errors
    InterpreterError(descriptor::InterpreterError),
    /// Bad Script Sig. As per standardness rules, only pushes are allowed in
    /// scriptSig. This error is invoked when op_codes are pushed onto the stack
    /// As per the current implementation, pushing an integer apart from 0 or 1
    /// will also trigger this. This is because, Miniscript only expects push
    /// bytes for pk, sig, preimage etc or 1 or 0 for `StackElement::Satisfied`
    /// or `StackElement::Dissatisfied`
    BadScriptSig,
    ///Witness must be empty for pre-segwit transactions
    NonEmptyWitness,
    ///ScriptSig must be empty for pure segwit transactions
    NonEmptyScriptSig,
    ///Incorrect Script pubkey Hash for the descriptor. This is used for both
    /// `PkH` and `Wpkh` descriptors
    IncorrectPubkeyHash,
    ///Incorrect Script pubkey Hash for the descriptor. This is used for both
    /// `Sh` and `Wsh` descriptors
    IncorrectScriptHash,
}

#[doc(hidden)]
impl<Pk> From<miniscript::types::Error<Pk>> for Error
where
    Pk: MiniscriptKey,
{
    fn from(e: miniscript::types::Error<Pk>) -> Error {
        Error::TypeCheck(e.to_string())
    }
}

fn errstr(s: &str) -> Error {
    Error::Unexpected(s.to_owned())
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::BadPubkey(ref e) => Some(e),
            Error::Psbt(ref e) => Some(e),
            _ => None,
        }
    }

    fn description(&self) -> &str {
        ""
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidOpcode(op) => write!(f, "invalid opcode {}", op),
            Error::NonMinimalVerify(tok) => write!(f, "{} VERIFY", tok),
            Error::InvalidPush(ref push) => write!(f, "invalid push {:?}", push), // TODO hexify this
            Error::Psbt(ref e) => fmt::Display::fmt(e, f),
            Error::Script(ref e) => fmt::Display::fmt(e, f),
            Error::CmsTooManyKeys(n) => write!(f, "checkmultisig with {} keys", n),
            Error::Unprintable(x) => write!(f, "unprintable character 0x{:02x}", x),
            Error::ExpectedChar(c) => write!(f, "expected {}", c),
            Error::UnexpectedStart => f.write_str("unexpected start of script"),
            Error::Unexpected(ref s) => write!(f, "unexpected «{}»", s),
            Error::MultiColon(ref s) => write!(f, "«{}» has multiple instances of «:»", s),
            Error::MultiAt(ref s) => write!(f, "«{}» has multiple instances of «@»", s),
            Error::AtOutsideOr(ref s) => write!(f, "«{}» contains «@» in non-or() context", s),
            Error::NonCanonicalTrue => f.write_str("Use «t:X» rather than «and_v(X,true())»"),
            Error::NonCanonicalFalse => {
                f.write_str("Use «u:X» «l:X» rather than «or_i(X,false)» «or_i(false,X)»")
            }
            Error::LikelyFalse => write!(f, "0 is not very likely (use «u:0»)"),
            Error::UnknownWrapper(ch) => write!(f, "unknown wrapper «{}:»", ch),
            Error::NonTopLevel(ref s) => write!(f, "non-T miniscript: {}", s),
            Error::Trailing(ref s) => write!(f, "trailing tokens: {}", s),
            Error::MissingHash(ref h) => write!(f, "missing preimage of hash {}", h),
            Error::MissingSig(ref pk) => write!(f, "missing signature for key {:?}", pk),
            Error::RelativeLocktimeNotMet(n) => {
                write!(f, "required relative locktime CSV of {} blocks, not met", n)
            }
            Error::AbsoluteLocktimeNotMet(n) => write!(
                f,
                "required absolute locktime CLTV of {} blocks, not met",
                n
            ),
            Error::CouldNotSatisfy => f.write_str("could not satisfy"),
            Error::BadPubkey(ref e) => fmt::Display::fmt(e, f),
            Error::TypeCheck(ref e) => write!(f, "typecheck: {}", e),
            Error::BadDescriptor => f.write_str("could not create a descriptor"),
            Error::Secp(ref e) => fmt::Display::fmt(e, f),
            Error::InterpreterError(ref e) => fmt::Display::fmt(e, f),
            #[cfg(feature = "compiler")]
            Error::CompilerError(ref e) => fmt::Display::fmt(e, f),
            Error::BadScriptSig => f.write_str("Script sig must only consist of pushes"),
            Error::NonEmptyWitness => f.write_str("Non empty witness for Pk/Pkh"),
            Error::NonEmptyScriptSig => f.write_str("Non empty script sig for segwit spend"),
            Error::IncorrectScriptHash => {
                f.write_str("Incorrect script hash for redeem script sh/wsh")
            }
            Error::IncorrectPubkeyHash => {
                f.write_str("Incorrect pubkey hash for given descriptor pkh/wpkh")
            }
        }
    }
}

#[doc(hidden)]
impl From<psbt::Error> for Error {
    fn from(e: psbt::Error) -> Error {
        Error::Psbt(e)
    }
}

#[doc(hidden)]
#[cfg(feature = "compiler")]
impl From<policy::compiler::CompilerError> for Error {
    fn from(e: policy::compiler::CompilerError) -> Error {
        Error::CompilerError(e)
    }
}

/// The size of an encoding of a number in Script
pub fn script_num_size(n: usize) -> usize {
    match n {
        n if n <= 0x10 => 1,      // OP_n
        n if n < 0x80 => 2,       // OP_PUSH1 <n>
        n if n < 0x8000 => 3,     // OP_PUSH2 <n>
        n if n < 0x800000 => 4,   // OP_PUSH3 <n>
        n if n < 0x80000000 => 5, // OP_PUSH4 <n>
        _ => 6,                   // OP_PUSH5 <n>
    }
}

/// Helper function used by tests
#[cfg(test)]
fn hex_script(s: &str) -> bitcoin::Script {
    let v: Vec<u8> = bitcoin::hashes::hex::FromHex::from_hex(s).unwrap();
    bitcoin::Script::from(v)
}
