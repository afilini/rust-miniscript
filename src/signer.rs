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

//! # Signer
//!
//! Defines traits and structus to work with secrets and signers inside the keys

use std::collections::HashMap;
use std::fmt;

use bitcoin::util::bip32::{ExtendedPrivKey, Fingerprint};
use bitcoin::util::psbt;
use bitcoin::PrivateKey;

use super::descriptor::{Descriptor, DescriptorXKey};
use miniscript::satisfy::BitcoinSig;
use miniscript::{Miniscript, ScriptContext};
use MiniscriptKey;

/// Identifier of a signer in the `SignersContainers`. Used as a key to find the right signer among
/// many of them
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum SignerId<Pk: MiniscriptKey> {
    PkHash(<Pk as MiniscriptKey>::Hash),
    Fingerprint(Fingerprint),
}

/// Signing error
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignerError {
    /// The private key is missing for the required public key
    MissingKey,
    /// The user canceled the operation
    UserCanceled,
    // ... add some more here
}

/// Trait for `MiniscriptKeys` that optionally contain secrets that can be "split out"
pub trait SplitSecret: MiniscriptKey {
    /// Type of the "public" variant returned when the split occurs
    type Public: MiniscriptKey<Hash = <Self as MiniscriptKey>::Hash>;

    /// Do the split, always returns the public part, optionally also the signer and the correct
    /// identifier
    fn split_secret(&self) -> (Self::Public, Option<(SignerId<Self::Public>, Box<Signer>)>);
}

/// Trait for signers
pub trait Signer: fmt::Debug {
    fn sign(&self, input: &psbt::Input) -> Result<BitcoinSig, SignerError>;
}

// TODO: implement Satisfier for Signers somehow

impl Signer for DescriptorXKey<ExtendedPrivKey> {
    fn sign(&self, input: &psbt::Input) -> Result<BitcoinSig, SignerError> {
        Err(SignerError::UserCanceled)
    }
}

impl Signer for PrivateKey {
    fn sign(&self, input: &psbt::Input) -> Result<BitcoinSig, SignerError> {
        Err(SignerError::UserCanceled)
    }
}

/// Struct that contains a parsed Miniscript and all the extracted signers
#[derive(Debug)]
pub struct MiniscriptWithSigners<Pk: SplitSecret, Ctx: ScriptContext> {
    /// The parsed `Miniscript`
    pub miniscript: Miniscript<<Pk as SplitSecret>::Public, Ctx>,
    /// The extracted signers
    pub signers: SignersContainer<<Pk as SplitSecret>::Public>,
}

/// Struct that contains a parsed Descriptor and all the extracted signers
#[derive(Debug)]
pub struct DescriptorWithSigners<Pk: SplitSecret> {
    /// The parsed descriptor
    pub descriptor: Descriptor<<Pk as SplitSecret>::Public>,
    /// The extracted signers
    pub signers: SignersContainer<<Pk as SplitSecret>::Public>,
}

/// Container for multiple signers associated to a `Miniscript<Pk, Ctx>` or a `Descriptor<Pk>`
#[derive(Debug)]
pub struct SignersContainer<Pk: MiniscriptKey>(HashMap<SignerId<Pk>, Box<Signer>>);

impl<Pk: MiniscriptKey> SignersContainer<Pk> {
    /// Default constructor
    pub fn new() -> Self {
        SignersContainer(HashMap::new())
    }

    /// Adds an external signer to the container for the specified id. Optionally returns the
    /// signer that was previosuly in the container, if any
    pub fn add_external(&mut self, id: SignerId<Pk>, signer: Box<Signer>) -> Option<Box<Signer>> {
        self.0.insert(id, signer)
    }

    /// Removes a signer from the container and returns it
    pub fn remove(&mut self, id: SignerId<Pk>) -> Option<Box<Signer>> {
        self.0.remove(&id)
    }

    /// Returns the list of identifiers of all the signers in the container
    pub fn ids(&self) -> Vec<&SignerId<Pk>> {
        self.0.keys().collect()
    }
}
