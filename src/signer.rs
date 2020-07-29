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

use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::util::bip32::{ExtendedPrivKey, Fingerprint};
use bitcoin::util::psbt;
use bitcoin::PrivateKey;

use super::descriptor::{Descriptor, DescriptorKey, DescriptorXKey};
use miniscript::satisfy::Satisfier;
use miniscript::{Miniscript, ScriptContext};
use BitcoinSig;
use Legacy;
use MiniscriptKey;
use Segwitv0;

/// Identifier of a signer in the `SignersContainers`. Used as a key to find the right signer among
/// many of them
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum SignerId<Pk: MiniscriptKey> {
    PkHash(<Pk as MiniscriptKey>::Hash),
    Fingerprint(Fingerprint),
}

impl From<hash160::Hash> for SignerId<DescriptorKey> {
    fn from(hash: hash160::Hash) -> SignerId<DescriptorKey> {
        SignerId::PkHash(hash)
    }
}

impl From<Fingerprint> for SignerId<DescriptorKey> {
    fn from(fing: Fingerprint) -> SignerId<DescriptorKey> {
        SignerId::Fingerprint(fing)
    }
}

/// Signing error
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignerError {
    /// The private key is missing for the required public key
    MissingKey,
    /// The user canceled the operation
    UserCanceled,
    /// The sighash is missing in the PSBT input
    MissingSighash,
    /// Input index is out of range
    InputIndexOutOfRange,
    /// The `non_witness_utxo` field of the transaction is required to sign this input
    MissingNonWitnessUtxo,
    /// The `non_witness_utxo` specified is invalid
    InvalidNonWitnessUtxo,
    /// The `witness_utxo` field of the transaction is required to sign this input
    MissingWitnessUtxo,
    /// The `witness_script` field of the transaction is requied to sign this input
    MissingWitnessScript,
    /// The fingerprint and derivation path are missing from the psbt input
    MissingHDKeypath,
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
    fn sign(
        &self,
        psbt: &mut psbt::PartiallySignedTransaction,
        input_index: usize,
    ) -> Result<(), SignerError>;
}

impl Signer for DescriptorXKey<ExtendedPrivKey> {
    fn sign(
        &self,
        psbt: &mut psbt::PartiallySignedTransaction,
        input_index: usize,
    ) -> Result<(), SignerError> {
        if input_index >= psbt.inputs.len() {
            return Err(SignerError::InputIndexOutOfRange);
        }

        let deriv_path = match psbt.inputs[input_index]
            .hd_keypaths
            .iter()
            .filter_map(|(_, &(fingerprint, ref path))| self.matches(fingerprint.clone(), &path))
            .next()
        {
            Some(deriv_path) => deriv_path,
            None => return Err(SignerError::MissingHDKeypath),
        };

        let ctx = Secp256k1::signing_only();

        let derived_key = self.xkey.derive_priv(&ctx, &deriv_path).unwrap();
        derived_key.private_key.sign(psbt, input_index)
    }
}

impl Signer for PrivateKey {
    fn sign(
        &self,
        psbt: &mut psbt::PartiallySignedTransaction,
        input_index: usize,
    ) -> Result<(), SignerError> {
        if input_index >= psbt.inputs.len() {
            return Err(SignerError::InputIndexOutOfRange);
        }

        let ctx = Secp256k1::signing_only();

        let pubkey = self.public_key(&ctx);
        if psbt.inputs[input_index].partial_sigs.contains_key(&pubkey) {
            return Ok(());
        }

        // FIXME: use the presence of `witness_utxo` as an indication that we should make a bip143
        // sig. Does this make sense? Should we add an extra argument to explicitly swith between
        // these? The original idea was to declare sign() as sign<Ctx: ScriptContex>() and use Ctx,
        // but that violates the rules for trait-objects, so we can't do it.
        let (hash, sighash) = match psbt.inputs[input_index].witness_utxo {
            Some(_) => Segwitv0::sighash(psbt, input_index)?,
            None => Legacy::sighash(psbt, input_index)?,
        };

        let signature = ctx.sign(
            &Message::from_slice(&hash.into_inner()[..]).unwrap(),
            &self.key,
        );

        let mut final_signature = Vec::with_capacity(75);
        final_signature.extend_from_slice(&signature.serialize_der());
        final_signature.push(sighash.as_u32() as u8);

        psbt.inputs[input_index]
            .partial_sigs
            .insert(pubkey, final_signature);

        Ok(())
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

impl<Pk: MiniscriptKey> Signer for SignersContainer<Pk> {
    fn sign(
        &self,
        psbt: &mut psbt::PartiallySignedTransaction,
        input_index: usize,
    ) -> Result<(), SignerError> {
        for signer in self.0.values() {
            signer.sign(psbt, input_index)?;
        }

        Ok(())
    }
}

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

    /// Finds the signer with a given id in the container
    pub fn find(&self, id: SignerId<Pk>) -> Option<&Box<Signer>> {
        self.0.get(&id)
    }
}

pub struct PSBTSigningContext<'p> {
    psbt: Mutex<&'p mut psbt::PartiallySignedTransaction>,
    input_index: usize,
    signers: Arc<SignersContainer<DescriptorKey>>,
}

impl<'p> PSBTSigningContext<'p> {
    pub fn new(
        psbt: &'p mut psbt::PartiallySignedTransaction,
        input_index: usize,
        signers: &Arc<SignersContainer<DescriptorKey>>,
    ) -> PSBTSigningContext<'p> {
        PSBTSigningContext {
            psbt: Mutex::new(psbt),
            input_index,
            signers: Arc::clone(signers),
        }
    }
}

impl<'p> Satisfier<DescriptorKey> for PSBTSigningContext<'p> {
    fn lookup_sig(&self, descriptor_key: &DescriptorKey) -> Option<BitcoinSig> {
        let mut psbt = self.psbt.lock().unwrap();

        assert!(self.input_index < psbt.inputs.len());

        let psbt_input = &psbt.inputs[self.input_index];

        let (pubkey, maybe_signer) = match descriptor_key {
            &DescriptorKey::PubKey(pubkey) => {
                (pubkey, self.signers.find(pubkey.to_pubkeyhash().into()))
            }
            &DescriptorKey::XPub(ref xpub) => {
                match psbt_input
                    .hd_keypaths
                    .iter()
                    .filter_map(|(&pubkey, &(fingerprint, ref path))| {
                        if xpub.matches(fingerprint.clone(), &path).is_some() {
                            Some((pubkey, self.signers.find(fingerprint.clone().into())))
                        } else {
                            None
                        }
                    })
                    .next()
                {
                    Some(tuple) => tuple,
                    None => return None,
                }
            }
        };

        if let Some(signer) = maybe_signer {
            signer.sign(psbt.borrow_mut(), self.input_index).unwrap(); // TODO: unwrap
        }

        psbt.inputs[self.input_index].lookup_sig(&pubkey)
    }
}
