use std::collections::HashMap;

use bitcoin::util::bip32::{ExtendedPrivKey, Fingerprint};
use bitcoin::util::psbt::PartiallySignedTransaction;

use crate::descriptor::DescriptorXKey;
use miniscript::satisfy::BitcoinSig;
use miniscript::{Miniscript, ScriptContext};
use MiniscriptKey;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum SignerId<Pk: MiniscriptKey> {
    PkHash(<Pk as MiniscriptKey>::Hash),
    Fingerprint(Fingerprint),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SignerError {
    MissingKey,
    UserCanceled,
    // ... add some more here
}

pub trait SplitSecret: Sized + MiniscriptKey {
    type Public: MiniscriptKey<Hash = <Self as MiniscriptKey>::Hash>;

    fn split_secret(
        &self,
    ) -> (
        Self::Public,
        Option<(SignerId<Self::Public>, Box<dyn Signer>)>,
    );
}

pub trait Signer {
    fn sign(&self, psbt: &PartiallySignedTransaction) -> Result<BitcoinSig, SignerError>;
}

// TODO: implement Satisfier for Signers somehow

impl Signer for DescriptorXKey<ExtendedPrivKey> {
    fn sign(&self, psbt: &PartiallySignedTransaction) -> Result<BitcoinSig, SignerError> {
        Err(SignerError::UserCanceled)
    }
}

pub struct MiniscriptWithSigners<Pk: SplitSecret, Ctx: ScriptContext> {
    pub miniscript: Miniscript<<Pk as SplitSecret>::Public, Ctx>,
    pub signers: SignersContainer<<Pk as SplitSecret>::Public>,
}

pub struct SignersContainer<Pk: MiniscriptKey>(HashMap<SignerId<Pk>, Box<dyn Signer>>);

impl<Pk: MiniscriptKey> SignersContainer<Pk> {
    pub fn new() -> Self {
        SignersContainer(HashMap::new())
    }

    pub fn add_external(
        &mut self,
        id: SignerId<Pk>,
        signer: Box<dyn Signer>,
    ) -> Option<Box<dyn Signer>> {
        self.0.insert(id, signer)
    }

    pub fn remove(&mut self, id: SignerId<Pk>) -> Option<Box<dyn Signer>> {
        self.0.remove(&id)
    }

    pub fn ids(&self) -> Vec<&SignerId<Pk>> {
        self.0.keys().collect()
    }
}
