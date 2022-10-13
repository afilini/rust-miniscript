// TODO: copyright etc
#![allow(unused)]
#![allow(missing_docs)]
//! A spending plan or *plan* for short is a representation of a particular spending path on a
//! descriptor. This allows us to analayze a choice of spending path without producing any
//! signatures or other witness data for it.
//!
//! To make a plan you provide the descriptor with "assets" like which keys you are able to use, hash
//! pre-images you have access to, the current block height etc.
//!
//! Once you've got a plan it can tell you its expected satisfaction weight which can be useful for
//! doing coin selection. Furthermore it provides which subset of those keys and hash pre-images you
//! will actually need as well as what locktime or sequence number you need to set.
//!
//! Once you've obstained signatures, hash pre-images etc required by the plan, it can create a
//! witness/script_sig for the input.

use crate::descriptor::{Bare, Wsh, WshInner};
use crate::miniscript::satisfy::{Placeholder, Satisfaction, Satisfier};
use crate::miniscript::{hash256, Miniscript};
use crate::{
    DefiniteDescriptorKey, Descriptor, MiniscriptKey, ScriptContext, Terminal, ToPublicKey,
};
use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::util::bip32::KeySource;
use bitcoin::util::taproot::TapLeafHash;
use bitcoin::{LockTime, Sequence};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

/// TODO
pub trait AssetProvider<Pk: MiniscriptKey> {
    /// Given a public key, look up an ECDSA signature with that key
    fn lookup_ecdsa_sig(&self, _: &Pk) -> bool {
        false
    }

    /// Lookup the tap key spend sig
    fn lookup_tap_key_spend_sig(&self) -> bool {
        false
    }

    /// Given a public key and a associated leaf hash, look up an schnorr signature with that key
    fn lookup_tap_leaf_script_sig(&self, _: &Pk, _: &TapLeafHash) -> bool {
        false
    }

    /// Given a raw `Pkh`, lookup corresponding `Pk`. TODO: da indietro lunghezza
    fn lookup_raw_pkh_pk<Ctx: ScriptContext>(&self, _: &hash160::Hash) -> Option<usize> {
        None
    }

    /// Given a keyhash, look up the EC signature and the associated key
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can be useful
    /// for dissatisfying pkh.
    fn lookup_raw_pkh_ecdsa_sig<Ctx: ScriptContext>(&self, _: &hash160::Hash) -> Option<usize> {
        None
    }

    /// Given a keyhash, look up the schnorr signature and the associated key
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can be useful
    /// for dissatisfying pkh.
    fn lookup_raw_pkh_tap_leaf_script_sig(&self, _: &(hash160::Hash, TapLeafHash)) -> bool {
        false
    }

    /// Given a SHA256 hash, look up its preimage
    fn lookup_sha256(&self, _: &Pk::Sha256) -> bool {
        false
    }

    /// Given a HASH256 hash, look up its preimage
    fn lookup_hash256(&self, _: &Pk::Hash256) -> bool {
        false
    }

    /// Given a RIPEMD160 hash, look up its preimage
    fn lookup_ripemd160(&self, _: &Pk::Ripemd160) -> bool {
        false
    }

    /// Given a HASH160 hash, look up its preimage
    fn lookup_hash160(&self, _: &Pk::Hash160) -> bool {
        false
    }

    /// Assert whether an relative locktime is satisfied
    fn check_older(&self, _: Sequence) -> bool {
        false
    }

    /// Assert whether a absolute locktime is satisfied
    fn check_after(&self, _: LockTime) -> bool {
        false
    }
}

struct LoggerAssetProvider(Assets);

macro_rules! impl_log_method {
    ( $name:ident, $( <$ctx:ident: ScriptContext > )? $( $arg:ident : $ty:ty, )* -> $ret_ty:ty ) => {
        fn $name $( <$ctx: ScriptContext> )? ( &self, $( $arg:$ty ),* ) -> $ret_ty {
            let ret = self.0.$name $( ::<$ctx> )*( $( $arg ),* );
            dbg!(stringify!( $name ), ( $( $arg ),* ), &ret);

            ret
        }
    }
}

impl AssetProvider<DefiniteDescriptorKey> for LoggerAssetProvider {
    impl_log_method!(lookup_ecdsa_sig, pk: &DefiniteDescriptorKey, -> bool);
    impl_log_method!(lookup_tap_key_spend_sig, -> bool);
    impl_log_method!(lookup_tap_leaf_script_sig, pk: &DefiniteDescriptorKey, leaf_hash: &TapLeafHash, -> bool);
    impl_log_method!(lookup_raw_pkh_pk, <Ctx: ScriptContext> hash: &hash160::Hash, -> Option<usize>);
    impl_log_method!(lookup_raw_pkh_ecdsa_sig, <Ctx: ScriptContext> hash: &hash160::Hash, -> Option<usize>);
    impl_log_method!(lookup_raw_pkh_tap_leaf_script_sig, hash: &(hash160::Hash, TapLeafHash), -> bool);
    impl_log_method!(lookup_sha256, hash: &sha256::Hash, -> bool);
    impl_log_method!(lookup_hash256, hash: &hash256::Hash, -> bool);
    impl_log_method!(lookup_ripemd160, hash: &ripemd160::Hash, -> bool);
    impl_log_method!(lookup_hash160, hash: &hash160::Hash, -> bool);
    impl_log_method!(check_older, s: Sequence, -> bool);
    impl_log_method!(check_after, t: LockTime, -> bool);
}

impl<T, Pk> AssetProvider<Pk> for T
where
    T: Satisfier<Pk>,
    Pk: MiniscriptKey + ToPublicKey,
{
    fn lookup_ecdsa_sig(&self, pk: &Pk) -> bool {
        Satisfier::lookup_ecdsa_sig(self, pk).is_some()
    }

    fn lookup_tap_key_spend_sig(&self) -> bool {
        Satisfier::lookup_tap_key_spend_sig(self).is_some()
    }

    fn lookup_tap_leaf_script_sig(&self, pk: &Pk, leaf_hash: &TapLeafHash) -> bool {
        Satisfier::lookup_tap_leaf_script_sig(self, pk, leaf_hash).is_some()
    }

    fn lookup_raw_pkh_pk<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        // Ctx::pk_len includes a one-byte OP_PUSH, which we don't need here
        Satisfier::lookup_raw_pkh_pk(self, hash).map(|p| Ctx::pk_len(&p) - 1)
    }

    fn lookup_raw_pkh_ecdsa_sig<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        // Ctx::pk_len includes a one-byte OP_PUSH, which we don't need here
        Satisfier::lookup_raw_pkh_ecdsa_sig(self, hash).map(|(p, _)| Ctx::pk_len(&p) - 1)
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(&self, hash: &(hash160::Hash, TapLeafHash)) -> bool {
        Satisfier::lookup_raw_pkh_tap_leaf_script_sig(self, hash).is_some()
    }

    fn lookup_sha256(&self, hash: &Pk::Sha256) -> bool {
        Satisfier::lookup_sha256(self, hash).is_some()
    }

    fn lookup_hash256(&self, hash: &Pk::Hash256) -> bool {
        Satisfier::lookup_hash256(self, hash).is_some()
    }

    fn lookup_ripemd160(&self, hash: &Pk::Ripemd160) -> bool {
        Satisfier::lookup_ripemd160(self, hash).is_some()
    }

    fn lookup_hash160(&self, hash: &Pk::Hash160) -> bool {
        Satisfier::lookup_hash160(self, hash).is_some()
    }

    fn check_older(&self, s: Sequence) -> bool {
        Satisfier::check_older(self, s)
    }

    fn check_after(&self, l: LockTime) -> bool {
        Satisfier::check_after(self, l)
    }
}

#[derive(Debug, Default)]
pub struct Assets {
    // TODO: add signatures as well
    // TODO: tap key_spend sig
    // TODO: key hashes
    keys: HashSet<DefiniteDescriptorKey>, // poi lo mettiamo generico con CanDerive per le DescPubKey
    sha256_preimages: HashSet<sha256::Hash>,
    hash256_preimages: HashSet<hash256::Hash>,
    ripemd160_preimages: HashSet<ripemd160::Hash>,
    hash160_preimages: HashSet<hash160::Hash>,
    absolute_timelock: Option<LockTime>,
    relative_timelock: Option<Sequence>,
}

impl AssetProvider<DefiniteDescriptorKey> for Assets {
    fn lookup_ecdsa_sig(&self, pk: &DefiniteDescriptorKey) -> bool {
        // TODO: match using keysource
        self.keys.contains(pk)
    }

    fn lookup_tap_key_spend_sig(&self) -> bool {
        false
    }

    fn lookup_tap_leaf_script_sig(&self, pk: &DefiniteDescriptorKey, _: &TapLeafHash) -> bool {
        // TODO: match using keysource
        self.keys.contains(pk)
    }

    fn lookup_raw_pkh_pk<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        None
    }

    fn lookup_raw_pkh_ecdsa_sig<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        None
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(&self, hash: &(hash160::Hash, TapLeafHash)) -> bool {
        false
    }

    fn lookup_sha256(&self, hash: &sha256::Hash) -> bool {
        self.sha256_preimages.contains(hash)
    }

    fn lookup_hash256(&self, hash: &hash256::Hash) -> bool {
        self.hash256_preimages.contains(hash)
    }

    fn lookup_ripemd160(&self, hash: &ripemd160::Hash) -> bool {
        self.ripemd160_preimages.contains(hash)
    }

    fn lookup_hash160(&self, hash: &hash160::Hash) -> bool {
        self.hash160_preimages.contains(hash)
    }

    fn check_older(&self, s: Sequence) -> bool {
        if let Some(rt) = &self.relative_timelock {
            return rt.partial_cmp(&s) == Some(Ordering::Less);
        }

        false
    }

    fn check_after(&self, l: LockTime) -> bool {
        if let Some(at) = &self.absolute_timelock {
            return at.partial_cmp(&l) == Some(Ordering::Less);
        }

        false
    }
}

pub trait IntoAssets {
    fn into_assets(self) -> Assets;
}

impl IntoAssets for DefiniteDescriptorKey {
    fn into_assets(self) -> Assets {
        Assets {
            keys: vec![self].into_iter().collect(),
            ..Default::default()
        }
    }
}

// TODO: all the other hash types
impl IntoAssets for sha256::Hash {
    fn into_assets(self) -> Assets {
        Assets {
            sha256_preimages: vec![self].into_iter().collect(),
            ..Default::default()
        }
    }
}

impl Assets {
    fn new() -> Self {
        Self::default()
    }

    fn add<A: IntoAssets>(mut self, asset: A) -> Self {
        self.append(asset.into_assets());
        self
    }

    fn older(mut self, seq: Sequence) -> Self {
        self.relative_timelock = Some(seq);
        self
    }

    fn after(mut self, lt: LockTime) -> Self {
        self.absolute_timelock = Some(lt);
        self
    }

    fn append(&mut self, b: Self) {
        self.keys.extend(b.keys.into_iter());
        self.sha256_preimages.extend(b.sha256_preimages.into_iter());
        self.hash256_preimages
            .extend(b.hash256_preimages.into_iter());
        self.ripemd160_preimages
            .extend(b.ripemd160_preimages.into_iter());
        self.hash160_preimages
            .extend(b.hash160_preimages.into_iter());

        self.relative_timelock = b.relative_timelock.or(self.relative_timelock);
        self.absolute_timelock = b.absolute_timelock.or(self.absolute_timelock);
    }
}

impl Descriptor<DefiniteDescriptorKey> {
    fn plan<P: AssetProvider<DefiniteDescriptorKey>>(
        &self,
        provider: &P,
    ) -> Satisfaction<Placeholder<DefiniteDescriptorKey>> {
        match *self {
            Descriptor::Bare(ref bare) => bare.plan(provider),
            Descriptor::Wsh(ref wsh) => wsh.plan(provider),
            _ => todo!(),
            /*
            Descriptor::Pkh(ref pkh) => pkh.get_satisfaction(satisfier),
            Descriptor::Wpkh(ref wpkh) => wpkh.get_satisfaction(satisfier),
            Descriptor::Wsh(ref wsh) => wsh.get_satisfaction(satisfier),
            Descriptor::Sh(ref sh) => sh.get_satisfaction(satisfier),
            Descriptor::Tr(ref tr) => tr.get_satisfaction(satisfier),
            */
        }
    }
}

impl Bare<DefiniteDescriptorKey> {
    fn plan<P: AssetProvider<DefiniteDescriptorKey>>(
        &self,
        provider: &P,
    ) -> Satisfaction<Placeholder<DefiniteDescriptorKey>> {
        self.as_inner().plan(provider)
    }
}

impl Wsh<DefiniteDescriptorKey> {
    fn plan<P: AssetProvider<DefiniteDescriptorKey>>(
        &self,
        provider: &P,
    ) -> Satisfaction<Placeholder<DefiniteDescriptorKey>> {
        self.as_inner().plan(provider)
    }
}
impl WshInner<DefiniteDescriptorKey> {
    fn plan<P: AssetProvider<DefiniteDescriptorKey>>(
        &self,
        provider: &P,
    ) -> Satisfaction<Placeholder<DefiniteDescriptorKey>> {
        match self {
            WshInner::SortedMulti(sm) => todo!(),
            WshInner::Ms(ms) => ms.plan(provider),
        }
    }
}

impl<Ctx: ScriptContext> Miniscript<DefiniteDescriptorKey, Ctx> {
    fn plan<P: AssetProvider<DefiniteDescriptorKey>>(
        &self,
        provider: &P,
    ) -> Satisfaction<Placeholder<DefiniteDescriptorKey>> {
        self.build_template(provider)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::miniscript::satisfy::Witness;
    use crate::*;
    use std::str::FromStr;

    #[test]
    fn test_plan() {
        let key = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";
        let desc = format!("wsh(and_v(or_c(pk(023fc33527afab09fa97135f2180bcd22ce637b1d2fbcb2db748b1f2c33f45b2b4),v:older(12960)),pk({}/1/2/*)))", key);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc).unwrap();

        let def_key = DefiniteDescriptorKey::from_str(&format!("{}/1/2/3", key)).unwrap();

        let assets = Assets::new()
            .add(def_key)
            .older(Sequence::from_height(1000));

        let result = desc.at_derivation_index(3).plan(&assets);
        assert!(matches!(result.stack, Witness::Stack(_)));
        assert_eq!(result.relative_timelock, Some(bitcoin::Sequence(12960)));
    }

    fn test_inner(
        ms: &str,
        keys: Vec<DefiniteDescriptorKey>,
        tests: Vec<(Vec<usize>, Option<usize>)>,
    ) {
        let ms = Miniscript::<DefiniteDescriptorKey, Segwitv0>::from_str(&ms).unwrap();

        for (key_indexes, expected) in tests {
            let mut assets = Assets::new();
            for ki in key_indexes {
                assets = assets.add(keys[ki].clone());
            }

            let result = ms.plan(&assets);
            dbg!(&result);
            assert_eq!(result.stack.size(), expected);
        }
    }

    #[test]
    fn test_or() {
        let keys = vec![
            DefiniteDescriptorKey::from_str(
                "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
            )
            .unwrap(),
            DefiniteDescriptorKey::from_str(
                "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
            )
            .unwrap(),
        ];

        let tests = vec![(vec![], None), (vec![0], Some(73)), (vec![0, 1], Some(73))];

        let ms = format!("t:or_c(pk({}),v:pkh({}))", keys[0], keys[1]);

        test_inner(&ms, keys, tests);
    }

    #[test]
    fn test_and() {
        let keys = vec![
            DefiniteDescriptorKey::from_str(
                "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
            )
            .unwrap(),
            DefiniteDescriptorKey::from_str(
                "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
            )
            .unwrap(),
        ];

        let tests = vec![(vec![], None), (vec![0], None), (vec![0, 1], Some(73 * 2))];

        let ms = format!("and_v(v:pk({}),pk({}))", keys[0], keys[1]);

        test_inner(&ms, keys, tests);
    }

    // #[test]
    // fn test_multi() {
    //     let keys = vec![
    //         DefiniteDescriptorKey::from_str("02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c").unwrap(),
    //         DefiniteDescriptorKey::from_str("0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a").unwrap(),
    //         DefiniteDescriptorKey::from_str("03500a2b48b0f66c8183cc0d6645ab21cc19c7fad8a33ff04d41c3ece54b0bc1c5").unwrap(),
    //         DefiniteDescriptorKey::from_str("033ad2d191da4f39512adbaac320cae1f12f298386a4e9d43fd98dec7cf5db2ac9").unwrap(),
    //     ];

    //     let tests = vec![
    //         (vec![], None),
    //         (vec![0, 1], None),
    //         (vec![0, 1, 3], Some(34 * 3)),
    //     ];

    //     let ms = format!("multi(3,{},{},{},{})", keys[0], keys[1], keys[2], keys[3]);

    //     test_inner(&ms, keys, tests);
    // }
}

// Esempio di API
/*
{
    let assets_che_ho = Assets::new().add(keys).add(preimages).add(psbt_input).at_least(10);
    let _tutti = Assets::everything();
    let plan = my_descriptor.plan(&assets)?;
    println!("{}", plan.weight());
    println!("{}", plan.assets_needed());
    plan.try_satisfy(satisfier, psbt, input_index); // or psbt input?
}
*/
