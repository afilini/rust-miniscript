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
use crate::miniscript::{hash256, Miniscript};
use crate::{DefiniteDescriptorKey, Descriptor, ScriptContext, Terminal};
use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::util::bip32::KeySource;
use bitcoin::{LockTime, Sequence};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct Assets {
    keys: HashSet<DefiniteDescriptorKey>, // poi lo mettiamo generico con CanDerive per le DescPubKey
    sha256_preimages: HashMap<sha256::Hash, usize>,
    hash256_preimages: HashMap<hash256::Hash, usize>,
    ripemd160_preimages: HashMap<ripemd160::Hash, usize>,
    hash160_preimages: HashMap<hash160::Hash, usize>,
    absolute_timelock: Timelock<LockTime>, // restrizioni
    relative_timelock: Timelock<Sequence>, // restrizioni
}

impl Default for Assets {
    fn default() -> Self {
        Assets {
            keys: Default::default(),
            sha256_preimages: Default::default(),
            hash256_preimages: Default::default(),
            ripemd160_preimages: Default::default(),
            hash160_preimages: Default::default(),
            absolute_timelock: Default::default(),
            relative_timelock: Default::default(),
        }
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

impl IntoAssets for (sha256::Hash, usize) {
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

    fn get_key<'s>(&'s self, k: &DefiniteDescriptorKey) -> Option<&'s DefiniteDescriptorKey> {
        // Piú check: fingerprint, canderive ecc
        self.keys.get(k)
    }

    fn add<A: IntoAssets>(mut self, asset: A) -> Self {
        self.append(asset.into_assets());
        self
    }

    fn at_least_relative(mut self, seq: Sequence) -> Result<Self, TimelockError> {
        self.relative_timelock.replace_at_least(Some(seq))?;
        Ok(self)
    }

    fn at_most_relative(mut self, seq: Sequence) -> Result<Self, TimelockError> {
        self.relative_timelock.replace_at_most(Some(seq))?;
        Ok(self)
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

        // TODO: merge timelocks
    }
}

#[derive(Debug, Clone, Default)]
pub struct AssetsRef<'a> {
    keys: Vec<&'a DefiniteDescriptorKey>, // poi lo mettiamo generico con CanDerive per le DescPubKey
    sha256_preimages: Vec<&'a (sha256::Hash, usize)>,
    hash256_preimages: Vec<&'a (hash256::Hash, usize)>,
    ripemd160_preimages: Vec<&'a (ripemd160::Hash, usize)>,
    hash160_preimages: Vec<&'a (hash160::Hash, usize)>,

    weight: usize,
}

impl<'a> AssetsRef<'a> {
    fn empty() -> Self {
        Self::default()
    }

    fn new_pk<Ctx: ScriptContext>(key: &'a DefiniteDescriptorKey) -> Self {
        AssetsRef {
            keys: vec![key],
            weight: Ctx::pk_len(key),

            ..Default::default()
        }
    }

    fn new_sha256(hash: &'a (sha256::Hash, usize)) -> Self {
        AssetsRef {
            sha256_preimages: vec![hash],
            weight: hash.1,

            ..Default::default()
        }
    }

    fn new_hash256(hash: &'a (hash256::Hash, usize)) -> Self {
        AssetsRef {
            hash256_preimages: vec![hash],
            weight: hash.1,

            ..Default::default()
        }
    }

    fn new_ripemd160(hash: &'a (ripemd160::Hash, usize)) -> Self {
        AssetsRef {
            ripemd160_preimages: vec![hash],
            weight: hash.1,

            ..Default::default()
        }
    }

    fn new_hash160(hash: &'a (hash160::Hash, usize)) -> Self {
        AssetsRef {
            hash160_preimages: vec![hash],
            weight: hash.1,

            ..Default::default()
        }
    }

    fn merge(mut a: Self, b: Self) -> Self {
        a.keys.extend(b.keys.into_iter());
        a.sha256_preimages.extend(b.sha256_preimages.into_iter());
        a.hash256_preimages.extend(b.hash256_preimages.into_iter());
        a.ripemd160_preimages
            .extend(b.ripemd160_preimages.into_iter());
        a.hash160_preimages.extend(b.hash160_preimages.into_iter());

        a.weight += b.weight;

        a
    }

    fn weight(&self) -> usize {
        self.weight
    }
}

// TODO change name
#[derive(Debug)]
pub struct Timelock<T> {
    at_least: Option<T>,
    at_most: Option<T>,
}

impl<T> Default for Timelock<T> {
    fn default() -> Self {
        Timelock {
            at_least: None,
            at_most: None,
        }
    }
}

// TODO: impl Error
#[derive(Debug)]
pub enum TimelockError {
    IncompatibleTimelocks,
    AtLeastGreaterThanAtMost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimelockComparison {
    Invalid,
    LowerThanAtLeast,
    Valid,
}

impl<T: PartialOrd + Clone + std::fmt::Debug> Timelock<T> {
    fn new(at_least: Option<T>, at_most: Option<T>) -> Result<Self, TimelockError> {
        if let (Some(l), Some(m)) = (&at_least, &at_most) {
            match l.partial_cmp(&m) {
                None => return Err(TimelockError::IncompatibleTimelocks),
                Some(Ordering::Greater) => return Err(TimelockError::AtLeastGreaterThanAtMost),
                _ => {}
            }
        }

        Ok(Timelock { at_least, at_most })
    }

    fn replace_at_most(&mut self, at_most: Option<T>) -> Result<(), TimelockError> {
        *self = Timelock::new(self.at_least.clone(), at_most)?;
        Ok(())
    }

    fn replace_at_least(&mut self, at_least: Option<T>) -> Result<(), TimelockError> {
        *self = Timelock::new(at_least, self.at_most.clone())?;
        Ok(())
    }

    fn is_valid(&self, to_compare: T) -> TimelockComparison {
        let Timelock { at_least, at_most } = &self;

        match at_most {
            Some(m) if m.partial_cmp(&to_compare).is_none() || to_compare > *m => {
                return TimelockComparison::Invalid;
            }
            _ => {}
        }

        match at_least {
            Some(l) if l.partial_cmp(&to_compare).is_none() => TimelockComparison::Invalid,
            Some(l) if to_compare < *l => TimelockComparison::LowerThanAtLeast,
            _ => TimelockComparison::Valid,
        }
    }
}

impl Descriptor<DefiniteDescriptorKey> {
    fn plan<'a>(&self, assets: &'a Assets) -> Option<Solution<'a>> {
        match *self {
            Descriptor::Bare(ref bare) => bare.plan(assets),
            Descriptor::Wsh(ref wsh) => wsh.plan(assets),
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
    fn plan<'a>(&self, assets: &'a Assets) -> Option<Solution<'a>> {
        self.as_inner().plan(assets)
    }
}

impl Wsh<DefiniteDescriptorKey> {
    fn plan<'a>(&self, assets: &'a Assets) -> Option<Solution<'a>> {
        self.as_inner().plan(assets)
    }
}
impl WshInner<DefiniteDescriptorKey> {
    fn plan<'a>(&self, assets: &'a Assets) -> Option<Solution<'a>> {
        match self {
            WshInner::SortedMulti(sm) => todo!(),
            WshInner::Ms(ms) => ms.plan(assets)
        }
    }
}

impl<Ctx: ScriptContext> Miniscript<DefiniteDescriptorKey, Ctx> {
    fn plan<'a>(&self, assets: &'a Assets) -> Option<Solution<'a>> {
        plan_helper(&self.node, assets)
    }
}

fn plan_helper<'a, Ctx: ScriptContext>(
    node: &Terminal<DefiniteDescriptorKey, Ctx>,
    assets: &'a Assets,
) -> Option<Solution<'a>> {
    let result = match node {
        Terminal::True => Some(Solution::new_optimal_empty()),
        Terminal::False => Some(Solution::new_optimal_empty()),
        Terminal::PkH(pk) | Terminal::PkK(pk) | Terminal::RawPkH(pk) => {
            Solution::new_pk::<Ctx>(pk, assets)
        }
        // absolute
        Terminal::After(t) => match assets.absolute_timelock.is_valid(t.into()) {
            TimelockComparison::Invalid => None,
            TimelockComparison::LowerThanAtLeast => Some(Solution::new_optimal_empty()),
            TimelockComparison::Valid => Some(Solution::new_with_timelock(Some(t.into()), None)),
        },
        // relative
        Terminal::Older(t) => match assets.relative_timelock.is_valid(*t) {
            TimelockComparison::Invalid => None,
            TimelockComparison::LowerThanAtLeast => Some(Solution::new_optimal_empty()),
            TimelockComparison::Valid => Some(Solution::new_with_timelock(None, Some(*t))),
        },
        // Terminal::Sha256(h) => {
        //     if assets.sha256_preimages.contains(h) {
        //         Solution::new_optimal_only(33)
        //     } else {
        //         Solution::Impossible
        //     }
        // }
        // Terminal::Hash256(h) => {
        //     if assets.hash256_preimages.contains(h) {
        //         Solution::new_optimal_only(33)
        //     } else {
        //         Solution::Impossible
        //     }
        // }
        // Terminal::Ripemd160(h) => {
        //     if assets.ripemd160_preimages.contains(h) {
        //         Solution::new_optimal_only(21)
        //     } else {
        //         Solution::Impossible
        //     }
        // }
        // Terminal::Hash160(h) => {
        //     if assets.hash160_preimages.contains(h) {
        //         Solution::new_optimal_only(21)
        //     } else {
        //         Solution::Impossible
        //     }
        // }
        Terminal::Alt(ms)
        | Terminal::Swap(ms)
        | Terminal::Check(ms)
        | Terminal::DupIf(ms)
        | Terminal::Verify(ms)
        | Terminal::NonZero(ms)
        | Terminal::ZeroNotEqual(ms) => plan_helper(&ms.node, assets),
        Terminal::AndV(ms1, ms2) | Terminal::AndB(ms1, ms2) => Solution::new_and(
            plan_helper(&ms1.node, assets),
            plan_helper(&ms2.node, assets),
        ),
        Terminal::AndOr(x, y, z) => Solution::new_or(
            Solution::new_and(plan_helper(&x.node, assets), plan_helper(&y.node, assets)),
            plan_helper(&z.node, assets),
        ),
        Terminal::OrB(a, b) | Terminal::OrD(a, b) | Terminal::OrC(a, b) | Terminal::OrI(a, b) => {
            Solution::new_or(plan_helper(&a.node, assets), plan_helper(&b.node, assets))
        }
        Terminal::Thresh(thresh, vec) => {
            let solutions = vec.iter().map(|ms| plan_helper(&ms.node, assets)).collect();
            Solution::new_thresh(*thresh, solutions)
        }
        Terminal::Multi(thresh, keys) | Terminal::MultiA(thresh, keys) => {
            let solutions = keys
                .into_iter()
                .map(|pk| Solution::new_pk::<Ctx>(pk, assets))
                .collect();
            Solution::new_thresh(*thresh, solutions)
        }

        _ => todo!(),
    };

    dbg!(&node, &result);

    result
}

#[derive(Debug, Clone)]
struct TimelockSolution<'a> {
    assets: AssetsRef<'a>,
    absolute: Option<LockTime>,
    relative: Option<Sequence>,
}

impl<'a> TimelockSolution<'a> {
    fn extend(a: Self, b: AssetsRef<'a>) -> Self {
        let assets = AssetsRef::merge(a.assets, b);

        TimelockSolution {
            assets,
            absolute: a.absolute,
            relative: a.relative,
        }
    }
}

#[derive(Debug, Clone)]
struct Solution<'a> {
    optimal: AssetsRef<'a>,
    with_timelock: Option<TimelockSolution<'a>>,
}

impl<'a> Solution<'a> {
    fn optimal(&self) -> usize {
        self.optimal.weight()
    }

    fn with_timelock(&self) -> Option<usize> {
        self.with_timelock.as_ref().map(|ts| ts.assets.weight())
    }

    fn new_optimal_empty() -> Self {
        Solution {
            optimal: AssetsRef::empty(),
            with_timelock: None,
        }
    }

    fn new_optimal_only(assets: AssetsRef<'a>) -> Self {
        Solution {
            optimal: assets,
            with_timelock: None,
        }
    }

    fn new_with_timelock(absolute: Option<LockTime>, relative: Option<Sequence>) -> Self {
        Solution {
            optimal: AssetsRef::empty(),
            with_timelock: Some(TimelockSolution {
                assets: AssetsRef::empty(),
                absolute,
                relative,
            }),
        }
    }

    fn new_pk<Ctx: ScriptContext>(pk: &DefiniteDescriptorKey, assets: &'a Assets) -> Option<Self> {
        assets.get_key(pk).map(|key| {
            let assets_ref = AssetsRef::new_pk::<Ctx>(key);
            Self::new_optimal_only(assets_ref)
        })
    }

    // TODO: new_hash

    fn new_and(a: Option<Self>, b: Option<Self>) -> Option<Self> {
        match (a, b) {
            (Some(a), Some(b)) => {
                let a_optimal = a.optimal.clone();
                let b_optimal = b.optimal.clone();

                let optimal = AssetsRef::merge(a.optimal, b.optimal);

                let with_timelock = match (a.with_timelock, b.with_timelock) {
                    (None, None) => None,
                    (Some(a), None) => Some(TimelockSolution::extend(a, b_optimal)),
                    (None, Some(b)) => Some(TimelockSolution::extend(b, a_optimal)),
                    (Some(a), Some(b)) => {
                        // Since the `optimal` solution is always <= `with_timelock`, we can just
                        // try which one of `a.optimal + b.with_timelock` and `a.with_timelock +
                        // b.optimal` is the best solution.

                        let x = TimelockSolution::extend(a, b_optimal);
                        let y = TimelockSolution::extend(b, a_optimal);

                        if x.assets.weight() < y.assets.weight() {
                            Some(x)
                        } else {
                            Some(y)
                        }
                    }
                };

                Some(Solution {
                    optimal,
                    with_timelock,
                })
            }
            _ => None,
        }
    }

    fn new_or(a: Option<Self>, b: Option<Self>) -> Option<Self> {
        match (a, b) {
            (Some(a), Some(b)) => {
                let optimal = if a.optimal.weight() < b.optimal.weight() {
                    a.optimal
                } else {
                    b.optimal
                };

                let with_timelock = match (a.with_timelock, b.with_timelock) {
                    (Some(a), Some(b)) => {
                        if a.assets.weight() < b.assets.weight() {
                            Some(a)
                        } else {
                            Some(b)
                        }
                    }
                    (None, None) => None,
                    (Some(a), _) => Some(a),
                    (_, Some(b)) => Some(b),
                };

                Some(Solution {
                    optimal,
                    with_timelock,
                })
            }
            (None, None) => None,
            (Some(a), _) => Some(a),
            (_, Some(b)) => Some(b),
        }
    }

    fn new_thresh(thresh: usize, list: Vec<Option<Solution>>) -> Option<Solution> {
        debug_assert!(thresh > 0);

        // Filter out the impossible items in the list, then sort by optimal weight
        let mut sorted_optimal = list
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.as_ref().map(|solution| (i, solution.optimal.clone())))
            .collect::<Vec<_>>();

        // If there aren't enough item after excluding the `Impossible`, this is also `Impossible`
        if sorted_optimal.len() < thresh {
            return None;
        }
        sorted_optimal.sort_unstable_by_key(|(_, optimal)| optimal.weight());

        // Try with all the items that can satisfy the timelock requirement
        let mut with_timelock_list = list
            .iter()
            .enumerate()
            .filter_map(|(i, p)| match p {
                Some(Solution {
                    with_timelock: Some(wt),
                    ..
                }) => {
                    // We take the current element with timelock weight,
                    // then we take the sorted_optimal list, we remove the current element,
                    // and we take the thresh - 1 best optimal weight
                    Some(TimelockSolution::extend(
                        wt.clone(),
                        sorted_optimal
                            .iter()
                            .filter(|(index, _)| *index != i)
                            .take(thresh - 1)
                            .fold(AssetsRef::empty(), |acc, (_, assets)| {
                                AssetsRef::merge(acc, assets.clone())
                            }),
                    ))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        // Sort by weight, and the first one is our with_timelock optimal solution (if any)
        with_timelock_list.sort_unstable_by_key(|ts| ts.assets.weight());

        Some(Solution {
            optimal: sorted_optimal
                .iter()
                .take(thresh)
                .fold(AssetsRef::empty(), |acc, (_, assets)| {
                    AssetsRef::merge(acc, assets.clone())
                }),
            with_timelock: with_timelock_list.get(0).cloned(),
        })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use crate::*;
    use super::*;

    #[test]
    fn test_plan() {
        let key = "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";
        let desc = format!("wsh(and_v(or_c(pk(023fc33527afab09fa97135f2180bcd22ce637b1d2fbcb2db748b1f2c33f45b2b4),v:older(12960)),pk({}/1/2/*)))", key);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc).unwrap();

        let def_key = DefiniteDescriptorKey::from_str(&format!("{}/1/2/3", key)).unwrap();

        let assets = Assets::new()
            .add(def_key)
            .at_least_relative(Sequence::from_height(1000)).unwrap()
            .at_most_relative(Sequence::from_height(13000)).unwrap();
        dbg!(&assets);

        let result = desc.at_derivation_index(3).plan(&assets);
        dbg!(&result);
    }

    fn test_inner(ms: &str, keys: Vec<DefiniteDescriptorKey>, tests: Vec<(Vec<usize>, Option<usize>)>) {
        let ms = Miniscript::<DefiniteDescriptorKey, Segwitv0>::from_str(&ms).unwrap();

        for (key_indexes, expected) in tests {
            let mut assets = Assets::new();
            for ki in key_indexes {
                assets = assets.add(keys[ki].clone());
            }

            let result = ms.plan(&assets).map(|sol| sol.optimal.weight());
            assert_eq!(expected, result);
        }
    }

    #[test]
    fn test_or() {
        let keys = vec![
            DefiniteDescriptorKey::from_str("02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c").unwrap(),
            DefiniteDescriptorKey::from_str("0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a").unwrap(),
        ];

        let tests = vec![
            (vec![], None),
            (vec![0], Some(34)),
            (vec![0, 1], Some(34)),
        ];

        let ms = format!("t:or_c(pk({}),v:pkh({}))", keys[0], keys[1]);

        test_inner(&ms, keys, tests);
    }

    #[test]
    fn test_and() {
        let keys = vec![
            DefiniteDescriptorKey::from_str("02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c").unwrap(),
            DefiniteDescriptorKey::from_str("0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a").unwrap(),
        ];

        let tests = vec![
            (vec![], None),
            (vec![0], None),
            (vec![0, 1], Some(34 * 2)),
        ];

        let ms = format!("and_v(v:pk({}),pk({}))", keys[0], keys[1]);

        test_inner(&ms, keys, tests);
    }

    #[test]
    fn test_multi() {
        let keys = vec![
            DefiniteDescriptorKey::from_str("02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c").unwrap(),
            DefiniteDescriptorKey::from_str("0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a").unwrap(),
            DefiniteDescriptorKey::from_str("03500a2b48b0f66c8183cc0d6645ab21cc19c7fad8a33ff04d41c3ece54b0bc1c5").unwrap(),
            DefiniteDescriptorKey::from_str("033ad2d191da4f39512adbaac320cae1f12f298386a4e9d43fd98dec7cf5db2ac9").unwrap(),
        ];

        let tests = vec![
            (vec![], None),
            (vec![0, 1], None),
            (vec![0, 1, 3], Some(34 * 3)),
        ];

        let ms = format!("multi(3,{},{},{},{})", keys[0], keys[1], keys[2], keys[3]);

        test_inner(&ms, keys, tests);
    }



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
