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

use crate::descriptor::Bare;
use crate::miniscript::{hash256, Miniscript};
use crate::{DefiniteDescriptorKey, Descriptor, ScriptContext, Terminal};
use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::util::bip32::KeySource;
use bitcoin::{LockTime, Sequence};
use std::cmp::Ordering;
use std::collections::HashSet;

pub struct Plan {}

pub struct Assets {
    keys: HashSet<DefiniteDescriptorKey>, // poi lo mettiamo generico con CanDerive per le DescPubKey
    sha256_preimages: HashSet<sha256::Hash>,
    hash256_preimages: HashSet<hash256::Hash>,
    ripemd160_preimages: HashSet<ripemd160::Hash>,
    hash160_preimages: HashSet<hash160::Hash>,
    absolute_timelock: Timelock<LockTime>, // restrizioni
    relative_timelock: Timelock<Sequence>, // restrizioni
}

pub struct AssetsRef<'a> {
    keys: HashSet<DefiniteDescriptorKey>, // poi lo mettiamo generico con CanDerive per le DescPubKey
    sha256_preimages: HashSet<sha256::Hash>,
    hash256_preimages: HashSet<hash256::Hash>,
    ripemd160_preimages: HashSet<ripemd160::Hash>,
    hash160_preimages: HashSet<hash160::Hash>,
    absolute_timelock: Timelock<LockTime>, // restrizioni
    relative_timelock: Timelock<Sequence>, // restrizioni
}

impl Assets {
    fn has_key(&self, k: &DefiniteDescriptorKey) -> bool {
        // Piú check: fingerprint, canderive ecc
        self.keys.contains(k)
    }
}

// TODO change name
pub struct Timelock<T> {
    at_least: Option<T>,
    at_most: Option<T>,
}

pub enum TimelockError {
    IncompatibleTimelocks,
    AtLeastGreaterThanAtMost,
}

impl<T: PartialOrd + Clone> Timelock<T> {
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

    fn get_solution(&self, to_compare: T) -> Solution {
        let Timelock { at_least, at_most } = &self;

        match at_most {
            Some(m) if !m.partial_cmp(&to_compare).is_none() || to_compare > *m => {
                return Solution::Impossible;
            }
            _ => {}
        }

        match at_least {
            Some(l) if !l.partial_cmp(&to_compare).is_none() => Solution::Impossible,
            Some(l) if to_compare < *l => Solution::new_optimal_only(0),
            _ => Solution::new_with_timelock(0),
        }
    }
}

impl Descriptor<DefiniteDescriptorKey> {
    fn plan(&self, assets: &Assets) -> Result<Plan, ()> {
        match *self {
            Descriptor::Bare(ref bare) => bare.plan(assets),
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
    fn plan(&self, assets: &Assets) -> Result<Plan, ()> {
        self.as_inner().plan(assets)
    }
}

impl<Ctx: ScriptContext> Miniscript<DefiniteDescriptorKey, Ctx> {
    fn plan(&self, assets: &Assets) -> Result<Plan, ()> {
        let solution = plan_helper(&self.node, assets);
        todo!()
    }
}

fn plan_helper<Ctx: ScriptContext>(
    node: &Terminal<DefiniteDescriptorKey, Ctx>,
    assets: &Assets,
) -> Solution {
    match node {
        Terminal::True => Solution::new_optimal_only(1),
        Terminal::False => Solution::new_optimal_only(1),
        Terminal::PkH(pk) | Terminal::PkK(pk) | Terminal::RawPkH(pk) => {
            Solution::new_pk::<Ctx>(pk, assets)
        }
        // absolute
        Terminal::After(t) => assets.absolute_timelock.get_solution(t.into()),
        // relative
        Terminal::Older(t) => assets.relative_timelock.get_solution(*t),
        Terminal::Sha256(h) => {
            if assets.sha256_preimages.contains(h) {
                Solution::new_optimal_only(33)
            } else {
                Solution::Impossible
            }
        }
        Terminal::Hash256(h) => {
            if assets.hash256_preimages.contains(h) {
                Solution::new_optimal_only(33)
            } else {
                Solution::Impossible
            }
        }
        Terminal::Ripemd160(h) => {
            if assets.ripemd160_preimages.contains(h) {
                Solution::new_optimal_only(21)
            } else {
                Solution::Impossible
            }
        }
        Terminal::Hash160(h) => {
            if assets.hash160_preimages.contains(h) {
                Solution::new_optimal_only(21)
            } else {
                Solution::Impossible
            }
        }
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
    }
}



#[derive(Debug, Clone)]
enum Solution {
    Weight {
        // in byte
        optimal: usize,
        with_timelock: Option<usize>,
        
    },
    Impossible,
}

impl Solution {
    fn new_optimal_only(optimal: usize) -> Self {
        Solution::Weight {
            optimal,
            with_timelock: None,
        }
    }

    fn new_with_timelock(optimal: usize) -> Self {
        Solution::Weight {
            optimal,
            with_timelock: Some(optimal),
        }
    }

    fn new_pk<Ctx: ScriptContext>(pk: &DefiniteDescriptorKey, assets: &Assets) -> Self {
        if assets.has_key(pk) {
            Solution::new_optimal_only(Ctx::pk_len(pk))
        } else {
            Solution::Impossible
        }
    }

    fn new_and(a: Solution, b: Solution) -> Self {
        match (a, b) {
            (Solution::Impossible, _) | (_, Solution::Impossible) => Solution::Impossible,
            (
                Solution::Weight {
                    optimal: a_optimal,
                    with_timelock: a_timelock,
                },
                Solution::Weight {
                    optimal: b_optimal,
                    with_timelock: b_timelock,
                },
            ) => {
                let with_timelock = match (a_timelock, b_timelock) {
                    (None, None) => None,
                    (Some(a), None) => Some(a + b_optimal),
                    (None, Some(b)) => Some(a_optimal + b),
                    (Some(a), Some(b)) => Some(std::cmp::min(a + b_optimal, b + a_optimal)),
                };

                Solution::Weight {
                    optimal: a_optimal + b_optimal,
                    with_timelock,
                }
            }
        }
    }

    fn new_or(a: Solution, b: Solution) -> Self {
        match (a, b) {
            (
                Solution::Weight {
                    optimal: a_optimal,
                    with_timelock: a_timelock,
                },
                Solution::Weight {
                    optimal: b_optimal,
                    with_timelock: b_timelock,
                },
            ) => Solution::Weight {
                optimal: std::cmp::min(a_optimal, b_optimal),
                with_timelock: std::cmp::min(a_timelock, b_timelock),
            },
            (Solution::Impossible, Solution::Impossible) => Solution::Impossible,
            (a, _) => a,
            (_, b) => b,
        }
    }

    fn new_thresh(thresh: usize, list: Vec<Solution>) -> Solution {
        debug_assert!(thresh > 0);

        // Filter out the impossible items in the list, then sort by optimal weight
        let mut sorted_optimal = list
            .iter()
            .enumerate()
            .filter_map(|(i, p)| match p {
                Solution::Impossible => None,
                Solution::Weight { optimal, .. } => Some((i, *optimal)),
            })
            .collect::<Vec<_>>();

        // If there aren't enough item after excluding the `Impossible`, this is also `Impossible`
        if sorted_optimal.len() < thresh {
            return Solution::Impossible;
        }
        sorted_optimal.sort_unstable_by_key(|(_, p)| *p);

        // Try with all the items that can satisfy the timelock requirement
        let mut with_timelock_list = list
            .iter()
            .enumerate()
            .filter_map(|(i, p)| match p {
                Solution::Weight {
                    with_timelock: Some(wt),
                    ..
                } => {
                    // We take the current element with timelock weight,
                    // then we take the sorted_optimal list, we remove the current element,
                    // and we take the thresh - 1 best optimal weight
                    Some(
                        wt + sorted_optimal
                            .iter()
                            .filter(|(index, _)| *index != i)
                            .map(|(_, w)| *w)
                            .take(thresh - 1)
                            .sum::<usize>(),
                    )
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        // Sort by weight, and the first one is our with_timelock optimal solution
        with_timelock_list.sort_unstable();

        Solution::Weight {
            optimal: sorted_optimal.iter().take(thresh).map(|(_, w)| *w).sum(),
            with_timelock: with_timelock_list.get(0).cloned(),
        }
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
