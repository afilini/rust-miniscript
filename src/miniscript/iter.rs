// Miniscript
// Written in 2020 by
//     Dr Maxim Orlovsky <orlovsky@pandoracore.com>
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

use super::decode::Terminal;
use super::{Miniscript, MiniscriptKey};
use std::collections::VecDeque;
use std::ops::Deref;
use std::sync::Arc;

/// Iterator-related extensions for [Miniscript]
impl<Pk: MiniscriptKey> Miniscript<Pk> {
    /// Creates a new [Iter] iterator that will iterate over all [Miniscript] items within
    /// AST by traversing its branches. For the specific algorithm please see
    /// [Iter::next] function.
    pub fn iter(&self) -> Iter<Pk> {
        Iter::new(self)
    }

    /// Creates a new [PubkeyIter] iterator that will iterate over all plain public keys (and not
    /// key hash values) present in [Miniscript] items within AST by traversing all its branches.
    /// For the specific algorithm please see [PubkeyIter::next] function.
    pub fn iter_pubkeys(&self) -> PubkeyIter<Pk> {
        PubkeyIter::new(self)
    }

    /// Creates a new [PubkeyHashIter] iterator that will iterate over all plain public keys (and not
    /// key hash values) present in Miniscript items within AST by traversing all its branches.
    /// For the specific algorithm please see [PubkeyHashIter::next] function.
    pub fn iter_pubkey_hashes(&self) -> PubkeyHashIter<Pk> {
        PubkeyHashIter::new(self)
    }

    /// Creates a new [PubkeyAndHashIter] iterator that will iterate over all plain public keys and
    /// key hash values present in Miniscript items within AST by traversing all its branches.
    /// For the specific algorithm please see [PubeyAndHashIter::next] function.
    pub fn iter_pubkeys_and_hashes(&self) -> PubkeyAndHashIter<Pk> {
        PubkeyAndHashIter::new(self)
    }

    /// Enumerates all child nodes of the current AST node (`self`) and returns a `Vec` referencing
    /// them.
    pub fn branches(&self) -> Vec<&Miniscript<Pk>> {
        use Terminal::*;
        match &self.node {
            Pk(_) | PkH(_) | ThreshM(_, _) => vec![],

            Alt(node) | Swap(node) | Check(node) | DupIf(node) | Verify(node) | NonZero(node)
            | ZeroNotEqual(node) => vec![node],

            AndV(node1, node2)
            | AndB(node1, node2)
            | OrB(node1, node2)
            | OrD(node1, node2)
            | OrC(node1, node2)
            | OrI(node1, node2) => vec![node1, node2],

            AndOr(node1, node2, node3) => vec![node1, node2, node3],

            Thresh(_, node_vec) => node_vec.iter().map(Arc::deref).collect(),

            _ => vec![],
        }
    }

    /// Returns `Vec` with cloned version of all public keys from the current miniscript item,
    /// if any. Otherwise returns an empty `Vec`.
    ///
    /// NB: The function analyzes only single miniscript item and not any of its descendants in AST.
    /// To obtain a list of all public keys within AST use [`iter_pubkeys()`] function, for example
    /// `miniscript.iter_pubkeys().collect()`.
    pub fn pubkeys(&self) -> Vec<Pk> {
        match self.node.clone() {
            Terminal::Pk(key) => vec![key],
            Terminal::ThreshM(_, keys) => keys,
            _ => vec![],
        }
    }

    /// Returns `Vec` with hashes of all public keys from the current miniscript item, if any.
    /// Otherwise returns an empty `Vec`.
    ///
    /// For each public key the function computes hash; for each hash of the public key the function
    /// returns it's cloned copy.
    ///
    /// NB: The function analyzes only single miniscript item and not any of its descendants in AST.
    /// To obtain a list of all public key hashes within AST use [`iter_pubkey_hashes()`] function,
    /// for example `miniscript.iter_pubkey_hashes().collect()`.
    pub fn pubkey_hashes(&self) -> Vec<Pk::Hash> {
        match self.node.clone() {
            Terminal::PkH(hash) => vec![hash],
            Terminal::Pk(key) => vec![key.to_pubkeyhash()],
            Terminal::ThreshM(_, keys) =>
                keys.iter().map(Pk::to_pubkeyhash).collect(),
            _ => vec![],
        }
    }

    /// Returns `Vec` of [PubkeyOrHash] entries, representing either public keys or public key
    /// hashes, depending on the data from the current miniscript item. If there is no public
    /// keys or hashes, the function returns an empty `Vec`.
    ///
    /// NB: The function analyzes only single miniscript item and not any of its descendants in AST.
    /// To obtain a list of all public keys or hashes within AST use [`iter_pubkeys_and_hashes()`]
    /// function, for example `miniscript.iter_pubkeys_and_hashes().collect()`.
    pub fn pubkeys_and_hashes(&self) -> Vec<PubkeyOrHash<Pk>> {
        use self::PubkeyOrHash::*;
        match self.node.clone() {
            Terminal::PkH(hash) => vec![HashedPubkey(hash)],
            Terminal::Pk(key) => vec![PlainPubkey(key)],
            Terminal::ThreshM(_, keys) => {
                keys.into_iter().map(PlainPubkey).collect()
            }
            _ => vec![],
        }
    }
}

/// Iterator for traversing all [Miniscript] miniscript AST references starting from some specific
/// node which constructs the iterator via [Miniscript::iter] method.
pub struct Iter<'a, Pk: 'a + MiniscriptKey> {
    next: Option<&'a Miniscript<Pk>>,
    path: Vec<(&'a Miniscript<Pk>, usize)>,
}

impl<'a, Pk: MiniscriptKey> Iter<'a, Pk> {
    fn new(miniscript: &'a Miniscript<Pk>) -> Self {
        Iter {
            next: Some(miniscript),
            path: vec![],
        }
    }
}

impl<'a, Pk: MiniscriptKey> Iterator for Iter<'a, Pk> {
    type Item = &'a Miniscript<Pk>;

    /// First, the function returns `self`, then the first child of the self (if any),
    /// then proceeds to the child of the child — down to a leaf of the tree in its first branch.
    /// When the leaf is reached, it goes in the reverse direction on the same branch until it
    /// founds a first branching node that had more than a single branch and returns it, traversing
    /// it with the same algorithm again.
    ///
    /// For example, for the given AST
    /// ```text
    /// A --+--> B -----> C --+--> D -----> E
    ///     |                 |
    ///     |                 +--> F
    ///     |                 |
    ///     |                 +--> G --+--> H
    ///     |                          |
    ///     |                          +--> I -----> J
    ///     +--> K
    /// ```
    /// `Iter::next()` will iterate over the nodes in the following order:
    /// `A > B > C > D > E > F > G > I > J > K`
    ///
    /// To enumerate the branches iterator uses [Miniscript::branches] function.
    fn next(&mut self) -> Option<Self::Item> {
        let mut curr = self.next;
        match curr {
            Some(node) => {
                self.next = node.branches().first().map(|x| *x);
                self.path.push((node, 1));
            }
            None => {
                while let Some((node, child)) = self.path.pop() {
                    curr = node.branches().get(child).map(|x| *x);
                    if curr.is_some() {
                        self.path.push((node, child + 1));
                        break;
                    }
                }
            }
        }
        curr
    }
}

/// Iterator for traversing all [MiniscriptKey]'s in AST starting from some specific node which
/// constructs the iterator via [Miniscript::iter_pubkeys] method.
pub struct PubkeyIter<'a, Pk: 'a + MiniscriptKey> {
    node_iter: Iter<'a, Pk>,
    keys_buff: VecDeque<Pk>,
}

impl<'a, Pk: MiniscriptKey> PubkeyIter<'a, Pk> {
    fn new(miniscript: &'a Miniscript<Pk>) -> Self {
        PubkeyIter {
            node_iter: Iter::new(miniscript),
            keys_buff: VecDeque::new(),
        }
    }
}

impl<'a, Pk: MiniscriptKey> Iterator for PubkeyIter<'a, Pk> {
    type Item = Pk;

    fn next(&mut self) -> Option<Self::Item> {
        let data= self.node_iter.next()?.pubkeys();
        self.keys_buff = VecDeque::from(data);
        self.keys_buff.pop_front()
    }
}

/// Iterator for traversing all [MiniscriptKey] hashes in AST starting from some specific node which
/// constructs the iterator via [Miniscript::iter_pubkey_hashes] method.
pub struct PubkeyHashIter<'a, Pk: 'a + MiniscriptKey> {
    node_iter: Iter<'a, Pk>,
    keys_buff: VecDeque<Pk::Hash>,
}

impl<'a, Pk: MiniscriptKey> PubkeyHashIter<'a, Pk> {
    fn new(miniscript: &'a Miniscript<Pk>) -> Self {
        PubkeyHashIter {
            node_iter: Iter::new(miniscript),
            keys_buff: VecDeque::new(),
        }
    }
}

impl<'a, Pk: MiniscriptKey> Iterator for PubkeyHashIter<'a, Pk> {
    type Item = Pk::Hash;

    fn next(&mut self) -> Option<Self::Item> {
        let data= self.node_iter.next()?.pubkey_hashes();
        self.keys_buff = VecDeque::from(data);
        self.keys_buff.pop_front()
    }
}

/// Enum representing either key or a key hash value coming from a miniscript item inside AST
pub enum PubkeyOrHash<Pk: MiniscriptKey> {
    /// Plain public key
    PlainPubkey(Pk),
    /// Hashed public key
    HashedPubkey(Pk::Hash),
}

/// Iterator for traversing all [MiniscriptKey]'s and hashes, depending what data are present in AST,
/// starting from some specific node which constructs the iterator via
/// [Miniscript::iter_keys_and_hashes] method.
pub struct PubkeyAndHashIter<'a, Pk: 'a + MiniscriptKey> {
    node_iter: Iter<'a, Pk>,
    keys_buff: VecDeque<PubkeyOrHash<Pk>>,
}

impl<'a, Pk: MiniscriptKey> PubkeyAndHashIter<'a, Pk> {
    fn new(miniscript: &'a Miniscript<Pk>) -> Self {
        PubkeyAndHashIter {
            node_iter: Iter::new(miniscript),
            keys_buff: VecDeque::new(),
        }
    }

    /// Returns a `Option`, listing all public keys found in AST starting from this
    /// `Miniscript` item, or `None` signifying that at least one key hash was found, making
    /// impossible to enumerate all source public keys from the script.
    ///
    /// * Differs from `Miniscript::iter_pubkeys().collect()` in the way that this function fails on
    ///   the first met public key hash, while [PubkeysIter] just ignores them.
    /// * Differs from `Miniscript::iter_pubkeys_and_hashes().collect()` in the way that it lists
    ///   only public keys, and not their hashes
    ///
    /// Unlike these functions, [pubkeys_only] returns an `Option` value with `Vec`, not an iterator,
    /// and consumes the iterator object.
    pub fn pubkeys_only(mut self) -> Option<Vec<Pk>> {
        self.try_fold(Vec::<Pk>::new(), |mut keys, item| match item {
                PubkeyOrHash::HashedPubkey(hash) => None,
                PubkeyOrHash::PlainPubkey(key) => {
                    keys.push(key);
                    Some(keys)
                }
            })
    }
}

impl<'a, Pk: MiniscriptKey> Iterator for PubkeyAndHashIter<'a, Pk> {
    type Item = PubkeyOrHash<Pk>;

    fn next(&mut self) -> Option<Self::Item> {
        use self::PubkeyOrHash::*;

        self.keys_buff.pop_front().or_else(|| {
            let data= self.node_iter.next()?.pubkeys_and_hashes();
            self.keys_buff = VecDeque::from(data);
            self.keys_buff.pop_front()
        })
    }
}
