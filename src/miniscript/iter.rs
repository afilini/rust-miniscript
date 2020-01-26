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

    /// Creates a new [KeyIter] iterator that will iterate over all plain public keys (and not
    /// key hash values) present in [Miniscript] items within AST by traversing all its branches.
    /// For the specific algorithm please see [KeyIter::next] function.
    pub fn iter_keys(&self) -> KeyIter<Pk> {
        KeyIter::new(self)
    }

    /// Creates a new [KeyHashIter] iterator that will iterate over all plain public keys (and not
    /// key hash values) present in Miniscript items within AST by traversing all its branches.
    /// For the specific algorithm please see [KeyHashIter::next] function.
    pub fn iter_key_hashes(&self) -> KeyHashIter<Pk> {
        KeyHashIter::new(self)
    }

    /// Creates a new [KeyAndHashIter] iterator that will iterate over all plain public keys and
    /// key hash values present in Miniscript items within AST by traversing all its branches.
    /// For the specific algorithm please see [KeyAndHashIter::next] function.
    pub fn iter_keys_and_hashes(&self) -> KeyAndHashIter<Pk> {
        KeyAndHashIter::new(self)
    }

    /// Returns a `Option`, either listing all public keys found in AST starting from this
    /// `Miniscript` item, or signifying that at least one key hash was found, making it impossible
    /// to enumerate all source public keys from the script.
    ///
    /// * Differs from [iter_keys] in a way that this function fails on the first met public key
    ///   hash.
    /// * Differs from [iter_keys_and_hashes] in a way that it lists only public keys, and not
    ///   their hashes
    ///
    /// Unlike these functions, [keys_only] returns an `Option` value with `Vec`, not an iterator.
    pub fn keys_only(&self) -> Option<Vec<Pk>> {
        self.iter_keys_and_hashes()
            .try_fold(Vec::<Pk>::new(), |mut keys, item| match item {
                KeyOrHash::HashedPubkey(hash) => None,
                KeyOrHash::PlainPubkey(key) => {
                    keys.push(key);
                    Some(keys)
                }
            })
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
/// constructs the iterator via [Miniscript::iter_keys] method.
pub struct KeyIter<'a, Pk: 'a + MiniscriptKey> {
    node_iter: Iter<'a, Pk>,
    keys_buff: VecDeque<Pk>,
}

impl<'a, Pk: MiniscriptKey> KeyIter<'a, Pk> {
    fn new(miniscript: &'a Miniscript<Pk>) -> Self {
        KeyIter {
            node_iter: Iter::new(miniscript),
            keys_buff: VecDeque::new(),
        }
    }
}

impl<'a, Pk: MiniscriptKey> Iterator for KeyIter<'a, Pk> {
    type Item = Pk;

    fn next(&mut self) -> Option<Self::Item> {
        self.keys_buff.pop_front().or_else(|| {
            self.keys_buff = self
                .node_iter
                .find_map(|ms| {
                    match ms.node.clone() {
                        Terminal::Pk(key) => Some(vec![key]),
                        Terminal::ThreshM(_, keys) => Some(keys),
                        _ => None,
                    }
                    .map(VecDeque::from)
                })
                .unwrap_or(VecDeque::default());
            self.keys_buff.pop_front()
        })
    }
}

/// Iterator for traversing all [MiniscriptKey] hashes in AST starting from some specific node which
/// constructs the iterator via [Miniscript::iter_key_hashes] method.
pub struct KeyHashIter<'a, Pk: 'a + MiniscriptKey> {
    node_iter: Iter<'a, Pk>,
    keys_buff: VecDeque<Pk::Hash>,
}

impl<'a, Pk: MiniscriptKey> KeyHashIter<'a, Pk> {
    fn new(miniscript: &'a Miniscript<Pk>) -> Self {
        KeyHashIter {
            node_iter: Iter::new(miniscript),
            keys_buff: VecDeque::new(),
        }
    }
}

impl<'a, Pk: MiniscriptKey> Iterator for KeyHashIter<'a, Pk> {
    type Item = Pk::Hash;

    fn next(&mut self) -> Option<Self::Item> {
        self.keys_buff.pop_front().or_else(|| {
            self.keys_buff = self
                .node_iter
                .find_map(|ms| {
                    match ms.node.clone() {
                        Terminal::PkH(hash) => Some(vec![hash]),
                        Terminal::Pk(key) => Some(vec![key.to_pubkeyhash()]),
                        Terminal::ThreshM(_, keys) => {
                            Some(keys.iter().map(Pk::to_pubkeyhash).collect())
                        }
                        _ => None,
                    }
                    .map(VecDeque::from)
                })
                .unwrap_or(VecDeque::default());
            self.keys_buff.pop_front()
        })
    }
}

/// Enum representing either key or a key hash value coming from a miniscript item inside AST
pub enum KeyOrHash<Pk: MiniscriptKey> {
    /// Plain public key
    PlainPubkey(Pk),
    /// Hashed public key
    HashedPubkey(Pk::Hash),
}

/// Iterator for traversing all [MiniscriptKey]'s and hashes, depending what data are present in AST,
/// starting from some specific node which constructs the iterator via
/// [Miniscript::iter_keys_and_hashes] method.
pub struct KeyAndHashIter<'a, Pk: 'a + MiniscriptKey> {
    node_iter: Iter<'a, Pk>,
    keys_buff: VecDeque<KeyOrHash<Pk>>,
}

impl<'a, Pk: MiniscriptKey> KeyAndHashIter<'a, Pk> {
    fn new(miniscript: &'a Miniscript<Pk>) -> Self {
        KeyAndHashIter {
            node_iter: Iter::new(miniscript),
            keys_buff: VecDeque::new(),
        }
    }
}

impl<'a, Pk: MiniscriptKey> Iterator for KeyAndHashIter<'a, Pk> {
    type Item = KeyOrHash<Pk>;

    fn next(&mut self) -> Option<Self::Item> {
        use self::KeyOrHash::*;

        self.keys_buff.pop_front().or_else(|| {
            self.keys_buff = self
                .node_iter
                .find_map(|ms| {
                    match ms.node.clone() {
                        Terminal::PkH(hash) => Some(vec![HashedPubkey(hash)]),
                        Terminal::Pk(key) => Some(vec![PlainPubkey(key)]),
                        Terminal::ThreshM(_, keys) => {
                            Some(keys.into_iter().map(PlainPubkey).collect())
                        }
                        _ => None,
                    }
                    .map(VecDeque::from)
                })
                .unwrap_or(VecDeque::default());
            self.keys_buff.pop_front()
        })
    }
}
