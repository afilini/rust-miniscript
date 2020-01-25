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

use std::ops::Deref;
use std::sync::Arc;
use std::collections::VecDeque;
use super::{Miniscript, MiniscriptKey, decode::Terminal};

/// Iterator-related extensions for `Miniscript`
impl<Pk: MiniscriptKey> Miniscript<Pk> {

    /// Creates a new `MiniscriptIter` iterator that will iterate over all Miniscript nodes in
    /// the AST by traversing its branches. For the specific algorithm please see
    /// [MiniscriptIter::next] function.
    pub fn iter(&self) -> MiniscriptIter<Pk> {
        MiniscriptIter::new(self)
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


/// Iterator for traversing all [Miniscript] nodes in AST starting from some specific node which
/// constructs the iterator via [Miniscript::iter] method.
pub struct MiniscriptIter<'a, Pk: MiniscriptKey> {
    next: Option<&'a Miniscript<Pk>>,
    path: Vec<(&'a Miniscript<Pk>, usize)>,
}

impl<'a, Pk: MiniscriptKey> MiniscriptIter<'a, Pk> {
    fn new(miniscript: &'a Miniscript<Pk>) -> Self {
        MiniscriptIter {
            next: Some(miniscript),
            path: vec![],
        }
    }
}

impl<'a, Pk: MiniscriptKey> Iterator for MiniscriptIter<'a, Pk> {
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
    /// `MiniscriptIter::next()` will iterate over the nodes in the following order:
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


pub enum MiniscriptKeyOrHash<Pk: MiniscriptKey> {
    Key(Pk),
    Hash(Pk::Hash),
}

/// Iterator for traversing all [MiniscriptKey]'s in AST starting from some specific node which
/// constructs the iterator via [Miniscript::iter_keys] method.
pub struct MiniscriptKeyIter<'a, Pk: MiniscriptKey>{
    node_iter: MiniscriptIter<'a, Pk>,
    keys_buff: VecDeque<Pk>,
}

impl<'a, Pk: MiniscriptKey> MiniscriptKeyIter<'a, Pk> {
    fn new(miniscript: &'a Miniscript<Pk>) -> Self {
        MiniscriptKeyIter {
            node_iter: MiniscriptIter::new(miniscript),
            keys_buff: VecDeque::new()
        }
    }
}

impl<'a, Pk: MiniscriptKey> Iterator for MiniscriptKeyIter<'a, Pk> {
    type Item = Pk;

    fn next(&mut self) -> Option<Self::Item> {
        self.keys_buff.pop_front().or_else(|| {
            self.keys_buff = self.node_iter.find_map(|ms| -> Option<VecDeque<Pk>> {
                match ms.node.clone() {
                    Terminal::Pk(key) => Some(vec![key]),
                    Terminal::ThreshM(_, keys) => Some(keys),
                    _ => None,
                }.map(VecDeque::from)
            }).unwrap_or(VecDeque::default());
            self.keys_buff.pop_front()
        })
    }
}
