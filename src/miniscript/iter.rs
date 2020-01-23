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

use std::{sync::Arc, ops::Deref};
use super::{Miniscript, MiniscriptKey};

impl<Pk: MiniscriptKey> Miniscript<Pk> {
    pub fn iter(&self) -> MiniscriptIter<Pk> {
        MiniscriptIter { stack: vec![&self] }
    }

    pub fn branches(&self) -> Vec<&Miniscript<Pk>> {
        use Terminal::*;
        match &self.node {
            Pk(_) |
            PkH(_) |
            ThreshM(_, _) =>
                vec![],

            Alt(node) |
            Swap(node) |
            Check(node) |
            DupIf(node) |
            Verify(node) |
            NonZero(node) |
            ZeroNotEqual(node) =>
                vec![node],

            AndV(node1, node2) |
            AndB(node1, node2) |
            OrB(node1, node2) |
            OrD(node1, node2) |
            OrC(node1, node2) |
            OrI(node1, node2) =>
                vec![node1, node2],

            AndOr(node1, node2, node3) =>
                vec![node1, node2, node3],

            Thresh(_, node_vec) =>
                node_vec.iter().map(Arc::deref).collect(),

            _ => vec![],
        }

    }
}

pub struct MiniscriptIter<'a, Pk: MiniscriptKey> {
    pub stack: Vec<&'a Miniscript<Pk>>,
}

impl<'a, Pk: MiniscriptKey> Iterator for MiniscriptIter<'a, Pk> {
    type Item = &'a Miniscript<Pk>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut top = self.stack.pop();
        if let Some(node) = top {
            self.stack.extend(node.branches());
        }
        top
    }
}
