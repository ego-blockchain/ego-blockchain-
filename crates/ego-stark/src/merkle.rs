use crate::{merge_nodes, Digest, Hash};
use winterfell::crypto::Hasher;

pub const POOL_TREE_DEPTH: usize = 29;

pub fn empty_subtree_roots(depth: usize) -> Vec<Digest> {
    let mut zeros = Vec::with_capacity(depth + 1);
    zeros.push(<Hash as Hasher>::Digest::default());
    for i in 1..=depth {
        let below = zeros[i - 1];
        zeros.push(merge_nodes(&below, &below));
    }
    zeros
}

#[derive(Debug, Clone, PartialEq)]
pub struct MerklePath {
    pub siblings: Vec<Digest>,
    pub is_right: Vec<bool>,
}

impl MerklePath {
    pub fn compute_root(&self, leaf: Digest) -> Digest {
        self.siblings
            .iter()
            .zip(&self.is_right)
            .fold(leaf, |cur, (sib, right)| {
                if *right { merge_nodes(sib, &cur) } else { merge_nodes(&cur, sib) }
            })
    }

    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    depth: usize,
    levels: Vec<Vec<Digest>>,
    zeros: Vec<Digest>,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        Self { depth, levels: vec![Vec::new(); depth + 1], zeros: empty_subtree_roots(depth) }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    pub fn capacity(&self) -> usize {
        1usize << self.depth
    }

    pub fn leaves(&self) -> &[Digest] {
        &self.levels[0]
    }

    fn node(&self, level: usize, idx: usize) -> Digest {
        self.levels[level].get(idx).copied().unwrap_or(self.zeros[level])
    }

    pub fn insert(&mut self, leaf: Digest) -> Result<usize, String> {
        if self.len() >= self.capacity() {
            return Err(format!("tree of depth {} is full", self.depth));
        }
        let index = self.len();
        self.levels[0].push(leaf);
        let mut idx = index;
        for level in 0..self.depth {
            let parent = idx >> 1;
            let h = merge_nodes(&self.node(level, parent * 2), &self.node(level, parent * 2 + 1));
            let above = &mut self.levels[level + 1];
            if parent < above.len() {
                above[parent] = h;
            } else {
                above.push(h);
            }
            idx = parent;
        }
        Ok(index)
    }

    pub fn root(&self) -> Digest {
        self.node(self.depth, 0)
    }

    pub fn path(&self, index: usize) -> Result<MerklePath, String> {
        if index >= self.len() {
            return Err(format!("no leaf at index {index}; tree has {}", self.len()));
        }
        let mut siblings = Vec::with_capacity(self.depth);
        let mut is_right = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            let right = idx & 1 == 1;
            let sibling_idx = if right { idx - 1 } else { idx + 1 };
            siblings.push(self.node(level, sibling_idx));
            is_right.push(right);
            idx >>= 1;
        }
        Ok(MerklePath { siblings, is_right })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IncrementalTree {
    depth: usize,
    next_index: usize,
    frontier: Vec<Digest>,
    root: Digest,
    zeros: Vec<Digest>,
}

impl IncrementalTree {
    pub fn new(depth: usize) -> Self {
        let zeros = empty_subtree_roots(depth);
        Self { depth, next_index: 0, frontier: zeros[..depth].to_vec(), root: zeros[depth], zeros }
    }

    pub fn from_parts(
        depth: usize,
        next_index: usize,
        frontier: Vec<Digest>,
        root: Digest,
    ) -> Result<Self, String> {
        if frontier.len() != depth {
            return Err(format!("frontier has {} entries for depth {depth}", frontier.len()));
        }
        if next_index > (1usize << depth) {
            return Err(format!("next index {next_index} exceeds a depth-{depth} tree"));
        }
        Ok(Self { depth, next_index, frontier, root, zeros: empty_subtree_roots(depth) })
    }

    pub fn parts(&self) -> (usize, usize, &[Digest], Digest) {
        (self.depth, self.next_index, &self.frontier, self.root)
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.next_index
    }

    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }

    pub fn capacity(&self) -> usize {
        1usize << self.depth
    }

    pub fn root(&self) -> Digest {
        self.root
    }

    pub fn frontier(&self) -> &[Digest] {
        &self.frontier
    }

    pub fn insert(&mut self, leaf: Digest) -> Result<usize, String> {
        if self.next_index >= self.capacity() {
            return Err(format!("tree of depth {} is full", self.depth));
        }
        let index = self.next_index;
        let mut cur = leaf;
        let mut idx = index;
        for level in 0..self.depth {
            if idx & 1 == 0 {
                self.frontier[level] = cur;
                cur = merge_nodes(&cur, &self.zeros[level]);
            } else {
                cur = merge_nodes(&self.frontier[level], &cur);
            }
            idx >>= 1;
        }
        self.root = cur;
        self.next_index += 1;
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::Note;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const DEPTH: usize = 4;

    fn rng() -> StdRng {
        StdRng::from_entropy()
    }

    fn leaf(i: u64) -> Digest {
        crate::hash_with_domain(crate::DOMAIN_LEAF, &[crate::Elem::new(1_000 + i)])
    }

    fn tree_with(n: usize) -> MerkleTree {
        let mut t = MerkleTree::new(DEPTH);
        for i in 0..n {
            t.insert(leaf(i as u64)).unwrap();
        }
        t
    }

    fn reference_node(leaves: &[Digest], zeros: &[Digest], level: usize, idx: usize) -> Digest {
        if level == 0 {
            return leaves.get(idx).copied().unwrap_or(zeros[0]);
        }
        if (idx << level) >= leaves.len() {
            return zeros[level];
        }
        merge_nodes(
            &reference_node(leaves, zeros, level - 1, 2 * idx),
            &reference_node(leaves, zeros, level - 1, 2 * idx + 1),
        )
    }

    #[test]
    fn an_empty_tree_has_the_precomputed_empty_root() {
        let t = MerkleTree::new(DEPTH);
        assert_eq!(t.root(), empty_subtree_roots(DEPTH)[DEPTH]);
    }

    #[test]
    fn every_leaf_has_a_path_that_reproduces_the_root() {
        let t = tree_with(7);
        let root = t.root();
        for i in 0..7 {
            let p = t.path(i).unwrap();
            assert_eq!(p.depth(), DEPTH);
            assert_eq!(p.compute_root(leaf(i as u64)), root, "leaf {i}");
        }
    }

    #[test]
    fn a_path_for_one_leaf_does_not_authenticate_another() {
        let t = tree_with(7);
        let p = t.path(2).unwrap();
        assert_ne!(p.compute_root(leaf(3)), t.root());
    }

    #[test]
    fn the_cached_tree_matches_the_recursive_definition_at_every_size() {
        let zeros = empty_subtree_roots(DEPTH);
        let mut t = MerkleTree::new(DEPTH);
        for n in 0..=(1usize << DEPTH) {
            assert_eq!(t.root(), reference_node(t.leaves(), &zeros, DEPTH, 0), "{n} leaves");
            if n < (1usize << DEPTH) {
                t.insert(leaf(n as u64)).unwrap();
            }
        }
    }

    #[test]
    fn the_incremental_tree_matches_the_full_tree_after_every_insert() {
        let depth = 5;
        let mut r = rng();
        let mut full = MerkleTree::new(depth);
        let mut inc = IncrementalTree::new(depth);
        assert_eq!(inc.root(), full.root(), "empty");
        for i in 0..(1usize << depth) {
            let l = Note::random(1_000_000, &mut r).leaf().unwrap();
            assert_eq!(full.insert(l).unwrap(), i);
            assert_eq!(inc.insert(l).unwrap(), i);
            assert_eq!(inc.root(), full.root(), "after leaf {i}");
        }
        assert!(full.insert(leaf(1)).is_err());
        assert!(inc.insert(leaf(1)).is_err());
    }

    #[test]
    fn an_incremental_tree_round_trips_through_its_parts() {
        let mut inc = IncrementalTree::new(DEPTH);
        for i in 0..7 {
            inc.insert(leaf(i)).unwrap();
        }
        let (depth, next, frontier, root) = inc.parts();
        let mut restored = IncrementalTree::from_parts(depth, next, frontier.to_vec(), root).unwrap();
        assert_eq!(restored, inc);
        restored.insert(leaf(7)).unwrap();
        inc.insert(leaf(7)).unwrap();
        assert_eq!(restored.root(), inc.root());
        assert_eq!(restored.root(), tree_with(8).root());
    }

    #[test]
    fn parts_of_the_wrong_shape_are_refused() {
        let zeros = empty_subtree_roots(DEPTH);
        assert!(IncrementalTree::from_parts(DEPTH, 0, zeros[..DEPTH - 1].to_vec(), zeros[DEPTH]).is_err());
        assert!(IncrementalTree::from_parts(DEPTH, (1 << DEPTH) + 1, zeros[..DEPTH].to_vec(), zeros[DEPTH]).is_err());
        assert!(IncrementalTree::from_parts(DEPTH, 1 << DEPTH, zeros[..DEPTH].to_vec(), zeros[DEPTH]).is_ok());
    }

    #[test]
    fn the_tree_refuses_to_overflow() {
        let mut t = MerkleTree::new(2);
        for i in 0..4 {
            t.insert(leaf(i)).unwrap();
        }
        assert!(t.insert(leaf(4)).is_err());
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn a_path_is_refused_for_a_leaf_that_does_not_exist() {
        let t = tree_with(3);
        assert!(t.path(3).is_err());
    }

    #[test]
    fn a_pool_depth_tree_still_costs_one_hash_per_level() {
        let mut r = rng();
        let mut t = IncrementalTree::new(POOL_TREE_DEPTH);
        for _ in 0..64 {
            t.insert(Note::random(1_000_000, &mut r).leaf().unwrap()).unwrap();
        }
        assert_eq!(t.len(), 64);
        assert_ne!(t.root(), empty_subtree_roots(POOL_TREE_DEPTH)[POOL_TREE_DEPTH]);
    }
}
