//! Discover bounded integer regions inside certified code. The independent
//! JIT sees block indices, never CPU state, selectors or guest addresses.

use super::{loops::branch_condition, translation};
use crate::{
    CpuModel,
    x86_decode::{self, DecodedInstruction},
};
use compat16_jit::{
    Instruction, MAX_BLOCK_INSTRUCTIONS, MAX_REGION_BLOCKS, MAX_REGION_INSTRUCTIONS, Region,
    RegionBlock, RegionBranch, RegionPosition, RegionTarget,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use x86_decoder::{Mnemonic, OpKind};

#[derive(Default)]
pub(super) struct Profile {
    counts: HashMap<u64, (u16, u16)>,
    pending: Option<(u64, u32, u32)>,
}
impl Profile {
    pub fn observe(&mut self, cs: u16, decoded: DecodedInstruction, integer: bool) {
        let mnemonic = decoded.instruction.mnemonic();
        if !integer && branch_condition(mnemonic).is_none() && mnemonic != Mnemonic::Jmp {
            // An unsupported successor ends the region. Sampling its incoming
            // edge cannot guide a compiled link and penalizes x87/I/O loops.
            self.pending = None;
            return;
        }
        let domain = u64::from(cs) << 32;
        if let Some((key, taken, fallthrough)) = self.pending.take()
            && key >> 32 == u64::from(cs)
            && (decoded.start_ip == taken || decoded.start_ip == fallthrough)
        {
            if self.counts.len() == 1024 && !self.counts.contains_key(&key) {
                self.counts.clear();
            }
            if self.counts.try_reserve(1).is_ok() {
                let pair = self.counts.entry(key).or_default();
                if decoded.start_ip == taken {
                    pair.0 = pair.0.saturating_add(1);
                } else {
                    pair.1 = pair.1.saturating_add(1);
                }
            }
        }
        let i = decoded.instruction;
        if branch_condition(i.mnemonic()).is_some()
            && matches!(i.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32)
        {
            self.pending = Some((
                domain | u64::from(decoded.start_ip),
                i.near_branch_target() as u32,
                decoded.next_ip,
            ));
        }
    }
    fn prefer_taken(&self, cs: u16, ip: u32) -> bool {
        self.counts
            .get(&(u64::from(cs) << 32 | u64::from(ip)))
            .is_none_or(|&(taken, fallthrough)| taken >= fallthrough)
    }
    pub fn barrier(&mut self) {
        self.pending = None;
    }
}

pub(super) struct Linked {
    pub ir: Region,
    sites: Vec<Vec<u32>>,
    exits: Vec<u32>,
}
impl Linked {
    pub fn site(&self, position: RegionPosition) -> Option<u32> {
        match position {
            RegionPosition::Block { block, instruction } => self
                .sites
                .get(usize::from(block))?
                .get(usize::from(instruction))
                .copied(),
            RegionPosition::Exit(i) => self.exits.get(usize::from(i)).copied(),
        }
    }
    pub fn decode(
        bytes: &[u8],
        ip: u32,
        bits: u32,
        protected: bool,
        model: CpuModel,
        profile: &Profile,
        cs: u16,
    ) -> Option<(Self, usize)> {
        struct Node {
            decoded: DecodedInstruction,
            integer: Option<Instruction>,
            preferred: bool,
        }
        let mut nodes = BTreeMap::<u32, Node>::new();
        let mut order = Vec::new();
        let mut queued = HashSet::from([ip]);
        let mut queue = VecDeque::from([ip]);
        let mut used = 0;
        while let Some(site) = queue.pop_front() {
            if nodes.len() == MAX_REGION_INSTRUCTIONS {
                break;
            }
            let Some(offset) = site
                .checked_sub(ip)
                .map(|v| v as usize)
                .filter(|&v| v < bytes.len())
            else {
                continue;
            };
            if nodes
                .range(..site)
                .next_back()
                .is_some_and(|(_, n)| n.decoded.next_ip > site)
            {
                // Overlapping x86 streams remain interpreter work.
                return None;
            }
            let Some(decoded) = x86_decode::decode_plain(&bytes[offset..], site, bits, protected)
            else {
                continue;
            };
            if decoded.next_ip <= site
                || !model.supports_instruction_features(decoded.required_cpu_features())
                || decoded.instruction.has_lock_prefix()
            {
                continue;
            }
            let length = decoded.instruction.len();
            if offset + length > bytes.len() {
                continue;
            }
            if nodes.range(site + 1..decoded.next_ip).next().is_some() {
                return None;
            }
            let i = decoded.instruction;
            let is_branch =
                i.mnemonic() == Mnemonic::Jmp || branch_condition(i.mnemonic()).is_some();
            let integer = translation::translate(decoded);
            if is_branch {
                if !matches!(i.op0_kind(), OpKind::NearBranch16 | OpKind::NearBranch32) {
                    continue;
                }
                let target = i.near_branch_target();
                // Near transfers validate their target before retirement.
                // Keep unguarded targets at the branch instruction, so the
                // ordinary executor delivers any fault at its original IP.
                if target < u64::from(ip) || target >= u64::from(ip) + bytes.len() as u64 {
                    continue;
                }
                used = used.max((target - u64::from(ip)) as usize + 1);
            } else if integer.is_none() {
                continue;
            }
            let preferred = profile.prefer_taken(cs, site);
            let mut successors = vec![decoded.next_ip];
            if is_branch {
                let target = i.near_branch_target() as u32;
                if i.mnemonic() == Mnemonic::Jmp {
                    successors = vec![target];
                } else if preferred {
                    successors.insert(0, target);
                } else {
                    successors.push(target);
                }
            }
            for successor in successors {
                if queued.insert(successor) {
                    queue.push_back(successor);
                }
            }
            used = used.max(offset + length);
            order.push(site);
            nodes.insert(
                site,
                Node {
                    decoded,
                    integer,
                    preferred,
                },
            );
        }
        let mut leaders = HashSet::from([ip]);
        let mut incoming = HashMap::<u32, usize>::new();
        for node in nodes.values() {
            let d = node.decoded;
            if node.integer.is_none() {
                leaders.insert(d.instruction.near_branch_target() as u32);
                leaders.insert(d.next_ip);
            } else {
                *incoming.entry(d.next_ip).or_default() += 1;
            }
        }
        for (site, count) in incoming {
            if count > 1 {
                leaders.insert(site);
            }
        }
        struct Pending {
            instructions: Vec<Instruction>,
            sites: Vec<u32>,
            end: u32,
            has_branch: bool,
        }
        let mut pending = Vec::new();
        let mut consumed = HashSet::new();
        let mut starts = HashMap::new();
        for first in order {
            if consumed.contains(&first) {
                continue;
            }
            if pending.len() == MAX_REGION_BLOCKS {
                return None;
            }
            starts.insert(first, pending.len() as u8);
            let mut instructions = Vec::new();
            let mut sites = Vec::new();
            let mut site = first;
            let mut has_branch = false;
            loop {
                let node = nodes.get(&site)?;
                consumed.insert(site);
                sites.push(site);
                let Some(integer) = node.integer else {
                    has_branch = true;
                    break;
                };
                instructions.push(integer);
                let next = node.decoded.next_ip;
                if instructions.len() == MAX_BLOCK_INSTRUCTIONS
                    || leaders.contains(&next)
                    || !nodes.contains_key(&next)
                {
                    site = next;
                    sites.push(site);
                    break;
                }
                site = next;
            }
            pending.push(Pending {
                instructions,
                sites,
                end: site,
                has_branch,
            });
        }
        // Single self-loops retain their smaller specialized backend.
        if pending.len() < 2 {
            return None;
        }
        let mut exits = Vec::new();
        let mut target = |site: u32| -> Option<RegionTarget> {
            if let Some(&block) = starts.get(&site) {
                return Some(RegionTarget::Block(block));
            }
            let index = match exits.iter().position(|&p| p == site) {
                Some(i) => i,
                None => {
                    exits.push(site);
                    exits.len() - 1
                }
            };
            Some(RegionTarget::Exit(u8::try_from(index).ok()?))
        };
        let mut blocks = Vec::new();
        let mut sites = Vec::new();
        let mut linked_branches = 0;
        for block in pending {
            let branch = if block.has_branch {
                let node = nodes.get(&block.end)?;
                let d = node.decoded;
                let taken = target(d.instruction.near_branch_target() as u32)?;
                linked_branches += usize::from(matches!(taken, RegionTarget::Block(_)));
                if let Some(condition) = branch_condition(d.instruction.mnemonic()) {
                    RegionBranch::Conditional {
                        condition,
                        taken,
                        fallthrough: target(d.next_ip)?,
                        prefer_taken: node.preferred,
                    }
                } else {
                    RegionBranch::Jump(taken)
                }
            } else {
                RegionBranch::Continue(target(block.end)?)
            };
            blocks.push(RegionBlock {
                instructions: block.instructions,
                branch,
            });
            sites.push(block.sites);
        }
        if linked_branches == 0 {
            return None;
        }
        let ir = Region::new(blocks, u8::try_from(exits.len()).ok()?)?;
        Some((Self { ir, sites, exits }, used))
    }
}
