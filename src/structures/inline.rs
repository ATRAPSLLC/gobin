//! Per-PC inlining tree decoder (`funcdata[FUNCDATA_InlTree]`).
//!
//! When the Go compiler inlines a callee into a caller, it records a small
//! tree of inlined-call records so the runtime can recover the logical call
//! chain at any PC. We expose that tree as a streaming iterator
//! ([`InlineTreeIter`]) yielding one [`InlineEntry`] per PC range during
//! which an inlined frame is active.
//!
//! ## On-disk layout (`inlinedCall`)
//!
//! Source: `src/runtime/symtabinl.go`. Each entry is a fixed 16 bytes:
//!
//! ```text
//! Offset  Size  Field      Description
//! 0       1     funcID     abi.FuncID of the inlined function
//! 1       3     _          padding
//! 4       4     nameOff    int32 offset into pclntab funcnametab
//! 8       4     parentPc   int32 PC of the call site (offset from func entry)
//! 12      4     startLine  int32 line of the inlined `func` keyword
//! ```
//!
//! ## Decoding chain
//!
//! 1. Read `funcdata[FUNCDATA_InlTree]` (constant `3`) for the function - a
//!    `u32` offset added to `moduledata.gofunc` to get the inline-tree blob's VA.
//! 2. Decode `pcdata[PCDATA_InlTreeIndex]` (constant `2`) - yields
//!    `(pc_offset, index)` pairs. `index < 0` means "not inlined here";
//!    `index >= 0` selects an entry in the inline-tree blob.
//! 3. For each non-negative range, read the 16-byte entry at
//!    `blob[index * 16..]` and resolve `nameOff` against `funcnametab`.
//! 4. Depth: walk `parentPc` upward through the same PCDATA index, counting
//!    steps until the parent's index is `< 0`.

use core::ops::Range;

use crate::{
    formats::BinaryContext,
    structures::{
        moduledata::Moduledata,
        pclntab::{FuncData, ParsedPclntab},
        util::slice_at,
    },
};

/// `FUNCDATA_InlTree` (Go `internal/abi/symtab.go`).
const FUNCDATA_INL_TREE: u8 = 3;

/// `PCDATA_InlTreeIndex` (Go `internal/abi/symtab.go`).
const PCDATA_INL_TREE_INDEX: u32 = 2;

/// Sentinel "no funcdata at this index" value (`^uint32(0)`).
const FUNCDATA_NIL: u32 = u32::MAX;

/// Size of an `inlinedCall` record on disk.
const INLINED_CALL_SIZE: usize = 16;

/// One inlined-call record, scoped to a PC range during which it is active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineEntry<'a> {
    /// PC range (offsets from the enclosing function's entry) during which
    /// this inlined frame is active. `pc_range.start` is inclusive,
    /// `pc_range.end` is exclusive.
    pub pc_range: Range<u32>,
    /// Index into the inline-tree array (the runtime's tree node id).
    pub index: u32,
    /// Resolved name of the inlined function (borrowed from `funcnametab`).
    pub function_name: &'a str,
    /// PC of the call site in the parent frame, as an offset from the
    /// enclosing function's entry. Walk this through
    /// `pcdata[PCDATA_InlTreeIndex]` to recover the parent's index.
    pub parent_pc: u32,
    /// Line number of the inlined function's `func` keyword.
    pub start_line: i32,
    /// `abi.FuncID` of the inlined function.
    pub func_id: u8,
    /// Inlining depth: 0 for the outermost inlined frame at this PC, +1 per
    /// additional level toward the leaf.
    ///
    /// # Bounds
    ///
    /// Real-world Go inline chains are very shallow - typically `< 5` - and
    /// the gobin walker caps depth at `32` to keep its cycle-detection
    /// scratch buffer fixed-size. In practice this field will always fit in
    /// a `u8`; consumers that store it in a narrower integer (e.g. visus
    /// pinning it to `u8` for compact rows) can safely clamp without losing
    /// information. The type stays `u32` to give breathing room if a future
    /// Go runtime change increases the bound.
    pub depth: u32,
}

/// Streaming iterator over [`InlineEntry`] records for a single function.
///
/// Each [`Iterator::next`] yields one PC range during which an inlined frame
/// is active, in the order they appear in the function's
/// `pcdata[PCDATA_InlTreeIndex]` table. PC ranges with index `< 0`
/// (no inlining) are skipped.
pub struct InlineTreeIter<'a> {
    pclntab: Option<ParsedPclntab<'a>>,
    /// Decoded `(pc, index)` pairs from `pcdata[PCDATA_InlTreeIndex]`.
    /// Cached eagerly because depth computation needs random-access lookup
    /// of parent PCs against this same table.
    pcdata: Vec<(u32, i32)>,
    /// Position into `pcdata`.
    pos: usize,
    /// `prev_pc` for the current iteration - start of the next range.
    prev_pc: u32,
    /// Inline-tree blob bytes (sequence of 16-byte `inlinedCall` records).
    blob: &'a [u8],
}

impl<'a> InlineTreeIter<'a> {
    /// Construct an iterator that yields nothing - used when prerequisites
    /// (pclntab, moduledata, funcdata blob) are missing.
    pub fn empty() -> Self {
        Self {
            pclntab: None,
            pcdata: Vec::new(),
            pos: 0,
            prev_pc: 0,
            blob: &[],
        }
    }

    /// Read the i-th `inlinedCall` record from the blob.
    fn read_entry(&self, index: u32) -> Option<InlinedCall> {
        let off = (index as usize).checked_mul(INLINED_CALL_SIZE)?;
        let bytes = slice_at::<INLINED_CALL_SIZE>(self.blob, off)?;
        Some(InlinedCall {
            func_id: *bytes.first()?,
            name_off: i32::from_le_bytes(slice_at::<4>(&bytes, 4)?),
            parent_pc: i32::from_le_bytes(slice_at::<4>(&bytes, 8)?),
            start_line: i32::from_le_bytes(slice_at::<4>(&bytes, 12)?),
        })
    }

    /// Look up the inline-tree index active at the given PC offset, by
    /// scanning the cached `pcdata` table. Returns `-1` if no entry covers
    /// the PC (i.e. not in any inlined frame at that point).
    fn index_at_pc(&self, pc: u32) -> i32 {
        // pcdata yields (pc_end, value) pairs where each pair covers
        // [prev_pc, pc_end). Find the first entry with pc_end > pc.
        for &(end, val) in &self.pcdata {
            if pc < end {
                return val;
            }
        }
        -1
    }

    /// Compute inlining depth, by walking the parent chain.
    /// Returns 0 for the outermost inlined frame; increases by 1 per level
    /// toward the leaf.
    ///
    /// Cycle-safe: stops as soon as we revisit any index, since a real Go
    /// inline tree is acyclic and any cycle is malformed input.
    fn depth_at(&self, start_index: i32) -> u32 {
        if start_index < 0 {
            return 0;
        }
        let mut depth: u32 = 0;
        let mut index = start_index;
        let mut visited: [i32; 32] = [-1; 32];
        let mut visited_len: usize = 0;
        loop {
            // Cycle / revisit check: bounded scratch buffer; legit Go inline
            // chains are very shallow (typically < 5).
            for &v in visited.iter().take(visited_len) {
                if v == index {
                    return depth;
                }
            }
            if visited_len < visited.len() {
                if let Some(slot) = visited.get_mut(visited_len) {
                    *slot = index;
                    visited_len = visited_len.saturating_add(1);
                }
            } else {
                // Chain longer than 32 - declare done. Beyond this point we
                // would also exceed any reasonable inlining depth.
                return depth;
            }

            let entry = match self.read_entry(index as u32) {
                Some(e) => e,
                None => return depth,
            };
            let parent_pc = entry.parent_pc as u32;
            let parent_idx = self.index_at_pc(parent_pc);
            if parent_idx < 0 || parent_idx == index {
                return depth;
            }
            depth = depth.saturating_add(1);
            index = parent_idx;
        }
    }
}

impl<'a> Iterator for InlineTreeIter<'a> {
    type Item = InlineEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let pclntab = self.pclntab?;
        loop {
            let &(pc_end, val) = self.pcdata.get(self.pos)?;
            let range = self.prev_pc..pc_end;
            self.prev_pc = pc_end;
            self.pos = self.pos.checked_add(1)?;

            if val < 0 {
                continue; // no inlined frame in this range
            }
            let index = val as u32;
            let entry = match self.read_entry(index) {
                Some(e) => e,
                None => continue,
            };
            let function_name = pclntab.func_name(entry.name_off as u32).unwrap_or("");
            let depth = self.depth_at(val);
            return Some(InlineEntry {
                pc_range: range,
                index,
                function_name,
                parent_pc: entry.parent_pc as u32,
                start_line: entry.start_line,
                func_id: entry.func_id,
                depth,
            });
        }
    }
}

/// One on-disk `inlinedCall` record.
#[derive(Debug, Clone, Copy)]
struct InlinedCall {
    func_id: u8,
    name_off: i32,
    parent_pc: i32,
    start_line: i32,
}

/// Construct a streaming inline-tree iterator for the given function.
///
/// Returns an empty iterator when:
/// - The function has no `funcdata[FUNCDATA_InlTree]` entry (no inlining).
/// - `moduledata.gofunc` is unavailable (Go 1.16-1.19, V2 binaries).
/// - The blob can't be located via `va_to_file`.
pub fn extract_iter<'a>(
    ctx: &'a BinaryContext<'_>,
    pclntab: ParsedPclntab<'a>,
    moduledata: Option<&Moduledata>,
    func: &FuncData,
) -> InlineTreeIter<'a> {
    let md = match moduledata {
        Some(m) => m,
        None => return InlineTreeIter::empty(),
    };
    let gofunc = match md.gofunc {
        Some(g) => g,
        None => return InlineTreeIter::empty(),
    };

    let off = match pclntab.funcdata_at(func, FUNCDATA_INL_TREE) {
        Some(o) if o != FUNCDATA_NIL => o,
        _ => return InlineTreeIter::empty(),
    };

    let blob_va = match gofunc.checked_add(off as u64) {
        Some(v) => v,
        None => return InlineTreeIter::empty(),
    };
    let blob = match ctx.slice_at_va(blob_va) {
        Some(s) => s,
        None => return InlineTreeIter::empty(),
    };

    // Find which pcdata index corresponds to PCDATA_InlTreeIndex (always 2).
    let pcdata_off = match pclntab.pcdata_at(func, PCDATA_INL_TREE_INDEX) {
        Some(o) => o,
        None => return InlineTreeIter::empty(),
    };

    let pcdata: Vec<(u32, i32)> = pclntab.decode_pcvalue(pcdata_off).collect();

    InlineTreeIter {
        pclntab: Some(pclntab),
        pcdata,
        pos: 0,
        prev_pc: 0,
        blob,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inlined_call_size_is_16_bytes() {
        // Sanity: matches the on-disk layout assumption.
        assert_eq!(INLINED_CALL_SIZE, 16);
    }

    #[test]
    fn funcdata_constants_match_go() {
        assert_eq!(FUNCDATA_INL_TREE, 3);
        assert_eq!(PCDATA_INL_TREE_INDEX, 2);
    }
}
