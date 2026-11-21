//! Per-PC inlining tree decoder (`funcdata[FUNCDATA_InlTree]`, Go 1.9+).
//!
//! When the Go compiler inlines a callee into a caller, it records a small
//! tree of inlined-call records so the runtime can recover the logical call
//! chain at any PC. We expose that tree as a streaming iterator
//! ([`InlineTreeIter`]) yielding one [`InlineEntry`] per PC range during
//! which an inlined frame is active.
//!
//! ## On-disk layouts (`inlinedCall`)
//!
//! The record has had three shapes ([`InlinedCallFormat`]):
//!
//! ```text
//! Go 1.9-1.11 (16 bytes)      Go 1.12-1.19 (20 bytes)      Go 1.20+ (16 bytes)
//! 0  parent   int32           0  parent   int16            0  funcID    uint8
//! 4  file     int32           2  funcID   uint8            4  nameOff   int32
//! 8  line     int32           4  file     int32            8  parentPc  int32
//! 12 func_    int32           8  line     int32            12 startLine int32
//!                             12 func_    int32
//!                             16 parentPc int32
//! ```
//!
//! Before Go 1.20 the record names the call site (`file`, `line`: in the
//! global filetab through Go 1.15, the enclosing function's compilation unit
//! after) and its parent node; from Go 1.20 it names the parent's call
//! instruction and the callee's first line instead, and the call site is the
//! position the enclosing function's line and file tables give that
//! instruction (`runtime.inlineUnwinder.fileLine`).
//!
//! Source: `src/runtime/symtab.go` (Go 1.9-1.19), `src/runtime/symtabinl.go`
//! (Go 1.20+).
//!
//! ## Decoding chain
//!
//! 1. Locate the function's `FUNCDATA_InlTree` block
//!    ([`crate::GoBinary::funcdata`]).
//! 2. Decode its `PCDATA_InlTreeIndex` table: `(pc_end, index)` steps, where
//!    `index < 0` means "not inlined here" and `index >= 0` selects a record.
//! 3. Read each selected record and resolve its name against `funcnametab`.
//! 4. Depth: follow the record's parent index (before Go 1.20) or its
//!    `parentPc` through the same table (Go 1.20+), until the outermost frame.

use core::ops::Range;
use std::collections::BTreeMap;

use crate::{
    structures::pclntab::{FuncData, FuncId, ParsedPclntab},
    util::{read_i32, read_u16},
};

/// The shape of an `inlinedCall` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InlinedCallFormat {
    /// Go 1.9-1.11: `parent`, `file`, `line`, `func_` (16 bytes).
    Go19,
    /// Go 1.12-1.19: adds the callee's funcID and the parent's call PC (20
    /// bytes).
    Go112,
    /// Go 1.20+: `funcID`, `nameOff`, `parentPc`, `startLine` (16 bytes).
    Go120,
}

impl InlinedCallFormat {
    /// Bytes per record.
    pub fn size(self) -> usize {
        match self {
            Self::Go19 | Self::Go120 => 16,
            Self::Go112 => 20,
        }
    }
}

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
    /// The inlined function's funcID, classified like a function's
    /// ([`FuncId::classify`]); [`FuncId::Normal`] before Go 1.12, whose
    /// records carry none.
    pub func_id: FuncId,
    /// The parent frame's call instruction, as an offset from the enclosing
    /// function's entry (Go 1.12+).
    pub parent_pc: Option<u32>,
    /// The parent node's index, `None` for the outermost inlined frame:
    /// recorded before Go 1.20, the node in effect at [`Self::parent_pc`]
    /// after.
    pub parent: Option<u32>,
    /// Line of the inlined function's `func` keyword (Go 1.20+).
    pub start_line: Option<i32>,
    /// The inlined function's source file: the file the enclosing function's
    /// file table gives the inlined function's code. Go 1.9 positions part
    /// of that code (the call's argument setup and result copy) at the call
    /// site; for the rare inlined call whose code it positions there
    /// entirely, this is the call site's file.
    pub source_file: Option<&'a str>,
    /// The call site's source file: recorded before Go 1.20, the position of
    /// [`Self::parent_pc`] after.
    pub call_file: Option<&'a str>,
    /// The call site's line: recorded before Go 1.20, the position of
    /// [`Self::parent_pc`] after.
    pub call_line: Option<i32>,
    /// Inlining depth: 0 for the outermost inlined frame at this PC, +1 per
    /// additional level toward the leaf.
    ///
    /// # Bounds
    ///
    /// Real-world Go inline chains are very shallow - typically `< 5` - and
    /// the walker caps depth at `32`, the bound of its cycle check. In
    /// practice this always fits in a `u8`; the type stays `u32` to give
    /// breathing room if a future Go runtime raises it.
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
    /// The enclosing function, whose compilation unit resolves call-site
    /// files.
    func: Option<FuncData>,
    format: InlinedCallFormat,
    /// Decoded `(pc_end, index)` steps from `pcdata[PCDATA_InlTreeIndex]`.
    /// Cached eagerly because depth computation needs random-access lookup
    /// of parent PCs against this same table.
    pcdata: Vec<(u32, i32)>,
    /// The enclosing function's `(pc_end, line)` steps.
    lines: Vec<(u32, i32)>,
    /// The enclosing function's `(pc_end, file index)` steps.
    files: Vec<(u32, u32)>,
    /// Each inline node's own file index ([`Self::callee_files`]).
    callee_files: BTreeMap<u32, u32>,
    /// Position into `pcdata`.
    pos: usize,
    /// `prev_pc` for the current iteration - start of the next range.
    prev_pc: u32,
    /// Inline-tree block bytes (a sequence of `inlinedCall` records).
    blob: &'a [u8],
}

impl<'a> InlineTreeIter<'a> {
    /// Construct an iterator that yields nothing - used when prerequisites
    /// (pclntab, the inline-tree block, its index table) are missing.
    pub fn empty() -> Self {
        Self {
            pclntab: None,
            func: None,
            format: InlinedCallFormat::Go120,
            pcdata: Vec::new(),
            lines: Vec::new(),
            files: Vec::new(),
            callee_files: BTreeMap::new(),
            pos: 0,
            prev_pc: 0,
            blob: &[],
        }
    }

    /// Iterate the inline tree of `func`: `blob` is its `FUNCDATA_InlTree`
    /// block, `pcdata` its `PCDATA_InlTreeIndex` table, `format` the record
    /// shape of the binary's Go version.
    pub fn new(
        pclntab: ParsedPclntab<'a>,
        func: FuncData,
        format: InlinedCallFormat,
        blob: &'a [u8],
        pcdata: Vec<(u32, i32)>,
    ) -> Self {
        let mut iter = Self {
            lines: pclntab.decode_pcln(&func).collect(),
            files: pclntab.decode_pcfile(&func).collect(),
            callee_files: BTreeMap::new(),
            pclntab: Some(pclntab),
            func: Some(func),
            format,
            pcdata,
            pos: 0,
            prev_pc: 0,
            blob,
        };
        iter.callee_files = iter.callee_files();
        iter
    }

    /// The call site of `entry`: recorded before Go 1.20, the position the
    /// enclosing function's tables give its `parentPc` after.
    fn call_site(&self, entry: &InlinedCall) -> (Option<&'a str>, Option<i32>) {
        let (Some(pclntab), Some(func)) = (self.pclntab, self.func) else {
            return (None, None);
        };
        let file_name = |index: u32| pclntab.resolve_file_index(func.cu_offset, index);
        match (entry.file, entry.line, entry.parent_pc) {
            (Some(file), line, _) => (u32::try_from(file).ok().and_then(file_name), line),
            (None, _, Some(pc)) => match u32::try_from(pc) {
                Ok(pc) => (
                    value_at(&self.files, pc).and_then(file_name),
                    value_at(&self.lines, pc),
                ),
                Err(_) => (None, None),
            },
            (None, _, None) => (None, None),
        }
    }

    /// The file index of each inline node's own code: the file of its PCs.
    /// In Go 1.10+ every PC the index table gives a node is its callee's; Go
    /// 1.9 also gives it the call's argument setup and result copy, at the
    /// call site, sometimes in a range of their own. So a node's file is the
    /// one among all its PCs other than its call site's, or that one when
    /// caller and callee share it or (Go 1.9) the node has no PC at the
    /// callee's position. One pass over the index and file tables, both in
    /// PC order.
    fn callee_files(&self) -> BTreeMap<u32, u32> {
        let (Some(pclntab), Some(func)) = (self.pclntab, self.func) else {
            return BTreeMap::new();
        };
        // Per node: its call site's file, the file chosen so far, and
        // whether that file is settled (not the call site's).
        let mut nodes: BTreeMap<u32, (Option<&str>, u32, bool)> = BTreeMap::new();
        let mut file_step = 0usize;
        let mut start = 0u32;
        for &(end, value) in &self.pcdata {
            let range = start..end;
            start = end;
            let Ok(index) = u32::try_from(value) else {
                continue;
            };
            // The first file step holding a PC of the range.
            while self
                .files
                .get(file_step)
                .is_some_and(|&(e, _)| e <= range.start)
            {
                file_step = file_step.saturating_add(1);
            }
            for &(file_end, file) in self.files.get(file_step..).unwrap_or(&[]) {
                let node = nodes.entry(index).or_insert_with(|| {
                    let call_file = self.read_entry(index).and_then(|e| self.call_site(&e).0);
                    (call_file, file, false)
                });
                if !node.2
                    && (node.0.is_none()
                        || pclntab.resolve_file_index(func.cu_offset, file) != node.0)
                {
                    *node = (node.0, file, true);
                }
                if file_end >= range.end {
                    break;
                }
            }
        }
        nodes
            .into_iter()
            .map(|(index, (_, file, _))| (index, file))
            .collect()
    }

    /// Read the i-th `inlinedCall` record from the block.
    fn read_entry(&self, index: u32) -> Option<InlinedCall> {
        let at = (index as usize).checked_mul(self.format.size())?;
        let field = |off: usize| read_i32(self.blob, at.checked_add(off)?);
        Some(match self.format {
            InlinedCallFormat::Go19 => InlinedCall {
                parent: Some(field(0)?),
                func_id: 0,
                file: Some(field(4)?),
                line: Some(field(8)?),
                name_off: field(12)?,
                parent_pc: None,
                start_line: None,
            },
            InlinedCallFormat::Go112 => InlinedCall {
                parent: Some(i32::from(read_u16(self.blob, at)? as i16)),
                func_id: *self.blob.get(at.checked_add(2)?)?,
                file: Some(field(4)?),
                line: Some(field(8)?),
                name_off: field(12)?,
                parent_pc: Some(field(16)?),
                start_line: None,
            },
            InlinedCallFormat::Go120 => InlinedCall {
                parent: None,
                func_id: *self.blob.get(at)?,
                file: None,
                line: None,
                name_off: field(4)?,
                parent_pc: Some(field(8)?),
                start_line: Some(field(12)?),
            },
        })
    }

    /// Look up the inline-tree index active at the given PC offset. Returns
    /// `-1` if no entry covers the PC (i.e. not in any inlined frame at that
    /// point).
    fn index_at_pc(&self, pc: u32) -> i32 {
        value_at(&self.pcdata, pc).unwrap_or(-1)
    }

    /// The parent node of record `index`: its recorded parent index (before
    /// Go 1.20), else the node in effect at its `parentPc`. Negative for the
    /// outermost frame.
    fn parent_of(&self, index: i32) -> i32 {
        let Some(entry) = u32::try_from(index).ok().and_then(|i| self.read_entry(i)) else {
            return -1;
        };
        match (entry.parent, entry.parent_pc) {
            (Some(parent), _) => parent,
            (None, Some(pc)) => u32::try_from(pc).map_or(-1, |pc| self.index_at_pc(pc)),
            (None, None) => -1,
        }
    }

    /// Compute inlining depth, by walking the parent chain.
    /// Returns 0 for the outermost inlined frame; increases by 1 per level
    /// toward the leaf.
    ///
    /// Cycle-safe: stops as soon as we revisit any index, since a real Go
    /// inline tree is acyclic and any cycle is malformed input.
    fn depth_at(&self, start_index: i32) -> u32 {
        let mut depth: u32 = 0;
        let mut index = start_index;
        let mut visited: [i32; 32] = [-1; 32];
        for step in 0..visited.len() {
            if index < 0 {
                return depth;
            }
            if let Some(slot) = visited.get_mut(step) {
                *slot = index;
            }
            let parent = self.parent_of(index);
            if parent < 0 || visited.contains(&parent) {
                return depth;
            }
            depth = depth.saturating_add(1);
            index = parent;
        }
        depth
    }
}

impl<'a> Iterator for InlineTreeIter<'a> {
    type Item = InlineEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let pclntab = self.pclntab?;
        let func = self.func?;
        loop {
            let &(pc_end, val) = self.pcdata.get(self.pos)?;
            let range = self.prev_pc..pc_end;
            self.prev_pc = pc_end;
            self.pos = self.pos.checked_add(1)?;

            let Ok(index) = u32::try_from(val) else {
                continue; // no inlined frame in this range
            };
            let entry = match self.read_entry(index) {
                Some(e) => e,
                None => continue,
            };
            let function_name = pclntab.func_name(entry.name_off as u32).unwrap_or("");
            let (call_file, call_line) = self.call_site(&entry);
            let source_file = self
                .callee_files
                .get(&index)
                .and_then(|&file| pclntab.resolve_file_index(func.cu_offset, file));
            return Some(InlineEntry {
                pc_range: range,
                index,
                function_name,
                func_id: FuncId::classify(entry.func_id, function_name, pclntab.wrapper_func_id),
                parent_pc: entry.parent_pc.and_then(|pc| u32::try_from(pc).ok()),
                parent: u32::try_from(self.parent_of(val)).ok(),
                start_line: entry.start_line,
                source_file,
                call_file,
                call_line,
                depth: self.depth_at(val),
            });
        }
    }
}

/// The value a PC-value table's `(pc_end, value)` steps give `pc`: that of
/// the first step ending after it (`runtime.pcvalue`).
fn value_at<T: Copy>(steps: &[(u32, T)], pc: u32) -> Option<T> {
    let at = steps.partition_point(|&(end, _)| end <= pc);
    steps.get(at).map(|&(_, value)| value)
}

/// One on-disk `inlinedCall` record, in any of its formats.
#[derive(Debug, Clone, Copy)]
struct InlinedCall {
    parent: Option<i32>,
    func_id: u8,
    file: Option<i32>,
    line: Option<i32>,
    name_off: i32,
    parent_pc: Option<i32>,
    start_line: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_at_takes_the_step_ending_after_the_pc() {
        let steps = [(4, 'a'), (10, 'b'), (11, 'c')];
        assert_eq!(value_at(&steps, 0), Some('a'));
        assert_eq!(value_at(&steps, 3), Some('a'));
        assert_eq!(value_at(&steps, 4), Some('b'));
        assert_eq!(value_at(&steps, 10), Some('c'));
        assert_eq!(value_at(&steps, 11), None);
        assert_eq!(value_at::<char>(&[], 0), None);
    }

    #[test]
    fn record_sizes_match_each_format() {
        assert_eq!(InlinedCallFormat::Go19.size(), 16);
        assert_eq!(InlinedCallFormat::Go112.size(), 20);
        assert_eq!(InlinedCallFormat::Go120.size(), 16);
    }
}
