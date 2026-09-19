//! PC/line table (pclntab) parser -- the crown jewel of Go binary analysis.
//!
//! The pclntab is the single most important structure for Go reverse engineering.
//! It is **required** by the Go runtime for stack traces, garbage collection, and
//! goroutine preemption, so it **cannot be removed** without breaking the binary.
//! Even stripped or obfuscated Go binaries retain full function names, source file
//! paths, and line number mappings in this structure.
//!
//! ## Section Names
//!
//! | Format | Section Name    |
//! |--------|-----------------|
//! | ELF    | `.gopclntab`    |
//! | Mach-O | `__gopclntab`   |
//! | PE     | (inside `.rdata`, found by magic scan) |
//!
//! ## Internal Layout (Go 1.16+)
//!
//! The pclntab section is one contiguous blob with these sub-tables:
//!
//! ```text
//! runtime.pclntab (carrier symbol)
//! +-- runtime.pcheader      pcHeader struct (magic, counts, offsets)
//! +-- runtime.funcnametab   null-terminated function name strings
//! +-- runtime.cutab         compilation unit -> file index mapping
//! +-- runtime.filetab       null-terminated source file path strings
//! +-- runtime.pctab         delta-encoded PC-value tables
//! +-- runtime.functab       function table entries + _func structs
//! +-- runtime.findfunctab   fast PC -> function lookup buckets
//! ```
//!
//! Source: `src/cmd/link/internal/ld/pcln.go:930-967`
//!
//! ## pcHeader Structure (Go 1.16+)
//!
//! ```text
//! Offset      Size(bytes) Field            Description
//! 0           4           magic            Version magic (see PclntabVersion)
//! 4           1           pad1             Always 0
//! 5           1           pad2             Always 0
//! 6           1           minLC            Min instruction size (1/2/4)
//! 7           1           ptrSize          Pointer size (4/8)
//! 8           ptrSize     nfunc            Number of functions
//! 8+1*ps      ptrSize     nfiles           Number of source files
//! 8+2*ps      ptrSize     textStart        `runtime.text` VA; Go 1.18-1.25 only
//!                                          (Go 1.26+ leaves the slot zeroed)
//! 8+3*ps      ptrSize     funcnameOffset   Offset to funcnametab
//! 8+4*ps      ptrSize     cuOffset         Offset to cutab
//! 8+5*ps      ptrSize     filetabOffset    Offset to filetab
//! 8+6*ps      ptrSize     pctabOffset      Offset to pctab
//! 8+7*ps      ptrSize     pclnOffset       Offset to functab
//! ```
//!
//! Total: 8 + 8*ptrSize bytes (40 bytes on 32-bit, 72 bytes on 64-bit).
//!
//! Source: `src/runtime/symtab.go:376-395`
//!
//! ## _func Structure (Per-Function Metadata)
//!
//! Each function has a 44-byte fixed-size record followed by variable-length arrays:
//!
//! ```text
//! Offset  Size  Type    Field         Description
//! 0       4     u32     entryOff      PC offset from moduledata.text
//! 4       4     i32     nameOff       Index into funcnametab
//! 8       4     i32     args          Argument size in bytes
//! 12      4     u32     deferreturn   Offset to deferreturn call
//! 16      4     u32     pcsp          Offset into pctab (SP delta table)
//! 20      4     u32     pcfile        Offset into pctab (file table)
//! 24      4     u32     pcln          Offset into pctab (line table)
//! 28      4     u32     npcdata       Number of PCDATA entries
//! 32      4     u32     cuOffset      Compilation unit offset in cutab
//! 36      4     i32     startLine     Line number of func keyword
//! 40      1     u8      funcID        Special function ID (see FuncID enum)
//! 41      1     u8      flag          Function flags
//! 42      1     u8      _pad          Padding
//! 43      1     u8      nfuncdata     Number of FUNCDATA entries (MUST BE LAST)
//! [44]    var   [u32]   pcdata[npcdata]     Offsets into pctab
//! [44+4*n]var   [u32]   funcdata[nfuncdata] Offsets into funcdata section
//! ```
//!
//! Source: `src/runtime/runtime2.go:1074-1099`
//!
//! ## functab Entry Format (Go 1.18+)
//!
//! Each entry is 8 bytes: `(entryoff: u32, funcoff: u32)`.
//! - `entryoff`: PC offset from `runtime.text`
//! - `funcoff`: offset within the functab section to the `_func` struct
//!
//! The functab has `nfunc + 1` entries (the last contains only an end-PC sentinel).
//!
//! Source: `src/runtime/symtab.go:579-582`
//!
//! ## Legacy Layout (Go 1.2-1.15)
//!
//! Binaries built with Go 1.2 through 1.15 use magic `0xfffffffb`
//! ([`PclntabVersion::Go12`]) and a markedly different layout with **no**
//! structured `pcHeader`, `funcnametab`, `cutab`, or `pctab`:
//!
//! - The 8-byte prefix (`magic`, two pad bytes, `minLC`, `ptrSize`) is followed
//!   immediately by a pointer-sized `nfunctab` and then the functab.
//! - functab entries are pointer-sized `(entry, funcoff)` pairs holding
//!   *absolute* PCs (like Go 1.16-1.17); `funcoff` is relative to the pcHeader.
//! - A `u32` after the functab points to the filetab, which is a `[]uint32`
//!   (slot 0 = count, later slots = pcHeader-relative path offsets).
//! - `_func.nameOff`, `pcsp`, `pcfile`, and `pcln` are all offsets relative to
//!   the pcHeader, not to separate sub-tables.
//!
//! This format is parsed by `parse_header_go12`; see its docs and
//! `func_layout` for the precise field offsets.
//!
//! Source: `src/debug/gosym/pclntab.go` (`go12Init`),
//! `src/runtime/symtab.go` (Go 1.2-1.15).

use crate::{
    formats::{BinaryContext, BinaryFormat, GoSections},
    structures::{
        Arch, PclntabVersion,
        util::{advance, advance_n, read_uintptr, read_uvarint, slice_at},
    },
};

/// All recognized pclntab magic values, in order from newest to oldest.
///
/// We check newest first since modern Go binaries are the most common analysis targets.
const MAGICS: &[([u8; 4], PclntabVersion)] = &[
    ([0xf1, 0xff, 0xff, 0xff], PclntabVersion::Go120),
    ([0xf0, 0xff, 0xff, 0xff], PclntabVersion::Go118),
    ([0xfa, 0xff, 0xff, 0xff], PclntabVersion::Go116),
    ([0xfb, 0xff, 0xff, 0xff], PclntabVersion::Go12),
];

/// A parsed pclntab header with accessors into function and file name tables.
///
/// All offsets are relative to the start of the pclntab section (`self.data[0]`
/// = the `pcHeader` magic bytes). The lifetime `'a` borrows from the address
/// space the parser ran on:
///
/// - For ELF / Mach-O / PE this is the input file bytes - zero-copy access.
/// - For Wasm this is the reconstructed linear-memory image owned by
///   [`crate::formats::BinaryContext`]; in that case the borrow lives only as
///   long as the `&BinaryContext` it was derived from. Cache the scalar
///   metadata via [`Self::meta`] if you need to re-attach later.
///
/// Cheap to copy - every field is `Copy` (`&'a [u8]` and integers).
#[derive(Debug, Clone, Copy)]
pub struct ParsedPclntab<'a> {
    /// The entire pclntab section data, starting at the pcHeader.
    pub data: &'a [u8],
    /// Absolute offset where this pclntab starts inside [`Self::data`]. For
    /// ELF/Mach-O/PE this is a file offset; for wasm a linear-memory offset
    /// (since `data` is the reconstructed linear-memory image).
    pub offset: usize,
    /// Detected pclntab version (determines struct layouts).
    pub version: PclntabVersion,
    /// Minimum instruction size in bytes (1=x86, 2=s390x, 4=ARM/MIPS/PPC).
    /// Used as the "PC quantum" for delta-encoded PC tables.
    pub min_lc: u8,
    /// Pointer size in bytes (4 for 32-bit, 8 for 64-bit).
    pub ptr_size: u8,
    /// Number of functions in the binary.
    pub nfunc: usize,
    /// Number of source files referenced.
    pub nfiles: usize,
    /// Offset from pcHeader to the start of `funcnametab` (null-terminated names).
    pub funcname_offset: usize,
    /// Offset from pcHeader to the start of `cutab` (compilation unit table).
    pub cu_offset: usize,
    /// Offset from pcHeader to the start of `filetab` (null-terminated file paths).
    pub filetab_offset: usize,
    /// Offset from pcHeader to the start of `pctab` (delta-encoded PC tables).
    pub pctab_offset: usize,
    /// Offset from pcHeader to the start of `functab` (function table + `_func` structs).
    pub functab_offset: usize,
    /// Absolute base PC that per-function `entryoff` values are measured from.
    ///
    /// Go 1.18+ stores `entryoff` directly in the functab/`_func` (relative to
    /// `runtime.text`), so this is `0`. Go 1.16-1.17 stored *absolute* PCs in
    /// the functab; we record the first (lowest) function PC here and subtract
    /// it so `FuncData::entry_off` is a relative offset for every version.
    pub text_start: u64,
    /// The pcHeader's `textStart` field (the `runtime.text` VA), added to the
    /// header in Go 1.18 and **retired in Go 1.26**, which left the slot in
    /// place but stopped writing it because storing it required a relocation
    /// (`runtime/symtab.go`: *"The next field used to be textStart. This is no
    /// longer stored… Code should use the moduledata text field instead."*).
    ///
    /// `None` for Go 1.16-1.17, which lack the field, and for Go 1.26+, where
    /// the slot reads as zero - a zero is reported as absent rather than as
    /// address `0`, so callers do not silently rebase every function entry
    /// against the bottom of the address space. Mirrors `moduledata.text`.
    pub header_text_start: Option<u64>,
}

/// Scalar metadata of a [`ParsedPclntab`] without the borrowed `data`.
///
/// Useful for callers that want to keep pclntab state across method calls
/// without holding a long-lived borrow of [`crate::formats::BinaryContext`].
/// Pair with [`ParsedPclntab::meta`] to extract; pair with
/// [`PclntabMeta::attach`] to rehydrate on demand against a fresh
/// `&BinaryContext`.
#[derive(Debug, Clone, Copy)]
pub struct PclntabMeta {
    /// See [`ParsedPclntab::offset`].
    pub offset: usize,
    /// See [`ParsedPclntab::version`].
    pub version: PclntabVersion,
    /// See [`ParsedPclntab::min_lc`].
    pub min_lc: u8,
    /// See [`ParsedPclntab::ptr_size`].
    pub ptr_size: u8,
    /// See [`ParsedPclntab::nfunc`].
    pub nfunc: usize,
    /// See [`ParsedPclntab::nfiles`].
    pub nfiles: usize,
    /// See [`ParsedPclntab::funcname_offset`].
    pub funcname_offset: usize,
    /// See [`ParsedPclntab::cu_offset`].
    pub cu_offset: usize,
    /// See [`ParsedPclntab::filetab_offset`].
    pub filetab_offset: usize,
    /// See [`ParsedPclntab::pctab_offset`].
    pub pctab_offset: usize,
    /// See [`ParsedPclntab::functab_offset`].
    pub functab_offset: usize,
    /// See [`ParsedPclntab::text_start`].
    pub text_start: u64,
    /// See [`ParsedPclntab::header_text_start`].
    pub header_text_start: Option<u64>,
}

impl PclntabMeta {
    /// Re-attach this metadata to the address-space buffer, reconstructing a
    /// borrowing [`ParsedPclntab`] whose `data` field starts at the pcHeader.
    ///
    /// `address_data` is the full address-space view the metadata was
    /// originally derived from (for ELF/Mach-O/PE, the input file bytes; for
    /// wasm, the reconstructed linear-memory image - typically obtained via
    /// [`crate::formats::BinaryContext::structure_search_data`]). This
    /// helper slices it at [`Self::offset`] so the returned struct's
    /// `data[0]` is the pcHeader's first byte, matching the layout
    /// `pclntab::parse` produces.
    ///
    /// Returns `None` if `address_data` does not cover `self.offset` -
    /// would only happen if the buffer the metadata came from is not the one
    /// passed in.
    pub fn attach<'a>(&self, address_data: &'a [u8]) -> Option<ParsedPclntab<'a>> {
        let data = address_data.get(self.offset..)?;
        Some(ParsedPclntab {
            data,
            offset: self.offset,
            version: self.version,
            min_lc: self.min_lc,
            ptr_size: self.ptr_size,
            nfunc: self.nfunc,
            nfiles: self.nfiles,
            funcname_offset: self.funcname_offset,
            cu_offset: self.cu_offset,
            filetab_offset: self.filetab_offset,
            pctab_offset: self.pctab_offset,
            functab_offset: self.functab_offset,
            text_start: self.text_start,
            header_text_start: self.header_text_start,
        })
    }
}

impl<'a> ParsedPclntab<'a> {
    /// Extract the scalar metadata, dropping the borrow of [`Self::data`].
    /// See [`PclntabMeta`] for the round-trip story.
    pub fn meta(&self) -> PclntabMeta {
        PclntabMeta {
            offset: self.offset,
            version: self.version,
            min_lc: self.min_lc,
            ptr_size: self.ptr_size,
            nfunc: self.nfunc,
            nfiles: self.nfiles,
            funcname_offset: self.funcname_offset,
            cu_offset: self.cu_offset,
            filetab_offset: self.filetab_offset,
            pctab_offset: self.pctab_offset,
            functab_offset: self.functab_offset,
            text_start: self.text_start,
            header_text_start: self.header_text_start,
        }
    }

    /// Infer the target architecture from `minLC` and `ptrSize`.
    ///
    /// See [`Arch`] for the mapping table and caveats. Several
    /// `(minLC, ptrSize)` combinations are ambiguous; in particular
    /// `(1, 8)` matches both `Arch::X86_64` and `Arch::Wasm`. This accessor
    /// always reports `Arch::X86_64` for that combination - use
    /// [`crate::GoBinary::arch`] for the format-disambiguated result.
    pub fn arch(&self) -> Arch {
        match (self.min_lc, self.ptr_size) {
            (1, 4) => Arch::X86,
            (1, 8) => Arch::X86_64,
            (4, 4) => Arch::Arm,
            (4, 8) => Arch::Arm64,
            (2, 8) => Arch::S390x,
            _ => Arch::Unknown,
        }
    }

    /// Look up a function name by its `nameOff` index into `funcnametab`.
    ///
    /// Names are null-terminated UTF-8 strings. Returns `None` if the offset
    /// is out of bounds or the data is not valid UTF-8.
    pub fn func_name(&self, name_off: u32) -> Option<&'a str> {
        let pos = self.funcname_offset.checked_add(name_off as usize)?;
        let remaining = self.data.get(pos..)?;
        let end = remaining.iter().position(|&b| b == 0)?;
        std::str::from_utf8(remaining.get(..end)?).ok()
    }

    /// Look up a source file path by its offset into `filetab`.
    ///
    /// Paths are null-terminated UTF-8 strings, typically absolute paths
    /// as seen by the compiler.
    pub fn file_name(&self, file_off: u32) -> Option<&'a str> {
        let pos = self.filetab_offset.checked_add(file_off as usize)?;
        let remaining = self.data.get(pos..)?;
        let end = remaining.iter().position(|&b| b == 0)?;
        std::str::from_utf8(remaining.get(..end)?).ok()
    }

    /// Iterate over `(entryoff, funcoff)` pairs from the functab.
    ///
    /// Each pair is 8 bytes (two `u32`s). There are `nfunc` entries
    /// (plus one end-sentinel that we skip).
    pub fn func_entries(&self) -> FuncEntryIter<'a> {
        FuncEntryIter {
            data: self.data,
            base: self.functab_offset,
            index: 0,
            count: self.nfunc,
            version: self.version,
            ptr_size: self.ptr_size,
            text_start: self.text_start,
        }
    }

    /// Base offset within [`Self::data`] that a functab entry's `funcoff` is
    /// measured from.
    ///
    /// In Go 1.16+, `funcoff` is relative to the functab section start
    /// ([`Self::functab_offset`]) - the `_func` structs sit there, after the
    /// `(nfunc+1)` entry pairs. In Go 1.2-1.15 there is no separate functab
    /// section: `funcoff` is an offset from the pcHeader itself (`data[0]`), so
    /// the base is `0`.
    ///
    /// Source: `src/debug/gosym/pclntab.go` (`go12Init` indexes `t.Data`).
    fn func_struct_base(&self) -> usize {
        match self.version {
            PclntabVersion::Go12 => 0,
            _ => self.functab_offset,
        }
    }

    /// Parse the `_func` struct at the given `funcoff` from a functab entry.
    ///
    /// `funcoff` is resolved against `func_struct_base`, which differs between
    /// the legacy (Go 1.2-1.15, pcHeader-relative) and modern (Go 1.16+,
    /// functab-section-relative) layouts.
    ///
    /// Source: `src/runtime/runtime2.go:1074-1099` (modern `_func`),
    /// `src/debug/gosym/pclntab.go` (`funcData`, legacy `_func`).
    pub fn parse_func(&self, func_off: u32) -> Option<FuncData> {
        let off = self.func_struct_base().checked_add(func_off as usize)?;
        let d = self.data.get(off..)?;
        let lay = func_layout(self.version, self.ptr_size);
        if d.len() < lay.size {
            return None;
        }
        // Go 1.2-1.17 store an absolute PC; rebase to an offset like 1.18+.
        let entry_off = if lay.entry_is_abs {
            let abs = read_uintptr(d, 0, self.ptr_size)?;
            u32::try_from(abs.saturating_sub(self.text_start)).unwrap_or(u32::MAX)
        } else {
            u32::from_le_bytes(slice_at::<4>(d, 0)?)
        };
        let start_line = match lay.start_line {
            Some(o) => i32::from_le_bytes(slice_at::<4>(d, o)?),
            None => 0,
        };
        let flag = match lay.flag {
            Some(o) => *d.get(o)?,
            None => 0,
        };
        // Optional in the legacy layout (no cutab / pre-1.12 funcID); read as 0.
        let cu_offset = match lay.cu_offset {
            Some(o) => u32::from_le_bytes(slice_at::<4>(d, o)?),
            None => 0,
        };
        let func_id = match lay.func_id {
            Some(o) => *d.get(o)?,
            None => 0,
        };
        let nfuncdata = match lay.nfuncdata {
            Some(o) => *d.get(o)?,
            None => 0,
        };
        Some(FuncData {
            func_off,
            entry_off,
            name_off: i32::from_le_bytes(slice_at::<4>(d, lay.name_off)?),
            args: i32::from_le_bytes(slice_at::<4>(d, lay.args)?),
            deferreturn: u32::from_le_bytes(slice_at::<4>(d, lay.deferreturn)?),
            pcsp: u32::from_le_bytes(slice_at::<4>(d, lay.pcsp)?),
            pcfile: u32::from_le_bytes(slice_at::<4>(d, lay.pcfile)?),
            pcln: u32::from_le_bytes(slice_at::<4>(d, lay.pcln)?),
            npcdata: u32::from_le_bytes(slice_at::<4>(d, lay.npcdata)?),
            cu_offset,
            start_line,
            func_id,
            flag,
            nfuncdata,
        })
    }

    /// Read the i-th `pcdata[]` table offset (raw `u32` into `pctab`) for the
    /// given function.
    ///
    /// Returns `None` if `i >= func.npcdata` or the read goes out of bounds.
    pub fn pcdata_at(&self, func: &FuncData, i: u32) -> Option<u32> {
        if i >= func.npcdata {
            return None;
        }
        let base = self
            .func_struct_base()
            .checked_add(func.func_off as usize)?
            .checked_add(func_layout(self.version, self.ptr_size).size)?;
        let pos = base.checked_add((i as usize).checked_mul(4)?)?;
        Some(u32::from_le_bytes(slice_at::<4>(self.data, pos)?))
    }

    /// Read the i-th `funcdata[]` offset for the given function. The value
    /// is a `u32` offset into `moduledata.gofunc`; `0xFFFFFFFF` (`^uint32(0)`)
    /// is the sentinel for "no funcdata at this index" - callers should treat
    /// it as `None`.
    ///
    /// Returns `None` if `i >= func.nfuncdata` or the read goes out of bounds.
    pub fn funcdata_at(&self, func: &FuncData, i: u8) -> Option<u32> {
        if i >= func.nfuncdata {
            return None;
        }
        let base = self
            .func_struct_base()
            .checked_add(func.func_off as usize)?
            .checked_add(func_layout(self.version, self.ptr_size).size)?;
        let pcdata_bytes = (func.npcdata as usize).checked_mul(4)?;
        let after_pcdata = base.checked_add(pcdata_bytes)?;
        let pos = after_pcdata.checked_add((i as usize).checked_mul(4)?)?;
        Some(u32::from_le_bytes(slice_at::<4>(self.data, pos)?))
    }

    /// Decode a PC-value table from the pctab.
    ///
    /// Go's pctab stores delta-encoded step functions mapping PC ranges to values.
    /// Each entry is a `(value_delta, pc_delta)` pair in unsigned varint encoding:
    /// - `value_delta` uses zigzag encoding (bit 0 = sign, remaining bits = magnitude)
    /// - `pc_delta` is unsigned, multiplied by `minLC` to get the real PC advance
    /// - A `pc_delta` of 0 terminates the table
    ///
    /// Returns `(pc_offset, value)` pairs where `pc_offset` is relative to
    /// the function entry and `value` is the accumulated decoded value.
    ///
    /// Source: `src/runtime/symtab.go:518-571` (`pcvalue`),
    /// `src/cmd/internal/obj/pcln.go:112-137` (encoder)
    pub fn decode_pcvalue(&self, pctab_off: u32) -> PcValueIter<'a> {
        let start = self.pctab_offset.saturating_add(pctab_off as usize);
        let data = self.data.get(start..).unwrap_or(&[]);
        PcValueIter {
            data,
            pos: 0,
            pc: 0,
            val: -1,
            min_lc: self.min_lc as u32,
            done: data.is_empty(),
        }
    }

    /// Streaming PC-to-line iterator. Line numbers are absolute
    /// (`start_line + accumulated delta`).
    pub fn decode_pcln(&self, func: &FuncData) -> PcLineIter<'a> {
        PcLineIter {
            inner: self.decode_pcvalue(func.pcln),
            start_line: func.start_line,
        }
    }

    /// Streaming PC-to-file iterator yielding `(pc_offset, file_index)`.
    /// `file_index` is unsigned and suitable for passing to
    /// [`Self::resolve_file_via_cu`] together with `func.cu_offset`.
    pub fn decode_pcfile(&self, func: &FuncData) -> PcFileIter<'a> {
        PcFileIter {
            inner: self.decode_pcvalue(func.pcfile),
        }
    }

    /// Streaming PC-to-file iterator that resolves each index to its source
    /// file path via the cutab. Skips entries whose index does not resolve.
    pub fn decode_pcfile_paths<'pcl>(&'pcl self, func: &FuncData) -> PcFilePathIter<'pcl, 'a> {
        PcFilePathIter {
            inner: self.decode_pcfile(func),
            pcl: self,
            cu_offset: func.cu_offset,
        }
    }

    /// Joined PC-to-line-and-file iterator yielding
    /// `(pc_offset, line, file_path)`.
    ///
    /// The pclntab encodes line numbers and file numbers as two independent
    /// run-length tables: pcfile only emits a transition when the *file*
    /// changes, while pcln emits one per line transition. To attribute a
    /// source file to each line event, callers otherwise have to pre-collect
    /// pcfile and run their own "latest pcfile entry ≤ pc" lookup. This
    /// helper folds that bookkeeping in.
    ///
    /// pcfile entries whose index doesn't resolve through the cutab are
    /// skipped (consistent with [`Self::decode_pcfile_paths`]). pcln events
    /// before the first pcfile transition are also skipped - they would
    /// have no file to attribute to.
    pub fn decode_pcln_with_files<'pcl>(&'pcl self, func: &FuncData) -> PcLineFileIter<'pcl, 'a> {
        PcLineFileIter {
            inner: self.decode_pcln(func),
            pcfile: self.decode_pcfile(func).collect(),
            cursor: None,
            pcl: self,
            cu_offset: func.cu_offset,
        }
    }

    /// Resolve the source file for a function via its pcfile and cutab entries.
    ///
    /// Returns the file name for the first (entry-point) file index. Wraps
    /// [`Self::decode_pcfile`] + [`Self::resolve_file_via_cu`] for the common
    /// "where does this function start in source?" use case.
    pub fn resolve_source_file(&self, func: &FuncData) -> Option<&'a str> {
        let (_, idx) = self.decode_pcfile(func).next()?;
        self.resolve_file_index(func.cu_offset, idx)
    }

    /// Resolve a `pcfile` file index to its source path, dispatching on the
    /// pclntab format.
    ///
    /// - **Go 1.16+** routes through the cutab via [`Self::resolve_file_via_cu`].
    /// - **Go 1.2-1.15** has no cutab; the index addresses the `[]uint32`
    ///   filetab directly via [`Self::resolve_file_go12`] (`cu_offset` unused).
    pub fn resolve_file_index(&self, cu_offset: u32, file_idx: u32) -> Option<&'a str> {
        match self.version {
            PclntabVersion::Go12 => self.resolve_file_go12(file_idx),
            _ => self.resolve_file_via_cu(cu_offset, file_idx),
        }
    }

    /// Resolve a file index through the cutab to get a filetab offset, then
    /// look up the file name string.
    ///
    /// The cutab is an array of u32 entries. For compilation unit `cu`, the file
    /// at local index `file_idx` is at `cutab[cu + file_idx]`, which gives an
    /// offset into filetab.
    ///
    /// Source: `src/runtime/symtab.go:714-726` (`funcfile`)
    pub fn resolve_file_via_cu(&self, cu_offset: u32, file_idx: u32) -> Option<&'a str> {
        let logical = (cu_offset as usize).checked_add(file_idx as usize)?;
        let byte_offset = logical.checked_mul(4)?;
        let cu_pos = self.cu_offset.checked_add(byte_offset)?;
        let file_off = u32::from_le_bytes(slice_at::<4>(self.data, cu_pos)?);
        self.file_name(file_off)
    }

    /// Resolve a file index for the legacy (Go 1.2-1.15) `[]uint32` filetab.
    ///
    /// The legacy filetab is an array of `u32` where slot `0` holds the entry
    /// count and slot `n` (`n >= 1`) holds the pcHeader-relative offset of the
    /// `n`-th null-terminated file path. The `pcfile` PC-value table yields the
    /// `n` directly, so `path_off = filetab[file_idx]`.
    ///
    /// Source: `src/debug/gosym/pclntab.go`
    /// (`t.string(t.binary.Uint32(t.filetab[4*fno:]))`).
    pub fn resolve_file_go12(&self, file_idx: u32) -> Option<&'a str> {
        // Slot 0 is the count, not a path; a 0 index means "no file".
        if file_idx == 0 {
            return None;
        }
        let entry_pos = self
            .filetab_offset
            .checked_add((file_idx as usize).checked_mul(4)?)?;
        let path_off = u32::from_le_bytes(slice_at::<4>(self.data, entry_pos)?) as usize;
        let remaining = self.data.get(path_off..)?;
        let end = remaining.iter().position(|&b| b == 0)?;
        std::str::from_utf8(remaining.get(..end)?).ok()
    }

    /// Get the line number range for a function: `(start_line, end_line)`.
    ///
    /// Streams the pcln table once to find the min and max line numbers.
    pub fn line_range(&self, func: &FuncData) -> Option<(i32, i32)> {
        let mut iter = self.decode_pcln(func);
        let (_, first) = iter.next()?;
        let (mut min, mut max) = (first, first);
        for (_, line) in iter {
            if line < min {
                min = line;
            }
            if line > max {
                max = line;
            }
        }
        Some((min, max))
    }

    /// Get the maximum stack frame size for a function.
    ///
    /// Streams the pcsp table once and returns the peak SP delta.
    pub fn max_frame_size(&self, func: &FuncData) -> Option<i32> {
        self.decode_pcvalue(func.pcsp).map(|(_, v)| v).max()
    }

    /// Iterate over all source file paths in the filetab.
    ///
    /// Yields each non-empty valid UTF-8 entry as a borrowed `&str`. The
    /// underlying encoding is version-dependent:
    ///
    /// - **Go 1.16+**: the filetab is a contiguous block of null-terminated
    ///   strings, walked in place.
    /// - **Go 1.2-1.15**: the filetab is a `[]uint32` whose slot `0` is the
    ///   entry count and whose remaining slots are pcHeader-relative offsets to
    ///   null-terminated strings; each slot is dereferenced.
    pub fn file_names(&self) -> FileNameIter<'a> {
        let kind = match self.version {
            PclntabVersion::Go12 => FileTabKind::U32Array,
            _ => FileTabKind::NullTerminated,
        };
        FileNameIter {
            data: self.data,
            filetab_offset: self.filetab_offset,
            kind,
            pos: 0,
            index: 1,
            count: self.nfiles,
        }
    }
}

/// Streaming iterator over functab `(entryoff, funcoff)` pairs.
///
/// Go 1.18+ entries are two `u32`s (8 bytes); Go 1.16-1.17 entries are two
/// `uintptr`s with an *absolute* `entry` PC, which we rebase against
/// [`ParsedPclntab::text_start`] so both yield relative offsets.
pub struct FuncEntryIter<'a> {
    data: &'a [u8],
    base: usize,
    index: usize,
    count: usize,
    version: PclntabVersion,
    ptr_size: u8,
    text_start: u64,
}

impl Iterator for FuncEntryIter<'_> {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        let (entry_off, func_off) =
            if matches!(self.version, PclntabVersion::Go12 | PclntabVersion::Go116) {
                let ps = self.ptr_size as usize;
                let stride = ps.checked_mul(2)?;
                let off = self
                    .index
                    .checked_mul(stride)
                    .and_then(|d| self.base.checked_add(d))?;
                let entry_abs = read_uintptr(self.data, off, self.ptr_size)?;
                let funcoff = read_uintptr(self.data, off.checked_add(ps)?, self.ptr_size)?;
                let eo =
                    u32::try_from(entry_abs.saturating_sub(self.text_start)).unwrap_or(u32::MAX);
                let fo = u32::try_from(funcoff).unwrap_or(u32::MAX);
                (eo, fo)
            } else {
                let off = self
                    .index
                    .checked_mul(8)
                    .and_then(|d| self.base.checked_add(d))?;
                let eo = u32::from_le_bytes(slice_at::<4>(self.data, off)?);
                let fo = u32::from_le_bytes(slice_at::<4>(self.data, off.checked_add(4)?)?);
                (eo, fo)
            };
        self.index = self.index.checked_add(1)?;
        Some((entry_off, func_off))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count.saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FuncEntryIter<'_> {}

/// On-disk encoding of the filetab, which [`FileNameIter`] walks differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileTabKind {
    /// Go 1.16+: a contiguous run of null-terminated path strings.
    NullTerminated,
    /// Go 1.2-1.15: a `[]uint32` of pcHeader-relative path offsets (slot 0 is
    /// the entry count).
    U32Array,
}

/// Streaming iterator over filetab file-name strings.
///
/// Handles both the modern null-terminated filetab and the legacy
/// (Go 1.2-1.15) `[]uint32` offset table; see [`ParsedPclntab::file_names`].
pub struct FileNameIter<'a> {
    /// Full pclntab data, starting at the pcHeader.
    data: &'a [u8],
    /// Offset of the filetab within [`Self::data`].
    filetab_offset: usize,
    /// Which encoding [`Self::data`]'s filetab uses.
    kind: FileTabKind,
    /// Byte cursor within the filetab (for [`FileTabKind::NullTerminated`]).
    pos: usize,
    /// Current `[]uint32` slot (for [`FileTabKind::U32Array`]); slot 0 is the
    /// count, so iteration starts at 1.
    index: usize,
    /// Total entry count (`nfiles`), used as the iteration bound.
    count: usize,
}

impl<'a> Iterator for FileNameIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        match self.kind {
            FileTabKind::NullTerminated => self.next_null_terminated(),
            FileTabKind::U32Array => self.next_u32_array(),
        }
    }
}

impl<'a> FileNameIter<'a> {
    /// Yield the next null-terminated path (Go 1.16+ filetab).
    fn next_null_terminated(&mut self) -> Option<&'a str> {
        let tab = self.data.get(self.filetab_offset..)?;
        while self.count > 0 && self.pos < tab.len() {
            let rest = tab.get(self.pos..)?;
            let end = rest.iter().position(|&b| b == 0)?;
            self.count = self.count.checked_sub(1)?;
            self.pos = self.pos.checked_add(end)?.checked_add(1)?;
            if end > 0
                && let Some(name_bytes) = rest.get(..end)
                && let Ok(name) = std::str::from_utf8(name_bytes)
            {
                return Some(name);
            }
        }
        None
    }

    /// Yield the next path dereferenced through the `[]uint32` offset table
    /// (Go 1.2-1.15 filetab).
    fn next_u32_array(&mut self) -> Option<&'a str> {
        while self.index < self.count {
            let slot = self.index;
            self.index = self.index.checked_add(1)?;
            let entry_pos = self.filetab_offset.checked_add(slot.checked_mul(4)?)?;
            let path_off = match slice_at::<4>(self.data, entry_pos) {
                Some(b) => u32::from_le_bytes(b) as usize,
                None => continue,
            };
            let rest = match self.data.get(path_off..) {
                Some(r) => r,
                None => continue,
            };
            let end = match rest.iter().position(|&b| b == 0) {
                Some(e) => e,
                None => continue,
            };
            if end > 0
                && let Some(name_bytes) = rest.get(..end)
                && let Ok(name) = std::str::from_utf8(name_bytes)
            {
                return Some(name);
            }
        }
        None
    }
}

/// Streaming iterator over a delta-encoded PC-value table.
///
/// Each [`Iterator::next`] decodes one `(value_delta, pc_delta)` varint pair
/// and yields the accumulated `(pc_offset, value)`. Stops at end-of-data,
/// `pc_delta == 0` (table terminator), or any malformed varint. Wrapping
/// arithmetic matches Go's runtime behaviour.
///
/// Source: `src/runtime/symtab.go:518-571` (`pcvalue`),
/// `src/cmd/internal/obj/pcln.go:112-137` (encoder).
pub struct PcValueIter<'a> {
    data: &'a [u8],
    pos: usize,
    pc: u32,
    val: i32,
    min_lc: u32,
    done: bool,
}

impl Iterator for PcValueIter<'_> {
    type Item = (u32, i32);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let (uvdelta, n1) = match self.data.get(self.pos..).and_then(read_uvarint) {
            Some(v) => v,
            None => {
                self.done = true;
                return None;
            }
        };
        self.pos = match self.pos.checked_add(n1) {
            Some(p) => p,
            None => {
                self.done = true;
                return None;
            }
        };

        // Zigzag decode: bit 0 = sign, remaining bits = magnitude. Wrapping
        // arithmetic matches Go's runtime decoder which permits signed wrap.
        let half = (uvdelta >> 1) as i32;
        let vdelta = if uvdelta & 1 != 0 {
            half.wrapping_neg().wrapping_sub(1)
        } else {
            half
        };
        self.val = self.val.wrapping_add(vdelta);

        let (uvpcdelta, n2) = match self.data.get(self.pos..).and_then(read_uvarint) {
            Some(v) => v,
            None => {
                self.done = true;
                return None;
            }
        };
        self.pos = match self.pos.checked_add(n2) {
            Some(p) => p,
            None => {
                self.done = true;
                return None;
            }
        };

        if uvpcdelta == 0 {
            self.done = true;
            return None;
        }
        self.pc = self
            .pc
            .wrapping_add((uvpcdelta as u32).wrapping_mul(self.min_lc));
        Some((self.pc, self.val))
    }
}

/// Streaming PC-to-line iterator. Wraps [`PcValueIter`] and adds the
/// function's `start_line` to each accumulated value.
pub struct PcLineIter<'a> {
    inner: PcValueIter<'a>,
    start_line: i32,
}

impl Iterator for PcLineIter<'_> {
    type Item = (u32, i32);

    fn next(&mut self) -> Option<Self::Item> {
        let (pc, v) = self.inner.next()?;
        Some((pc, v.wrapping_add(self.start_line)))
    }
}

/// Streaming PC-to-file-index iterator. Re-types the value to `u32` since
/// file indices are non-negative.
pub struct PcFileIter<'a> {
    inner: PcValueIter<'a>,
}

impl Iterator for PcFileIter<'_> {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        let (pc, v) = self.inner.next()?;
        Some((pc, v as u32))
    }
}

/// Streaming PC-to-file-path iterator. Resolves each file index through the
/// pclntab's cutab; entries that fail to resolve are skipped silently.
pub struct PcFilePathIter<'pcl, 'a> {
    inner: PcFileIter<'a>,
    pcl: &'pcl ParsedPclntab<'a>,
    cu_offset: u32,
}

impl<'a> Iterator for PcFilePathIter<'_, 'a> {
    type Item = (u32, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (pc, idx) = self.inner.next()?;
            if let Some(path) = self.pcl.resolve_file_index(self.cu_offset, idx) {
                return Some((pc, path));
            }
        }
    }
}

/// Streaming PC-to-line iterator with the active source file pre-joined.
///
/// Yields `(pc_offset, line, file_path)`. The file table only emits a
/// transition when the active source file *changes*, so the joined iterator
/// carries the latest transition forward across `pcln` events. Entries whose
/// file index doesn't resolve through the cutab are skipped silently - same
/// rule as [`PcFilePathIter`].
///
/// This replaces the hand-rolled "walk pcfile and pcln in lockstep" state
/// machine that every consumer otherwise reinvents.
pub struct PcLineFileIter<'pcl, 'a> {
    inner: PcLineIter<'a>,
    /// Pre-collected `(pc_offset, file_index)` transitions, in PC order.
    pcfile: Vec<(u32, u32)>,
    /// Index into `pcfile` of the most recent transition whose pc ≤ current.
    /// Starts as `None` until at least one event has been observed.
    cursor: Option<usize>,
    pcl: &'pcl ParsedPclntab<'a>,
    cu_offset: u32,
}

impl<'a> Iterator for PcLineFileIter<'_, 'a> {
    type Item = (u32, i32, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (pc, line) = self.inner.next()?;

            // Advance the pcfile cursor to the latest transition with pc ≤ current.
            // pcfile transitions are emitted in monotonically increasing PC order,
            // and we walk pcln in the same order - so the cursor only ever moves
            // forward.
            let mut next_idx = match self.cursor {
                Some(c) => c.saturating_add(1),
                None => 0,
            };
            while let Some(&(t_pc, _)) = self.pcfile.get(next_idx) {
                if t_pc > pc {
                    break;
                }
                self.cursor = Some(next_idx);
                next_idx = match next_idx.checked_add(1) {
                    Some(n) => n,
                    None => break,
                };
            }

            let cursor = match self.cursor {
                Some(c) => c,
                // No pcfile transition yet ≤ current pc - try the next pcln event.
                None => continue,
            };
            let (_, file_idx) = match self.pcfile.get(cursor) {
                Some(t) => *t,
                None => continue,
            };
            match self.pcl.resolve_file_index(self.cu_offset, file_idx) {
                Some(path) => return Some((pc, line, path)),
                None => continue,
            }
        }
    }
}

/// Parsed `_func` structure fields (per-function metadata).
///
/// See the module-level documentation for the full struct layout.
///
/// ## Notable Fields for Reverse Engineering
///
/// - `name_off`: index into `funcnametab` to get the package-qualified function name
/// - `entry_off`: PC offset from `runtime.text`, used to map addresses back to functions
/// - `start_line`: source line where the `func` keyword appears
/// - `func_id`: nonzero for special runtime functions (see FuncID constants below)
///
/// ## FuncID Values (from `src/internal/abi/symtab.go:62-96`)
///
/// | Value | Name                    | Description                    |
/// |-------|-------------------------|--------------------------------|
/// | 0     | `FuncIDNormal`          | Regular user/library function  |
/// | 80    | `FuncID_abort`          | `runtime.abort`                |
/// | 86    | `FuncID_goexit`         | Goroutine exit                 |
/// | 91    | `FuncID_morestack`      | Stack growth                   |
/// | 92    | `FuncID_mstart`         | Machine/thread start           |
/// | 94    | `FuncID_rt0_go`         | Runtime entry point            |
/// | 96    | `FuncID_runtime_main`   | `runtime.main`                 |
/// | 100   | `FuncIDWrapper`         | Auto-generated wrapper         |
#[derive(Debug)]
pub struct FuncData {
    /// Offset of this `_func` struct within the functab section. Required to
    /// locate the variable-length `pcdata[]` and `funcdata[]` arrays that
    /// follow the 44-byte fixed prefix.
    pub func_off: u32,
    /// PC offset from `moduledata.text` (the start of executable code).
    ///
    /// This is **not** a `goblin`-derived RVA. Use
    /// [`crate::GoBinary::entry_va`] or [`crate::GoBinary::entry_rva`] to
    /// translate to a disassembler-friendly address; both fold the
    /// `runtime.text` lookup and the PE image-base correction into one call.
    pub entry_off: u32,
    /// Index into `funcnametab` for this function's name.
    pub name_off: i32,
    /// Total argument size in bytes (input + output parameters).
    pub args: i32,
    /// Offset from function entry to the `deferreturn` call (0 if none).
    pub deferreturn: u32,
    /// Offset into `pctab` for the stack-pointer delta table.
    pub pcsp: u32,
    /// Offset into `pctab` for the file-number table.
    pub pcfile: u32,
    /// Offset into `pctab` for the line-number table.
    pub pcln: u32,
    /// Number of PCDATA entries following this struct.
    pub npcdata: u32,
    /// Compilation unit offset in `cutab`.
    pub cu_offset: u32,
    /// Source line number of the `func` keyword.
    pub start_line: i32,
    /// Special function identifier (0 = normal function).
    pub func_id: u8,
    /// Function flags (`FuncFlagTopFrame`, `FuncFlagSPWrite`, `FuncFlagAsm`).
    pub flag: u8,
    /// Number of FUNCDATA entries following the PCDATA array.
    pub nfuncdata: u8,
}

impl FuncData {
    /// Total argument size in bytes (input + output parameters).
    ///
    /// Returns the same byte count as [`Self::args`], reinterpreted as
    /// unsigned. The Go runtime stores this as `int32` for signed-arithmetic
    /// reasons internal to the linker, but the value is logically a
    /// non-negative byte count: a well-formed binary never emits a negative
    /// value here. Negative readings collapse to `0` instead of wrapping
    /// around to a giant `u32`, so callers can treat the result as a true
    /// byte count without further validation.
    pub fn args_size(&self) -> u32 {
        if self.args < 0 { 0 } else { self.args as u32 }
    }
}

/// Parse a pclntab from binary data.
///
/// Uses a layered detection strategy, from cheapest/most reliable to most expensive:
///
/// 1. **Known section + magic** - If the binary has a `.gopclntab` section, validate
///    its start against the known magic bytes. This is the fastest and most reliable path.
/// 2. **Full magic scan** - Scan the entire binary at 4-byte aligned offsets for one
///    of the four known magic values, then validate the full header.
/// 3. **Relaxed header scan** - If magic bytes were wiped (common in malware), scan
///    for the pcHeader structural pattern without requiring magic. Validates
///    `pad1==0, pad2==0, minLC∈{1,2,4}, ptrSize∈{4,8}` plus sub-table offset
///    monotonicity and funcname spot-checking. (Strategy A from RESEARCH.md §1.5)
/// 4. **moduledata pointer chain** - Scan data sections for pointer-aligned values
///    that point into the `.gopclntab` section range, then validate the target with
///    relaxed header validation. This mirrors how the Go runtime itself finds the
///    pclntab via `runtime.firstmoduledata.pcHeader`. (Strategy B from RESEARCH.md §1.5)
/// 5. **functab monotonicity** - Scan read-only sections for long arrays of
///    `(u32, u32)` pairs with strictly monotonically increasing first elements.
///    Work backwards to find the pcHeader. (Strategy C from RESEARCH.md §1.5)
pub fn parse<'a>(ctx: &'a BinaryContext<'a>) -> Option<ParsedPclntab<'a>> {
    let data = ctx.data();
    let sections = ctx.sections();

    // Strategy 0: known section + magic validation (cheapest)
    if let Some(ref range) = sections.gopclntab
        && let Some(raw_end) = range.offset.checked_add(range.size)
    {
        let end = raw_end.min(data.len());
        if let Some(section_data) = data.get(range.offset..end)
            && let Some(parsed) = try_parse_at(section_data, range.offset)
        {
            return Some(parsed);
        }
    }

    // Strategy 1: full-binary magic scan. ELF/Mach-O/PE place the pcHeader
    // at a 4-byte-aligned file offset. Wasm fragments the pclntab across
    // many data segments separated by zero-fill gaps, so we scan the
    // reconstructed *linear-memory image* for it (offsets in the pcHeader
    // are relative to its linear-memory address, not its file offset).
    let (search_data, stride) = if ctx.format() == BinaryFormat::Wasm {
        (ctx.structure_search_data(), 1usize)
    } else {
        (data, 4usize)
    };
    if let Some(parsed) = scan_for_magic_strided(search_data, stride) {
        return Some(parsed);
    }

    // Strategy A: relaxed header scan (no magic required)
    if let Some(parsed) = scan_relaxed(data, sections) {
        return Some(parsed);
    }

    // Strategy B: moduledata pointer chain
    if let Some(parsed) = scan_via_moduledata(ctx) {
        return Some(parsed);
    }

    // Strategy C: functab monotonicity
    scan_via_functab(data)
}

/// Attempt to parse a pclntab starting at the beginning of `data`, requiring
/// a valid magic match.
fn try_parse_at(data: &[u8], base_offset: usize) -> Option<ParsedPclntab<'_>> {
    if data.len() < 8 {
        return None;
    }

    let magic_bytes = slice_at::<4>(data, 0)?;
    let version = MAGICS
        .iter()
        .find(|(m, _)| *m == magic_bytes)
        .map(|(_, v)| *v)?;

    parse_header(data, base_offset, version)
}

/// Scan the binary for pclntab magic bytes at `stride`-byte offsets.
///
/// `stride = 4` covers ELF/Mach-O/PE where the pcHeader is 4-byte-aligned in
/// the file. `stride = 1` is needed for Wasm, where the Data-section payload
/// sits at an arbitrary file offset.
fn scan_for_magic_strided(data: &[u8], stride: usize) -> Option<ParsedPclntab<'_>> {
    for offset in (0..data.len().saturating_sub(72)).step_by(stride) {
        let magic = match slice_at::<4>(data, offset) {
            Some(m) => m,
            None => continue,
        };
        if MAGICS.iter().any(|(m, _)| *m == magic)
            && let Some(rest) = data.get(offset..)
            && let Some(parsed) = try_parse_at(rest, offset)
        {
            return Some(parsed);
        }
    }
    None
}

/// Attempt to parse a pclntab at `data` without requiring a magic match.
///
/// Validates structural constraints that cannot be wiped without breaking the
/// binary: pad bytes, minLC/ptrSize ranges, sub-table offset monotonicity,
/// and a funcname spot-check for plausible ASCII strings.
///
/// Source: `src/runtime/symtab.go:623-631` - the runtime's own validation.
fn try_parse_relaxed(data: &[u8], base_offset: usize) -> Option<ParsedPclntab<'_>> {
    if data.len() < 8 {
        return None;
    }

    // Try magic first to get a definite version
    let magic_bytes = slice_at::<4>(data, 0)?;
    let version = MAGICS
        .iter()
        .find(|(m, _)| *m == magic_bytes)
        .map(|(_, v)| *v)
        .unwrap_or(PclntabVersion::Go120); // assume newest if magic is wiped

    // Validate pad bytes (must be zero)
    if *data.get(4)? != 0 || *data.get(5)? != 0 {
        return None;
    }

    let min_lc = *data.get(6)?;
    let ptr_size = *data.get(7)?;
    if !matches!(min_lc, 1 | 2 | 4) || !matches!(ptr_size, 4 | 8) {
        return None;
    }

    let parsed = parse_header(data, base_offset, version)?;

    // Additional validation: sub-table offsets must be monotonically increasing.
    // The linker emits them in order: funcnametab < cutab < filetab < pctab < functab
    // Source: src/cmd/link/internal/ld/pcln.go:981-986
    if !(parsed.funcname_offset < parsed.cu_offset
        && parsed.cu_offset < parsed.filetab_offset
        && parsed.filetab_offset < parsed.pctab_offset
        && parsed.pctab_offset < parsed.functab_offset)
    {
        return None;
    }

    // Spot-check: the first byte of funcnametab should be a null byte (the empty
    // name at index 0), followed by plausible ASCII function name characters.
    if let Some(fndata) = data.get(parsed.funcname_offset..) {
        // funcnametab[0] is always '\0' (the zero-index name is empty)
        if fndata.first() != Some(&0) {
            return None;
        }
        // Check that some bytes after the first null look like ASCII text
        if fndata.len() > 2 {
            let scan_end = fndata.len().min(32);
            if let Some(window) = fndata.get(1..scan_end)
                && !window.iter().any(|&b| b.is_ascii_alphanumeric())
            {
                return None;
            }
        }
    }

    Some(parsed)
}

/// Scan the gopclntab section (or the full binary) with relaxed validation.
fn scan_relaxed<'a>(data: &'a [u8], sections: &GoSections) -> Option<ParsedPclntab<'a>> {
    // If we have the section bounds, only scan within them
    if let Some(ref range) = sections.gopclntab {
        let raw_end = range.offset.checked_add(range.size)?;
        let end = raw_end.min(data.len());
        let section_data = data.get(range.offset..end)?;
        return try_parse_relaxed(section_data, range.offset);
    }

    // Otherwise scan the whole binary at pointer-aligned offsets.
    // This is more expensive, so step by 8 (common ptrSize alignment).
    for offset in (0..data.len().saturating_sub(72)).step_by(8) {
        if let Some(rest) = data.get(offset..)
            && let Some(parsed) = try_parse_relaxed(rest, offset)
        {
            return Some(parsed);
        }
    }
    // Retry at 4-byte alignment for 32-bit binaries
    for offset in (4..data.len().saturating_sub(40)).step_by(8) {
        if let Some(rest) = data.get(offset..)
            && let Some(parsed) = try_parse_relaxed(rest, offset)
        {
            return Some(parsed);
        }
    }
    None
}

/// Scan data sections for a pointer to the pclntab section, mimicking how the
/// Go runtime locates pclntab via `runtime.firstmoduledata.pcHeader`.
///
/// The first field of `moduledata` is a pointer to the pcHeader. If we know the
/// gopclntab section's VA range, we can scan writable data sections for a
/// pointer-aligned value that falls within that range.
///
/// Source: `src/runtime/symtab.go:402` (`pcHeader *pcHeader` is field 0),
/// `src/cmd/link/internal/ld/symtab.go:593-594` (linker writes this pointer).
fn scan_via_moduledata<'a>(ctx: &BinaryContext<'a>) -> Option<ParsedPclntab<'a>> {
    let data = ctx.data();
    let pclntab_range = ctx.sections().gopclntab.as_ref()?;
    let pclntab_va = pclntab_range.va;
    if pclntab_va == 0 || !ctx.has_va_mapping() {
        return None;
    }

    // Determine pointer size from the binary format (try 8 first, then 4)
    for &ptr_size in &[8u8, 4u8] {
        let ps = ptr_size as usize;

        // Scan the entire binary at pointer-aligned offsets looking for values
        // that point into the gopclntab section VA range.
        let pclntab_va_end = pclntab_va.checked_add(pclntab_range.size as u64)?;
        let header_window_end = pclntab_va.checked_add(64)?;

        for offset in (0..data.len().saturating_sub(ps)).step_by(ps) {
            let candidate_va = match ps {
                4 => match slice_at::<4>(data, offset) {
                    Some(b) => u32::from_le_bytes(b) as u64,
                    None => continue,
                },
                8 => match slice_at::<8>(data, offset) {
                    Some(b) => u64::from_le_bytes(b),
                    None => continue,
                },
                _ => continue,
            };

            // Must point to the start of the gopclntab section (pcHeader is at the beginning)
            // Allow a small tolerance - the pointer should be within the first 64 bytes
            if candidate_va >= pclntab_va
                && candidate_va < header_window_end
                && candidate_va < pclntab_va_end
            {
                let target_file_off = match ctx.va_to_file(candidate_va) {
                    Some(o) => o,
                    None => continue,
                };
                let header_end = match target_file_off.checked_add(72) {
                    Some(e) => e,
                    None => continue,
                };
                if header_end <= data.len()
                    && let Some(rest) = data.get(target_file_off..)
                    && let Some(parsed) = try_parse_relaxed(rest, target_file_off)
                {
                    return Some(parsed);
                }
            }
        }
    }
    None
}

/// The minimum number of consecutive monotonically-increasing functab entries
/// required to consider a candidate region as a real functab.
const FUNCTAB_MIN_RUN: usize = 100;

/// Scan for functab by finding long runs of monotonically increasing `(u32, u32)` pairs,
/// then work backwards to locate the pcHeader.
///
/// The functab is an array of `(entryoff: u32, funcoff: u32)` where `entryoff` values
/// are strictly monotonically increasing. The runtime enforces this invariant at startup.
///
/// Source: `src/runtime/symtab.go:635-653`
fn scan_via_functab<'a>(data: &'a [u8]) -> Option<ParsedPclntab<'a>> {
    // We need at least FUNCTAB_MIN_RUN * 8 bytes for the functab + 72 for the header
    let min_required = FUNCTAB_MIN_RUN.checked_mul(8)?.checked_add(72)?;
    if data.len() < min_required {
        return None;
    }

    // Scan at 4-byte aligned offsets for runs of monotonically increasing u32 pairs
    let mut offset: usize = 0;
    let run_bytes = FUNCTAB_MIN_RUN.checked_mul(8)?;
    while let Some(end) = offset.checked_add(run_bytes) {
        if end > data.len() {
            break;
        }
        let window = match data.get(offset..) {
            Some(w) => w,
            None => break,
        };
        let run_len = count_monotonic_run(window);
        if run_len >= FUNCTAB_MIN_RUN {
            // We found a candidate functab at `offset` with `run_len` entries.
            // Try to locate the pcHeader by scanning backwards.
            if let Some(parsed) = recover_header_from_functab(data, offset, run_len) {
                return Some(parsed);
            }
            // Skip past this run
            let skip = run_len.checked_mul(8)?;
            offset = offset.checked_add(skip)?;
        } else {
            // Advance by 8 bytes (one functab entry) to find the next candidate
            offset = offset.checked_add(8)?;
        }
    }
    None
}

/// Count consecutive monotonically-increasing `(u32, u32)` pairs starting at `data`.
///
/// Returns the number of pairs where `pair[i].entryoff < pair[i+1].entryoff`.
fn count_monotonic_run(data: &[u8]) -> usize {
    let mut count: usize = 0;
    let mut prev_entry: u32 = 0;
    let mut i: usize = 0;

    while let Some(end) = i.checked_add(8) {
        if end > data.len() {
            break;
        }
        let entry_off = match slice_at::<4>(data, i) {
            Some(b) => u32::from_le_bytes(b),
            None => break,
        };
        // First entry: just record it
        if count == 0 {
            prev_entry = entry_off;
            count = 1;
            i = match i.checked_add(8) {
                Some(v) => v,
                None => break,
            };
            continue;
        }
        // Must be strictly increasing
        if entry_off <= prev_entry {
            break;
        }
        prev_entry = entry_off;
        count = match count.checked_add(1) {
            Some(v) => v,
            None => break,
        };
        i = match i.checked_add(8) {
            Some(v) => v,
            None => break,
        };
    }
    count
}

/// Given a functab location and its entry count, try to find the pcHeader
/// by scanning backwards through candidate offsets.
///
/// The pcHeader stores `pclnOffset` (at `8 + 7*ptrSize`) which is the offset
/// from the pcHeader to the functab. So: `pcHeader_offset = functab_offset - pclnOffset`.
fn recover_header_from_functab<'a>(
    data: &'a [u8],
    functab_file_offset: usize,
    run_len: usize,
) -> Option<ParsedPclntab<'a>> {
    // The pcHeader is always at least 4-byte aligned, so step by 4.
    // We infer the actual ptrSize from each candidate's header byte rather
    // than assuming it, since the distance to the functab may not be
    // ptrSize-aligned in edge cases.
    let max_distance = functab_file_offset.min(16 * 1024 * 1024);

    let mut dist: usize = 4;
    while dist <= max_distance {
        let candidate = match functab_file_offset.checked_sub(dist) {
            Some(c) => c,
            None => break,
        };

        let hdr = match data.get(candidate..) {
            Some(h) => h,
            None => break,
        };
        if hdr.len() < 8 {
            dist = match dist.checked_add(4) {
                Some(d) => d,
                None => break,
            };
            continue;
        }

        // Quick structural check: pad1==0, pad2==0, minLC valid, ptrSize valid
        let pad1 = match hdr.get(4) {
            Some(b) => *b,
            None => break,
        };
        let pad2 = match hdr.get(5) {
            Some(b) => *b,
            None => break,
        };
        let min_lc = match hdr.get(6) {
            Some(b) => *b,
            None => break,
        };
        let ptr_size = match hdr.get(7) {
            Some(b) => *b,
            None => break,
        };
        if pad1 != 0 || pad2 != 0 {
            dist = dist.checked_add(4)?;
            continue;
        }
        if !matches!(min_lc, 1 | 2 | 4) || !matches!(ptr_size, 4 | 8) {
            dist = dist.checked_add(4)?;
            continue;
        }

        let ps = ptr_size as usize;
        let header_size = ps.checked_mul(8).and_then(|x| x.checked_add(8))?;
        let header_end = candidate.checked_add(header_size)?;
        if header_end > data.len() {
            dist = dist.checked_add(4)?;
            continue;
        }

        // Read the pclnOffset (functab offset) from the header
        let pclnoffset_pos = ps.checked_mul(7).and_then(|x| x.checked_add(8))?;
        let read_end = candidate
            .checked_add(pclnoffset_pos)
            .and_then(|x| x.checked_add(ps))?;
        if read_end > data.len() {
            dist = dist.checked_add(4)?;
            continue;
        }
        let read_pos = candidate.checked_add(pclnoffset_pos)?;
        let pln_offset = usize::try_from(read_uintptr(data, read_pos, ptr_size)?).ok()?;

        // Check if this header's pclnOffset actually points to our functab
        if pln_offset == dist {
            let nfunc_pos = candidate.checked_add(8)?;
            let nfunc = usize::try_from(read_uintptr(data, nfunc_pos, ptr_size)?).ok()?;

            // nfunc should be close to run_len (run_len may include the +1 sentinel)
            let nfunc_plus_one = nfunc.checked_add(1);
            let run_plus_one = run_len.checked_add(1);
            if nfunc > 0
                && (nfunc == run_len
                    || nfunc_plus_one == Some(run_len)
                    || Some(nfunc) == run_plus_one)
                && let Some(rest) = data.get(candidate..)
                && let Some(parsed) = try_parse_relaxed(rest, candidate)
            {
                return Some(parsed);
            }
        }

        dist = dist.checked_add(4)?;
    }
    None
}

/// Parse a pcHeader at the start of `data` with a known version.
///
/// Validates field ranges (nfunc, nfiles, offsets) but does NOT check magic bytes -
/// the caller is responsible for version determination.
fn parse_header(
    data: &[u8],
    base_offset: usize,
    version: PclntabVersion,
) -> Option<ParsedPclntab<'_>> {
    // The Go 1.2-1.15 pclntab has no structured pcHeader - a different parser.
    if version == PclntabVersion::Go12 {
        return parse_header_go12(data, base_offset);
    }

    // Validate padding bytes (must be zero)
    if *data.get(4)? != 0 || *data.get(5)? != 0 {
        return None;
    }

    let min_lc = *data.get(6)?;
    let ptr_size = *data.get(7)?;
    if !matches!(min_lc, 1 | 2 | 4) || !matches!(ptr_size, 4 | 8) {
        return None;
    }

    let ps = ptr_size as usize;

    // The `textStart` field was added to the pcHeader in Go 1.18. Go 1.16-1.17
    // omit it, so their offset fields (funcnameOffset..pclnOffset) sit one
    // pointer slot earlier.
    let off_base: usize = match version {
        PclntabVersion::Go116 => 2,
        _ => 3,
    };
    let header_size = advance_n(8, off_base.saturating_add(5), ps)?;
    if data.len() < header_size {
        return None;
    }

    // Read a pointer-sized field at the i-th slot after the 8-byte header
    // prefix (`field_off(i) = 8 + i*ps`). Wraps `read_uintptr` and narrows
    // to `usize`, returning `None` on overflow.
    let read_field = |idx: usize| -> Option<usize> {
        let off = advance_n(8, idx, ps)?;
        usize::try_from(read_uintptr(data, off, ptr_size)?).ok()
    };

    let nfunc = read_field(0)?;
    let nfiles = read_field(1)?;
    let funcname_offset = read_field(off_base)?;
    let cu_offset = read_field(off_base.saturating_add(1))?;
    let filetab_offset = read_field(off_base.saturating_add(2))?;
    let pctab_offset = read_field(off_base.saturating_add(3))?;
    let functab_offset = read_field(off_base.saturating_add(4))?;

    // Sanity: reject obviously bogus values
    if nfunc > 10_000_000 || nfiles > 10_000_000 {
        return None;
    }
    if funcname_offset > data.len() || filetab_offset > data.len() || functab_offset > data.len() {
        return None;
    }

    // Go 1.16-1.17 functab entries hold *absolute* PCs. Record the first
    // (lowest) function's PC so we can present relative `entry_off`s like newer
    // versions do. Go 1.18+ already stores offsets, so this stays 0.
    let text_start = match version {
        PclntabVersion::Go116 => read_uintptr(data, functab_offset, ptr_size).unwrap_or(0),
        _ => 0,
    };

    // The pcHeader gained a `textStart` field at index 2 in Go 1.18; Go
    // 1.16-1.17 (off_base == 2) do not have it, and Go 1.26+ zeroed it out
    // (see `ParsedPclntab::header_text_start`). `runtime.text` is never 0 in a
    // real image - even wasm, whose PCs start at 0, carries the value in the
    // moduledata rather than here - so a zero means "not recorded".
    let header_text_start = if off_base > 2 {
        let off = advance_n(8, 2, ps)?;
        read_uintptr(data, off, ptr_size).filter(|&va| va != 0)
    } else {
        None
    };

    Some(ParsedPclntab {
        data,
        offset: base_offset,
        version,
        min_lc,
        ptr_size,
        nfunc,
        nfiles,
        funcname_offset,
        cu_offset,
        filetab_offset,
        pctab_offset,
        functab_offset,
        text_start,
        header_text_start,
    })
}

/// Parse the legacy (Go 1.2-1.15) pclntab header.
///
/// Unlike Go 1.16+, the legacy format has no structured `pcHeader`: the 8-byte
/// prefix (`magic`, two pad bytes, `minLC`, `ptrSize`) is followed immediately
/// by a pointer-sized `nfunctab` and the functab itself. There is no separate
/// `funcnametab`, `cutab`, or `pctab` - function names and the `pcsp`/`pcfile`/
/// `pcln` tables are addressed by offsets relative to the pcHeader (`data[0]`),
/// so [`ParsedPclntab::funcname_offset`] and [`ParsedPclntab::pctab_offset`]
/// are both `0`. The filetab is located by a `u32` stored immediately after the
/// functab and is itself a `[]uint32` (slot 0 = count, later slots = path
/// offsets), so [`ParsedPclntab::cu_offset`] is unused.
///
/// Layout:
///
/// ```text
/// 0        4        magic (0xfffffffb)
/// 4        2        pad (0, 0)
/// 6        1        minLC
/// 7        1        ptrSize
/// 8        ptrSize  nfunctab
/// 8+ps     ...      functab: (2*nfunctab + 1) * ptrSize bytes
///                   = nfunctab (entry, funcoff) uintptr pairs + 1 end-PC
/// +functabsize  4   fileoff (u32): pcHeader-relative offset to the filetab
/// fileoff  4        nfiletab (u32), then (nfiletab-1) u32 path offsets
/// ```
///
/// Source: `src/debug/gosym/pclntab.go` (`go12Init`),
/// `src/runtime/symtab.go` (Go 1.2-1.15 `pclntab` layout).
fn parse_header_go12(data: &[u8], base_offset: usize) -> Option<ParsedPclntab<'_>> {
    // Pad bytes must be zero; minLC/ptrSize must be in range. The legacy parser
    // in debug/gosym requires at least 16 bytes (header + nfunctab).
    if data.len() < 16 || *data.get(4)? != 0 || *data.get(5)? != 0 {
        return None;
    }
    let min_lc = *data.get(6)?;
    let ptr_size = *data.get(7)?;
    if !matches!(min_lc, 1 | 2 | 4) || !matches!(ptr_size, 4 | 8) {
        return None;
    }
    let ps = ptr_size as usize;

    // nfunctab: pointer-sized count at offset 8.
    let nfunctab = usize::try_from(read_uintptr(data, 8, ptr_size)?).ok()?;
    if nfunctab == 0 || nfunctab > 10_000_000 {
        return None;
    }

    // functab starts right after nfunctab and spans (2*nfunctab + 1) uintptrs:
    // nfunctab (entry, funcoff) pairs plus a trailing end-PC sentinel.
    let functab_offset = advance(8, ps)?;
    let functab_words = nfunctab.checked_mul(2)?.checked_add(1)?;
    let functab_size = functab_words.checked_mul(ps)?;

    // The filetab offset is a u32 stored immediately after the functab.
    let fileoff_pos = functab_offset.checked_add(functab_size)?;
    let filetab_offset = u32::from_le_bytes(slice_at::<4>(data, fileoff_pos)?) as usize;
    if filetab_offset == 0 || filetab_offset >= data.len() {
        return None;
    }

    // filetab[0] is the entry count (including itself); later slots are path
    // offsets resolved by `resolve_file_go12`.
    let nfiletab = u32::from_le_bytes(slice_at::<4>(data, filetab_offset)?) as usize;
    if nfiletab > 10_000_000 {
        return None;
    }

    // The first functab entry's absolute PC is the lowest function address,
    // i.e. `runtime.text`. Record it so `entry_off` can be presented relative
    // to text (matching newer versions) and so `text_va` can recover the base
    // even though the legacy moduledata is parsed separately.
    let text_start = read_uintptr(data, functab_offset, ptr_size)?;

    Some(ParsedPclntab {
        data,
        offset: base_offset,
        version: PclntabVersion::Go12,
        min_lc,
        ptr_size,
        nfunc: nfunctab,
        nfiles: nfiletab,
        // Names are pcHeader-relative (`nameoff` indexes `data` from 0).
        funcname_offset: 0,
        // No cutab in the legacy format.
        cu_offset: 0,
        filetab_offset,
        // pcsp/pcfile/pcln are pcHeader-relative offsets, not pctab indices.
        pctab_offset: 0,
        functab_offset,
        text_start,
        header_text_start: Some(text_start),
    })
}

/// Byte offsets of the fields within a `_func` struct, which changed shape
/// across Go versions:
///
/// - **Go 1.2-1.15**: leads with an absolute `entry uintptr`; no `cuOffset`,
///   no `startLine`, no `flag`. `funcID` only exists from Go 1.12, so it is
///   read defensively (`None` for this layout). Size `ptrSize + 32`.
/// - **Go 1.16-1.17**: leads with an absolute `entry uintptr`; adds `cuOffset`
///   and `funcID`; no `startLine`, no `flag`. Size `ptrSize + 36`.
/// - **Go 1.18-1.19**: `u32` `entryoff`; adds `flag`; still no `startLine`.
///   Size `40`.
/// - **Go 1.20+**: adds `startLine`. Size `44`.
#[derive(Clone, Copy)]
struct FuncLayout {
    /// Total struct size - the stride before the `pcdata`/`funcdata` arrays.
    size: usize,
    /// Whether the leading `entry` field is a pointer-sized absolute PC
    /// (Go 1.2-1.17) rather than a `u32` offset.
    entry_is_abs: bool,
    name_off: usize,
    args: usize,
    deferreturn: usize,
    pcsp: usize,
    pcfile: usize,
    pcln: usize,
    npcdata: usize,
    /// `cuOffset` offset (Go 1.16+), else `None` - Go 1.2-1.15 has no cutab and
    /// resolves files directly through the `[]uint32` filetab (read as 0).
    cu_offset: Option<usize>,
    /// `startLine` offset (Go 1.20+), else `None` (read as 0).
    start_line: Option<usize>,
    /// `funcID` offset, else `None` (read as 0). Absent before Go 1.12; left
    /// `None` for the Go 1.2-1.15 layout since the magic alone cannot tell
    /// pre-1.12 from 1.12-1.15 apart and the field is non-critical.
    func_id: Option<usize>,
    /// `flag` offset (Go 1.18+), else `None` (read as 0).
    flag: Option<usize>,
    /// `nfuncdata` offset, else `None` (read as 0). The Go 1.2-1.15 `_func`
    /// stores `pcsp`/`pcfile`/`pcln` as direct pclntab offsets rather than
    /// `pcdata[]` indices, so its `funcdata[]` array is not consumed here.
    nfuncdata: Option<usize>,
}

fn func_layout(version: PclntabVersion, ptr_size: u8) -> FuncLayout {
    let p = ptr_size as usize;
    match version {
        // Go 1.2-1.15: entry uintptr @0; no cuOffset. The fixed fields end at
        // npcdata (@p+24); funcID (Go 1.12+) and nfuncdata follow but their
        // exact positions vary within the range and they are non-critical, so
        // they are left `None`. Stride to the trailing pcdata/funcdata arrays
        // is `p + 32` (`npcdata` + `funcID`/pad + `nfuncdata`).
        //
        // Source: `src/debug/gosym/pclntab.go` (`go12Init`/`funcData`),
        // `src/runtime/runtime2.go` `_func` (Go 1.2-1.15).
        PclntabVersion::Go12 => FuncLayout {
            size: p.saturating_add(32),
            entry_is_abs: true,
            name_off: p,
            args: p.saturating_add(4),
            deferreturn: p.saturating_add(8),
            pcsp: p.saturating_add(12),
            pcfile: p.saturating_add(16),
            pcln: p.saturating_add(20),
            npcdata: p.saturating_add(24),
            cu_offset: None,
            start_line: None,
            func_id: None,
            flag: None,
            nfuncdata: None,
        },
        // Go 1.16-1.17: entry uintptr @0; +cuOffset, +funcID.
        PclntabVersion::Go116 => FuncLayout {
            size: p.saturating_add(36),
            entry_is_abs: true,
            name_off: p,
            args: p.saturating_add(4),
            deferreturn: p.saturating_add(8),
            pcsp: p.saturating_add(12),
            pcfile: p.saturating_add(16),
            pcln: p.saturating_add(20),
            npcdata: p.saturating_add(24),
            cu_offset: Some(p.saturating_add(28)),
            start_line: None,
            func_id: Some(p.saturating_add(32)),
            flag: None,
            nfuncdata: Some(p.saturating_add(35)),
        },
        // Go 1.18-1.19: u32 entryoff @0, +flag, no startLine.
        PclntabVersion::Go118 => FuncLayout {
            size: 40,
            entry_is_abs: false,
            name_off: 4,
            args: 8,
            deferreturn: 12,
            pcsp: 16,
            pcfile: 20,
            pcln: 24,
            npcdata: 28,
            cu_offset: Some(32),
            start_line: None,
            func_id: Some(36),
            flag: Some(37),
            nfuncdata: Some(39),
        },
        // Go 1.20+: +startLine.
        PclntabVersion::Go120 => FuncLayout {
            size: 44,
            entry_is_abs: false,
            name_off: 4,
            args: 8,
            deferreturn: 12,
            pcsp: 16,
            pcfile: 20,
            pcln: 24,
            npcdata: 28,
            cu_offset: Some(32),
            start_line: Some(36),
            func_id: Some(40),
            flag: Some(41),
            nfuncdata: Some(43),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::{GoSections, SectionRange};

    /// Build a synthetic pcHeader (Go 1.20+, 64-bit ARM64) with valid sub-tables.
    /// Returns a data buffer with the header at offset 0 and minimal sub-table stubs.
    fn build_synthetic_pclntab(magic: [u8; 4]) -> Vec<u8> {
        let mut data = vec![0u8; 4096];

        // pcHeader: magic(4) + pad(2) + minLC(1) + ptrSize(1) + 8 ptr fields
        data[0..4].copy_from_slice(&magic);
        data[4] = 0; // pad1
        data[5] = 0; // pad2
        data[6] = 4; // minLC = ARM
        data[7] = 8; // ptrSize = 64-bit

        let nfunc: u64 = 3;
        let nfiles: u64 = 2;
        data[8..16].copy_from_slice(&nfunc.to_le_bytes());
        data[16..24].copy_from_slice(&nfiles.to_le_bytes());
        // unused field at 8+2*8=24
        data[24..32].copy_from_slice(&0u64.to_le_bytes());

        // Sub-table offsets (monotonically increasing):
        //   funcname=100, cutab=200, filetab=300, pctab=400, functab=500
        let offsets: [u64; 5] = [100, 200, 300, 400, 500];
        for (i, &off) in offsets.iter().enumerate() {
            let pos = 8 + (3 + i) * 8;
            data[pos..pos + 8].copy_from_slice(&off.to_le_bytes());
        }

        // funcnametab at offset 100: starts with null byte, then ASCII name
        data[100] = 0; // empty name at index 0
        data[101..111].copy_from_slice(b"runtime.ma");
        data[111] = 0; // null terminator

        // functab at offset 500: 3 entries + sentinel, monotonically increasing
        let functab_base = 500;
        for i in 0..4u32 {
            let entry_off = (i + 1) * 0x100;
            let func_off = i * 44;
            let pos = functab_base + (i as usize) * 8;
            data[pos..pos + 4].copy_from_slice(&entry_off.to_le_bytes());
            data[pos + 4..pos + 8].copy_from_slice(&func_off.to_le_bytes());
        }

        data
    }

    #[test]
    fn test_magic_detection() {
        let magic: [u8; 4] = [0xf1, 0xff, 0xff, 0xff];
        let version = MAGICS.iter().find(|(m, _)| *m == magic).map(|(_, v)| *v);
        assert_eq!(version, Some(PclntabVersion::Go120));
    }

    #[test]
    fn test_arch_detection() {
        let data = build_synthetic_pclntab([0xf1, 0xff, 0xff, 0xff]);
        let ctx = BinaryContext::new(&data);

        let parsed = parse(&ctx).unwrap();
        assert_eq!(parsed.version, PclntabVersion::Go120);
        assert_eq!(parsed.min_lc, 4);
        assert_eq!(parsed.ptr_size, 8);
        assert_eq!(parsed.nfunc, 3);
        assert_eq!(parsed.arch(), Arch::Arm64);
    }

    #[test]
    fn test_strategy_a_relaxed_header_zeroed_magic() {
        // Build a valid pclntab, then zero the magic - relaxed scan should still find it
        let mut data = build_synthetic_pclntab([0xf1, 0xff, 0xff, 0xff]);
        data[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // wipe magic

        let ctx = BinaryContext::new(&data);
        let parsed = parse(&ctx).unwrap();
        assert_eq!(parsed.min_lc, 4);
        assert_eq!(parsed.ptr_size, 8);
        assert_eq!(parsed.nfunc, 3);
        // Version defaults to Go120 when magic is wiped
        assert_eq!(parsed.version, PclntabVersion::Go120);
    }

    #[test]
    fn test_strategy_a_relaxed_rejects_garbage() {
        // Random data should not produce a false positive
        let data = vec![0x42u8; 4096];
        let ctx = BinaryContext::new(&data);
        assert!(parse(&ctx).is_none());
    }

    #[test]
    fn test_strategy_a_relaxed_with_section_hint() {
        // Embed a magic-zeroed pclntab at offset 1024 and tell the parser where it is.
        // Use internal scan_relaxed directly since BinaryContext::new() can't set
        // custom section ranges on synthetic data.
        let mut data = vec![0u8; 8192];
        let pclntab = build_synthetic_pclntab([0x00, 0x00, 0x00, 0x00]); // zeroed magic
        data[1024..1024 + pclntab.len()].copy_from_slice(&pclntab);

        let sections = GoSections {
            has_gopclntab: true,
            has_go_buildinfo: false,
            has_go_buildid_note: false,
            gopclntab: Some(SectionRange {
                offset: 1024,
                size: pclntab.len(),
                va: 0x400000,
            }),
            go_buildinfo: None,
            go_module: None,
            typelink: None,
            itablink: None,
            go_type: None,
            go_func: None,
            fipsinfo: None,
            noptrdata: None,
            data_section: None,
            text_section: None,
        };

        let parsed = scan_relaxed(&data, &sections).unwrap();
        assert_eq!(parsed.offset, 1024);
        assert_eq!(parsed.nfunc, 3);
    }

    #[test]
    fn test_strategy_c_functab_monotonicity() {
        // Build a buffer with a valid pcHeader at offset 0 and a long functab at offset 500.
        // Zero the magic so strategies 0/1 fail. The relaxed scan (A) should find it first,
        // but let's verify the functab run detection utility works.
        let data = build_synthetic_pclntab([0xf1, 0xff, 0xff, 0xff]);
        let run = count_monotonic_run(&data[500..]);
        // We wrote 4 entries (3 funcs + 1 sentinel) with increasing entryoffs
        assert_eq!(run, 4);
    }

    #[test]
    fn test_monotonic_run_rejects_nonmonotonic() {
        let mut data = vec![0u8; 64];
        // Two entries: first entryoff=0x200, second entryoff=0x100 (decreasing)
        data[0..4].copy_from_slice(&0x200u32.to_le_bytes());
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        data[8..12].copy_from_slice(&0x100u32.to_le_bytes());
        data[12..16].copy_from_slice(&44u32.to_le_bytes());

        let run = count_monotonic_run(&data);
        assert_eq!(run, 1); // only the first entry before the break
    }

    #[test]
    fn test_strategy_c_recover_header() {
        // Build a large buffer with a valid pcHeader + long functab, zero the magic,
        // and ensure recover_header_from_functab can trace back from the functab.
        let mut data = build_synthetic_pclntab([0x00, 0x00, 0x00, 0x00]); // zeroed magic

        // Extend the functab to FUNCTAB_MIN_RUN + 1 entries for the scanner threshold.
        // Update nfunc to match.
        let nfunc = FUNCTAB_MIN_RUN as u64;
        data[8..16].copy_from_slice(&nfunc.to_le_bytes());

        // Ensure data is large enough
        let functab_offset = 500;
        let needed = functab_offset + (FUNCTAB_MIN_RUN + 1) * 8 + 256;
        data.resize(needed, 0);

        // Write FUNCTAB_MIN_RUN + 1 monotonically increasing entries
        for i in 0..=(FUNCTAB_MIN_RUN as u32) {
            let entry_off = (i + 1) * 0x10;
            let func_off = i * 44;
            let pos = functab_offset + (i as usize) * 8;
            data[pos..pos + 4].copy_from_slice(&entry_off.to_le_bytes());
            data[pos + 4..pos + 8].copy_from_slice(&func_off.to_le_bytes());
        }

        let result = recover_header_from_functab(&data, functab_offset, FUNCTAB_MIN_RUN + 1);
        assert!(result.is_some(), "should recover pcHeader from functab");
        let parsed = result.unwrap();
        assert_eq!(parsed.offset, 0);
        assert_eq!(parsed.nfunc, FUNCTAB_MIN_RUN);
    }

    /// Build a synthetic legacy (Go 1.2-1.15, magic `0xfffffffb`) pclntab for a
    /// 64-bit x86 target with two functions and two source files.
    ///
    /// The byte layout mirrors `debug/gosym`'s `go12Init`: an 8-byte header, a
    /// pointer-sized `nfunctab`, a `(2*nfunctab + 1)`-uintptr functab holding
    /// absolute PCs, a trailing `u32` filetab offset, and a `[]uint32` filetab
    /// whose slot 0 is the count. Names and file paths are null-terminated
    /// strings addressed by pcHeader-relative offsets.
    fn build_synthetic_go12_pclntab() -> Vec<u8> {
        let mut data = vec![0u8; 4096];
        let put_u64 = |d: &mut [u8], off: usize, v: u64| {
            d[off..off + 8].copy_from_slice(&v.to_le_bytes());
        };
        let put_u32 = |d: &mut [u8], off: usize, v: u32| {
            d[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        let put_str = |d: &mut [u8], off: usize, s: &str| {
            d[off..off + s.len()].copy_from_slice(s.as_bytes());
            d[off + s.len()] = 0;
        };

        // Header: magic + pad + minLC=1 (x86) + ptrSize=8.
        data[0..4].copy_from_slice(&[0xfb, 0xff, 0xff, 0xff]);
        data[6] = 1;
        data[7] = 8;

        // nfunctab @8; functab @16.
        put_u64(&mut data, 8, 2);
        let text = 0x1000u64;
        put_u64(&mut data, 16, text); // entry0 (absolute)
        put_u64(&mut data, 24, 100); // funcoff0 (pcHeader-relative)
        put_u64(&mut data, 32, 0x1100); // entry1
        put_u64(&mut data, 40, 150); // funcoff1
        put_u64(&mut data, 48, 0x1200); // maxpc sentinel

        // fileoff u32 right after the functab ((2*2+1)*8 = 40 bytes from @16).
        put_u32(&mut data, 56, 300);
        // filetab []uint32 @300: slot0=count(3), slot1/2 = path offsets.
        put_u32(&mut data, 300, 3);
        put_u32(&mut data, 304, 400);
        put_u32(&mut data, 308, 420);

        // Name strings (nameoff is pcHeader-relative).
        put_str(&mut data, 200, "main.main");
        put_str(&mut data, 230, "main.worker");
        // File path strings.
        put_str(&mut data, 400, "/src/main.go");
        put_str(&mut data, 420, "/src/util.go");

        // _func0 @100: entry uintptr + nameoff i32 @ ptrSize.
        put_u64(&mut data, 100, text);
        put_u32(&mut data, 108, 200);
        // _func1 @150.
        put_u64(&mut data, 150, 0x1100);
        put_u32(&mut data, 158, 230);

        data
    }

    #[test]
    fn go12_header_parses_legacy_layout() {
        let data = build_synthetic_go12_pclntab();
        let ctx = BinaryContext::new(&data);
        let p = parse(&ctx).expect("legacy pclntab should parse");

        assert_eq!(p.version, PclntabVersion::Go12);
        assert_eq!(p.min_lc, 1);
        assert_eq!(p.ptr_size, 8);
        assert_eq!(p.arch(), Arch::X86_64);
        assert_eq!(p.nfunc, 2);
        assert_eq!(p.nfiles, 3); // includes the count slot
        // funcname/pctab tables are pcHeader-relative in the legacy layout.
        assert_eq!(p.funcname_offset, 0);
        assert_eq!(p.pctab_offset, 0);
        assert_eq!(p.functab_offset, 16);
        assert_eq!(p.filetab_offset, 300);
        // runtime.text recovered from the first function's absolute PC.
        assert_eq!(p.text_start, 0x1000);
        assert_eq!(p.header_text_start, Some(0x1000));
    }

    #[test]
    fn go12_func_entries_and_names() {
        let data = build_synthetic_go12_pclntab();
        let ctx = BinaryContext::new(&data);
        let p = parse(&ctx).unwrap();

        let entries: Vec<(u32, u32)> = p.func_entries().collect();
        // entry_off is rebased against text_start (0x1000); funcoff is
        // pcHeader-relative.
        assert_eq!(entries, vec![(0x0, 100), (0x100, 150)]);

        let f0 = p.parse_func(100).expect("func0");
        assert_eq!(f0.entry_off, 0);
        assert_eq!(f0.name_off, 200);
        assert_eq!(p.func_name(f0.name_off as u32), Some("main.main"));

        let f1 = p.parse_func(150).expect("func1");
        assert_eq!(f1.entry_off, 0x100);
        assert_eq!(p.func_name(f1.name_off as u32), Some("main.worker"));
    }

    #[test]
    fn go12_filetab_is_u32_array() {
        let data = build_synthetic_go12_pclntab();
        let ctx = BinaryContext::new(&data);
        let p = parse(&ctx).unwrap();

        // file_names walks the []uint32 offset table, dereferencing each slot.
        let files: Vec<&str> = p.file_names().collect();
        assert_eq!(files, vec!["/src/main.go", "/src/util.go"]);

        // Direct index resolution: slot 0 is the count (no file), 1.. are paths.
        assert_eq!(p.resolve_file_go12(0), None);
        assert_eq!(p.resolve_file_go12(1), Some("/src/main.go"));
        assert_eq!(p.resolve_file_go12(2), Some("/src/util.go"));
        // resolve_file_index dispatches to the legacy resolver for Go12.
        assert_eq!(p.resolve_file_index(0, 1), Some("/src/main.go"));
    }
}
