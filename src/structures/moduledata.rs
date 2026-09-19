//! Go `moduledata` structure parser with version-aware layout.
//!
//! The `moduledata` is the linker-generated master record that ties together all
//! runtime metadata in a Go binary. Its layout has changed across Go versions,
//! requiring version-specific parsing.
//!
//! ## Version History
//!
//! | Variant | Go Versions | Key Differences                                    |
//! |---------|-------------|----------------------------------------------------|
//! | V1      | 1.5-1.15    | Legacy "Go 1.2" pclntab: no `pcHeader`/`funcnametab`/`cutab`/`pctab`; `pclntable` is the whole pclntab; `[]uint32` `filetab`. `types`/`typelinks []int32` from 1.7; `itablinks` from 1.6; plugin fields from 1.8; `hasmain`/`bad` from 1.10 |
//! | V2      | 1.16-1.17   | New `pcHeader`; no rodata/gofunc, covctrs, inittasks, epclntab |
//! | V3      | 1.18-1.25   | +rodata/gofunc; +covctrs (1.20+); +inittasks (1.21+)|
//! | V4      | 1.26        | +epclntab                                          |
//! | V5      | 1.27+       | -typelinks, -itablinks, +typedesclen, +itaboffset  |
//!
//! Source: `src/runtime/symtab.go` (field offsets verified per release tag,
//! most recently against `go1.27.1`).
//!
//! ## Picking a layout
//!
//! V5 moved `types`' neighbours, so a wrong guess shifts every field from
//! `etypes` onward while still passing a head-only validity check. The
//! out-of-band signals in [`LayoutHints`] are not sufficient on their own - PE
//! carries no `.typelink` section at *any* Go version - so [`Moduledata::parse`]
//! parses both candidates and keeps the one that is internally consistent.

use crate::structures::{
    PclntabVersion,
    goslice::{GoSlice, GoStr},
    util::{advance, align_up, read_uintptr},
};

/// A `[start, end)` virtual-address range for a moduledata memory region.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VaRange {
    /// Start virtual address (inclusive).
    pub start: u64,
    /// End virtual address (exclusive).
    pub end: u64,
}

impl VaRange {
    /// Size of the range in bytes (`end - start`, saturating).
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the range is empty (`end <= start`).
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// One entry of `moduledata.textsectmap` (`runtime.textsect`): a sub-range of
/// the text segment. Present (length > 1) only when the linker split code
/// across multiple text sections in a large binary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TextSect {
    /// Virtual address of the section start.
    pub vaddr: u64,
    /// Virtual address one past the section end.
    pub end: u64,
    /// Base address the section was relocated to.
    pub baseaddr: u64,
}

impl TextSect {
    /// Binary size: 3 * pointer_size.
    pub fn size(ps: u8) -> usize {
        (ps as usize).saturating_mul(3)
    }

    /// Parse from raw bytes at `offset`.
    pub fn parse(data: &[u8], offset: usize, ps: u8) -> Option<Self> {
        let p = ps as usize;
        Some(Self {
            vaddr: read_uintptr(data, offset, ps)?,
            end: read_uintptr(data, offset.checked_add(p)?, ps)?,
            baseaddr: read_uintptr(data, offset.checked_add(p.checked_mul(2)?)?, ps)?,
        })
    }
}

/// One entry of `moduledata.ptab` (`runtime.ptabEntry`) - an exported symbol of
/// a Go plugin. Both fields are offsets relative to `moduledata.types`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtabEntry<'a> {
    /// Exported symbol name, resolved from the names table.
    pub name: Option<&'a str>,
    /// `TypeOff` of the symbol's type descriptor (relative to
    /// `moduledata.types`).
    pub type_offset: i32,
}

/// One entry of `moduledata.pkghashes` / `modulehashes` (`runtime.modulehash`) -
/// a per-package ABI hash used to verify plugin / shared-object
/// compatibility at load time. Populated only for plugin / shared builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleHash<'a> {
    /// Imported module / package path.
    pub module_name: Option<&'a str>,
    /// Link-time ABI hash (the value compared against the dependency's
    /// run-time hash). This is the package-level "abi hash".
    pub linktime_hash: Option<&'a str>,
}

/// A Go `bitvector` (`runtime.bitvector`): `{ n int32; bytedata *byte }` - a
/// bit count plus a pointer to the packed bit data. In moduledata these
/// describe the GC pointer maps for the data and bss segments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bitvector {
    /// Number of bits.
    pub n: i32,
    /// Virtual address of the packed bit data (`bytedata`).
    pub bytedata: u64,
}

impl Bitvector {
    /// Binary size: `int32` + (pointer-aligned) `*byte` = `2 * ptr_size`.
    pub fn size(ps: u8) -> usize {
        (ps as usize).saturating_mul(2)
    }

    /// Parse from raw bytes at `offset` (the `*byte` sits one pointer in).
    pub fn parse(data: &[u8], offset: usize, ps: u8) -> Option<Self> {
        Some(Self {
            n: crate::structures::util::read_i32(data, offset)?,
            bytedata: read_uintptr(data, offset.checked_add(ps as usize)?, ps)?,
        })
    }
}

/// Version-specific moduledata layout.
///
/// Contains the parsed fields common to all versions plus version-specific
/// optional fields like `typelinks` and `itablinks`.
#[derive(Debug, Clone)]
pub struct Moduledata {
    /// VA of the pcHeader.
    pub pc_header: u64,
    /// funcnametab slice.
    pub funcnametab: GoSlice,
    /// cutab slice.
    pub cutab: GoSlice,
    /// filetab slice.
    pub filetab: GoSlice,
    /// pctab slice.
    pub pctab: GoSlice,
    /// pclntable slice (points to the functab section).
    pub pclntable: GoSlice,
    /// ftab slice.
    pub ftab: GoSlice,
    /// findfunctab pointer.
    pub findfunctab: u64,
    /// Minimum PC value.
    pub minpc: u64,
    /// Maximum PC value.
    pub maxpc: u64,
    /// Start of text (code) section.
    pub text: u64,
    /// End of text section.
    pub etext: u64,
    /// `[noptrdata, enoptrdata)` - non-pointer initialized data (`.noptrdata`).
    pub noptrdata: VaRange,
    /// `[data, edata)` - pointer-containing initialized data (`.data`).
    pub data: VaRange,
    /// `[bss, ebss)` - zero-initialized pointer-containing data (`.bss`).
    pub bss: VaRange,
    /// `[noptrbss, enoptrbss)` - zero-initialized non-pointer data (`.noptrbss`).
    pub noptrbss: VaRange,
    /// End VA of the whole module image.
    pub end: u64,
    /// VA of the GC data bitmap (`gcdata`).
    pub gcdata: u64,
    /// VA of the GC bss bitmap (`gcbss`).
    pub gcbss: u64,
    /// `[covctrs, ecovctrs)` coverage-counter region. `Some` and non-empty
    /// only for coverage-instrumented builds (Go 1.20+); `None` pre-1.20.
    pub covctrs: Option<VaRange>,
    /// VA of the types region start.
    pub types: u64,
    /// Length of the type-descriptor region (`typedesclen`, Go 1.27+ / V5).
    /// `None` pre-1.27.
    pub typedesclen: Option<u64>,
    /// VA of the types region end.
    pub etypes: u64,
    /// VA of the start of `.rodata` (Go 1.18+ / V3 / V4 / V5). `None` for V2.
    pub rodata: Option<u64>,
    /// VA used as the base for resolving `funcdata[]` offsets - every value
    /// returned by [`crate::structures::pclntab::ParsedPclntab::funcdata_at`]
    /// is added to this base to get the funcdata blob's VA. Go 1.18+ / V3 /
    /// V4 / V5; `None` for V2 binaries (where funcdata used a different
    /// addressing scheme).
    pub gofunc: Option<u64>,
    /// typelinks slice (present in Go 1.16-1.26, absent in future).
    pub typelinks: Option<GoSlice>,
    /// itablinks slice (present in Go 1.16-1.26, absent in future).
    pub itablinks: Option<GoSlice>,
    /// VA of the itab array (Go 1.27+ / V5 only). In V5 the `itablinks`
    /// slice was removed; itabs are stored contiguously at
    /// `[itaboffset .. itaboffset + itabsize]`. `None` for V2-V4.
    pub itaboffset: Option<u64>,
    /// Byte length of the itab array (Go 1.27+ / V5 only). `None` for V2-V4.
    pub itabsize: Option<u64>,
    /// VA of `epclntab` - one past the end of the pclntab (Go 1.26+ / V4+).
    /// `None` pre-1.26.
    pub epclntab: Option<u64>,
    /// inittasks slice: `[]*initTask`, the linker-built list of package
    /// init tasks (Go 1.21+). `None` for pre-1.21 binaries.
    pub inittasks: Option<GoSlice>,
    /// `textsectmap` slice (one `textsect` per text section). Length > 1 only
    /// for large binaries the linker split across multiple text sections.
    pub textsectmap: GoSlice,
    /// `ptab` slice (`[]ptabEntry`) - exported plugin symbols. Non-empty only
    /// for `-buildmode=plugin`.
    pub ptab: GoSlice,
    /// `pluginpath` string header. Non-empty only for `-buildmode=plugin`.
    pub pluginpath: GoStr,
    /// `pkghashes` slice (`[]modulehash`) - per-package ABI hashes used to
    /// verify plugin/shared compatibility. Non-empty only for plugin/shared.
    pub pkghashes: GoSlice,
    /// `modulename` string header. Set for plugins / shared libraries; empty
    /// for an ordinary executable.
    pub modulename: GoStr,
    /// `modulehashes` slice (`[]modulehash`) - dependency ABI hashes for
    /// plugin/shared compatibility checks.
    pub modulehashes: GoSlice,
    /// `hasmain` flag - this module contains the program's `main` (true for
    /// the main executable, false for plugins / shared libraries). Best-effort
    /// tail read; `false` if the tail was truncated.
    pub has_main: bool,
    /// `bad` flag - the runtime marks a module that failed to load and should
    /// be ignored. Best-effort tail read.
    pub bad: bool,
    /// `gcdatamask` bitvector - GC pointer map for the data segment.
    pub gcdatamask: Bitvector,
    /// `gcbssmask` bitvector - GC pointer map for the bss segment.
    pub gcbssmask: Bitvector,
    /// VA of the runtime `typemap` (`map[typeOff]*_type`) - cross-module type
    /// deduplication map, populated at load time. `0` if absent.
    pub typemap: u64,
    /// VA of the `next` moduledata in the linked list, or `0` for the last
    /// (the only entry in a normal statically-linked executable). Follow it to
    /// enumerate additional modules (plugins / shared libraries).
    pub next: u64,
    /// The moduledata version that was used to parse.
    pub version: ModuledataVersion,
}

/// Which moduledata layout was detected. Boundaries are field-accurate
/// against `runtime/symtab.go` across releases (note: `epclntab` was added in
/// Go 1.26, not 1.24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuledataVersion {
    /// Go 1.5-1.15 (legacy "Go 1.2" pclntab): no `pcHeader`/`funcnametab`/
    /// `cutab`/`pctab`; `pclntable` is the whole pclntab and `filetab` is a
    /// `[]uint32`. Field-introduction versions: `itablinks` (1.6);
    /// `types`/`etypes`, `typelinks []int32`, `typemap` (1.7);
    /// `textsectmap`/`ptab`/`pluginpath`/`pkghashes` (1.8); `hasmain`/`bad`
    /// (1.10).
    V1,
    /// Go 1.16-1.17: no `rodata`/`gofunc`, no `covctrs`, no `inittasks`.
    V2,
    /// Go 1.18-1.25: `+rodata`/`gofunc`; `+covctrs` (1.20+); `+inittasks`
    /// (1.21+); no `epclntab`.
    V3,
    /// Go 1.26: `+epclntab`.
    V4,
    /// Go 1.27+: no `typelinks`/`itablinks`; `+typedesclen`,
    /// `+itaboffset`/`itabsize`.
    V5,
}

/// Out-of-band signals used to pick the moduledata layout.
///
/// Everything here is derived from the *containing binary* rather than from
/// the moduledata bytes themselves, so it has to be threaded in by the caller.
/// Grouping the signals keeps [`Moduledata::parse`] from growing a row of
/// positional booleans whose meaning is invisible at the call site.
#[derive(Debug, Clone, Copy)]
pub struct LayoutHints {
    /// pclntab magic of the binary, which fixes the Go-version floor: `Go118`
    /// implies 1.18+ (`rodata`/`gofunc`), `Go120` implies 1.20+ (`covctrs`).
    pub pclntab_version: PclntabVersion,
    /// Go minor version, when a version string was recovered. `None` for
    /// binaries whose version was stripped or obfuscated away.
    pub go_minor: Option<u32>,
    /// Whether a `.typelink` / `__typelink` section was found. Its *absence*
    /// is weak evidence of Go 1.27+ - PE, wasm, and RELRO ELF links spelled
    /// `.data.rel.ro.typelink` have no such section at any version - so it is
    /// never used alone. See [`Moduledata::parse`].
    pub has_typelink_section: bool,
    /// Whether a `.go.type` / `__go_type` section was found. This one *is* a
    /// positive Go 1.27+ signal: the section did not exist before.
    pub has_go_type_section: bool,
}

impl LayoutHints {
    /// Whether the pclntab magic proves Go 1.18+, i.e. `rodata` and `gofunc`
    /// are present in the moduledata.
    fn has_rodata_gofunc(&self) -> bool {
        matches!(
            self.pclntab_version,
            PclntabVersion::Go118 | PclntabVersion::Go120
        )
    }

    /// Whether the pclntab magic proves Go 1.20+, i.e. the `covctrs` /
    /// `ecovctrs` pair is present (it sits *before* `types`, so its presence
    /// shifts every later field).
    fn has_covctrs(&self) -> bool {
        matches!(self.pclntab_version, PclntabVersion::Go120)
    }

    /// Whether the V5 (Go 1.27+) layout should be tried before the pre-V5 one.
    ///
    /// V5 needs the Go 1.20+ magic as a floor. Beyond that, a `.go.type`
    /// section settles it outright; otherwise we fall back to the weak
    /// "no typelink section" signal, which only counts when the recovered
    /// version agrees (or there is no version to disagree).
    fn prefer_v5(&self) -> bool {
        self.has_covctrs()
            && (self.has_go_type_section
                || (!self.has_typelink_section && self.go_minor.is_none_or(|m| m >= 27)))
    }
}

impl Moduledata {
    /// Parse a moduledata from raw bytes with version detection.
    ///
    /// Field presence is determined per-field:
    /// 1. pclntab magic Go120 -> has `covctrs`/`rodata`/`gofunc` (Go 1.20+)
    /// 2. Go minor version -> `inittasks` (1.21+), `epclntab` (1.26+)
    /// 3. V5 (Go 1.27+) -> see below
    ///
    /// # Choosing between the V5 and pre-V5 layouts
    ///
    /// V5 moved `types`' neighbours around (`+typedesclen`, `+itaboffset`,
    /// `+itabsize`, `-typelinks`, `-itablinks`), so guessing wrong shifts every
    /// field from `etypes` onward and yields a moduledata that still passes a
    /// head-only validity check - `minpc`/`maxpc`/`funcnametab` are ahead of
    /// the divergence - while silently reporting an empty types region, no
    /// itabs, no init tasks and `has_main == false`.
    ///
    /// The hints alone cannot settle it: PE never emits a `.typelink` section
    /// at any Go version, so on a PE binary whose version string was scrubbed
    /// the only remaining signal points the wrong way. Instead of trusting the
    /// hints, this parses *both* candidate layouts (hint-preferred first) and
    /// returns the first one that is internally self-consistent - see
    /// [`Moduledata::layout_self_consistent`]. Only if neither validates does
    /// the hint-preferred layout win, so callers still get the head fields.
    pub fn parse(data: &[u8], ps: u8, hints: LayoutHints) -> Option<Self> {
        // The Go 1.5-1.15 moduledata has an entirely different head and is
        // parsed separately; it has no V5/pre-V5 ambiguity.
        if hints.pclntab_version == PclntabVersion::Go12 {
            return Self::parse_go12_legacy(data, ps, hints.go_minor);
        }

        let prefer_v5 = hints.prefer_v5();
        for v5 in [prefer_v5, !prefer_v5] {
            // V5 requires the Go 1.20+ magic; never consider it below that.
            if v5 && !hints.has_covctrs() {
                continue;
            }
            if let Some(md) = Self::parse_modern(data, ps, hints, v5)
                && md.layout_self_consistent()
            {
                return Some(md);
            }
        }
        Self::parse_modern(data, ps, hints, prefer_v5)
    }

    /// Whether the parsed layout is internally consistent - the arbiter used by
    /// [`Self::parse`] to decide whether it guessed V5 correctly.
    ///
    /// Checks only relationships that hold in *every* real Go image, so a
    /// correctly-guessed layout always passes and a mis-guessed one reliably
    /// fails:
    ///
    /// - `etypes >= types`. Reading a V5 moduledata with the pre-V5 layout puts
    ///   `typedesclen` (a small length) where `etypes` belongs, so `etypes`
    ///   lands far below `types`.
    /// - Every V5 sub-region fits inside `[types, etypes)` and the descriptor
    ///   region precedes the itab region. Reading a pre-V5 moduledata as V5
    ///   picks up unrelated pointers as `typedesclen`/`itaboffset`, which then
    ///   dwarf the (collapsed) types span.
    /// - `rodata`, `gofunc` and `epclntab` are image addresses at or above
    ///   `text`, never the small integers a misaligned read produces.
    pub fn layout_self_consistent(&self) -> bool {
        let Some(span) = self.etypes.checked_sub(self.types) else {
            return false;
        };
        if self.version == ModuledataVersion::V5 {
            let (Some(typedesclen), Some(itaboffset), Some(itabsize)) =
                (self.typedesclen, self.itaboffset, self.itabsize)
            else {
                return false;
            };
            let Some(itab_end) = itaboffset.checked_add(itabsize) else {
                return false;
            };
            // Layout of `.go.type` (cmd/link/internal/ld/data.go, dodataSect
            // STYPE case): ptrSize skip, `type:*`, typelink descriptors up to
            // `typedesclen`, non-typelink descriptors, then itabs.
            if typedesclen > span || itaboffset > span || itab_end > span {
                return false;
            }
            if typedesclen > itaboffset {
                return false;
            }
        }
        // A misaligned read lands on lengths, flags and slice fields, which
        // read as small integers rather than addresses inside the image.
        [self.rodata, self.gofunc, self.epclntab]
            .into_iter()
            .flatten()
            .all(|va| va >= self.text)
    }

    /// Parse a Go 1.16+ moduledata with the layout fixed by `hints` and the
    /// explicit `v5` choice. Shared by both arms of [`Self::parse`]'s
    /// arbitration, which is why the V5 decision is a parameter rather than
    /// something re-derived here.
    fn parse_modern(data: &[u8], ps: u8, hints: LayoutHints, v5: bool) -> Option<Self> {
        let go_version_minor = hints.go_minor;
        let p = ps as usize;
        let slice_sz = GoSlice::size(ps);
        // A Go `string` header is (ptr, len) = 2 pointers.
        let string_sz = p.saturating_mul(2);
        let mut off: usize = 0;

        let pc_header = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        let funcnametab = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let cutab = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let filetab = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let pctab = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let pclntable = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let ftab = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;

        let findfunctab = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let minpc = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let maxpc = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        // The middle/tail layout is determined per-field from the pclntab
        // magic and the Go minor version, verified against runtime/symtab.go
        // across releases:
        //   - rodata / gofunc           : Go 1.18+ (magic Go118 or Go120)
        //   - covctrs                   : Go 1.20+ (magic Go120)
        //   - inittasks                 : Go 1.21+
        //   - epclntab                  : Go 1.26+ (absent in 1.24 / 1.25!)
        //   - V5 (typedesclen + itaboffset/itabsize, no typelinks/itablinks):
        //                                 Go 1.27+, chosen by the caller
        let text = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let etext = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        // Data-segment boundaries: four `(start, end)` VA pairs.
        let read_range = |off: &mut usize| -> Option<VaRange> {
            let start = read_uintptr(data, *off, ps)?;
            *off = advance(*off, p)?;
            let end = read_uintptr(data, *off, ps)?;
            *off = advance(*off, p)?;
            Some(VaRange { start, end })
        };
        let noptrdata = read_range(&mut off)?;
        let data_seg = read_range(&mut off)?;
        let bss = read_range(&mut off)?;
        let noptrbss = read_range(&mut off)?;

        // `covctrs` sits *before* `types`, so its presence shifts every later
        // field; `rodata`/`gofunc` sit *after* `etypes`. They were added in
        // different releases (1.20 vs 1.18), so they must be gated separately.
        let has_covctrs = hints.has_covctrs();
        let has_rodata_gofunc = hints.has_rodata_gofunc();
        let has_inittasks = v5 || go_version_minor.is_none_or(|m| m >= 21);

        // covctrs, ecovctrs (Go 1.20+)
        let covctrs = if has_covctrs {
            Some(read_range(&mut off)?)
        } else {
            None
        };
        // end, gcdata, gcbss
        let end = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let gcdata = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let gcbss = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        let types = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let typedesclen = if v5 {
            let n = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            Some(n)
        } else {
            None
        };
        let etypes = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        // itaboffset / itabsize (V5 only): itabs live inline at
        // [types + itaboffset .. + itabsize].
        let (itaboffset, itabsize) = if v5 {
            let io = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            let is = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            (Some(io), Some(is))
        } else {
            (None, None)
        };

        // rodata, gofunc (Go 1.18+)
        let (rodata, gofunc) = if has_rodata_gofunc {
            let r = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            let g = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            (Some(r), Some(g))
        } else {
            (None, None)
        };

        // epclntab (Go 1.26+, and always present in V5). When the minor
        // version is unknown, probe structurally: the field here is either the
        // `textsectmap` slice (no epclntab) or a lone `epclntab` pointer.
        let has_epclntab = if v5 {
            true
        } else if has_covctrs {
            match go_version_minor {
                Some(m) => m >= 26,
                None => !looks_like_slice_header(data, off, ps),
            }
        } else {
            false
        };
        let epclntab = if has_epclntab {
            let e = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            Some(e)
        } else {
            None
        };

        // textsectmap (slice)
        let textsectmap = GoSlice::parse(data, off, ps).unwrap_or_default();
        off = advance(off, slice_sz)?;

        // typelinks, itablinks (slices) - removed in V5.
        let (typelinks, itablinks) = if v5 {
            (None, None)
        } else {
            let tl = GoSlice::parse(data, off, ps)?;
            off = advance(off, slice_sz)?;
            let il = GoSlice::parse(data, off, ps)?;
            off = advance(off, slice_sz)?;
            (Some(tl), Some(il))
        };

        // ptab (slice), pluginpath (string), pkghashes (slice)
        let ptab = GoSlice::parse(data, off, ps).unwrap_or_default();
        off = advance(off, slice_sz)?;
        let pluginpath = GoStr::parse(data, off, ps).unwrap_or_default();
        off = advance(off, string_sz)?;
        let pkghashes = GoSlice::parse(data, off, ps).unwrap_or_default();
        off = advance(off, slice_sz)?;

        // inittasks []*initTask (Go 1.21+) - best-effort tail read; a malformed
        // tail collapses to `None` rather than failing the whole parse.
        let inittasks = if has_inittasks {
            let it = GoSlice::parse(data, off, ps);
            off = off.saturating_add(slice_sz);
            it
        } else {
            None
        };

        // Tail (all best-effort - a truncated moduledata must not fail the
        // whole parse, since the parser needs nothing past this point):
        //   modulename (string), modulehashes (slice), hasmain (uint8), then a
        //   version-divergent block. In Go 1.24+ `bad` moved to right after
        //   `hasmain`; before 1.24 it sat between `typemap` and `next`:
        //     <1.24:  hasmain, gcdatamask, gcbssmask, typemap, bad, next
        //     >=1.24: hasmain, bad, gcdatamask, gcbssmask, typemap, next
        let bv_sz = Bitvector::size(ps);
        let modulename = GoStr::parse(data, off, ps).unwrap_or_default();
        off = off.saturating_add(string_sz);
        let modulehashes = GoSlice::parse(data, off, ps).unwrap_or_default();
        off = off.saturating_add(slice_sz);
        let has_main = data.get(off).is_some_and(|&b| b != 0);
        off = off.saturating_add(1);

        let bad_after_hasmain = go_version_minor.is_none_or(|m| m >= 24);
        let (bad, gcdatamask, gcbssmask, typemap, next) = if bad_after_hasmain {
            let bad = data.get(off).is_some_and(|&b| b != 0);
            // Align to the pointer boundary the bitvector struct sits on.
            let mut o = align_up(off.saturating_add(1), p).unwrap_or(off);
            let gcdatamask = Bitvector::parse(data, o, ps).unwrap_or_default();
            o = o.saturating_add(bv_sz);
            let gcbssmask = Bitvector::parse(data, o, ps).unwrap_or_default();
            o = o.saturating_add(bv_sz);
            let typemap = read_uintptr(data, o, ps).unwrap_or(0);
            o = o.saturating_add(p);
            let next = read_uintptr(data, o, ps).unwrap_or(0);
            (bad, gcdatamask, gcbssmask, typemap, next)
        } else {
            let mut o = align_up(off, p).unwrap_or(off);
            let gcdatamask = Bitvector::parse(data, o, ps).unwrap_or_default();
            o = o.saturating_add(bv_sz);
            let gcbssmask = Bitvector::parse(data, o, ps).unwrap_or_default();
            o = o.saturating_add(bv_sz);
            let typemap = read_uintptr(data, o, ps).unwrap_or(0);
            o = o.saturating_add(p);
            let bad = data.get(o).is_some_and(|&b| b != 0);
            let o2 = align_up(o.saturating_add(1), p).unwrap_or(o);
            let next = read_uintptr(data, o2, ps).unwrap_or(0);
            (bad, gcdatamask, gcbssmask, typemap, next)
        };

        let version = if v5 {
            ModuledataVersion::V5
        } else if has_epclntab {
            ModuledataVersion::V4
        } else if has_rodata_gofunc {
            ModuledataVersion::V3
        } else {
            ModuledataVersion::V2
        };

        Some(Moduledata {
            pc_header,
            funcnametab,
            cutab,
            filetab,
            pctab,
            pclntable,
            ftab,
            findfunctab,
            minpc,
            maxpc,
            text,
            etext,
            noptrdata,
            data: data_seg,
            bss,
            noptrbss,
            end,
            gcdata,
            gcbss,
            covctrs,
            types,
            typedesclen,
            etypes,
            rodata,
            gofunc,
            epclntab,
            typelinks,
            itablinks,
            itaboffset,
            itabsize,
            inittasks,
            textsectmap,
            ptab,
            pluginpath,
            pkghashes,
            modulename,
            modulehashes,
            has_main,
            bad,
            gcdatamask,
            gcbssmask,
            typemap,
            next,
            version,
        })
    }

    /// Parse the legacy (Go 1.5-1.15) `moduledata`.
    ///
    /// This layout predates the `pcHeader` indirection: it begins with the
    /// `pclntable []byte` slice (pointing at the whole pclntab) rather than a
    /// `pcHeader` pointer, has no `funcnametab`/`cutab`/`pctab`, and stores a
    /// `[]uint32` `filetab`. The tail grew across releases, so fields are gated
    /// on the detected Go minor version (defaulting to the most complete
    /// 1.9-1.15 shape when the version is unknown):
    ///
    /// - `types`/`etypes` and `typelinks []int32`: Go 1.7+ (pre-1.7 used
    ///   `typelinks []*_type` and had no `types` base; handled by skipping the
    ///   type fields).
    /// - `textsectmap`, `ptab`, `pluginpath`, `pkghashes`, `hasmain`,
    ///   `typemap`: Go 1.8+ (`typemap` from 1.7).
    /// - `bad`: Go 1.9+.
    ///
    /// Modern-only fields (`pcHeader`, `funcnametab`, `cutab`, `pctab`,
    /// `covctrs`, `rodata`, `gofunc`, `inittasks`, `epclntab`, V5 itab fields)
    /// are left empty/`None`.
    ///
    /// Source: `src/runtime/symtab.go` `moduledata` (Go 1.5-1.15).
    fn parse_go12_legacy(data: &[u8], ps: u8, go_version_minor: Option<u32>) -> Option<Self> {
        // `moduledata` was introduced in Go 1.5. Go 1.2-1.4 have none, so when
        // the version is known to predate 1.5 we refuse to parse - otherwise a
        // pclntab-address pointer elsewhere in the image could be mistaken for
        // a (false) moduledata. When the version is unknown we still attempt it
        // and rely on the locator's structural validation.
        if go_version_minor.is_some_and(|m| m < 5) {
            return None;
        }

        let p = ps as usize;
        let slice_sz = GoSlice::size(ps);
        let string_sz = p.checked_mul(2)?;
        let bv_sz = Bitvector::size(ps);

        // Feature gates keyed on the Go minor version, verified field-by-field
        // against runtime/symtab.go per release tag:
        //   itablinks                                : Go 1.6
        //   types/etypes, typelinks []int32, typemap : Go 1.7
        //   textsectmap, ptab, pluginpath, pkghashes : Go 1.8 (plugin support)
        //   hasmain, bad                             : Go 1.10
        // Go 1.5 is the leanest (`typelinks []*_type` pointers, no types/etypes,
        // no itablinks, no typemap); Go 1.9 has the plugin fields but not
        // hasmain/bad. An unknown minor assumes the richest 1.10-1.15 shape and
        // degrades gracefully via the best-effort tail reads below.
        let has_itablinks = go_version_minor.is_none_or(|m| m >= 6);
        let has_types = go_version_minor.is_none_or(|m| m >= 7);
        let has_typemap = go_version_minor.is_none_or(|m| m >= 7);
        let has_textsectmap = go_version_minor.is_none_or(|m| m >= 8);
        let has_plugin_fields = go_version_minor.is_none_or(|m| m >= 8);
        let has_hasmain = go_version_minor.is_none_or(|m| m >= 10);
        let has_bad = go_version_minor.is_none_or(|m| m >= 10);

        let mut off = 0usize;

        // Head: pclntable, ftab, filetab slices; findfunctab, minpc, maxpc.
        let pclntable = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let ftab = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let filetab = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let findfunctab = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let minpc = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let maxpc = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        let text = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let etext = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        let read_range = |off: &mut usize| -> Option<VaRange> {
            let start = read_uintptr(data, *off, ps)?;
            *off = advance(*off, p)?;
            let end = read_uintptr(data, *off, ps)?;
            *off = advance(*off, p)?;
            Some(VaRange { start, end })
        };
        let noptrdata = read_range(&mut off)?;
        let data_seg = read_range(&mut off)?;
        let bss = read_range(&mut off)?;
        let noptrbss = read_range(&mut off)?;

        let end = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let gcdata = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;
        let gcbss = read_uintptr(data, off, ps)?;
        off = advance(off, p)?;

        // types/etypes (Go 1.7+).
        let (types, etypes) = if has_types {
            let t = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            let e = read_uintptr(data, off, ps)?;
            off = advance(off, p)?;
            (t, e)
        } else {
            (0, 0)
        };

        // textsectmap (Go 1.8+).
        let textsectmap = if has_textsectmap {
            let ts = GoSlice::parse(data, off, ps).unwrap_or_default();
            off = advance(off, slice_sz)?;
            ts
        } else {
            GoSlice::default()
        };

        // typelinks (present from Go 1.5; `[]*_type` pointers pre-1.7, `[]int32`
        // offsets from Go 1.7) followed by itablinks (`[]*itab`, Go 1.6+).
        let typelinks = GoSlice::parse(data, off, ps)?;
        off = advance(off, slice_sz)?;
        let itablinks = if has_itablinks {
            let il = GoSlice::parse(data, off, ps)?;
            off = advance(off, slice_sz)?;
            Some(il)
        } else {
            None
        };

        // ptab, pluginpath, pkghashes (Go 1.8+).
        let (ptab, pluginpath, pkghashes) = if has_plugin_fields {
            let pt = GoSlice::parse(data, off, ps).unwrap_or_default();
            off = advance(off, slice_sz)?;
            let pp = GoStr::parse(data, off, ps).unwrap_or_default();
            off = advance(off, string_sz)?;
            let pk = GoSlice::parse(data, off, ps).unwrap_or_default();
            off = advance(off, slice_sz)?;
            (pt, pp, pk)
        } else {
            (GoSlice::default(), GoStr::default(), GoSlice::default())
        };

        // Tail (best-effort - a truncated moduledata must not fail the parse):
        // modulename, modulehashes, [hasmain], gcdatamask, gcbssmask,
        // [typemap], [bad], next.
        let modulename = GoStr::parse(data, off, ps).unwrap_or_default();
        off = off.saturating_add(string_sz);
        let modulehashes = GoSlice::parse(data, off, ps).unwrap_or_default();
        off = off.saturating_add(slice_sz);

        let has_main = if has_hasmain {
            let hm = data.get(off).is_some_and(|&b| b != 0);
            off = off.saturating_add(1);
            hm
        } else {
            // Pre-1.8 had no `hasmain`; a statically-linked executable is the
            // main module by definition.
            true
        };

        // Bitvectors sit on a pointer boundary.
        let mut o = align_up(off, p).unwrap_or(off);
        let gcdatamask = Bitvector::parse(data, o, ps).unwrap_or_default();
        o = o.saturating_add(bv_sz);
        let gcbssmask = Bitvector::parse(data, o, ps).unwrap_or_default();
        o = o.saturating_add(bv_sz);

        let typemap = if has_typemap {
            let tm = read_uintptr(data, o, ps).unwrap_or(0);
            o = o.saturating_add(p);
            tm
        } else {
            0
        };

        // `bad` (Go 1.9+) sits between `typemap` and `next`.
        let bad = if has_bad {
            let b = data.get(o).is_some_and(|&v| v != 0);
            o = align_up(o.saturating_add(1), p).unwrap_or(o);
            b
        } else {
            false
        };
        let next = read_uintptr(data, o, ps).unwrap_or(0);

        Some(Moduledata {
            // Legacy has no pcHeader; record the pclntab address it points at.
            pc_header: pclntable.ptr,
            funcnametab: GoSlice::default(),
            cutab: GoSlice::default(),
            filetab,
            pctab: GoSlice::default(),
            pclntable,
            ftab,
            findfunctab,
            minpc,
            maxpc,
            text,
            etext,
            noptrdata,
            data: data_seg,
            bss,
            noptrbss,
            end,
            gcdata,
            gcbss,
            covctrs: None,
            types,
            typedesclen: None,
            etypes,
            rodata: None,
            gofunc: None,
            epclntab: None,
            // Pre-1.7 `typelinks` are `[]*_type` pointers, not the `[]int32`
            // offsets-from-`types` the extractor expects, so they are not
            // surfaced (type extraction needs the Go 1.7+ typeOff scheme).
            typelinks: if has_types { Some(typelinks) } else { None },
            itablinks,
            itaboffset: None,
            itabsize: None,
            inittasks: None,
            textsectmap,
            ptab,
            pluginpath,
            pkghashes,
            modulename,
            modulehashes,
            has_main,
            bad,
            gcdatamask,
            gcbssmask,
            typemap,
            next,
            version: ModuledataVersion::V1,
        })
    }
}

/// Heuristic: do the three pointer-sized words at `off` look like a Go slice
/// header `(ptr, len, cap)` with `len == cap` and a small length?
///
/// Used to distinguish the Go 1.24/1.25 moduledata (no `epclntab`, so
/// `textsectmap` sits here) from Go 1.26+ (a lone `epclntab` pointer first)
/// when no Go version string is available. `textsectmap` has one entry per
/// text section, so its length is tiny.
fn looks_like_slice_header(data: &[u8], off: usize, ps: u8) -> bool {
    let p = ps as usize;
    let (Some(len_off), Some(cap_off)) = (off.checked_add(p), off.checked_add(p.saturating_mul(2)))
    else {
        return false;
    };
    let (Some(len), Some(cap)) = (
        read_uintptr(data, len_off, ps),
        read_uintptr(data, cap_off, ps),
    ) else {
        return false;
    };
    len == cap && (1..4096).contains(&len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hints for a binary with neither a `.typelink` nor a `.go.type` section -
    /// the shape a PE, a wasm module, or a stripped RELRO ELF presents.
    fn hints(pclntab_version: PclntabVersion, go_minor: Option<u32>) -> LayoutHints {
        LayoutHints {
            pclntab_version,
            go_minor,
            has_typelink_section: false,
            has_go_type_section: false,
        }
    }

    /// Write a little-endian `u64` at `off`.
    fn put(d: &mut [u8], off: usize, v: u64) {
        d[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Field offsets of the 64-bit V5 (Go 1.27+) moduledata, counted from the
    /// `pcHeader` pointer at 0. Derived by walking `parse_modern`'s reads.
    mod v5_off {
        pub const TEXT: usize = 176;
        pub const ETEXT: usize = 184;
        pub const TYPES: usize = 296;
        pub const TYPEDESCLEN: usize = 304;
        pub const ETYPES: usize = 312;
        pub const ITABOFFSET: usize = 320;
        pub const ITABSIZE: usize = 328;
        pub const RODATA: usize = 336;
        pub const GOFUNC: usize = 344;
        pub const EPCLNTAB: usize = 352;
    }

    /// Field offsets of the 64-bit V3 (Go 1.20-1.25) moduledata. Identical to
    /// V5 up to `types`, then diverges: no `typedesclen`, no itab fields.
    mod v3_off {
        pub const TEXT: usize = 176;
        pub const ETEXT: usize = 184;
        pub const TYPES: usize = 296;
        pub const ETYPES: usize = 304;
        pub const RODATA: usize = 312;
        pub const GOFUNC: usize = 320;
        pub const TEXTSECTMAP_PTR: usize = 328;
        pub const TEXTSECTMAP_LEN: usize = 336;
        pub const TEXTSECTMAP_CAP: usize = 344;
    }

    /// A structurally plausible 64-bit V5 moduledata: every sub-region of
    /// `[types, etypes)` is in range and the segment pointers are real
    /// addresses, so [`Moduledata::layout_self_consistent`] accepts it.
    fn synthetic_v5() -> Vec<u8> {
        let mut d = vec![0u8; 700];
        put(&mut d, v5_off::TEXT, 0x401000);
        put(&mut d, v5_off::ETEXT, 0x4a0000);
        put(&mut d, v5_off::TYPES, 0x500000);
        put(&mut d, v5_off::TYPEDESCLEN, 0x1000);
        put(&mut d, v5_off::ETYPES, 0x520000);
        put(&mut d, v5_off::ITABOFFSET, 0x1f000);
        put(&mut d, v5_off::ITABSIZE, 0x400);
        put(&mut d, v5_off::RODATA, 0x490000);
        put(&mut d, v5_off::GOFUNC, 0x4f0000);
        put(&mut d, v5_off::EPCLNTAB, 0x4ffff0);
        d
    }

    /// A structurally plausible 64-bit V3 moduledata. The `textsectmap` slice
    /// header at the position `epclntab` would occupy keeps the Go 1.26 probe
    /// on the V3 side when the minor version is unknown.
    fn synthetic_v3() -> Vec<u8> {
        let mut d = vec![0u8; 700];
        put(&mut d, v3_off::TEXT, 0x401000);
        put(&mut d, v3_off::ETEXT, 0x4a0000);
        put(&mut d, v3_off::TYPES, 0x4a2000);
        put(&mut d, v3_off::ETYPES, 0x4d9000);
        put(&mut d, v3_off::RODATA, 0x4a2000);
        put(&mut d, v3_off::GOFUNC, 0x55c000);
        put(&mut d, v3_off::TEXTSECTMAP_PTR, 0x400000);
        put(&mut d, v3_off::TEXTSECTMAP_LEN, 1);
        put(&mut d, v3_off::TEXTSECTMAP_CAP, 1);
        d
    }

    #[test]
    fn version_detection_go116() {
        // V2 moduledata needs enough space for the full prefix + version-specific section
        // Prefix: 1 ptr + 6 slices + 4 ptrs + 8 skipped ptrs = 1*8 + 6*24 + 4*8 + 8*8 = 248
        // V2 tail: 3 ptrs + 2 ptrs + 1 slice + 2 slices = 3*8 + 2*8 + 24 + 2*24 = 112
        let data = vec![0u8; 400];
        let md = Moduledata::parse(&data, 8, hints(PclntabVersion::Go116, None));
        assert!(md.is_some());
        assert_eq!(md.unwrap().version, ModuledataVersion::V2);
    }

    #[test]
    fn version_detection_go118_is_v3_with_rodata() {
        // Go 1.18-1.19 (Go118 magic): rodata/gofunc present (V3), but no
        // covctrs. Distinct from the V2 (Go116) layout.
        let data = vec![0u8; 500];
        let md = Moduledata::parse(&data, 8, hints(PclntabVersion::Go118, Some(19)))
            .expect("Go118 moduledata should parse");
        assert_eq!(md.version, ModuledataVersion::V3);
        assert!(md.rodata.is_some(), "Go 1.18+ has rodata");
        assert!(md.gofunc.is_some(), "Go 1.18+ has gofunc");
    }

    #[test]
    fn version_detection_go116_is_v2_no_rodata() {
        let data = vec![0u8; 500];
        let md = Moduledata::parse(&data, 8, hints(PclntabVersion::Go116, Some(16)))
            .expect("Go116 moduledata should parse");
        assert_eq!(md.version, ModuledataVersion::V2);
        assert!(md.rodata.is_none(), "Go 1.16-1.17 has no rodata");
    }

    #[test]
    fn version_detection_go120_minor_22() {
        let data = vec![0u8; 500];
        let md = Moduledata::parse(&data, 8, hints(PclntabVersion::Go120, Some(22)));
        assert!(md.is_some());
        assert_eq!(md.unwrap().version, ModuledataVersion::V3);
    }

    #[test]
    fn version_detection_go120_minor_25_is_v3_no_epclntab() {
        // Go 1.24 / 1.25 have NO epclntab field -> V3 layout, not V4.
        let data = vec![0u8; 500];
        let md = Moduledata::parse(&data, 8, hints(PclntabVersion::Go120, Some(25)));
        assert!(md.is_some());
        assert_eq!(md.unwrap().version, ModuledataVersion::V3);
    }

    #[test]
    fn version_detection_go120_minor_26_is_v4() {
        // epclntab was added in Go 1.26 -> V4.
        let data = vec![0u8; 500];
        let md = Moduledata::parse(&data, 8, hints(PclntabVersion::Go120, Some(26)));
        assert!(md.is_some());
        assert_eq!(md.unwrap().version, ModuledataVersion::V4);
    }

    #[test]
    fn version_detection_go120_minor_27_v5() {
        // minor > 26 and no typelink section -> V5 (Go 1.27+).
        let data = synthetic_v5();
        let md = Moduledata::parse(&data, 8, hints(PclntabVersion::Go120, Some(27)))
            .expect("V5 moduledata should parse");
        assert_eq!(md.version, ModuledataVersion::V5);
        assert_eq!(md.typedesclen, Some(0x1000));
        assert_eq!(md.itaboffset, Some(0x1f000));
        assert_eq!(md.itabsize, Some(0x400));
        assert!(md.typelinks.is_none());
        assert!(md.itablinks.is_none());
        // rodata/gofunc are still present in V5 (regression guard against
        // the old speculative branch that hardcoded them to None).
        assert_eq!(md.rodata, Some(0x490000));
        assert_eq!(md.gofunc, Some(0x4f0000));
        assert_eq!(md.epclntab, Some(0x4ffff0));
    }

    #[test]
    fn v4_falls_back_to_typelinks_not_v5() {
        // minor 27 but a typelink section is present -> stay on V4 layout.
        let data = vec![0u8; 600];
        let md = Moduledata::parse(
            &data,
            8,
            LayoutHints {
                pclntab_version: PclntabVersion::Go120,
                go_minor: Some(27),
                has_typelink_section: true,
                has_go_type_section: false,
            },
        )
        .expect("should parse");
        assert_eq!(md.version, ModuledataVersion::V4);
    }

    #[test]
    fn pre_v5_layout_survives_a_missing_version_string() {
        // Regression guard: PE binaries never carry a `.typelink` section, so
        // for a version-scrubbed PE the only hint points at V5. Reading a
        // pre-V5 moduledata with the V5 layout collapses the types span while
        // leaving a huge `typedesclen`, which the consistency check rejects -
        // so the parser must fall back to V3 rather than return the garbage.
        let data = synthetic_v3();
        let md = Moduledata::parse(&data, 8, hints(PclntabVersion::Go120, None))
            .expect("V3 moduledata should parse");
        assert_eq!(md.version, ModuledataVersion::V3);
        assert_eq!(md.types, 0x4a2000);
        assert_eq!(md.etypes, 0x4d9000);
        assert_eq!(md.rodata, Some(0x4a2000));
        assert_eq!(md.gofunc, Some(0x55c000));
        assert!(md.typedesclen.is_none());
        assert!(md.itaboffset.is_none());
    }

    #[test]
    fn v5_layout_wins_without_a_version_string() {
        // The mirror case: a genuine V5 moduledata read as V3/V4 puts
        // `typedesclen` where `etypes` belongs, leaving `etypes < types`. The
        // consistency check rejects that, so V5 is chosen even though no
        // version string is available.
        let data = synthetic_v5();
        let md = Moduledata::parse(&data, 8, hints(PclntabVersion::Go120, None))
            .expect("V5 moduledata should parse");
        assert_eq!(md.version, ModuledataVersion::V5);
        assert_eq!(md.itaboffset, Some(0x1f000));
    }

    #[test]
    fn go_type_section_selects_v5_despite_a_stale_typelink_section() {
        // `.go.type` only exists from Go 1.27, so it outranks the weak
        // "a typelink section is present" signal.
        let data = synthetic_v5();
        let md = Moduledata::parse(
            &data,
            8,
            LayoutHints {
                pclntab_version: PclntabVersion::Go120,
                go_minor: None,
                has_typelink_section: true,
                has_go_type_section: true,
            },
        )
        .expect("V5 moduledata should parse");
        assert_eq!(md.version, ModuledataVersion::V5);
    }

    #[test]
    fn v5_is_never_chosen_below_the_go120_magic() {
        // V5 requires covctrs, which the Go118 magic rules out - so even with
        // every V5 hint set the layout must stay pre-V5.
        let data = synthetic_v5();
        let md = Moduledata::parse(
            &data,
            8,
            LayoutHints {
                pclntab_version: PclntabVersion::Go118,
                go_minor: None,
                has_typelink_section: false,
                has_go_type_section: true,
            },
        )
        .expect("should parse");
        assert_ne!(md.version, ModuledataVersion::V5);
    }

    #[test]
    fn inconsistent_layouts_fall_back_to_the_preferred_hint() {
        // When neither candidate validates (truncated / garbage tail), the
        // hint-preferred layout is returned so callers still get the head
        // fields rather than nothing at all.
        let mut data = synthetic_v5();
        // Break both layouts: types above etypes with a nonsensical span.
        put(&mut data, v5_off::TYPES, 0x900000);
        put(&mut data, v5_off::ETYPES, 0x100000);
        let md = Moduledata::parse(&data, 8, hints(PclntabVersion::Go120, Some(27)))
            .expect("should still parse");
        assert_eq!(md.version, ModuledataVersion::V5);
        assert_eq!(md.minpc, 0);
    }

    #[test]
    fn go12_legacy_parses_v1() {
        // Minimal legacy (Go 1.5-1.15) moduledata head: pclntable slice, then
        // ftab/filetab/findfunctab/minpc/maxpc, text/etext, four data ranges,
        // end/gcdata/gcbss, types/etypes. The tail is read best-effort.
        let mut data = vec![0u8; 512];
        // pclntable slice @0 (ptr, len, cap).
        put(&mut data, 0, 0x5000);
        put(&mut data, 8, 0x100);
        put(&mut data, 16, 0x100);
        put(&mut data, 80, 0x1000); // minpc
        put(&mut data, 88, 0x2000); // maxpc
        put(&mut data, 96, 0x1000); // text
        put(&mut data, 104, 0x2000); // etext
        put(&mut data, 200, 0x9000); // types
        put(&mut data, 208, 0xa000); // etypes

        let md = Moduledata::parse(&data, 8, hints(PclntabVersion::Go12, Some(10)))
            .expect("legacy moduledata should parse");
        assert_eq!(md.version, ModuledataVersion::V1);
        assert_eq!(md.pclntable.ptr, 0x5000);
        assert_eq!(md.minpc, 0x1000);
        assert_eq!(md.maxpc, 0x2000);
        assert_eq!(md.text, 0x1000);
        assert_eq!(md.etext, 0x2000);
        assert_eq!(md.types, 0x9000);
        assert_eq!(md.etypes, 0xa000);
        // Modern-only fields are absent in the legacy layout.
        assert!(md.rodata.is_none());
        assert!(md.gofunc.is_none());
        assert_eq!(md.funcnametab.ptr, 0);
    }

    #[test]
    fn too_short_returns_none() {
        let data = vec![0u8; 10];
        assert!(Moduledata::parse(&data, 8, hints(PclntabVersion::Go120, Some(25))).is_none());
    }
}
