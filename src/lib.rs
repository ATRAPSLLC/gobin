//! # gobin: Go Binary Reverse Engineering Library
//!
//! A pure-Rust library for statically analyzing compiled Go binaries. Given an arbitrary
//! byte slice, `gobin` can determine whether it was produced by the Go toolchain and
//! extract rich metadata that the Go runtime embeds in every binary.
//!
//! ## Motivation
//!
//! Go binaries are unusually rich targets for static analysis. Unlike C/C++ binaries,
//! stripped Go binaries still contain:
//!
//! - **Full function names** (package-qualified, e.g. `net/http.(*Client).Do`)
//! - **Source file paths** (the full path used at compile time)
//! - **Go version** and **module dependency** information
//! - **Type descriptors** for every type used in the program
//!
//! This metadata survives stripping (`-ldflags="-s -w"`) because the Go runtime requires
//! it for stack traces, garbage collection, and interface dispatch. These structures are
//! defined in the Go source tree under `src/runtime/` and `src/internal/abi/`.
//!
//! ## Quick Start
//!
//! ```no_run
//! use gobin::GoBinary;
//!
//! let data = std::fs::read("some_binary").unwrap();
//! if let Some(bin) = GoBinary::parse(&data) {
//!     println!("Go version: {:?}", bin.go_version());
//!     for f in bin.functions() {
//!         println!("  {}", f.name);
//!     }
//! }
//! ```
//!
//! ## Supported Formats
//!
//! | Format | Detection | Build ID            | Build Info | pclntab | Functions |
//! |--------|-----------|---------------------|------------|---------|-----------|
//! | ELF    | Yes       | ELF note + raw      | Yes        | Yes     | Yes       |
//! | Mach-O | Yes       | Raw marker          | Yes        | Yes     | Yes       |
//! | PE     | Yes       | Raw marker          | Yes        | Yes     | Yes       |
//! | Wasm   | Yes       | `go:buildid` section| Version only | Yes   | Yes       |
//!
//! Wasm support reconstructs a single linear-memory image from the wasm
//! Data section's individual segments so runtime structures (pclntab,
//! moduledata, type descriptors) that span multiple disjoint segments can
//! be addressed by their linear-memory VA - see
//! [`structures::wasm`] and the [`BinaryFormat::Wasm`]
//! variant rustdoc for details.
//!
//! ## Architecture
//!
//! The crate is organized into two API layers:
//!
//! - **Low-level**: [`formats::BinaryContext`] parses the binary format once and provides
//!   zero-copy section slicing, VA translation, and ELF note access. Individual structure
//!   parsers ([`structures::pclntab`], [`structures::buildid`], etc.) take `&BinaryContext`.
//! - **High-level**: [`GoBinary`] wraps `BinaryContext` and performs the full Go metadata
//!   extraction pipeline, exposing comfortable accessors for functions, types, build info, etc.

// The `missing_docs`, `clippy::unwrap_used`, `clippy::expect_used`,
// `clippy::panic`, `clippy::arithmetic_side_effects`, and
// `clippy::indexing_slicing` lints are declared in `Cargo.toml` under
// `[lints]` so they enforce on every build regardless of the consuming
// workspace. gobin is used in malware-analysis pipelines where every
// input byte is adversarial and the parser must not panic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]

pub mod detection;
pub mod formats;
pub mod metadata;
mod names;
pub mod structures;
mod symbols;
mod util;

pub use symbols::{Symbol, SymbolKind, Symbols};

use crate::{
    detection::{
        Confidence, ConfidenceReport, ConfidenceSignal, LayoutEvidence, ParseError, VersionSource,
        heuristic_hits,
    },
    formats::{BinaryContext, BinaryFormat},
    metadata::{
        BuildInfo, Compiler, FipsInfo, FunctionInfo, FunctionIter, InitFunc, InitTask,
        ObfuscationKind,
    },
    structures::{
        Arch, PclntabVersion,
        bounds::BoundWord,
        buildid::{self, BuildId, BuildIdSource},
        buildinfo, coverage, embed, funcdata, gcprog,
        goslice::{GoSlice, GoStr},
        inittask, inline, itab,
        locate::{LocatedModuledata, ModuledataLocator},
        moduledata::{
            self, LayoutHints, ModuleHash, Moduledata, ModuledataVersion, PtabEntry, TextSect,
        },
        name::decode_name,
        pclntab::{self, LegacyFuncLayout, ParsedPclntab, PclntabMeta},
        strings as gostrings, types, wasm,
    },
    util::{find_bytes, read_i32, read_uintptr},
};

/// A parsed Go binary with all extractable metadata.
///
/// Created via [`GoBinary::parse`], which performs a multi-layered analysis:
///
/// 1. **Binary context** -- Parses the executable format once (via `goblin`),
///    collecting section locations, VA mappings, and ELF notes.
/// 2. **Section discovery** -- `.gopclntab`, `.go.buildinfo`, `.note.go.buildid`, etc.
/// 3. **Magic byte scanning** -- build ID prefix, build info header, pclntab magic
/// 4. **Structure parsing** -- pcHeader, functab, _func structs, build info blobs
/// 5. **Heuristic fallback** -- runtime string patterns for heavily patched binaries
///
/// The lifetime `'a` ties all extracted string references back to the original byte slice,
/// enabling zero-copy access to function names and source file paths.
pub struct GoBinary<'a> {
    report: ConfidenceReport,
    ctx: BinaryContext<'a>,
    build_id: Option<BuildId<'a>>,
    build_info: Option<BuildInfo<'a>>,
    /// Cached pclntab scalars. The borrowing [`ParsedPclntab`] view is
    /// reconstructed on demand via [`Self::pclntab`] so it can borrow from
    /// `&self.ctx` - important for wasm, where the address space pclntab
    /// lives in is the linear-memory image owned by the context (and is
    /// therefore not borrowable with the input lifetime `'a`).
    pclntab_meta: Option<PclntabMeta>,
    go_version: Option<&'a str>,
    moduledata: Option<Moduledata>,
    /// Offset of [`Self::moduledata`] in the address-space view
    /// ([`BinaryContext::structure_search_data`]).
    moduledata_offset: Option<usize>,
    /// Whether a text offset names a function by its index rather than by
    /// its PC offset: wasm from Go 1.25 on (see [`indexed_text_offsets`]).
    indexed_text_offsets: bool,
    /// Where this binary's itab records put their fields (see
    /// [`choose_itab_layout`]).
    itab_layout: itab::ItabLayout,
    /// The Go minor versions the binary's tables can be from (see
    /// [`minor_range`]).
    minor_range: Option<MinorRange>,
    /// `moduledata.textsectmap`, decoded once: every text address and offset
    /// consults it.
    text_sections: Vec<TextSect>,
}

impl<'a> GoBinary<'a> {
    /// Analyze a byte slice and return a [`GoBinary`] if it appears to be a Go binary.
    ///
    /// Returns `None` if no Go-specific indicators are found. The detection uses
    /// multiple independent signals so that even binaries with some markers patched
    /// out can still be identified (at a lower [`Confidence`] level).
    ///
    /// # Detection Order
    ///
    /// 1. Section names (`.gopclntab`, `.go.buildinfo`, `.note.go.buildid`)
    /// 2. Build ID raw marker (`\xff Go build ID: "..."`)
    /// 3. Build info header (`\xff Go buildinf:`)
    /// 4. pclntab magic bytes (`0xfffffff1` etc.)
    /// 5. Heuristic string patterns (`runtime.main`, `runtime.goexit`, etc.)
    ///
    /// # Working with mmap-ed input
    ///
    /// `parse` borrows the input for the lifetime of the returned [`GoBinary`].
    /// Any byte slice works - including one backed by `memmap2::Mmap` -
    /// regardless of source. There is no separate mmap-specific entry point;
    /// just pass `&mmap[..]`.
    ///
    /// Convenience wrapper around [`Self::try_parse`] that discards the
    /// [`ParseError`] detail. Use `try_parse` if you need the structured
    /// detection report on failure (for diagnostics or analyst-facing output).
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        Self::try_parse(data).ok()
    }

    /// Like [`Self::parse`], but returns a structured [`ParseError`] on failure
    /// containing the [`ConfidenceReport`] gathered during detection.
    ///
    /// Detection signals are also retained on success, accessible via
    /// [`Self::report`] - useful for surfacing analyst-facing diagnostics
    /// (e.g. "Go binary, but pclntab missing - likely heavily patched").
    pub fn try_parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if let Some(slices) = formats::macho_slices(data) {
            return Err(ParseError::Universal { slices });
        }
        let ctx = BinaryContext::new(data);
        let mut report = ConfidenceReport::empty();

        let sections = ctx.sections();
        if sections.has_gopclntab {
            report.push(ConfidenceSignal::GopclntabSectionPresent);
            report.raise_to(Confidence::High);
        }
        if sections.has_go_buildinfo {
            report.push(ConfidenceSignal::BuildinfoSectionPresent);
            report.raise_to(Confidence::High);
        }
        if sections.has_go_buildid_note {
            report.push(ConfidenceSignal::BuildidNotePresent);
            report.raise_to(Confidence::High);
        }
        // Type-metadata sections. `.typelink` / `.itablink` are the Go ≤1.26
        // spelling; Go 1.27 replaced both with `.go.type` / `.go.func`. All
        // four names are Go-linker-specific, so each is structural proof.
        for (present, section) in [
            (sections.typelink.is_some(), ".typelink"),
            (sections.itablink.is_some(), ".itablink"),
            (sections.go_type.is_some(), ".go.type"),
            (sections.go_func.is_some(), ".go.func"),
        ] {
            if present {
                report.push(ConfidenceSignal::TypeSectionPresent { section });
                report.raise_to(Confidence::High);
            }
        }

        let build_id = buildid::extract(&ctx);
        if build_id.is_some() {
            report.push(ConfidenceSignal::BuildIdMarkerFound);
            report.raise_to(Confidence::High);
        }

        let build_info_result = buildinfo::extract(&ctx);
        match build_info_result.as_ref() {
            Some(_) => {
                report.push(ConfidenceSignal::BuildinfoParsed);
                report.raise_to(Confidence::Medium);
            }
            None => {
                report.push(ConfidenceSignal::BuildinfoMissing {
                    reason: "no buildinfo magic header found",
                });
            }
        }

        let pclntab_meta = pclntab::parse(&ctx).as_ref().map(ParsedPclntab::meta);
        match pclntab_meta {
            Some(m) => {
                report.push(ConfidenceSignal::PclntabParsed {
                    version: m.version,
                    nfunc: m.nfunc,
                });
                report.raise_to(Confidence::High);
            }
            None => {
                report.push(ConfidenceSignal::PclntabMissing {
                    reason: "no pclntab magic / structural pattern matched",
                });
            }
        }

        let (go_version, version_source): (Option<&'a str>, VersionSource) =
            match build_info_result.as_ref().and_then(|bi| bi.go_version) {
                Some(v) => (Some(v), VersionSource::BuildInfoBlob),
                None => match wasm::go_producer_version(data) {
                    Some(v) => (Some(v), VersionSource::WasmProducers),
                    None => (
                        buildinfo::find_version_string(data),
                        VersionSource::StringScan,
                    ),
                },
            };
        if go_version.is_some() {
            report.push(ConfidenceSignal::GoVersionString {
                source: version_source,
            });
            report.raise_to(Confidence::Medium);
        }

        if report.tier == Confidence::None {
            let hits = heuristic_hits(data);
            if hits >= 3 {
                report.push(ConfidenceSignal::HeuristicStringsMatched { hits });
                report.raise_to(Confidence::Low);
            }
        }

        if report.tier == Confidence::None {
            return Err(ParseError::NotAGoBinary { report });
        }

        let located = pclntab_meta.and_then(|meta| {
            let pcl = meta.attach(ctx.structure_search_data())?;
            find_moduledata(&ctx, &pcl, go_version)
        });
        let moduledata_offset = located.as_ref().map(|found| found.offset);
        let located_source = located
            .as_ref()
            .map(|found| (found.moduledata.version, found.source));
        let moduledata = located.map(|found| found.moduledata);
        let indexed_text_offsets = indexed_text_offsets(&ctx, pclntab_meta);
        let minor_range = minor_range(go_version, pclntab_meta.as_ref(), moduledata.as_ref());
        let itab_layout = choose_itab_layout(&ctx, pclntab_meta, minor_range, moduledata.as_ref());
        let pclntab_meta = pclntab_meta.map(|meta| PclntabMeta {
            inline_index_pcdata: minor_range
                .and_then(|range| range.decide(|m| funcdata::PcDataKind::InlTreeIndex.index(m)))
                .flatten(),
            ..meta
        });

        match located_source {
            Some((version, source)) => {
                report.push(ConfidenceSignal::ModuledataLocated { version, source });
            }
            None => report.push(ConfidenceSignal::ModuledataMissing),
        }
        match (ctx.format(), ctx.has_symbols()) {
            (BinaryFormat::Wasm | BinaryFormat::Unknown, _) => {}
            (_, false) => report.push(ConfidenceSignal::SymbolTableStripped),
            (_, true) => report.push(ConfidenceSignal::SymbolTable),
        }

        let mut bin = GoBinary {
            report,
            ctx,
            build_id,
            build_info: build_info_result,
            pclntab_meta,
            go_version,
            moduledata,
            moduledata_offset,
            indexed_text_offsets,
            itab_layout,
            minor_range,
            text_sections: Vec::new(),
        };
        bin.text_sections = bin.decode_text_sections();
        let layouts = ConfidenceSignal::LayoutsChosen {
            itab: bin.itab_layout,
            map: bin.map_layout(),
            text_offsets_indexed: bin.indexed_text_offsets,
            decided_by: if go_version.and_then(parse_go_minor_version).is_some() {
                LayoutEvidence::VersionString
            } else {
                LayoutEvidence::Structure
            },
        };
        bin.report.push(layouts);
        Ok(bin)
    }

    /// The raw byte slice this analysis was built from.
    pub fn data(&self) -> &'a [u8] {
        self.ctx.data()
    }

    /// The low-level binary context providing section data and VA translation.
    pub fn context(&self) -> &BinaryContext<'a> {
        &self.ctx
    }

    /// How confident the library is that this is a Go binary.
    pub fn confidence(&self) -> Confidence {
        self.report.tier
    }

    /// Structured detection report - the confidence tier plus every signal
    /// observed during parse.
    ///
    /// Useful for analyst-facing diagnostics ("Go binary, but pclntab is
    /// missing - likely heavily patched") and for surfacing details in bug
    /// reports.
    pub fn report(&self) -> &ConfidenceReport {
        &self.report
    }

    /// The Go toolchain version, e.g. `"go1.26.1"`.
    ///
    /// Extracted from the build info blob or by scanning for `"go1."` string patterns.
    pub fn go_version(&self) -> Option<&'a str> {
        self.go_version
    }

    /// The `GOEXPERIMENT` experiments the toolchain was built or run with
    /// that differ from its defaults, as Go records them after its version
    /// (`go1.28 X:arenas,nogreenteagc`): an experiment turned on by name, one
    /// turned off by `no` and its name. Empty when the build changed none.
    ///
    /// Read from the version the build info records, or without build info
    /// from the runtime's own copy of its version string.
    pub fn go_experiments(&self) -> Vec<&'a str> {
        let list = match self.build_info.as_ref() {
            Some(info) => info.go_version.and_then(buildinfo::version_experiments),
            None => buildinfo::find_version_experiments(self.ctx.data()),
        };
        list.map_or_else(Vec::new, |list| list.split(',').collect())
    }

    /// Where the binary was built, read off the source paths its pclntab
    /// records: GOROOT, the module cache, GOPATH, the main package's
    /// directory and the home directory they are under. Empty for a build
    /// with `-trimpath`, which records paths relative.
    ///
    /// Each root follows from where a package's import path places its
    /// files, so no layout is assumed: the runtime under `<goroot>/src/`, a
    /// module under `<cache>/<module>@<version>/`, a GOPATH-mode package
    /// under `<gopath>/src/`.
    pub fn build_paths(&self) -> metadata::BuildPaths<'_> {
        let Some(pcl) = self.pclntab() else {
            return metadata::BuildPaths::default();
        };
        // Each function's entry file. A function's name does not always place
        // it (a linknamed `runtime.cmpstring` is in `internal/bytealg`, a
        // generated one has no file of its own), so every function is offered
        // and the roots are read off those whose file sits where their
        // package's import path puts it.
        let files = self.function_records().filter_map(|(name, func)| {
            let (_, index) = pcl.decode_pcfile(&func).next()?;
            Some((
                names::package_of(name)?,
                pcl.resolve_file_index(func.cu_offset, index)?,
            ))
        });
        metadata::BuildPaths::from_files(files)
    }

    /// The container's symbol table (ELF `.symtab`, Mach-O `LC_SYMTAB`, PE
    /// COFF symbols): the functions and globals the Go linker named, with
    /// their addresses and sizes. Empty for a stripped (`-ldflags=-s`)
    /// binary and for wasm. Read on each call; keep the result to look up
    /// many addresses ([`symbols::Symbols::at`]).
    pub fn symbols(&self) -> symbols::Symbols<'a> {
        symbols::Symbols::read(self.ctx.data(), self.ctx.format())
    }

    /// The coverage metadata of a `-cover` build (Go 1.20+): each
    /// instrumented package with its functions and their coverable units
    /// ([`structures::coverage`]). Read from the blobs the symbol table names
    /// (`<pkg>.goCover_<id>_M`), so empty for a stripped binary; there,
    /// decode each blob from the address its package's registration call
    /// passes ([`Self::coverage_meta_at`]).
    pub fn coverage(&self) -> Vec<coverage::CoveragePackage<'_>> {
        if !self.is_coverage_build() {
            return Vec::new();
        }
        self.symbols()
            .iter()
            .filter(|s| s.name.contains(".goCover_") && s.name.ends_with("_M"))
            .filter_map(|s| self.coverage_meta_at(s.va))
            .collect()
    }

    /// The coverage metadata blob at `va`: the first argument of a
    /// `runtime.addCovMeta` call ([`metadata::HookKind::CoverageRegistration`]),
    /// for a disassembler working on a stripped `-cover` build. The result's
    /// `length` and `hash` equal the call's second and third arguments when
    /// `va` is right. `None` unless a well-formed blob starts at `va`.
    pub fn coverage_meta_at(&self, va: u64) -> Option<coverage::CoveragePackage<'_>> {
        coverage::CoveragePackage::parse(self.ctx.slice_at_va(va)?)
    }

    /// The Go build ID.
    ///
    /// For executables this is a 4-part string: `actionID/actionID/contentID/contentID`,
    /// where each part is 20 characters of URL-safe base64 derived from SHA256 hashes.
    ///
    /// See [`structures::buildid`] for format details.
    pub fn build_id(&self) -> Option<&'a str> {
        self.build_id.as_ref().map(|build_id| build_id.id)
    }

    /// Where the binary records its build ID ([`Self::build_id`]): the Go
    /// build ID note on ELF, or a marker blob elsewhere, the `go:buildid`
    /// symbol at or near the start of the text on Mach-O and PE and the
    /// `go:buildid` custom section of a wasm module. A
    /// [`BuildIdSource::Marker`]'s `blob` is its file-offset extent, from the
    /// first byte of `\xff Go build ID: "` through the last of `"\n \xff`; it
    /// indexes [`BinaryContext::data`], and [`BinaryContext::file_to_va`] maps
    /// it to the address space where the blob is loaded (a wasm custom section
    /// is not).
    pub fn build_id_source(&self) -> Option<&BuildIdSource> {
        self.build_id.as_ref().map(|build_id| &build_id.source)
    }

    /// Build metadata including module path, dependencies, and build settings.
    ///
    /// Contains GOOS, GOARCH, CGO_ENABLED, VCS info, and the full dependency list.
    /// See [`BuildInfo`] for accessor methods.
    pub fn build_info(&self) -> Option<&BuildInfo<'a>> {
        self.build_info.as_ref()
    }

    /// The parsed pclntab, if found. Provides zero-copy access to function names,
    /// source files, architecture, pointer size, and all other pclntab metadata.
    ///
    /// Returned by value because the borrowing struct is rehydrated on each
    /// call from cached metadata; the borrow inside it is tied to `&self`.
    /// Callers that need to hold pclntab state across many calls should hold
    /// `&self` (i.e. the [`GoBinary`]) for the duration; the rebuild itself
    /// is just a struct construction (no I/O, no parsing).
    pub fn pclntab(&self) -> Option<ParsedPclntab<'_>> {
        self.pclntab_meta?.attach(self.ctx.structure_search_data())
    }

    /// Streaming iterator over every function recovered from the pclntab.
    ///
    /// Yields zero items if the binary has no recoverable pclntab.
    ///
    /// For bulk per-function processing where you also need decoded pcsp /
    /// pcln / pcfile tables, use [`crate::metadata::for_each_function`]
    /// instead - it amortizes table-decode buffers across the whole walk.
    pub fn functions(&self) -> FunctionIter<'_> {
        FunctionIter::new(self.pclntab())
    }

    /// Streaming iterator over the per-PC inlining tree for a function (Go
    /// 1.9+).
    ///
    /// Yields one [`inline::InlineEntry`] per PC range during which an inlined
    /// frame is active. PC ranges with no inlining are skipped silently.
    /// Empty when the function has no inlined calls, its Go version predates
    /// the tree, or the binary has no recoverable pclntab. Each record is read
    /// in its Go version's shape ([`inline::InlinedCallFormat`]).
    ///
    /// Source: `src/runtime/symtabinl.go` (`inlineUnwinder`).
    pub fn inline_tree(&self, func: &FunctionInfo<'_>) -> inline::InlineTreeIter<'_> {
        let (Some(pcl), Some(blob), Some(index)) = (
            self.pclntab(),
            self.funcdata_block(func, funcdata::FuncDataKind::InlTree),
            self.pcdata(func, funcdata::PcDataKind::InlTreeIndex),
        ) else {
            return inline::InlineTreeIter::empty();
        };
        let format = match pcl.version {
            PclntabVersion::Go12 => match pcl.legacy_func {
                Some(LegacyFuncLayout::DeferReturn) => inline::InlinedCallFormat::Go112,
                _ => inline::InlinedCallFormat::Go19,
            },
            PclntabVersion::Go116 | PclntabVersion::Go118 => inline::InlinedCallFormat::Go112,
            PclntabVersion::Go120 => inline::InlinedCallFormat::Go120,
        };
        inline::InlineTreeIter::new(pcl, func.func, format, blob, index.collect())
    }

    /// The function whose code holds address `pc`: the one a stack trace
    /// would name for it, as the runtime's `findfunc` finds it.
    ///
    /// `pc` may be a function's entry or any address inside it (a return
    /// address, a resume point on wasm). `None` when `pc` lies outside the
    /// Go code or the binary has no recoverable pclntab.
    pub fn function_at(&self, pc: u64) -> Option<FunctionInfo<'_>> {
        let off = self.text_off(pc)?;
        let pcl = self.pclntab()?;
        let (_, func_off) = pcl.func_containing(off)?;
        let func = pcl.parse_func(func_off)?;
        Some(FunctionInfo::from_func(&pcl, func))
    }

    /// The address of `func`'s `kind` data block (`runtime.funcdata`), or
    /// `None` when the function has none or the binary's Go version has no
    /// such kind ([`funcdata::FuncDataKind::index`]).
    ///
    /// Go 1.18+ records a `u32` offset from `moduledata.gofunc` (`^0` for
    /// none); through Go 1.17 a pointer, in a slot aligned to 8 bytes on
    /// 64-bit targets (zero for none).
    pub fn funcdata(&self, func: &FunctionInfo<'_>, kind: funcdata::FuncDataKind) -> Option<u64> {
        let index = self.minor_range?.decide(|m| kind.index(m))??;
        if index >= func.func.nfuncdata {
            return None;
        }
        let pcl = self.pclntab()?;
        match pcl.version {
            PclntabVersion::Go118 | PclntabVersion::Go120 => {
                let off = pcl.funcdata_at(&func.func, index)?;
                if off == u32::MAX {
                    return None;
                }
                self.moduledata
                    .as_ref()?
                    .gofunc?
                    .checked_add(u64::from(off))
            }
            PclntabVersion::Go12 | PclntabVersion::Go116 => {
                let ps = pcl.ptr_size;
                let mut slot = pcl.offset.checked_add(pcl.funcdata_slots(&func.func)?)?;
                let slot_va = self.ctx.view_to_va(slot)?;
                if ps == 8 && slot_va & 4 != 0 {
                    slot = slot.checked_add(4)?;
                }
                let at = slot.checked_add(usize::from(index).checked_mul(usize::from(ps))?)?;
                let va = read_uintptr(self.ctx.structure_search_data(), at, ps)?;
                (va != 0).then_some(va)
            }
        }
    }

    /// The bytes from `func`'s `kind` data block onward ([`Self::funcdata`]).
    fn funcdata_block(
        &self,
        func: &FunctionInfo<'_>,
        kind: funcdata::FuncDataKind,
    ) -> Option<&[u8]> {
        self.ctx.slice_at_va(self.funcdata(func, kind)?)
    }

    /// `func`'s `kind` per-PC table (`runtime.pcdatavalue`): `(pc_end,
    /// value)` steps from the function's entry, as [`ParsedPclntab::decode_pcvalue`]
    /// yields them. `None` when the function has none or the binary's Go
    /// version has no such kind ([`funcdata::PcDataKind::index`]).
    pub fn pcdata(
        &self,
        func: &FunctionInfo<'_>,
        kind: funcdata::PcDataKind,
    ) -> Option<pclntab::PcValueIter<'_>> {
        let index = self.minor_range?.decide(|m| kind.index(m))??;
        let pcl = self.pclntab()?;
        let table = pcl.pcdata_at(&func.func, index)?;
        (table != 0).then(|| pcl.decode_pcvalue(table))
    }

    /// For a wrapper, the function it wraps (`FUNCDATA_WrapInfo`, Go 1.18+):
    /// what a method value, interface or `go`-statement wrapper calls, as
    /// the runtime's execution tracer resolves it (`startPCForTrace`).
    pub fn wrapped_function(&self, func: &FunctionInfo<'_>) -> Option<FunctionInfo<'_>> {
        let block = self.funcdata_block(func, funcdata::FuncDataKind::WrapInfo)?;
        let off = funcdata::parse_wrap_info(block)?;
        self.function_at(self.text_addr(off)?)
    }

    /// `func`'s argument layout (`FUNCDATA_ArgInfo`, Go 1.17+): the
    /// arguments a traceback prints, with their offsets and sizes.
    pub fn arg_layout(&self, func: &FunctionInfo<'_>) -> Option<funcdata::ArgLayout> {
        funcdata::ArgLayout::parse(self.funcdata_block(func, funcdata::FuncDataKind::ArgInfo)?)
    }

    /// Where `func`'s open-coded defers keep their state
    /// (`FUNCDATA_OpenCodedDeferInfo`, Go 1.14+), in its Go version's format.
    pub fn open_defers(&self, func: &FunctionInfo<'_>) -> Option<funcdata::OpenDefers> {
        let block = self.funcdata_block(func, funcdata::FuncDataKind::OpenCodedDeferInfo)?;
        // The format is that of the newest version in each of its eras.
        let era = |m: u32| match m {
            ..=17 => 17,
            18..=21 => 21,
            _ => 22,
        };
        funcdata::OpenDefers::parse(block, self.minor_range?.decide(era)?)
    }

    /// `func`'s stack objects (`FUNCDATA_StackObjects`, Go 1.12+): the
    /// addressable locals and arguments its frame holds, with their type
    /// (resolve [`funcdata::StackObject::type_va`] with [`Self::type_at`],
    /// Go 1.12-1.16) or size and pointer layout (Go 1.17+).
    pub fn stack_objects(&self, func: &FunctionInfo<'_>) -> Option<Vec<funcdata::StackObject>> {
        let block = self.funcdata_block(func, funcdata::FuncDataKind::StackObjects)?;
        let ps = self.pclntab_meta?.ptr_size;
        let rodata = self.moduledata.as_ref().and_then(|m| m.rodata);
        let era = |m: u32| match m {
            ..=16 => 16,
            17 => 17,
            _ => 18,
        };
        funcdata::parse_stack_objects(block, ps, self.minor_range?.decide(era)?, rodata)
    }

    /// `func`'s GC pointer maps of its arguments (`kind` =
    /// [`funcdata::FuncDataKind::ArgsPointerMaps`]) or locals
    /// ([`funcdata::FuncDataKind::LocalsPointerMaps`]), borrowed from the
    /// binary; [`funcdata::PcDataKind::StackMapIndex`] selects the map in
    /// effect at a PC.
    pub fn pointer_maps(
        &self,
        func: &FunctionInfo<'_>,
        kind: funcdata::FuncDataKind,
    ) -> Option<funcdata::PointerMaps<'_>> {
        if !matches!(
            kind,
            funcdata::FuncDataKind::ArgsPointerMaps | funcdata::FuncDataKind::LocalsPointerMaps
        ) {
            return None;
        }
        let format = self
            .minor_range?
            .decide(funcdata::PointerMapFormat::for_go_minor)?;
        funcdata::PointerMaps::parse(self.funcdata_block(func, kind)?, format)
    }

    /// The parsed moduledata, if discoverable.
    ///
    /// This carries cross-cutting runtime addresses such as the start/end of
    /// the Go-emitted text segment ([`Self::text_va`], [`Self::etext_va`]),
    /// the type-descriptor region, and slice headers for the runtime tables.
    pub fn moduledata(&self) -> Option<&Moduledata> {
        self.moduledata.as_ref()
    }

    /// All modules in the `moduledata` linked list, starting from the first.
    ///
    /// The runtime links one `moduledata` per loaded module (the main binary
    /// plus any plugins / shared libraries) via the `next` field. **That field
    /// is populated at load time**, so in a static on-disk binary it is almost
    /// always nil and this returns a single entry - the chain is followed
    /// defensively (with a cycle guard) for the rare multi-module image and so
    /// plugin/shared objects analyzed on their own parse correctly. Empty if
    /// the binary has no locatable moduledata.
    pub fn modules(&self) -> Vec<Moduledata> {
        const MAX_MODULES: usize = 1024;
        let mut out = Vec::new();
        let first = match self.moduledata.clone() {
            Some(m) => m,
            None => return out,
        };
        let mut next_va = first.next;
        let mut seen: Vec<u64> = vec![first.pc_header];
        out.push(first);
        while next_va != 0 && out.len() < MAX_MODULES {
            if seen.contains(&next_va) {
                break; // cycle guard
            }
            seen.push(next_va);
            let md = match self.parse_moduledata_at(next_va) {
                Some(m) => m,
                None => break,
            };
            next_va = md.next;
            out.push(md);
        }
        out
    }

    /// Parse a `moduledata` located at virtual address `va` (used to follow the
    /// `next` chain), reusing this binary's pclntab version and Go version.
    fn parse_moduledata_at(&self, va: u64) -> Option<Moduledata> {
        let meta = self.pclntab_meta?;
        let bytes = self.ctx.slice_at_va(va)?;
        let hints = layout_hints(&self.ctx, meta.version, self.go_version);
        Moduledata::parse(bytes, meta.ptr_size, hints)
    }

    /// Virtual address of `runtime.text` - the first byte of Go-emitted code.
    ///
    /// A function's `entry_off` (in [`FunctionInfo::func`]) is measured
    /// relative to this address.
    /// In most cases callers should reach for [`Self::entry_va`] /
    /// [`Self::entry_rva`] instead, which fold both the `text_va` lookup and
    /// the (PE-only) image-base translation into one accessor.
    ///
    /// # Fallbacks
    ///
    /// Legacy (Go 1.2-1.15) binaries are parsed without a moduledata, and a
    /// heavily-stripped modern binary may also lack one, so three sources are
    /// tried in decreasing order of authority:
    ///
    /// 1. `moduledata.text`.
    /// 2. The pclntab's own record of `runtime.text` - the pcHeader
    ///    `textStart` field on Go 1.18-1.25, or the lowest absolute function
    ///    PC on Go 1.2-1.17 (both surface as `header_text_start` /
    ///    `text_start`).
    /// 3. The base of the executable text section. Go 1.26 stopped writing
    ///    `textStart` into the pcHeader, which leaves a moduledata-less 1.26+
    ///    binary with no recorded value at all; the Go linker places
    ///    `runtime.text` at the start of `.text` / `__text` on every format,
    ///    so the section header supplies it.
    ///
    /// Returns `None` rather than `0` when nothing is available - a bogus
    /// `Some(0)` would silently turn every [`Self::entry_va`] into a raw
    /// `entry_off`.
    pub fn text_va(&self) -> Option<u64> {
        if let Some(m) = self.moduledata.as_ref() {
            return Some(m.text);
        }
        if let Some(pcl) = self.pclntab() {
            if let Some(va) = pcl.header_text_start {
                return Some(va);
            }
            // Go 1.16-1.17 store absolute PCs in the functab; the parser keeps
            // the lowest one here to rebase `entry_off`, which makes it
            // `runtime.text`.
            if pcl.text_start != 0 {
                return Some(pcl.text_start);
            }
        }
        self.ctx
            .sections()
            .text_section
            .map(|s| s.va)
            .filter(|&va| va != 0)
    }

    /// The address of the code at text offset `off`: what the runtime's
    /// `moduledata.textAddr` computes.
    ///
    /// A text offset is how Go's tables name code: a function's `entry_off`,
    /// a method's `ifn`/`tfn`, the entries of the function table. The address
    /// is [`Self::text_va`] plus the offset, with two refinements the runtime
    /// makes:
    ///
    /// - When the linker split the code across several text sections, the
    ///   section that holds `off` places it (`baseaddr + off - vaddr`).
    /// - On wasm from Go 1.25 on, code is not in linear memory and a text
    ///   offset is a function's index while a PC is `text + (index << 16) +
    ///   resume_point`. The result is that PC, the value an itab, a `func`
    ///   value or an init task holds for the function. The runtime computes
    ///   it as `(text + off) << 16` with `text` at `0` in Go 1.25-1.27, and as
    ///   `text + (off << 16)` with `text` at `1 << 63` from Go 1.28, which
    ///   agree. Before Go 1.25 a wasm text offset is a PC offset like any
    ///   other.
    ///
    /// `None` when [`Self::text_va`] is unavailable or the address overflows.
    pub fn text_addr(&self, off: u32) -> Option<u64> {
        moduledata::text_addr(
            self.text_va()?,
            self.split_text_sections(),
            off,
            self.indexed_text_offsets,
        )
    }

    /// The text offset of the code at address `pc`: what the runtime's
    /// `moduledata.textOff` computes, the inverse of [`Self::text_addr`].
    ///
    /// On wasm a PC inside a function (a resume point) yields that function's
    /// offset, as the runtime's does. `None` when [`Self::text_va`] is
    /// unavailable, `pc` lies before the code or in no text section, or the
    /// offset does not fit the 32 bits Go's tables give it.
    pub fn text_off(&self, pc: u64) -> Option<u32> {
        moduledata::text_off(
            self.text_va()?,
            self.split_text_sections(),
            pc,
            self.indexed_text_offsets,
        )
    }

    /// The text sections, when the linker split the code across more than
    /// one: the only case in which a text offset is not simply added to
    /// `runtime.text`. Empty otherwise, without decoding the table.
    fn split_text_sections(&self) -> &[TextSect] {
        match self.moduledata.as_ref() {
            Some(md) if md.textsectmap.len > 1 => &self.text_sections,
            _ => &[],
        }
    }

    /// Binary-level virtual address of a function's entry point: the
    /// [`Self::text_addr`] of its `entry_off`.
    ///
    /// Returns `None` when [`Self::text_va`] is unavailable (binary lacks
    /// moduledata or VA mapping) or the address overflows.
    ///
    /// For ELF and Mach-O this is the address a disassembler will use
    /// directly. For PE this is still a true VA - pass it to
    /// [`Self::entry_rva`] (or subtract [`BinaryContext::image_base`]) to get
    /// the RVA most PE-aware tools expect. For wasm it is the function's
    /// runtime PC, the value code pointers to it hold (see
    /// [`Self::text_addr`]), not a byte position in the Code section.
    pub fn entry_va(&self, func: &FunctionInfo<'_>) -> Option<u64> {
        self.text_addr(func.func.entry_off)
    }

    /// Image-base-relative entry RVA.
    ///
    /// For PE binaries this returns `entry_va − image_base`, the form most PE
    /// disassemblers index by. For ELF and Mach-O the image base is `0`, so
    /// this is identical to [`Self::entry_va`].
    ///
    /// Returns `None` when [`Self::entry_va`] is unavailable or the binary's
    /// `text_va` lies below the recorded image base (corrupt input).
    pub fn entry_rva(&self, func: &FunctionInfo<'_>) -> Option<u64> {
        self.entry_va(func)?.checked_sub(self.ctx.image_base())
    }

    /// Virtual address of `runtime.etext` - one past the last byte of
    /// Go-emitted code.
    ///
    /// `etext_va() - text_va()` gives the total size of all Go-emitted code,
    /// useful as an "amount of Go code in this binary" metric - except on
    /// wasm, where both are PCs (see [`Self::text_addr`]) and the difference
    /// counts functions in units of `1 << 16`.
    pub fn etext_va(&self) -> Option<u64> {
        self.moduledata.as_ref().map(|m| m.etext)
    }

    /// End of the `textsectmap` section that holds the last byte of Go code:
    /// the first address past the section whose range contains
    /// `etext_va() - 1`.
    ///
    /// The section is the one the Go linker laid out, so it may end past
    /// [`Self::etext_va`] where that linker padded it (across the sample
    /// corpus by 1 to 20 bytes from Go 1.21 on, internally and externally
    /// linked alike, and not at all before). A host linker that places C code
    /// after Go's leaves this section where Go put it, so its end need not be
    /// the end of the containing executable section.
    ///
    /// `None` without a moduledata, before Go 1.8 (no `textsectmap`), or when
    /// no section holds that byte.
    pub fn text_section_end_va(&self) -> Option<u64> {
        let etext = self.etext_va()?;
        self.text_sections
            .iter()
            .filter_map(TextSect::va_range)
            .find(|range| range.start < etext && etext <= range.end)
            .map(|range| range.end)
    }

    /// The words of the image that hold a text bound, ascending by address.
    ///
    /// These are the runtime's own statements of where its code begins and
    /// ends, not pointers to functions: the `moduledata` words `minpc`,
    /// `maxpc`, `text` and `etext`, the base address of each `textsectmap`
    /// entry, the `pcHeader.textStart` field (Go 1.18-1.25) and the end
    /// sentinel of a Go 1.2-1.17 function table (see
    /// [`TextBound`](structures::bounds::TextBound)). A tool that collects the
    /// data words holding code addresses can drop these by
    /// [`BoundWord::va`] and keep every other word, including the function
    /// table's own entries: in a Go 1.2-1.17 binary each entry before the
    /// sentinel is the absolute entry PC of a function and stays a legitimate
    /// code pointer; in Go 1.18+ the table holds 32-bit offsets and no
    /// pointers at all.
    ///
    /// Addresses are in the same space as [`Self::text_va`] (for PE the image
    /// base is included). Each word that cannot be placed - no moduledata, no
    /// pclntab, an unmapped offset - is left out, so the list is empty for a
    /// binary whose runtime structures were not found.
    pub fn text_bound_words(&self) -> Vec<BoundWord> {
        let Some(ps) = self.pclntab_meta.map(|meta| meta.ptr_size) else {
            return Vec::new();
        };
        let mut words = Vec::new();
        if let Some(pcl) = self.pclntab()
            && let Some(va) = self.ctx.view_to_va(pcl.offset)
        {
            words.extend(pcl.bound_words(va));
        }
        if let Some(md) = self.moduledata.as_ref()
            && let Some(va) = self
                .moduledata_offset
                .and_then(|offset| self.ctx.view_to_va(offset))
        {
            words.extend(md.bound_words(va, ps, &self.text_sections));
        }
        words.sort_unstable_by_key(|word| word.va);
        words
    }

    /// Whether this module contains the program's `main` - true for the main
    /// executable, false for a plugin / shared library.
    ///
    /// Read from `moduledata.hasmain`. `None` if moduledata is unavailable.
    pub fn is_main_module(&self) -> Option<bool> {
        self.moduledata.as_ref().map(|m| m.has_main)
    }

    /// Pointer map of the initialized data segment (`[data, edata)`) - which
    /// pointer-sized words hold pointers, decoded from the `gcdata` GC program.
    ///
    /// This is the precise location of every pointer in global initialized
    /// memory (function pointers, `itab`/interface pointers, string/slice
    /// headers, global `*T` variables) - recoverable without disassembly.
    /// `None` if moduledata / the GC data is unavailable.
    pub fn data_pointer_map(&self) -> Option<gcprog::PointerMap> {
        let md = self.moduledata.as_ref()?;
        self.pointer_map(md.gcdata, md.data)
    }

    /// Pointer map of the bss segment (`[bss, ebss)`), decoded from the
    /// `gcbss` GC program. See [`Self::data_pointer_map`].
    pub fn bss_pointer_map(&self) -> Option<gcprog::PointerMap> {
        let md = self.moduledata.as_ref()?;
        self.pointer_map(md.gcbss, md.bss)
    }

    /// Decode a GC program at `prog_va` into a [`gcprog::PointerMap`] over
    /// `segment` (`[start, end)`).
    fn pointer_map(
        &self,
        prog_va: u64,
        segment: structures::moduledata::VaRange,
    ) -> Option<gcprog::PointerMap> {
        let ptr_size = self.pclntab_meta.map(|m| m.ptr_size).unwrap_or(0);
        if ptr_size == 0 || prog_va == 0 || segment.is_empty() {
            return None;
        }
        let max_words = usize::try_from(segment.size().checked_div(u64::from(ptr_size))?).ok()?;
        let prog = self.ctx.slice_at_va(prog_va)?;
        let words = gcprog::run_gc_prog(prog, max_words);
        Some(gcprog::PointerMap {
            base_va: segment.start,
            ptr_size,
            words,
        })
    }

    /// The module name (`moduledata.modulename`), set for plugins / shared
    /// libraries. `None` for an ordinary executable (where it is empty) or
    /// when moduledata is unavailable.
    pub fn module_name(&self) -> Option<&str> {
        self.resolve_go_str(self.moduledata.as_ref()?.modulename)
    }

    /// The plugin path (`moduledata.pluginpath`), set only for
    /// `-buildmode=plugin`. `None` otherwise.
    pub fn plugin_path(&self) -> Option<&str> {
        self.resolve_go_str(self.moduledata.as_ref()?.pluginpath)
    }

    /// Whether the binary was built with coverage instrumentation
    /// (`-cover`) - detected via a non-empty `moduledata` coverage-counter
    /// region. Always `false` for Go < 1.20 (the region did not exist).
    pub fn is_coverage_build(&self) -> bool {
        self.moduledata
            .as_ref()
            .and_then(|m| m.covctrs)
            .is_some_and(|r| !r.is_empty())
    }

    /// Resolve a [`GoStr`] header to a borrowed `&str` via the address space.
    /// Returns `None` for empty, unmapped, or non-UTF-8 strings.
    fn resolve_go_str(&self, s: GoStr) -> Option<&str> {
        if s.is_empty() {
            return None;
        }
        let bytes = self.ctx.slice_at_va(s.ptr)?.get(..s.len as usize)?;
        std::str::from_utf8(bytes).ok()
    }

    /// Text sub-sections from `moduledata.textsectmap`. A single entry for an
    /// ordinary binary; multiple only when the linker split a large binary's
    /// code across several text sections.
    pub fn text_sections(&self) -> Vec<TextSect> {
        self.text_sections.clone()
    }

    /// Decode `moduledata.textsectmap` (see [`Self::text_sections`]).
    fn decode_text_sections(&self) -> Vec<TextSect> {
        let md = match self.moduledata.as_ref() {
            Some(m) => m,
            None => return Vec::new(),
        };
        let ps = self.pclntab_meta.map(|m| m.ptr_size).unwrap_or(0);
        decode_slice(&self.ctx, &md.textsectmap, ps, TextSect::size(ps), |buf| {
            TextSect::parse(buf, 0, ps)
        })
    }

    /// Exported plugin symbols from `moduledata.ptab`. Empty for non-plugin
    /// builds (`-buildmode=plugin` only).
    pub fn plugin_exports(&self) -> Vec<PtabEntry<'_>> {
        let md = match self.moduledata.as_ref() {
            Some(m) => m,
            None => return Vec::new(),
        };
        let ps = self.pclntab_meta.map(|m| m.ptr_size).unwrap_or(0);
        let types_base = md.types;
        let legacy = self.legacy_names();
        decode_slice(&self.ctx, &md.ptab, ps, 8, |buf| {
            let name_off = read_i32(buf, 0)?;
            let type_offset = read_i32(buf, 4)?;
            let name = self.resolve_name_off(types_base, name_off, legacy);
            Some(PtabEntry { name, type_offset })
        })
    }

    /// Per-package ABI hashes from `moduledata.pkghashes` (imported-package
    /// hashes). Populated only for plugin / shared builds. See also
    /// [`Self::module_hashes`].
    pub fn package_hashes(&self) -> Vec<ModuleHash<'_>> {
        let md = match self.moduledata.as_ref() {
            Some(m) => m,
            None => return Vec::new(),
        };
        self.decode_module_hashes(&md.pkghashes)
    }

    /// Dependency module ABI hashes from `moduledata.modulehashes`. Populated
    /// only for plugin / shared builds.
    pub fn module_hashes(&self) -> Vec<ModuleHash<'_>> {
        let md = match self.moduledata.as_ref() {
            Some(m) => m,
            None => return Vec::new(),
        };
        self.decode_module_hashes(&md.modulehashes)
    }

    /// Decodes a `[]modulehash` slice (`pkghashes` or `modulehashes`) into
    /// resolved [`ModuleHash`] entries.
    fn decode_module_hashes(&self, slice: &GoSlice) -> Vec<ModuleHash<'_>> {
        let ps = self.pclntab_meta.map(|m| m.ptr_size).unwrap_or(0);
        if ps == 0 {
            return Vec::new();
        }
        // modulehash = { modulename string; linktimehash string; runtimehash *string }
        let entry_size = (ps as usize).saturating_mul(5);
        let p = ps as usize;
        decode_slice(&self.ctx, slice, ps, entry_size, |buf| {
            let module_name = GoStr::parse(buf, 0, ps).and_then(|s| self.resolve_go_str(s));
            let linktime_hash =
                GoStr::parse(buf, p.checked_mul(2)?, ps).and_then(|s| self.resolve_go_str(s));
            Some(ModuleHash {
                module_name,
                linktime_hash,
            })
        })
    }

    /// Whether this binary writes a type name's length as a big-endian
    /// `uint16` (Go 1.16 and before) rather than a varint (Go 1.17 on).
    ///
    /// Go 1.16 and 1.17 share one pclntab version, so that alone cannot tell
    /// them apart: the toolchain version decides where the binary states it,
    /// and otherwise the first reflected type's name, which only its own
    /// encoding reads as a clean name (the other reads the varint's byte as a
    /// zero length, or a big-endian length that runs into the next names).
    pub fn legacy_names(&self) -> bool {
        let Some(meta) = self.pclntab_meta else {
            return false;
        };
        match meta.version {
            PclntabVersion::Go12 => true,
            PclntabVersion::Go116 => match self.go_version().and_then(parse_go_minor_version) {
                Some(minor) => minor < 17,
                None => self.reads_legacy_names(meta),
            },
            _ => false,
        }
    }

    /// Whether the first reflected type's name reads cleanly in the legacy
    /// encoding ([`Self::legacy_names`]); `true` when no type is reflected.
    fn reads_legacy_names(&self, meta: PclntabMeta) -> bool {
        let Some(module) = self.moduledata.as_ref() else {
            return true;
        };
        types::extract_types_iter(&self.ctx, module, self.type_abi_with(meta, true))
            .next()
            .is_none_or(|t| !t.name.is_empty() && !t.name.bytes().any(|b| b < 0x20))
    }

    /// Resolve a `NameOff` (relative to `moduledata.types`) to a name string.
    fn resolve_name_off(&self, types_base: u64, name_off: i32, legacy: bool) -> Option<&str> {
        if name_off == 0 {
            return None;
        }
        let name_va = (types_base as i64).saturating_add(name_off as i64) as u64;
        let bytes = self.ctx.slice_at_va(name_va)?;
        decode_name(bytes, legacy).filter(|s| !s.is_empty())
    }

    /// Target architecture, disambiguated using the binary container format.
    ///
    /// [`ParsedPclntab::arch`] derives the arch purely from `(minLC, ptrSize)`
    /// header bytes, which conflates `Arch::X86_64` with `Arch::Wasm`
    /// (both report `(1, 8)`). This accessor folds in the container format
    /// to resolve the ambiguity:
    ///
    /// - [`BinaryFormat::Wasm`] always yields [`structures::Arch::Wasm`].
    /// - Other formats defer to the pclntab-derived arch.
    /// - When no pclntab is available, falls back to the build-info
    ///   `GOARCH` setting if present, or [`structures::Arch::Unknown`].
    pub fn arch(&self) -> Arch {
        if self.ctx.format() == BinaryFormat::Wasm {
            return Arch::Wasm;
        }
        if let Some(p) = self.pclntab() {
            return p.arch();
        }
        match self.build_info.as_ref().and_then(BuildInfo::goarch) {
            Some("386") => Arch::X86,
            Some("amd64") => Arch::X86_64,
            Some("arm") => Arch::Arm,
            Some("arm64") => Arch::Arm64,
            Some("mips") | Some("mipsle") => Arch::Mips32,
            Some("mips64") | Some("mips64le") => Arch::Mips64,
            Some("ppc64") | Some("ppc64le") => Arch::Ppc64,
            Some("riscv64") => Arch::RiscV,
            Some("s390x") => Arch::S390x,
            Some("wasm") => Arch::Wasm,
            _ => Arch::Unknown,
        }
    }

    /// Which Go compiler toolchain produced this binary.
    ///
    /// Detection order:
    /// 1. `-compiler` build setting (`gc`, `gccgo`, etc.) - authoritative.
    /// 2. `tinygo` substring in the Go version string.
    /// 3. Presence of pclntab → `gc` (TinyGo and gccgo do not produce it).
    /// 4. Otherwise [`Compiler::Unknown`].
    pub fn compiler(&self) -> Compiler {
        if let Some(info) = self.build_info.as_ref() {
            match info.setting("-compiler") {
                Some("gc") => return Compiler::Gc,
                Some("gccgo") => return Compiler::Gccgo,
                Some("tinygo") => return Compiler::TinyGo,
                _ => {}
            }
        }
        if self
            .go_version
            .map(|v| v.to_ascii_lowercase().contains("tinygo"))
            .unwrap_or(false)
        {
            return Compiler::TinyGo;
        }
        if self.pclntab_meta.is_some() {
            return Compiler::Gc;
        }
        Compiler::Unknown
    }

    /// Heuristic obfuscation/protection detection.
    ///
    /// Currently recognizes `garble`-processed binaries by combining:
    /// - A high fraction of function package names matching the garble token
    ///   shape (`^[A-Za-z0-9_]{8,16}$`, no `/` separators).
    /// - Scrubbed module dependency list (typical of `garble -tiny`).
    /// - Buildinfo missing or buildinfo deps absent (`-trimpath`-like).
    pub fn obfuscation(&self) -> ObfuscationKind {
        if self.pclntab_meta.is_none() {
            return ObfuscationKind::None;
        }

        let mut user_pkgs = std::collections::BTreeSet::new();
        for (name, _) in self.function_records() {
            let Some(pkg) = names::package_of(name) else {
                continue;
            };
            if name.starts_with("runtime.") || metadata::is_internal_path(pkg) {
                continue;
            }
            user_pkgs.insert(pkg);
        }
        if user_pkgs.is_empty() {
            return ObfuscationKind::None;
        }
        let total = user_pkgs.len();
        let obfuscated = user_pkgs.iter().filter(|p| is_garble_token(p)).count();
        let ratio = obfuscated as f32 / total as f32;

        let deps_scrubbed = self
            .build_info
            .as_ref()
            .map(|i| i.deps.is_empty())
            .unwrap_or(true);

        let confidence = if ratio >= 0.5 && deps_scrubbed {
            Confidence::High
        } else if ratio >= 0.5 {
            Confidence::Medium
        } else if ratio >= 0.2 {
            Confidence::Low
        } else {
            return ObfuscationKind::None;
        };
        ObfuscationKind::Garble { confidence }
    }

    /// Convenience: `true` if [`Self::obfuscation`] returned a `Garble` verdict.
    pub fn is_likely_garbled(&self) -> bool {
        matches!(self.obfuscation(), ObfuscationKind::Garble { .. })
    }

    /// The Go internal commit hash, if the binary was built from a development
    /// toolchain: `2dbf8b413a` in `"go1.28-devel_2dbf8b413a Fri Nov 20 ..."`
    /// (the form `cmd/dist` writes since the Go 1.25 cycle) or `abc1234` in
    /// `"devel go1.23-abc1234 ..."` (the form before).
    ///
    /// Returns `None` for released-version binaries (`"go1.22.3"`), where the
    /// commit hash is not stamped into the version string.
    ///
    /// For CVE matching against the Go toolchain itself, the commit hash is
    /// more precise than the marketing version - released versions only narrow
    /// to a tag.
    pub fn runtime_commit(&self) -> Option<&str> {
        toolchain_commit(self.go_version?)
    }

    /// FIPS-140 build info, if the binary was compiled in FIPS mode
    /// (`GOFIPS140=…`, Go 1.24+).
    ///
    /// FIPS-140 mode info, if the binary was built with `GOFIPS140` (Go 1.24+).
    ///
    /// The decision is driven by the authoritative `GOFIPS140` build setting,
    /// not the `__go_fipsinfo` section (which is linked into every
    /// crypto-using binary regardless of FIPS mode). The section's integrity
    /// sum is folded in as a supplementary content id when present. Returns
    /// `None` for non-FIPS builds and when build info is unavailable
    /// (e.g. stripped by `garble`).
    pub fn fips_info(&self) -> Option<FipsInfo<'a>> {
        let info = self.build_info.as_ref()?;
        let version = info.setting("GOFIPS140")?;
        let enforced_by_default = info
            .setting("DefaultGODEBUG")
            .is_some_and(|v| v.split(',').any(|kv| kv == "fips140=on"));
        let module_sum = self.fips_module_sum();
        Some(FipsInfo {
            version,
            enforced_by_default,
            module_sum,
        })
    }

    /// The raw 32-byte integrity sum from `__go_fipsinfo`, independent of FIPS
    /// mode. Present in every crypto-linked Go 1.24+ binary; `None` if the
    /// section is missing or lacks the expected `go:fipsinfo` magic.
    fn fips_module_sum(&self) -> Option<[u8; 32]> {
        // go:fipsinfo := struct { Magic [16]byte; Sum [32]byte }
        const EXPECTED_MAGIC: &[u8; 16] = b"\xff Go fipsinfo \xff\x00";
        let range = self.ctx.sections().fipsinfo.as_ref()?;
        let data = self.ctx.section_data(range)?;
        if data.get(0..16)? != EXPECTED_MAGIC.as_slice() {
            return None;
        }
        let mut sum = [0u8; 32];
        sum.copy_from_slice(data.get(16..48)?);
        Some(sum)
    }

    /// Assets embedded via `//go:embed` into an `embed.FS`.
    ///
    /// Locates the generated `[]file` arrays by scanning for their slice
    /// headers and decodes each entry into its virtual path, directory flag,
    /// and backing bytes (borrowed from read-only data). Works on stripped
    /// binaries. Returns an empty `Vec` when the binary embeds nothing.
    ///
    /// Only the multi-file `embed.FS` form is recovered - the single-file
    /// `//go:embed` string/`[]byte` forms compile to plain variables with no
    /// recognizable anchor and are not surfaced. This is the path Visus uses
    /// to recurse embedded dropper payloads out of Go binaries.
    pub fn embedded_assets(&self) -> Vec<embed::EmbeddedAsset<'_>> {
        let ptr_size = self.pclntab_meta.map(|m| m.ptr_size).unwrap_or(0);
        if ptr_size == 0 {
            return Vec::new();
        }
        embed::extract(&self.ctx, ptr_size)
    }

    /// Package initialization order, decoded from `moduledata.inittasks`
    /// (Go 1.24+).
    ///
    /// Returns one [`InitTask`] per linker-built init task, each carrying its
    /// ordered init functions (entry VA + resolved name). Empty when the
    /// binary predates Go 1.24, lacks moduledata, or carries no init tasks.
    ///
    /// Init order reveals which packages run setup code at startup and in what
    /// sequence - a useful lens on staging / persistence behaviour.
    pub fn init_order(&self) -> Vec<InitTask<'_>> {
        let md = match self.moduledata.as_ref() {
            Some(m) => m,
            None => return Vec::new(),
        };
        let ptr_size = self.pclntab_meta.map(|m| m.ptr_size).unwrap_or(0);
        let raw = inittask::decode(&self.ctx, md, ptr_size);
        if raw.is_empty() {
            return Vec::new();
        }

        // Resolve the init PCs to names with one pass over the function table.
        //
        // A binary has thousands of functions and a couple of dozen init
        // tasks, so the pass collects only the entry offsets the tasks
        // actually reference - indexing every function into a map costs more
        // memory than the whole rest of this call and throws almost all of it
        // away. It also walks `func_entries` rather than `functions()`, which
        // would additionally decode a source file, line range and frame size
        // for every function in the binary.
        let mut wanted: Vec<u32> = raw
            .iter()
            .flatten()
            .filter_map(|&pc| self.text_off(pc))
            .collect();
        wanted.sort_unstable();
        wanted.dedup();

        let mut names: Vec<(u32, &str)> = Vec::with_capacity(wanted.len());
        if !wanted.is_empty()
            && let Some(pcl) = self.pclntab()
        {
            for (entry_off, func_off) in pcl.func_entries() {
                if wanted.binary_search(&entry_off).is_err() {
                    continue;
                }
                if let Some(func) = pcl.parse_func(func_off)
                    && let Some(name) = pcl.func_name(func.name_off as u32)
                {
                    names.push((entry_off, name));
                }
            }
            names.sort_unstable_by_key(|(off, _)| *off);
        }

        let resolve = |pc_va: u64| -> Option<&str> {
            let off = self.text_off(pc_va)?;
            names
                .binary_search_by_key(&off, |(o, _)| *o)
                .ok()
                .and_then(|i| names.get(i))
                .map(|(_, n)| *n)
        };

        raw.into_iter()
            .map(|pcs| {
                let functions: Vec<InitFunc<'_>> = pcs
                    .into_iter()
                    .map(|pc| InitFunc {
                        entry_va: pc,
                        name: resolve(pc),
                    })
                    .collect();
                let package = functions
                    .iter()
                    .find_map(|f| f.name)
                    .and_then(names::package_of);
                InitTask { package, functions }
            })
            .collect()
    }

    /// All `(interface, concrete type)` pairs the linker proved at build time.
    ///
    /// Decoded from the `.itablink` / `__itablink` section if present, falling
    /// back to `moduledata.itablinks` (Go ≤1.26) or the inline itab region at
    /// `types+itaboffset` (Go 1.27+ / V5). Returns an empty iterator when no
    /// source is available (heavily stripped binaries).
    ///
    /// Useful for "what implements `io.Reader` in this binary?" queries -
    /// pair with [`Self::types`] to resolve each VA back to a named type.
    pub fn itab_pairs(&self) -> itab::ItabIter<'_> {
        let ptr_size = self.pclntab_meta.map(|m| m.ptr_size).unwrap_or(0);
        itab::extract_iter(
            &self.ctx,
            ptr_size,
            self.moduledata.as_ref(),
            self.itab_layout,
        )
    }

    /// The methods of an itab (see [`Self::itab_pairs`]): for each interface
    /// method, in interface order, its name and the concrete method its
    /// `Fun` word binds it to, resolved to that function.
    pub fn itab_methods(&self, pair: &itab::ItabPair) -> Vec<itab::ItabMethod<'_>> {
        let ptr_size = self.pclntab_meta.map(|m| m.ptr_size).unwrap_or(0);
        let names: Vec<&str> = match self.type_at(pair.iface_type_va).map(|t| t.detail) {
            Some(types::TypeDetail::Interface { methods, .. }) => {
                methods.into_iter().map(|m| m.name).collect()
            }
            _ => Vec::new(),
        };
        itab::itab_methods(&self.ctx, pair, ptr_size, self.itab_layout)
            .into_iter()
            .enumerate()
            .map(|(i, va)| itab::ItabMethod {
                name: names.get(i).copied(),
                va,
                function: self
                    .text_off(va)
                    .and_then(|off| self.function_entered_at(off)),
            })
            .collect()
    }

    /// The functions a concrete type's method (a [`types::MethodEntry`] of
    /// [`types::GoType::methods`]) runs when called directly and through an
    /// interface.
    pub fn method_functions(&self, method: &types::MethodEntry<'_>) -> types::MethodFunctions<'_> {
        let resolve = |off: Option<i32>| {
            off.and_then(|off| u32::try_from(off).ok())
                .and_then(|off| self.function_entered_at(off))
        };
        types::MethodFunctions {
            direct: resolve(method.function_text_offset),
            interface: resolve(method.interface_text_offset),
        }
    }

    /// The function whose entry is text offset `off`: what a method's
    /// `tfn`/`ifn` or an itab word names. `None` when `off` lies inside a
    /// function rather than at its start, which no code pointer does.
    fn function_entered_at(&self, off: u32) -> Option<FunctionInfo<'_>> {
        self.function_at(self.text_addr(off)?)
            .filter(|f| f.func.entry_off == off)
    }

    /// Where this binary's itab records put their `hash` and method words,
    /// which Go changed three times (see [`itab::ItabLayout`]).
    pub fn itab_layout(&self) -> itab::ItabLayout {
        self.itab_layout
    }

    /// Whether the binary links cgo (`runtime/cgo`): it holds a function only
    /// such a binary has, a stub cgo generates to call a C function
    /// (`pkg._Cfunc_<name>`), the runtime's exports to the C side
    /// (`_cgo_panic`, `_cgo_topofstack`) or its cgo pointer check. The
    /// runtime's own entry into C (`runtime.cgocall`) is in every binary
    /// from Go 1.7, with or without cgo, so it is no evidence.
    pub fn has_cgo(&self) -> bool {
        self.function_records()
            .any(|(name, _)| names::is_cgo_marker(name))
    }

    /// The runtime and `syscall` functions the compiler lowers goroutine,
    /// channel, `select`, `defer`, `panic`, cgo and system-call operations to
    /// ([`metadata::HookKind`]), as found in this binary.
    ///
    /// The runtime itself starts goroutines and uses channels, so most of
    /// these functions are in every binary; what marks a program's own use
    /// of an operation is a call to one, which a disassembler finds by
    /// matching call targets against these entries.
    pub fn runtime_hooks(&self) -> Vec<metadata::RuntimeHook<'_>> {
        let Some(pcl) = self.pclntab() else {
            return Vec::new();
        };
        self.function_records()
            .filter_map(|(name, func)| {
                Some(metadata::RuntimeHook {
                    kind: metadata::HookKind::of(name)?,
                    function: FunctionInfo::from_func(&pcl, func),
                })
            })
            .collect()
    }

    /// Every function's name with its record, without decoding its tables
    /// as [`Self::functions`] does: for checks that need only names.
    fn function_records(&self) -> impl Iterator<Item = (&str, pclntab::FuncData)> + '_ {
        self.pclntab().into_iter().flat_map(|pcl| {
            pcl.func_entries().filter_map(move |(_, off)| {
                let func = pcl.parse_func(off)?;
                Some((pcl.func_name(func.name_off as u32)?, func))
            })
        })
    }

    /// Streaming iterator over all types extracted from Go `abi.Type` descriptors.
    ///
    /// Uses the `.typelink` section (an array of `int32` offsets) and the
    /// `abi.Type` struct layout to recover every type the binary exposes to
    /// reflection. Each yielded [`types::GoType`] includes its name, kind, size,
    /// flags, kind-specific detail and resolved methods.
    ///
    /// Yields zero items if the required sections (`.typelink` / `.go.module`)
    /// or moduledata are not present. Adversarial input cannot panic the
    /// iteration; failed descriptor parses are skipped silently.
    ///
    /// Collect with `bin.types().collect::<Vec<_>>()` if you need an owned
    /// container.
    pub fn types(&self) -> types::TypeIter<'_> {
        let (Some(meta), Some(md)) = (self.pclntab_meta, self.moduledata.as_ref()) else {
            return types::TypeIter::empty(&self.ctx);
        };
        types::extract_types_iter(&self.ctx, md, self.type_abi(meta))
    }

    /// Parse the type descriptor at a specific virtual address into a
    /// [`types::GoType`].
    ///
    /// Resolves the `elem_va` / `type_va` / `key_va` references that other
    /// types carry (e.g. a slice's element type, a struct field's type) into a
    /// full type. Returns `None` if `va` does not point at a parseable
    /// descriptor.
    pub fn type_at(&self, va: u64) -> Option<types::GoType<'_>> {
        let meta = self.pclntab_meta?;
        let types_base = self.moduledata.as_ref()?.types;
        types::type_at_va(&self.ctx, va, types_base, self.type_abi(meta))
    }

    /// Enumerate **every** reachable type descriptor, not just the
    /// reflection-registered `typelink` set returned by [`Self::types`].
    ///
    /// Seeds from `typelink` and from every descriptor laid out in the type
    /// region that holds as one ([`types::scan_descriptors`]: the types only
    /// code allocates, such as a closure's context), and transitively follows
    /// every referenced type
    /// (pointer/slice/array/chan elements, map key/value, struct field types,
    /// func parameter/result types, method signatures, and each type's
    /// pointer-to-this), parsing each descriptor independently by virtual
    /// address. This reaches types absent from `typelink` - e.g. a struct type
    /// used only as a pointer's element, together with its field tags. Capped
    /// to bound pathological graphs.
    pub fn all_types(&self) -> Vec<types::GoType<'_>> {
        let meta = match self.pclntab_meta {
            Some(m) => m,
            None => return Vec::new(),
        };
        let (types_base, etypes) = match self.moduledata.as_ref() {
            Some(m) => (m.types, m.etypes),
            None => return Vec::new(),
        };
        // The reflection tables reach the types a program can name; the type
        // region also holds those only code allocates (a closure's context),
        // found where a laid-out descriptor holds as one.
        let mut seeds: Vec<types::GoType<'_>> = self.types().collect();
        seeds.extend(self.laid_out_types());
        types::extract_all_types(&self.ctx, seeds, types_base, etypes, self.type_abi(meta))
    }

    /// Every type descriptor laid out in the module's type region that holds
    /// as one ([`types::scan_descriptors`]): the reflection tables' types and
    /// the ones only code reaches. Empty without moduledata.
    pub fn laid_out_types(&self) -> Vec<types::GoType<'_>> {
        let (Some(meta), Some(module)) = (self.pclntab_meta, self.moduledata.as_ref()) else {
            return Vec::new();
        };
        types::scan_descriptors(&self.ctx, module.types, module.etypes, self.type_abi(meta))
    }

    /// The per-binary constants every type-descriptor read depends on.
    ///
    /// The `abi.MapType` layout is the one that needs deriving: the map
    /// descriptor changed shape six times between Go 1.7 and 1.27, and its size
    /// feeds the position of every map type's `UncommonType`, so it has to be
    /// settled before any descriptor is read. See [`types::MapLayout::infer`].
    fn type_abi(&self, meta: PclntabMeta) -> types::TypeAbi {
        self.type_abi_with(meta, self.legacy_names())
    }

    /// [`Self::type_abi`] with the name encoding `legacy_names` states.
    fn type_abi_with(&self, meta: PclntabMeta, legacy_names: bool) -> types::TypeAbi {
        types::TypeAbi {
            ps: meta.ptr_size,
            legacy_names,
            map_layout: self.map_layout_for(meta),
        }
    }

    /// The `abi.MapType` layout of the binary's Go version: the one every
    /// version its tables can be from shares, else what
    /// [`types::MapLayout::infer`] reads off the structure, which may be
    /// [`types::MapLayout::Probe`] (decided per map type descriptor). `None`
    /// without a pclntab.
    pub fn map_layout(&self) -> Option<types::MapLayout> {
        Some(self.map_layout_for(self.pclntab_meta?))
    }

    /// [`Self::map_layout`] for the pclntab `meta` describes.
    fn map_layout_for(&self, meta: PclntabMeta) -> types::MapLayout {
        if let Some(layout) = self
            .minor_range
            .and_then(|range| range.decide(types::MapLayout::for_go_minor))
        {
            return layout;
        }
        let md_version = self.moduledata.as_ref().map(|m| m.version);
        types::MapLayout::infer(
            None,
            meta.version == PclntabVersion::Go120,
            md_version == Some(ModuledataVersion::V5),
            md_version == Some(ModuledataVersion::V4),
        )
    }

    /// Streaming iterator over Go string literals discovered by scanning the
    /// binary for `(ptr, len)` headers that resolve to in-binary UTF-8 bytes.
    ///
    /// Recovers strings that a generic byte-string extractor would miss
    /// (Go strings are not NUL-terminated) or split (they may contain
    /// internal NULs). Useful for TLSH / SSDeep / MinHash signal recovery
    /// on Go binaries.
    ///
    /// Yields zero items when the binary lacks VA mapping. Length filter:
    /// 2..=4096 bytes. UTF-8 is **not** required - malware frequently stashes
    /// non-UTF-8 payloads in length-prefixed rodata entries; use
    /// [`gostrings::GoString::as_bytes`] for raw bytes,
    /// [`gostrings::GoString::try_as_str`] / [`gostrings::GoString::as_str`]
    /// for text. Pointers into the text segment (`[moduledata.text,
    /// moduledata.etext)`) are excluded. **Duplicates are not filtered** -
    /// a string referenced from N positions yields N times. Collect into a
    /// `HashSet` if you want unique results.
    pub fn strings(&self) -> gostrings::GoStringIter<'_> {
        let ptr_size = self.pclntab_meta.map(|m| m.ptr_size).unwrap_or(0);
        gostrings::extract_iter(&self.ctx, self.moduledata.as_ref(), ptr_size)
    }
}

/// Fast best-effort check for "is this byte slice a Go binary?" without
/// running the full parse pipeline.
///
/// Scans for any of three structural markers:
/// - The buildinfo magic header (`"\xff Go buildinf:"`)
/// - The build-id raw marker (`"\xff Go build ID:"`)
/// - A pclntab magic value at any 4-byte aligned offset
///
/// This is dramatically cheaper than [`GoBinary::parse`] because it does no
/// `goblin` format parse, no header decode, and no string-table walks. Use it
/// in ingest pipelines that need to *tag* a binary before deciding whether to
/// invoke the full analyzer.
///
/// False negatives are possible (heavily patched binaries where every marker
/// has been wiped). False positives are unlikely - these magic byte sequences
/// don't naturally appear in non-Go binaries.
pub fn detect(data: &[u8]) -> bool {
    if find_bytes(data, b"\xff Go buildinf:").is_some() {
        return true;
    }
    if find_bytes(data, b"\xff Go build ID:").is_some() {
        return true;
    }
    const PCLNTAB_MAGICS: &[[u8; 4]] = &[
        [0xf1, 0xff, 0xff, 0xff],
        [0xf0, 0xff, 0xff, 0xff],
        [0xfa, 0xff, 0xff, 0xff],
        [0xfb, 0xff, 0xff, 0xff],
    ];
    let limit = data.len().saturating_sub(4);
    let mut offset: usize = 0;
    while offset <= limit {
        let end = match offset.checked_add(4) {
            Some(e) => e,
            None => break,
        };
        let m = match data.get(offset..end) {
            Some(s) => s,
            None => break,
        };
        for magic in PCLNTAB_MAGICS {
            if m == magic {
                return true;
            }
        }
        offset = match offset.checked_add(4) {
            Some(o) => o,
            None => break,
        };
    }
    false
}

/// Whether `pkg` looks like a garble-emitted obfuscated package token: 8-16
/// characters of `[A-Za-z0-9_]` with no `/` (path) separators and at least
/// one digit (real Go package names rarely contain digits).
fn is_garble_token(pkg: &str) -> bool {
    if pkg.contains('/') || pkg.contains('.') {
        return false;
    }
    let len = pkg.len();
    if !(8..=16).contains(&len) {
        return false;
    }
    let mut has_digit = false;
    for b in pkg.bytes() {
        if !(b.is_ascii_alphanumeric() || b == b'_') {
            return false;
        }
        if b.is_ascii_digit() {
            has_digit = true;
        }
    }
    has_digit
}

/// Parse the minor version from a Go version string like `"go1.26.1"` -> `26`.
/// Decode the fixed-size entries of a moduledata slice `(ptr, len)` by reading
/// the array at `slice.ptr` and applying `parse` to each `entry_size`-byte
/// window. Bounds- and count-capped; never panics on malformed input.
fn decode_slice<T>(
    ctx: &BinaryContext<'_>,
    slice: &structures::goslice::GoSlice,
    ps: u8,
    entry_size: usize,
    mut parse: impl FnMut(&[u8]) -> Option<T>,
) -> Vec<T> {
    const MAX_ENTRIES: u64 = 10_000_000;
    if ps == 0 || entry_size == 0 || slice.len == 0 || slice.len > MAX_ENTRIES {
        return Vec::new();
    }
    let arr = match ctx.slice_at_va(slice.ptr) {
        Some(a) => a,
        None => return Vec::new(),
    };
    let n = slice.len as usize;
    let mut out = Vec::with_capacity(n.min(1024));
    for i in 0..n {
        let off = match i.checked_mul(entry_size) {
            Some(o) => o,
            None => break,
        };
        let end = match off.checked_add(entry_size) {
            Some(e) => e,
            None => break,
        };
        let buf = match arr.get(off..end) {
            Some(b) => b,
            None => break,
        };
        if let Some(item) = parse(buf) {
            out.push(item);
        }
    }
    out
}

/// The commit hash a development toolchain's version string names: the hex
/// run after `-devel_` (`go1.28-devel_2dbf8b413a ...`, since the Go 1.25
/// cycle) or after the `-` of `devel go1.23-abc1234 ...` (before). At least
/// seven hex digits, as `git log --format=%h` abbreviates. See
/// [`GoBinary::runtime_commit`].
fn toolchain_commit(v: &str) -> Option<&str> {
    let bytes = v.as_bytes();
    let mut i: usize = 0;
    while let Some(&byte) = bytes.get(i) {
        if byte == b'-' {
            let mut start = i.checked_add(1)?;
            if v.get(start..)
                .is_some_and(|rest| rest.starts_with("devel_"))
            {
                start = start.checked_add("devel_".len())?;
            }
            let mut end = start;
            while bytes.get(end).is_some_and(|b| b.is_ascii_hexdigit()) {
                end = end.checked_add(1)?;
            }
            if end.checked_sub(start)? >= 7 {
                return v.get(start..end);
            }
            i = end;
        } else {
            i = i.checked_add(1)?;
        }
    }
    None
}

/// The minor version a Go version string names (`go1.27.4` -> 27), in every
/// form the toolchain writes: release, pre-release, and both development forms.
fn parse_go_minor_version(version: &str) -> Option<u32> {
    // A development toolchain before the Go 1.25 cycle wrote `devel go1.N-...`.
    let version = version.strip_prefix("devel ").unwrap_or(version);
    let rest = version.strip_prefix("go1.")?;
    // Take the leading run of digits so pre-release strings parse too:
    // `go1.27.4` -> 27, `go1.27rc1` -> 27, `go1.27-devel_abc1234` -> 27.
    let minor_str = rest
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .filter(|s| !s.is_empty())?;
    minor_str.parse().ok()
}

/// Locate and parse the moduledata, with its position in the address-space
/// view, for accessor-only use (text/etext/types region addresses).
///
/// Delegates to [`ModuledataLocator`], which owns every discovery strategy -
/// the `.go.module` section on Go 1.26+ ELF / Mach-O, and the `pcHeader`-
/// pointer scan everywhere else. Returns `None` if the binary lacks VA
/// mappings or the moduledata cannot be located; callers degrade gracefully
/// (the affected accessors return `None`).
fn find_moduledata(
    ctx: &BinaryContext<'_>,
    pclntab: &ParsedPclntab<'_>,
    go_version: Option<&str>,
) -> Option<LocatedModuledata> {
    let hints = layout_hints(ctx, pclntab.version, go_version);
    ModuledataLocator::new(ctx, pclntab.ptr_size, pclntab.offset, hints).locate()
}

/// The itab layout a binary uses: the one every Go version its tables can be
/// from emits ([`MinorRange`]), or where they differ, the one its structure
/// shows.
///
/// Without a version a Go 1.5-1.15 moduledata reads as the richest shape of
/// its era (Go 1.10-1.15, as [`Moduledata::parse`] assumes), so `Padded`. A
/// later binary is `Padded` (1.10-1.22) or `Abi` (1.23+), which differ only
/// on 32-bit, where the first record tells them apart: the word after `hash`
/// is the zero padding of `Padded` or `fun[0]` of `Abi`, which the linker
/// fills in every itab it emits from Go 1.10 on.
fn choose_itab_layout(
    ctx: &BinaryContext<'_>,
    meta: Option<PclntabMeta>,
    minor_range: Option<MinorRange>,
    moduledata: Option<&Moduledata>,
) -> itab::ItabLayout {
    if let Some(layout) = minor_range.and_then(|range| range.decide(itab::ItabLayout::for_go_minor))
    {
        return layout;
    }
    if moduledata.is_some_and(|md| md.version == ModuledataVersion::V1) {
        return itab::ItabLayout::Padded;
    }
    let ptr_size = meta.map_or(0, |m| m.ptr_size);
    if ptr_size != 4 {
        return itab::ItabLayout::Abi;
    }
    let first = itab::extract_iter(ctx, ptr_size, moduledata, itab::ItabLayout::Abi).next();
    let after_hash = first.and_then(|pair| {
        let bytes = ctx.slice_at_va(pair.itab_va.checked_add(12)?)?;
        Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
    });
    match after_hash {
        Some(0) => itab::ItabLayout::Padded,
        _ => itab::ItabLayout::Abi,
    }
}

/// Whether the binary's text offsets name functions by index: wasm
/// (`GOARCH=wasm`, 8-byte pointers) from Go 1.25 on.
///
/// The Go 1.25 linker (`cmd/link/internal/ld/pcln.go`, `textOff`; Go commit
/// `9c507e7942`) writes a wasm function's index into the function table and
/// the method tables, where it used to write the function's PC offset; the
/// runtime's `textAddr` shifts it into a PC. The table itself says which:
/// consecutive functions' PCs are at least `1 << 16` apart (a PC's low 16 bits
/// number resume points inside a function), while their indices step by one.
/// The `wasm32` port (4-byte pointers) does not index.
fn indexed_text_offsets(ctx: &BinaryContext<'_>, meta: Option<PclntabMeta>) -> bool {
    let Some(meta) = meta else {
        return false;
    };
    if ctx.format() != BinaryFormat::Wasm || meta.ptr_size != 8 {
        return false;
    }
    let Some(pcl) = meta.attach(ctx.structure_search_data()) else {
        return false;
    };
    let mut entries = pcl.func_entries().map(|(entry_off, _)| entry_off);
    match (entries.next(), entries.next()) {
        (Some(first), Some(second)) => second.checked_sub(first).is_some_and(|step| step < 1 << 16),
        _ => false,
    }
}

/// The Go minor versions a binary's tables can be from: its version string's
/// when it states one, else the range its structure allows (the pclntab
/// format, the Go 1.2-1.15 `_func` layout, the moduledata layout).
fn minor_range(
    go_version: Option<&str>,
    pclntab: Option<&PclntabMeta>,
    moduledata: Option<&Moduledata>,
) -> Option<MinorRange> {
    if let Some(minor) = go_version.and_then(parse_go_minor_version) {
        return Some(MinorRange {
            lo: minor,
            hi: minor,
        });
    }
    let (lo, hi) = match pclntab?.version {
        PclntabVersion::Go12 => match pclntab?.legacy_func {
            Some(LegacyFuncLayout::FrameSize) => (2, 4),
            Some(LegacyFuncLayout::FramePlaceholder) => (5, 9),
            Some(LegacyFuncLayout::FuncIdWord) => (10, 11),
            _ => (12, 15),
        },
        PclntabVersion::Go116 => (16, 17),
        PclntabVersion::Go118 => (18, 19),
        PclntabVersion::Go120 => match moduledata.map(|m| m.version) {
            Some(ModuledataVersion::V3) => (20, 25),
            Some(ModuledataVersion::V4) => (26, 26),
            _ => (27, MinorRange::NEWEST),
        },
    };
    Some(MinorRange { lo, hi })
}

/// The Go minor versions a binary's tables can be from, inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MinorRange {
    /// The oldest.
    lo: u32,
    /// The newest; [`Self::NEWEST`] when no newer layout bounds it.
    hi: u32,
}

impl MinorRange {
    /// A bound past every Go version this crate knows the layouts of, which
    /// later versions are assumed to share with the newest it knows.
    const NEWEST: u32 = 40;

    /// What `f` gives for every version in the range, if it gives the same
    /// for all of them; `None` when the versions disagree, so a format the
    /// structure cannot pin down is not guessed.
    fn decide<T: PartialEq>(self, f: impl Fn(u32) -> T) -> Option<T> {
        let first = f(self.lo);
        (self.lo..=self.hi).all(|m| f(m) == first).then_some(first)
    }
}

/// Collect the out-of-band signals [`Moduledata::parse`] uses to pick between
/// the V5 (Go 1.27+) and pre-V5 moduledata layouts.
fn layout_hints(
    ctx: &BinaryContext<'_>,
    pclntab_version: PclntabVersion,
    go_version: Option<&str>,
) -> LayoutHints {
    let sections = ctx.sections();
    LayoutHints {
        pclntab_version,
        go_minor: go_version.and_then(parse_go_minor_version),
        has_typelink_section: sections.typelink.is_some(),
        has_go_type_section: sections.go_type.is_some(),
        code_outside_data: ctx.format() == BinaryFormat::Wasm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toolchain_commit_reads_both_devel_forms() {
        let tip = "go1.28-devel_2dbf8b413a Fri Nov 20 21:43:22 2026 -0800";
        assert_eq!(toolchain_commit(tip), Some("2dbf8b413a"));
        let experiment = "go1.28-devel_2dbf8b413a Fri Nov 20 21:43:22 2026 -0800 X:cgobindings";
        assert_eq!(toolchain_commit(experiment), Some("2dbf8b413a"));
        assert_eq!(
            toolchain_commit("devel go1.23-abc1234 Tue Jan 2 2024"),
            Some("abc1234")
        );
        for release in ["go1.27.4", "go1.27rc1", "go1.28"] {
            assert_eq!(toolchain_commit(release), None, "{release}");
        }
    }

    #[test]
    fn go_minor_parses_every_version_form() {
        for (version, minor) in [
            ("go1.27.4", 27),
            ("go1.27rc1", 27),
            ("go1.28-devel_2dbf8b413a Fri Nov 20 21:43:22 2026 -0800", 28),
            ("devel go1.23-abc1234 Tue Jan 2 2024", 23),
            ("go1.9", 9),
        ] {
            assert_eq!(parse_go_minor_version(version), Some(minor), "{version}");
        }
        assert_eq!(parse_go_minor_version("devel +abc1234"), None);
    }
}
