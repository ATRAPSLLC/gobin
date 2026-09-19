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
pub mod structures;

use crate::{
    detection::{
        Confidence, ConfidenceReport, ConfidenceSignal, ParseError, VersionSource, find_bytes,
        heuristic_hits,
    },
    formats::{BinaryContext, BinaryFormat},
    metadata::{BuildInfo, Compiler, FipsInfo, FunctionIter, InitFunc, InitTask, ObfuscationKind},
    structures::{
        Arch, PclntabVersion, buildid, buildinfo, embed, gcprog,
        goslice::{GoSlice, GoStr},
        inittask, inline, itab,
        locate::ModuledataLocator,
        moduledata::{LayoutHints, ModuleHash, Moduledata, ModuledataVersion, PtabEntry, TextSect},
        name::decode_name,
        pclntab::{self, FuncData, ParsedPclntab, PclntabMeta},
        strings as gostrings, types,
        util::read_i32,
    },
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
    build_id: Option<&'a str>,
    build_info: Option<BuildInfo<'a>>,
    /// Cached pclntab scalars. The borrowing [`ParsedPclntab`] view is
    /// reconstructed on demand via [`Self::pclntab`] so it can borrow from
    /// `&self.ctx` - important for wasm, where the address space pclntab
    /// lives in is the linear-memory image owned by the context (and is
    /// therefore not borrowable with the input lifetime `'a`).
    pclntab_meta: Option<PclntabMeta>,
    go_version: Option<&'a str>,
    moduledata: Option<Moduledata>,
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
                None => (
                    buildinfo::find_version_string(data),
                    VersionSource::StringScan,
                ),
            };
        if let Some(v) = go_version {
            report.push(ConfidenceSignal::GoVersionString {
                version: v.to_string(),
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

        let moduledata = pclntab_meta.and_then(|meta| {
            let pcl = meta.attach(ctx.structure_search_data())?;
            find_moduledata(&ctx, &pcl, go_version)
        });

        Ok(GoBinary {
            report,
            ctx,
            build_id,
            build_info: build_info_result,
            pclntab_meta,
            go_version,
            moduledata,
        })
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

    /// The Go build ID.
    ///
    /// For executables this is a 4-part string: `actionID/actionID/contentID/contentID`,
    /// where each part is 20 characters of URL-safe base64 derived from SHA256 hashes.
    ///
    /// See [`structures::buildid`] for format details.
    pub fn build_id(&self) -> Option<&'a str> {
        self.build_id
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

    /// Streaming iterator over the per-PC inlining tree for a function.
    ///
    /// Yields one [`inline::InlineEntry`] per PC range during which an inlined
    /// frame is active. PC ranges with no inlining are skipped silently.
    /// Returns an empty iterator when:
    ///
    /// - The function has no inlined calls (no `funcdata[FUNCDATA_InlTree]`).
    /// - The binary has no recoverable pclntab.
    /// - `moduledata.gofunc` is unavailable (Go 1.16-1.19 / V2 binaries do not
    ///   expose this base, so funcdata cannot be resolved).
    ///
    /// Source: `src/runtime/symtabinl.go` (`inlineUnwinder`).
    pub fn inline_tree(&self, func: &FuncData) -> inline::InlineTreeIter<'_> {
        let pcl = match self.pclntab() {
            Some(p) => p,
            None => return inline::InlineTreeIter::empty(),
        };
        inline::extract_iter(&self.ctx, pcl, self.moduledata.as_ref(), func)
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
    /// `entry_off` on each [`FuncData`] is measured relative to this address.
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

    /// Binary-level virtual address of a function's entry point.
    ///
    /// Folds together `text_va + func.entry_off` so callers don't reimplement
    /// the translation. Returns `None` when [`Self::text_va`] is unavailable
    /// (binary lacks moduledata or VA mapping) or the addition overflows.
    ///
    /// For ELF and Mach-O this is the address a disassembler will use
    /// directly. For PE this is still a true VA - pass it to
    /// [`Self::entry_rva`] (or subtract [`BinaryContext::image_base`]) to get
    /// the RVA most PE-aware tools expect.
    pub fn entry_va(&self, func: &FuncData) -> Option<u64> {
        self.text_va()?.checked_add(u64::from(func.entry_off))
    }

    /// Image-base-relative entry RVA.
    ///
    /// For PE binaries this returns `entry_va − image_base`, the form most PE
    /// disassemblers index by. For ELF and Mach-O the image base is `0`, so
    /// this is identical to [`Self::entry_va`].
    ///
    /// Returns `None` when [`Self::entry_va`] is unavailable or the binary's
    /// `text_va` lies below the recorded image base (corrupt input).
    pub fn entry_rva(&self, func: &FuncData) -> Option<u64> {
        self.entry_va(func)?.checked_sub(self.ctx.image_base())
    }

    /// Virtual address of `runtime.etext` - one past the last byte of
    /// Go-emitted code.
    ///
    /// `etext_va() - text_va()` gives the total size of all Go-emitted code,
    /// useful as an "amount of Go code in this binary" metric.
    pub fn etext_va(&self) -> Option<u64> {
        self.moduledata.as_ref().map(|m| m.etext)
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

    /// Whether this binary uses the pre-1.17 (`Go116`) type-name encoding.
    fn legacy_names(&self) -> bool {
        self.pclntab_meta
            .map(|m| matches!(m.version, PclntabVersion::Go116 | PclntabVersion::Go12))
            .unwrap_or(false)
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
        for f in self.functions() {
            if f.is_runtime() || f.is_internal() {
                continue;
            }
            if let Some(pkg) = f.package() {
                user_pkgs.insert(pkg.to_string());
            }
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
    /// toolchain (e.g. `"devel go1.23-abc1234 ..."`).
    ///
    /// Returns `None` for released-version binaries (`"go1.22.3"`), where the
    /// commit hash is not stamped into the version string.
    ///
    /// For CVE matching against the Go toolchain itself, the commit hash is
    /// more precise than the marketing version - released versions only narrow
    /// to a tag.
    pub fn runtime_commit(&self) -> Option<&str> {
        let v = self.go_version?;
        let bytes = v.as_bytes();
        let mut i: usize = 0;
        while let Some(&byte) = bytes.get(i) {
            if byte == b'-' {
                let start = i.checked_add(1)?;
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
        let text_va = self.text_va();
        let entry_off_of =
            |pc_va: u64| -> Option<u32> { u32::try_from(pc_va.checked_sub(text_va?)?).ok() };

        let mut wanted: Vec<u32> = raw
            .iter()
            .flatten()
            .filter_map(|pc| entry_off_of(*pc))
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
            let off = entry_off_of(pc_va)?;
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
                    .and_then(metadata::package_of);
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
        itab::extract_iter(&self.ctx, ptr_size, self.moduledata.as_ref())
    }

    /// The `Fun[]` method-pointer array of an itab - the concrete-type methods
    /// bound to each interface method, in interface order (a `0` entry means
    /// the method is unbound). Pair with [`Self::itab_pairs`].
    pub fn itab_methods(&self, pair: &itab::ItabPair) -> Vec<u64> {
        let ptr_size = self.pclntab_meta.map(|m| m.ptr_size).unwrap_or(0);
        itab::itab_methods(&self.ctx, pair, ptr_size)
    }

    /// Whether the binary's pclntab references any cgo-related runtime
    /// functions (`runtime.cgocall`, `runtime.cgocallback`, etc.).
    ///
    /// This is a binary-level "did this binary use cgo at all?" signal - a
    /// strong indicator the program may execute native code from C (DLLs,
    /// syscalls, exploits). Per-call-site enumeration would require
    /// disassembly support, which the crate does not have today.
    pub fn has_cgo(&self) -> bool {
        // Short-circuits on the first matching function via the streaming
        // iterator - does not materialize the whole function list.
        self.functions().any(|f| is_cgo_runtime_fn(f.name))
    }

    /// Whether the binary references Go concurrency primitives
    /// (`runtime.newproc`, channel send/recv, select).
    ///
    /// Like [`Self::has_cgo`], this is a binary-level signal. A binary that
    /// imports `sync` but never calls `go` may still trigger this if the
    /// stdlib internally spawns goroutines. Short-circuits on the first
    /// matching function.
    pub fn uses_concurrency(&self) -> bool {
        self.functions().any(|f| is_concurrency_runtime_fn(f.name))
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
    /// Seeds from `typelink` and transitively follows every referenced type
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
        types::extract_all_types(
            &self.ctx,
            self.types().collect(),
            types_base,
            etypes,
            self.type_abi(meta),
        )
    }

    /// The per-binary constants every type-descriptor read depends on.
    ///
    /// The `abi.MapType` layout is the one that needs deriving: the map
    /// descriptor changed shape six times between Go 1.7 and 1.27, and its size
    /// feeds the position of every map type's `UncommonType`, so it has to be
    /// settled before any descriptor is read. See [`types::MapLayout::infer`].
    fn type_abi(&self, meta: PclntabMeta) -> types::TypeAbi {
        let md_version = self.moduledata.as_ref().map(|m| m.version);
        types::TypeAbi {
            ps: meta.ptr_size,
            legacy_names: self.legacy_names(),
            map_layout: types::MapLayout::infer(
                self.go_version().and_then(parse_go_minor_version),
                meta.version == PclntabVersion::Go120,
                md_version == Some(ModuledataVersion::V5),
                md_version == Some(ModuledataVersion::V4),
            ),
        }
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

/// Runtime function names indicating cgo usage.
///
/// Source: `src/runtime/cgo.go`, `src/runtime/cgocall.go`,
/// `src/runtime/cgocallback.go`.
const CGO_RUNTIME_FNS: &[&str] = &[
    "runtime.cgocall",
    "runtime.cgocallback",
    "runtime.cgocall_native",
    "runtime.asmcgocall",
    "runtime.cgoCheckPointer",
    "runtime._cgo_panic",
];

/// Runtime function names indicating goroutine / channel use.
///
/// Source: `src/runtime/proc.go` (newproc), `src/runtime/chan.go`
/// (chan{send,recv,close,recv1,recv2}), `src/runtime/select.go`.
const CONCURRENCY_RUNTIME_FNS: &[&str] = &[
    "runtime.newproc",
    "runtime.chansend",
    "runtime.chansend1",
    "runtime.chanrecv",
    "runtime.chanrecv1",
    "runtime.chanrecv2",
    "runtime.closechan",
    "runtime.selectgo",
];

fn is_cgo_runtime_fn(name: &str) -> bool {
    CGO_RUNTIME_FNS.contains(&name)
}

fn is_concurrency_runtime_fn(name: &str) -> bool {
    CONCURRENCY_RUNTIME_FNS.contains(&name)
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

fn parse_go_minor_version(version: &str) -> Option<u32> {
    let rest = version.strip_prefix("go1.")?;
    // Take the leading run of digits so pre-release strings parse too:
    // `go1.27.4` -> 27, `go1.27rc1` -> 27, `go1.27-devel_abc1234` -> 27.
    let minor_str = rest
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .filter(|s| !s.is_empty())?;
    minor_str.parse().ok()
}

/// Locate and parse the moduledata for accessor-only use (text/etext/types
/// region addresses).
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
) -> Option<Moduledata> {
    let hints = layout_hints(ctx, pclntab.version, go_version);
    ModuledataLocator::new(ctx, pclntab.ptr_size, pclntab.offset, hints).locate()
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
    }
}
