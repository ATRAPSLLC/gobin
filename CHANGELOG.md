# Changelog

All notable changes to `gobin` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1]

Maintenance release. No functional change.

### Changed

- Refreshed transitive dependencies (`cargo update`); no direct dependency
  changed version (`goblin` 0.10.7 and `divan` 0.1.21 are current).
- Replaced em-dashes and en-dashes with plain hyphens throughout rustdoc,
  comments, the changelog and the sample-corpus docs.

## [0.5.0]

Go 1.27 verified against the released toolchain, plus a performance pass.
Layouts were checked field-by-field against the `go1.27.1` and `go1.26.8`
source trees: the V5 moduledata support from 0.3.0 is **correct as released**,
so what needed fixing was the code paths it shares with older versions.

### Fixed

- **The V5 layout could be chosen for a pre-1.27 binary, silently emptying it.**
  It was selected from a *negative* signal - no `.typelink` section - which PE
  never has at any version, nor wasm, nor RELRO ELF. With no version string to
  disagree, a Go 1.20-1.26 binary decoded as V5 and every field past `types`
  shifted: on a version-scrubbed `basic_go124_windows_amd64.exe`, types went
  494 → 0, itabs 16 → 0, init tasks 17 → 0 and `has_main` true → false, with no
  error raised. `Moduledata::parse` now parses both candidate layouts and keeps
  the one that is internally self-consistent (`layout_self_consistent`).
- **`abi.MapType` was read with the Go 1.27 layout on every Go version.** The
  map descriptor has changed shape six times and had its flag bits renumbered
  once more; gobin implemented one. On Go ≤ 1.26 it over-read the record (24
  bytes on 1.24-1.26, 48 on 1.14-1.23), so every `TypeDetail::Map` field past
  `Hasher` was garbage, and `descriptor_size` mislocated the trailing
  `UncommonType`. `MapLayout` now models all six eras, selected from the Go
  version or - when scrubbed - from the moduledata version and pclntab magic,
  with a structural probe for the one window those cannot separate.
  `MapFlags` normalizes the three flag encodings.
- **`text_va()` returned `Some(0)` on Go 1.26+ without a moduledata.** Go 1.26
  stopped writing `textStart` into the pcHeader but left the slot, so every
  `entry_va` collapsed to a raw `entry_off`. Zero now reads as absent, and the
  executable section base is used as a real fallback.
- **The Go 1.27 type walk ran past its bound**, using `etypes` where
  `runtime.moduleTypelinks` uses `types + typedesclen` - a field that was
  parsed but never read. Past the bound it surfaced unnamed junk types.
- **One unparseable record ended the whole descriptor walk**, which on Go 1.27
  is the only type-enumeration strategy there is. It now skips and continues
  under a bounded budget. `itab_stride` likewise stops rather than guessing a
  method count, which desynchronized the inline itab walk.
- **`internal/runtime/*` was not classified as runtime code**, so half the
  runtime of a Go 1.24+ binary read as ordinary internal library code.

### Added

- `.go.type` / `.go.func` (`__go_type` / `__go_func`) section recognition. Go
  1.27 replaced `.typelink` / `.itablink` with these; their presence is a
  positive V5 signal and a Go detection marker
  (`ConfidenceSignal::TypeSectionPresent`).
- RELRO section names: `-buildmode=pie` / `c-shared` / `c-archive` prefix these
  with `.data.rel.ro`, which the classifier now strips. Previously every PIE
  binary looked like it had no type sections.
- `TFLAG_GC_MASK_ON_DEMAND` / `TFLAG_DIRECT_IFACE` / `TFLAG_REGULAR_MEMORY`
  with matching `AbiType` accessors. Go 1.27 deleted type-level GC programs and
  dropped `abi.MaxPtrmaskBytes` from 2048 to 16, so `Type.GCData` now usually
  addresses an empty BSS slot rather than a bitmap; `gc_mask_va` reports those
  as absent.
- `benches/extract.rs`, a `divan` suite over the fixture corpus with allocation
  profiling and stage-level benches (`stage_context`, `stage_buildinfo`,
  `stage_pclntab`).

### Changed - breaking

- `Moduledata::parse` takes a `LayoutHints` struct instead of a
  `(PclntabVersion, bool, Option<u32>)` tail.
- `types::extract_types_iter` takes the `&Moduledata` and a `TypeAbi` bundle
  instead of re-deriving both; `type_at_va` and `extract_all_types` follow.
- `TypeDetail::Map` carries `key_va` / `elem_va` / `group_va` plus a boxed
  `MapTypeExtra` tagged with the `MapLayout` it was read under. Fields a layout
  does not record are `None` rather than `0`. `GoType` shrank 392 → 176 bytes.
- `GoSections` gained `go_type`, `go_func`, `noptrdata`, `data_section` and
  `text_section`.
- moduledata discovery moved to `structures::locate::ModuledataLocator`,
  replacing three near-identical scan loops.

### Performance

Extraction is 47-74% faster and allocates about a fifth as much. `full_sweep`
(parse plus functions, types, itabs, strings, init order and embeds):

| Fixture         | Before   | After   |      | Allocations | Bytes             |
|-----------------|----------|---------|------|-------------|-------------------|
| ELF 1.26        | 4.80 ms  | 2.56 ms | −47% | 725 → 320   | 416 KB → 49 KB    |
| ELF 1.27        | 4.73 ms  | 2.53 ms | −47% | 1035 → 292  | 594 KB → 44 KB    |
| Mach-O stripped | 3.98 ms  | 1.90 ms | −52% | 1126 → 297  | 595 KB → 48 KB    |
| PE 1.27         | 10.42 ms | 3.11 ms | −70% | 1176 → 334  | 630 KB → 48 KB    |
| wasm 1.27       | 11.99 ms | 3.18 ms | −74% | 961 → 262   | 1.70 MB → 1.28 MB |

- The build-info magic scan walked the image twice, the "aligned" pass one byte
  at a time. Now one sweep, narrowed first to the regions that can hold a
  `SBUILDINFO` symbol: PE `parse` 4.10 ms → **160 µs**, wasm → 1.52 ms.
- `types()` / `all_types()` / `type_at()` re-ran moduledata discovery - scan
  included - on every call; they now reuse the parsed one: **−88% PE, −90% wasm**.
- `init_order()` indexed all ~1800 functions to resolve a dozen init PCs:
  **1.12 ms → 22 µs, 206 KB → 2.1 KB**.
- `embedded_assets()` allocated two `String`s per candidate entry for a
  compare-only sort key, re-read each word three times, and swept the
  executable section and pclntab: **2.12 ms → 361 µs, 401 allocations → 5**.
- `find_bytes` searches eight bytes at a time (SWAR), backing the build-ID,
  build-info and heuristic scans; the moduledata scan compares words, not
  slices.

### Test corpus

- `go127` fixtures rebuilt with **released go1.27.1**; `build.sh` no longer
  special-cases them via `gotip`. `go127` gained the variants it lacked against
  the `go126` anchor (`embed`, `cgo`, `minimal`, `_cover`, `_fips`, stripped),
  so those surfaces run against a V5 moduledata for the first time.
- New `go111` / `go112` / `go113` / `go123` fixtures complete the `abi.MapType`
  coverage; the sweep asserts all six eras are present.
- New `basic_go127_linux_amd64_pie` (RELRO names),
  `basic_go124_windows_amd64_noversion.exe` (scrubbed version) and
  `embed_go127_wasip1_wasm` (the one case where the address-space view is not
  the file) cover the inputs that exposed the bugs above.

## [0.4.1]

### Fixed

- Replaced a `match` that current clippy flags as expressible with `?` in
  `structures::types`. Behaviour is unchanged; the lint did not exist when CI
  last ran, and the workflow pins `@stable`, so it now fails the `-D warnings`
  gate on every build.

### Changed

- Recorded ATRAPS LLC as copyright holder and added a `NOTICE` file. No functional change.
- Dropped the deprecated `authors` field and repointed `repository` at the organisation.
- Refreshed transitive dependencies (`cargo update`); no direct dependency changed version.
- Publishing now uses crates.io trusted publishing instead of a stored registry token.

## [0.4.0]

### Added

Support for the legacy Go 1.2-1.15 binary layout, which previously parsed as
garbage (a Go 1.9.x binary produced millions of bogus source-file names and
unprintable "package" strings). The pre-1.16 pclntab and moduledata are
genuinely different structures, now parsed natively:

- `pclntab::parse_header_go12` handles the legacy "Go 1.2" pclntab (magic
  `0xfffffffb`): an 8-byte header (no structured `pcHeader`), a pointer-sized
  functab of absolute PCs, and the `[]uint32` `filetab` - the table that
  previously misparsed into millions of entries. Function names and the
  `pcsp`/`pcfile`/`pcln` tables are pcHeader-relative; `text_va` is recovered
  from the lowest function PC when no moduledata is present.
- `Moduledata::parse_go12_legacy` parses the V1 moduledata (Go 1.5-1.15) with
  per-minor field gating verified against `runtime/symtab.go`: `itablinks`
  (1.6), `types`/`typelinks []int32`/`typemap` (1.7), plugin fields (1.8),
  `hasmain`/`bad` (1.10). Go 1.2-1.4 have no moduledata and are left as such.
  The moduledata locators (in `lib` and `types`) validate the legacy layout
  through its `text` boundary, since it has no `funcnametab`.

Test infrastructure was consolidated and broadened: a single self-contained
`tests/samples/build.sh` builds a per-version fixture matrix spanning Go 1.2
through 1.27 across ELF / Mach-O / PE / Wasm, plus new `types`, `generics`, and
`cgo` harnesses that exercise the type-descriptor zoo, generic instantiations,
and CGO surfaces. The `mod matrix` / `mod harness` integration tests assert the
per-version pclntab and moduledata layouts and the advanced-feature extraction.

## [0.3.1]

### Fixed

Func-type descriptor parsing mislocated the trailing `UncommonType`. The
`funcType` struct is padded to pointer-size alignment before the inline
parameter array, but the parser skipped only the bare `FuncTypeExtra` (4
bytes), landing the `UncommonType` short by the padding. That read a
garbage `mcount` (up to `0xFFFF` from padding bytes), and resolving those
phantom methods followed garbage `mtyp` offsets into unrelated
descriptors - inflating `all_types()` from the ~850 genuinely-reachable
types to ~12.8k and surfacing stdlib structs not actually reachable from
typelinks.

- `build_go_type` now accounts for the alignment padding when sizing the
  `Func` extra (mirroring `descriptor::descriptor_size`), so the
  `UncommonType` is located correctly.
- `read_func_params` skips the `UncommonType` block when present, since Go
  places the inline parameter array *after* it (`abi.FuncType.InSlice`) -
  keeping the parameter VAs (and the types they reach) correct.
- `resolve_concrete_methods` / `resolve_interface_methods` now stop on the
  first empty/unresolved method name rather than fabricating thousands of
  empty methods when an over-run `mcount`/slice length walks past the real
  array. Both also drop the speculative `4096`-capacity pre-allocation.

## [0.3.0]

Go 1.27 support, plus five new extraction surfaces aimed at malware /
supply-chain triage. Verified end-to-end against a `go1.27-devel` toolchain
and committed sample fixtures (see `tests/samples/README.md`).

### Added

Go 1.27 ("V5") moduledata support - the upstream runtime removed the
`typelinks`/`itablinks` slices and now stores interface tables inline:

- `ModuledataVersion::V5` is fully parsed: `itaboffset`/`itabsize`,
  `typedesclen`, and the still-present `rodata`/`gofunc`/`inittasks` fields.
  The previous speculative V5 branch stopped at `etypes` and hardcoded
  `rodata`/`gofunc` to `None`, which **silently disabled** `inline_tree()`
  and `itab_pairs()` on Go 1.27 binaries - now fixed.
- `itab_pairs()` gained a third strategy: it walks the inline, variable-size
  itab records at `types + itaboffset` (Go 1.27+), in addition to the
  `.itablink` section and `moduledata.itablinks` slice used by Go ≤1.26.
- `parse_go_minor_version` now accepts pre-release toolchain strings
  (`go1.27-devel_…`, `go1.27rc1`), so V5 detection works before GA.

New extraction surfaces:

- `bin.fips_info() -> Option<FipsInfo>` - FIPS-140 mode (the `GOFIPS140`
  build setting) plus the `__go_fipsinfo` integrity sum. Returns `None` for
  non-FIPS builds (the integrity section is linked into every Go 1.24+
  binary, so it alone is not a FIPS signal).
- `bin.init_order() -> Vec<InitTask>` - package initialization order decoded
  from `moduledata.inittasks` (Go 1.24+), with init-function entry VAs
  resolved to names. Captured for both V4 and V5 layouts.
- `bin.embedded_assets() -> Vec<EmbeddedAsset>` - `//go:embed` payloads
  (path, dir flag, backing bytes) decoded from `embed.FS` `[]file` arrays.
  Symbol-independent (works on stripped binaries) and cross-format
  (ELF/Mach-O/PE/wasm); validated by enforcing `embed`'s canonical sort
  order and dir/file hash consistency to avoid false positives. The
  single-file `embed.String`/`embed.Bytes` form is not recovered (no anchor).
- `BuildInfo::deps_full()` and `BuildInfo::module_sum()` - surface the
  already-parsed `go.sum` hashes and `replace` directives that the
  `dependencies()` convenience iterator collapses (supply-chain analysis).

**Complete moduledata extraction.** The parser walks the whole struct to
locate types/itabs/funcdata but previously kept only a fraction; now every
field is captured (the caller decides what is useful), version-gated and
verified against go1.16-1.27 `runtime/symtab.go`:

- Data/bss segment boundaries (`noptrdata`/`data`/`bss`/`noptrbss` as
  `VaRange`), `end`, `gcdata`/`gcbss`, `covctrs` (`Option<VaRange>`),
  `typedesclen` (V5), `epclntab` (1.26+), `textsectmap`, `ptab`,
  `pluginpath`/`modulename` (`GoStr`), `pkghashes`/`modulehashes`, `has_main`,
  `bad`, `gcdatamask`/`gcbssmask` (`Bitvector`), `typemap`, and `next`.
- The version-divergent tail is handled correctly: `bad` sits between
  `typemap` and `next` before Go 1.24 but moves to right after `hasmain` in
  1.24+; the GC-mask `bitvector`s are pointer-aligned.
- New `GoBinary` accessors: `is_main_module()` (vs. plugin/shared),
  `module_name()`, `plugin_path()`, `is_coverage_build()` (detects `-cover`
  via a non-empty coverage-counter region).
- New public types `VaRange`, `Bitvector` (in `structures::moduledata`) and
  `GoStr` (in `structures::goslice`). The `dump` example prints a new "Module"
  section.

**Complete type-descriptor extraction.** `abi.Type` now captures the `Equal`
(equality-function) and `GCData` (GC-bitmap) pointers it previously skipped,
and `GoType` exposes the full descriptor: `descriptor_va` (its own VA), `tflag`
(raw flag byte), `ptr_to_this` (the `*T` `TypeOff`), `equal_va`, `gcdata_va`,
and `pkg_path` - the import path resolved from the `UncommonType` (distinct
from the name-derived `package()`).

The kind-specific `TypeDetail` variants and `MethodEntry` now carry every
parsed field: `Array.slice_va`; `Map.group_va`/`hasher_va`/`key_stride`/
`elem_stride`/`flags`; `Interface.pkg_path`; struct `StructField.tag` (the
decoded struct tag, e.g. `json:"id"`); and `MethodEntry.interface_text_offset`
(the `ifn` wrapper entry, alongside the `tfn` direct entry - both now correctly
treat the `-1` "no body" sentinel as `None`).

**Deep type / runtime enumeration.** New accessors:

- `bin.all_types()` - transitively enumerates **every** reachable type
  descriptor (BFS from the `typelink` seed set, following element / key /
  field / parameter / method / pointer-to-this references, each parsed
  independently by VA and bounded to `[types, etypes)`). Reaches types absent
  from `typelink` (e.g. a struct used only as a pointer's element, with its
  field tags). `bin.type_at(va)` parses a single descriptor by address.
- `bin.data_pointer_map()` / `bss_pointer_map()` - decode the `gcdata` /
  `gcbss` **GC programs** (`runGCProg` bytecode) into a per-word pointer
  bitmap: the precise location of every pointer in global memory (function
  pointers, `itab`/interface pointers, string/slice headers, global `*T`),
  recoverable without disassembly. New `gcprog::{run_gc_prog, PointerMap}`.
- `bin.modules()` - walk the `moduledata.next` linked list (one module for a
  normal static binary; defensive for multi-module images).
- `bin.itab_methods(pair)` - the `Fun[]` method-pointer array of an itab.
- `bin.text_sections()`, `bin.plugin_exports()` (ptab), `bin.package_hashes()`
  / `bin.module_hashes()` (per-package link-time ABI hashes) - decode the
  remaining moduledata sub-slices (`textsectmap`, `ptab`, `pkghashes`,
  `modulehashes`).
- `ParsedPclntab` gained `header_text_start` (the pcHeader `textStart` field,
  Go 1.18+).
- New name-decoder `decode_name_and_tag` (handles the struct-tag suffix, both
  varint and pre-1.17 encodings).

- **Mach-O chained-fixups support.** Externally-linked Mach-O objects (CGO /
  `-buildmode=plugin` / c-shared) store data pointers as
  `LC_DYLD_CHAINED_FIXUPS` chains rather than absolute values. The crate now
  walks those chains and rebases every pointer into an owned shadow image
  (`structures::macho_fixups`), so pointer-dependent extraction - types,
  itabs, `ptab` plugin exports, per-package hashes, plugin path - works on
  these objects exactly as on a pure-Go executable. Supports the
  `DYLD_CHAINED_PTR_64` and `DYLD_CHAINED_PTR_64_OFFSET` pointer formats.
  Pure-Go executables are unaffected (no fixups load command → no rebasing).

`Moduledata` gained `itaboffset`, `itabsize`, and `inittasks` fields. New
public types: `FipsInfo`, `InitTask`, `InitFunc` (in `metadata`),
`EmbeddedAsset` (in `structures::embed`), `TypeRef` (in `structures::types`).
The `dump` example prints a new "Runtime & Linker Surfaces" section.

### Changed

- **Breaking (type-name resolution):** `TypeDetail::Func` `inputs` /
  `outputs` changed from `Vec<u64>` to `Vec<TypeRef>` (VA **plus** resolved
  display name). `StructField`, `MethodEntry`, and `InterfaceMethod` each
  gained a `type_name: Option<&str>` field. Method/interface-method
  signature types are unnamed Go func types, so their `type_name` is usually
  `None` - resolve the offset to a `TypeDetail::Func` for the full,
  name-resolved signature. Leaf (param/field) types resolve to names.
- `itab::extract_iter` now takes `Option<&Moduledata>` instead of
  `Option<&GoSlice>` (it needs `itaboffset`/`itabsize` for V5).
- **goblin slimmed down.** Format detection now dispatches to the per-format
  parser (`elf::Elf`, `mach::MachO`, `pe::PE`) instead of the unified
  `goblin::Object::parse`, dropping the `te` (UEFI Terse Executable) default
  feature. PE parsing runs with `ParseOptions` that disable resource, import,
  certificate, and TLS parsing - none of which the crate reads - avoiding
  wasted work on Go binaries with large import/resource tables. No change to
  extracted data.

### Fixed

**Go 1.16-1.17 support** - the parser previously handled only Go 1.18+. The
pre-1.18 binary format is now decoded: the pcHeader without `textStart`, the
`2×ptrSize` functab with absolute PCs, the `_func` struct led by an absolute
`entry uintptr`, and the pre-1.17 type-name encoding (2-byte big-endian length
vs varint). `entry_off` is rebased against the first function's PC
(`ParsedPclntab::text_start`) so it stays relative across versions.

**`_func` struct layout is now version-accurate.** `startLine` was added in
Go 1.20, so the 1.18-1.19 `_func` is 40 bytes (not 44); the parser previously
assumed the 1.20 layout and mis-read `func_id` / `flag` / `nfuncdata` /
`start_line` for every 1.18-1.19 binary (function *names* were unaffected,
which hid it). Decoded via a version-gated `func_layout`.

Moduledata parsing across Go versions, surfaced by rebuilding the test corpus
against real go1.16 / 1.19 / 1.21 / 1.24 / 1.26 / 1.27 toolchains:

- **`rodata`/`gofunc` are gated to Go 1.18+**, separately from `covctrs`
  (Go 1.20+). They were previously gated together on the Go120 magic, so
  1.18-1.19 binaries read `typelinks`/`itablinks` two pointers early - breaking
  type/itab extraction on PE 1.18-1.19 (ELF/Mach-O were masked by the
  section-based path). Moduledata `V2` now means 1.16-1.17; `V3` is 1.18-1.25.

- **`epclntab` is gated to Go 1.26+** (it does not exist in 1.24 / 1.25). The
  old coarse "V4 = 1.24-1.26" mapping skipped a phantom `epclntab` pointer on
  1.24 / 1.25, shifting `typelinks`/`itablinks`/`inittasks` by one pointer and
  producing wrong (or empty) results. The walk is now driven by per-field
  version predicates; the `ModuledataVersion` boundaries are corrected
  (1.24/1.25 are V3, only 1.26 is V4).
- **`inittasks` is recognized from Go 1.21+** (was assumed 1.24+), so
  `init_order()` now works on 1.21-1.23 binaries.
- **Section-less moduledata discovery** (`find_moduledata_by_scan`): the
  dedicated `.go.module` section was only added in Go 1.26, so pre-1.26
  ELF / Mach-O binaries kept moduledata in `.noptrdata` with no section name.
  Discovery now falls back to a pcHeader-pointer scan for those (previously
  only PE / wasm did), restoring types, itabs, init order, and inline-tree
  resolution on Go 1.21-1.25 native binaries.
- `parse_go_minor_version` parses pre-release toolchain strings
  (`go1.27-devel_…`), fixing V5 detection before GA.

The fixture corpus was rebuilt reproducibly as a version × format matrix; the integration suite gained a `mod matrix` cross-version sweep. See `tests/samples/README.md`.

## [0.2.1]

Full WebAssembly container support, a broad set of public-API ergonomics
upgrades, and a redesigned pclntab caching model that does not leak memory.

### Added

WebAssembly support - `GOOS=js GOARCH=wasm` (and the newer `wasip1` Go 1.21+
target) now parses end-to-end with the same surface as ELF / Mach-O / PE:

- New `BinaryFormat::Wasm` variant; `\0asm` magic detection in
  `detect_format`.
- New `structures::wasm` module exposes a minimal section walker, a Data
  section segment decoder (`data_segments`), and a linear-memory image
  reconstructor (`build_linear_memory_image`). Several Go runtime
  structures (pcHeader, moduledata, type descriptors) span multiple
  disjoint segments in linear memory; the reconstructed image lets the
  same parsers that handle native formats address them by VA.
- pclntab parsing, function enumeration, type extraction, string scanning,
  inline-tree walking, and moduledata discovery all work on wasm. The
  Go-emitted `go:buildid` custom section is recognized; build ID and Go
  version extraction succeed. Test sample committed at
  `tests/samples/basic_wasm.wasm`.
- Adversarial wasm with absurd linear-memory offsets is gated behind a
  256 MiB sanity cap on the reconstructed image.

New accessors and ergonomics helpers:

- `bin.entry_va(func)` / `bin.entry_rva(func)` - fold
  `text_va + entry_off` (and the PE-only `image_base` subtraction) into
  one accessor so downstream disassemblers do not have to reimplement it.
  `BinaryContext::image_base()` exposed in support.
- `bin.arch()` - format-disambiguated architecture accessor that resolves
  the `(minLC=1, ptrSize=8)` ambiguity between `Arch::X86_64` and
  `Arch::Wasm` using the container format, and falls back to build-info
  `GOARCH` when no pclntab is present.
- `Display` and stable `as_str` on every public enum that downstreams
  persist: `Confidence`, `PclntabVersion`, `Arch`, plus `kind_str` on
  `TypeDetail` and `ObfuscationKind`. Stability contract documented
  on each type.
- `BuildMode::as_str() -> Cow<'static, str>` + `Display`, round-tripping
  through `BuildMode::parse`.
- `ParsedPclntab::decode_pcln_with_files(func)` - joined iterator yielding
  `(pc, line, file_path)` per source-line transition with the active file
  pre-attached, replacing the "walk pcln and pcfile in lockstep" loop
  callers otherwise reinvent.
- Direct `TypeDetail` accessors: `array_len`, `chan_dir`, `func_arity`,
  `struct_field_count`, `interface_method_count`.
- Stdlib / runtime classification on `GoType` (`is_runtime`, `is_internal`,
  `is_stdlib`) plus shared free helpers `is_runtime_path` /
  `is_internal_path` / `is_stdlib_path` so type-side and function-side
  classifications agree on one canonical rule.
- `FuncData::args_size() -> u32` - typed view of the raw signed `args`
  field (negative readings collapse to `0`).
- `GoString::as_bytes()` and `try_as_str() -> Result<&str, Utf8Error>`.
  The string scanner no longer silently drops non-UTF-8 length-prefixed
  payloads (common in malware rodata).

Address-space + caching internals:

- `BinaryContext::structure_search_data()` returns the wasm linear-memory
  image for wasm and the file bytes otherwise; `BinaryContext::va_to_file`
  produces offsets into this view for every format.
- `BinaryContext::slice_at_va(va)` - borrow a slice starting at the byte
  at virtual address `va`; spans wasm data-segment boundaries seamlessly.
- `PclntabMeta` - scalar metadata of a `ParsedPclntab` without the
  borrowed `data`. Cache it; rehydrate via `PclntabMeta::attach(data)`.
  `ParsedPclntab::meta()` extracts it.
- `ParsedPclntab` is now `Copy` (every field already was).

### Changed

`GoBinary` no longer caches a `ParsedPclntab` borrowing from the input.
Instead it caches the scalar `PclntabMeta` and rebuilds the borrowing
struct against `&self.ctx.structure_search_data()` per call. This is what
allows wasm support without a `Box::leak` - the wasm linear-memory image
is owned by `BinaryContext` and borrows handed out to callers tie to
`&self`.

- `GoBinary::pclntab(&self) -> Option<ParsedPclntab<'_>>` - was
  `Option<&ParsedPclntab<'a>>` (breaking). Method calls and
  `let Some(pcl) = ...` patterns are unchanged; sites that explicitly
  named the reference type must drop the `&`.
- `FunctionIter::new(pcl: Option<ParsedPclntab<'a>>)` - takes the struct
  by value (it's `Copy`) instead of by reference. The iterator is no
  longer parameterized on the pcl-borrow lifetime: `FunctionIter<'a>`
  (was `FunctionIter<'p, 'a>`).
- `TypeIter`, `ItabIter`, `GoStringIter`, `InlineTreeIter` - lost their
  `'ctx` / `'pcl` lifetime parameter; yielded items borrow from
  `&BinaryContext` (was the input lifetime). Callers that collect into a
  `Vec` keep working as long as they hold the `GoBinary`.
- `pclntab::parse(ctx)` now takes `&'a BinaryContext<'a>` - required so
  the returned struct can borrow from either the input bytes or the wasm
  linear-memory image with one lifetime.
- Stability-policy sections lifted to type-level rustdoc on `Confidence`,
  `BuildMode`, `ObfuscationKind`, `Arch`, `PclntabVersion`, `TypeDetail`:
  variants append-only, `Display` strings frozen, `Debug` not a stability
  surface.
- `bin.strings()` no longer pre-filters UTF-8. Use `GoString::try_as_str` /
  `as_str` for text or `as_bytes` for raw rodata.
- `ParsedPclntab::arch()` rustdoc clarified: `(1, 8)` always returns
  `Arch::X86_64`; use `GoBinary::arch()` for format-aware disambiguation.
- `text_va()` rustdoc no longer publishes a manual translation recipe -
  it points to the new `entry_va` / `entry_rva` instead.
- Lints moved from a `#![deny(...)]` attribute on `lib.rs` to a `[lints]`
  table in `Cargo.toml`, so they enforce on every consuming workspace
  build (not just standalone). Tests, examples, and the integration test
  binary explicitly `#![allow(...)]` the test-friendly subset.
- `InlineEntry::depth` rustdoc documents the realistic upper bound (real
  Go inline chains are < 5 deep; the walker caps at 32). Type stays `u32`
  for forward compatibility.

### Fixed

- Wasm binaries now report `Arch::Wasm` from `GoBinary::arch()`
  (previously misreported as `X86_64`, a side-effect of the
  `(minLC=1, ptrSize=8)` ambiguity).
- `examples/dump.rs`: `--explain` argv handling no longer panics if
  `argv[0]` is missing; SDK-file path arithmetic uses checked offsets.
- Workspace lint enforcement caught a handful of pre-existing lint
  violations in `examples/dump.rs` (indexing and arithmetic on
  input-derived values), now fixed.

### Documentation

- `BinaryFormat::Wasm` rustdoc explains why wasm gets a reconstructed
  linear-memory image, why `image_base = 0`, and why `text_va`/`etext_va`
  are PC values rather than file offsets.
- `BinaryContext` accessor block reordered (basic accessors → translation
  → address-space helpers → format-specific) with the wasm-aware members
  documented inline.
- Top-level `## Supported Formats` table now includes Wasm.
- All inline `crate::...` paths in code (not docs) hoisted to `use`
  statements at the top of their files.

## [0.2.0]

A large feature pass plus internal hardening for use in malware analysis
pipelines. **Many breaking API changes** - see *Removed* and *Changed*.

### Added - new extraction surfaces

- **Per-PC inlining tree** - `bin.inline_tree(func)` yields
  `inline::InlineEntry { pc_range, function_name, parent_pc, start_line,
  func_id, depth }` per PC range with cycle-safe parent-chain walk for
  depth computation.
- **Go string literal scanner** - `bin.strings()` yields `GoString<'a> {
  va, len, bytes }` for every `(ptr, len)` header that resolves to in-binary
  UTF-8. Recovers strings a generic byte-string extractor would miss or
  split on internal NULs.
- **Itab pairs** - `bin.itab_pairs()` yields `ItabPair { iface_type_va,
  concrete_type_va, hash, itab_va }` for every `(interface, concrete type)`
  pair the linker proved at build time.
- **Per-function inlining accessors** - `FuncData::func_off`,
  `ParsedPclntab::pcdata_at`, `ParsedPclntab::funcdata_at` for the
  variable-length tables after the `_func` 44-byte prefix.
- **Garble obfuscation detection** - `bin.obfuscation()` returns
  `ObfuscationKind { None, Garble { confidence }, Other { reason } }`;
  `bin.is_likely_garbled()` convenience.
- **Compiler identification** - `bin.compiler()` returns `Compiler { Gc,
  TinyGo, Gccgo, Unknown }`.
- **Cgo / concurrency presence** - `bin.has_cgo()` and
  `bin.uses_concurrency()` short-circuit on the first matching function.
  Per-call-site enumeration deferred (needs disassembler).
- **Runtime address accessors** - `bin.text_va()`, `bin.etext_va()` expose
  `runtime.text` / `runtime.etext` with documented translation recipe for
  `entry_off → VA / RVA`.
- **Runtime commit hash** - `bin.runtime_commit()` extracts the dev commit
  from `devel go1.X-<hash>` version strings.
- **Build mode / tags / dependencies** - `BuildInfo::build_mode()` returns
  `BuildMode` enum; `build_tags()` iterates `-tags`; `dependencies()` and
  `build_settings_iter()` provide iterator accessors.
- **Module replacements + sums** - `DepEntry { path, version, sum,
  replacement }` + `DepReplacement` parsed from modinfo `dep` /
  `=>` / sum lines.
- **Method extraction on types** - `GoType.methods: Vec<MethodEntry>` for
  every type with an `UncommonType`. Resolves names, type-descriptor
  offsets, text offsets, and exported flag.
- **Deep type structure** - `TypeDetail` extended with:
  - `Struct.fields: Vec<StructField>` with name / type VA / offset / embedded
  - `Interface.methods: Vec<InterfaceMethod>`
  - `Map { key_va, elem_va }`, `Pointer { elem_va }`, `Slice { elem_va }`,
    `Chan { dir, elem_va }`, `Array { len, elem_va }`
  - `Func { in_count, out_count, is_variadic, inputs: Vec<u64>,
    outputs: Vec<u64> }`
- **`FuncFlags` newtype** - `FunctionInfo::func_flags()` returns typed view
  of the `_func.flag` byte; `is_top_frame()`, `is_sp_write()`,
  `is_asm()`, `is_systemstack()` accessors.
- **Receiver parsing** - `FunctionInfo::receiver_type() ->
  Option<ReceiverSpec { name, pointer, generic_args }>` plus
  `method_name()` and `generic_args()` accessors.
- **Per-PC file resolution** - `ParsedPclntab::resolve_file_via_cu` is now
  `pub`; `decode_pcfile_paths(func)` streams `(pc, &str)` per inlined
  region.
- **Structured detection report** - `GoBinary::try_parse() ->
  Result<GoBinary, ParseError>` returning `ConfidenceReport` of typed
  `ConfidenceSignal` variants on success or failure. `bin.report()`
  accessor exposes the same on success.
- **Bulk function decoder** - `metadata::for_each_function(pcl, |info,
  tables|)` walks every function with reusable per-PC table buffers,
  amortizing allocation across the whole binary.
- **Fast detection** - `gobin::detect(&[u8]) -> bool` does magic-byte +
  buildinfo header check without invoking `goblin` parse.
- **`examples/dump --explain`** - prints structured detection report
  (Confidence tier + per-signal breakdown).
- **moduledata accessors** - `bin.moduledata()`, `Moduledata::rodata`,
  `Moduledata::gofunc` exposed.
- **Iterator-style API throughout** - `bin.functions()`, `bin.types()`,
  `bin.itab_pairs()`, `bin.strings()`, `bin.inline_tree()` are all true
  streaming iterators (`FunctionIter`, `TypeIter`, `ItabIter`,
  `GoStringIter`, `InlineTreeIter`). Per-PC table decoders likewise
  (`PcValueIter`, `PcLineIter`, `PcFileIter`, `PcFilePathIter`).
- **Property tests** - `package() + "." + short_name() == name` round-trip
  property test plus a corpus of well-known Go function-name shapes.
- **Centralized helpers** in `structures::util`: `slice_at::<N>`,
  `advance`, `advance_n`, `align_up`, `align_up_u64`, `read_uvarint`,
  `read_uintptr`, `read_u32`, `read_i32`, `read_u16` - single source of
  truth for offset arithmetic and primitive reads.

### Changed - borrowed metadata types (breaking)

All metadata types now borrow from the input binary via lifetime `'a`,
matching `FunctionInfo<'a>`. Callers that need to outlive the binary's
lifetime must `.to_owned()` at the boundary.

- `GoType` → `GoType<'a>` - `name: String` becomes `&'a str`; `methods:
  Vec<MethodEntry<'a>>`; `detail: TypeDetail<'a>`.
- `MethodEntry`, `StructField`, `InterfaceMethod` - same treatment.
- `BuildInfo` → `BuildInfo<'a>` - all string fields borrow from the modinfo
  blob.
- `DepEntry` → `DepEntry<'a>`, `DepReplacement` → `DepReplacement<'a>`.
- `GoBinary.go_version` and `GoBinary.build_id` - now `Option<&'a str>`
  storage; accessors return `Option<&'a str>`.

### Changed - name parsing rewrites (breaking semantics)

- `FunctionInfo::package()` and `short_name()` rewritten - boundary is now
  "first `.` after the last `/`" plus a `gopkg.in`-style `.vN` extension.
  Third-party functions like `github.com/spf13/cobra.(*Command).Run` now
  return `package = "github.com/spf13/cobra"` instead of `"github"`.
- `FunctionInfo::is_method()` - structural parser. Catches value-receiver
  methods (`time.Time.String`) the old `".("` substring heuristic missed,
  and excludes closures.
- `FunctionInfo::is_closure()` - strict: requires `.funcN` / `.gowrapN`
  numeric suffix and excludes asm-flagged functions.
- `decode_pcvalue` for pcfile - `decode_pcfile(func)` yields `(u32, u32)`
  (was `(u32, i32)`); file indices are unsigned.

### Changed - streaming-only iterator API (breaking)

Every `Vec`-returning method that had a streaming counterpart was dropped.
Iterators replace them under the same names:

- `bin.types() -> TypeIter` (was `Vec<GoType>`).
- `bin.itab_pairs() -> ItabIter` (was `Vec<ItabPair>`).
- `pclntab.decode_pcvalue / decode_pcln / decode_pcfile / decode_pcfile_paths`
  now return iterators (were `Vec`).
- `BuildInfo::build_tags() -> impl Iterator<Item = &'a str>` (was
  `Vec<&str>`).
- Internal helpers `for_each_function`, `bin.has_cgo()`,
  `bin.uses_concurrency()`, `bin.obfuscation()` now use the new iterators
  internally; `has_cgo` and `uses_concurrency` short-circuit on the first
  match.

To get an owned `Vec`, call `.collect()`.

### Changed - module renames

- `structures::gostring::GoString` → `GoStringHeader` (it was always just
  the `(ptr, len)` header pair). The `GoString<'a>` name now belongs to
  the public scanned-string type in `structures::strings`.

### Removed - legacy convenience APIs (breaking)

- `metadata::extract_functions(pcl) -> Vec<FunctionInfo>` - use
  `bin.functions()` or `FunctionIter::new(Some(pcl))`.
- `bin.types_iter()` / `bin.itab_pairs_iter()` aliases - the canonical
  names (`bin.types()` / `bin.itab_pairs()`) now return the iterators.
- `pclntab.decode_pcvalue_into / decode_pcln_into / decode_pcfile_into`
  buffer-reuse variants - use `buf.clear(); buf.extend(decode_*(...))`
  with the streaming iterators (same allocation behavior).
- `ParsedPclntab::read_ptr` - was dead code internally.

### Fixed

- `read_pointer_array` and several other internal helpers now bounds-check
  every read.
- Heuristic obfuscation thresholds ignore runtime / internal packages so
  the ratio reflects user code only.
- Buildinfo modinfo parser now handles `=>` replacement lines and `dep`
  sum-hash columns it previously ignored.
- `gopkg.in/yaml.v3.Marshal`-style names no longer split as
  `package = "gopkg.in/yaml"` (now `"gopkg.in/yaml.v3"`).

### Security - panic-free lint sweep

This crate is used for malware analysis: every input byte is adversarial
and must not be allowed to panic the parser.

- Adopted `#![deny(missing_docs, clippy::unwrap_used, clippy::expect_used,
  clippy::panic, clippy::arithmetic_side_effects, clippy::indexing_slicing)]`
  in `lib.rs` (test code allows them).
- Swept **413 violations** across all 22 source files to zero. Every
  indexing operation now uses `.get(...)?`, every arithmetic on
  input-derived values uses `checked_*` / `saturating_*` per intent, every
  `unwrap` outside tests is replaced with `?` propagation.
- Wrapping arithmetic preserved where intentional (the pcvalue zigzag
  decoder matches Go's runtime behaviour) with explanatory comments.

A non-malicious adversarial binary can no longer panic the parser through
any `parse` / `extract` / `decode` path. Failures degrade to `None` /
`Err` / empty iterator / zero items.

### Documentation

- `examples/dump.rs` extended with `--explain` mode; updated for the
  iterator-first API and borrowed metadata types.
- `bin.text_va()` doc now includes the `entry_off` translation recipe.
- pclntab parser docs reference exact Go runtime source line ranges.

### Coverage

- 222 tests pass (130 unit + 88 integration + 4 doc).
- Property tests cover `package()` / `short_name()` invariants.
- Integration tests verify zero-copy borrowing (asserting `BuildInfo`
  fields' pointers fall inside the input slice).
- Inline-tree decoder exercised on the basic_normal corpus: 1,979
  functions with inlining, 24,438 entries, depth distribution
  `{0: 17686, 1: 5604, 2: 1022, 3: 124, 4: 2}`.
- String scanner verified across Mach-O / ELF / PE plus stripped
  binaries (1k-1.5k unique strings recovered per binary).

## [0.1.0] - initial release

Initial public release.

- Detection of ELF, Mach-O, and PE Go binaries.
- pclntab parsing with magic-byte + structural-fallback strategies.
- Build info, build ID, Go version extraction.
- Function metadata (`FunctionInfo`) and source file resolution.
- Type descriptor extraction via `.typelink` and descriptor walking.
- Heuristic confidence scoring (`Confidence` enum).

[0.5.1]: https://github.com/ATRAPSLLC/gobin/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/ATRAPSLLC/gobin/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/ATRAPSLLC/gobin/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ATRAPSLLC/gobin/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/ATRAPSLLC/gobin/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/ATRAPSLLC/gobin/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/ATRAPSLLC/gobin/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/ATRAPSLLC/gobin/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ATRAPSLLC/gobin/releases/tag/v0.1.0
