# gobin

Static analysis library for Go compiled binaries.

This crate extracts metadata that the Go runtime embeds in every binary:
function names, source file paths, Go version, module dependencies, build
settings, and type descriptors. All of this survives stripping
(`-ldflags="-s -w"`) because the runtime needs it at execution time.

## Quick start

```rust
use gobin::GoBinary;

let data = std::fs::read("some_go_binary").unwrap();
if let Some(bin) = GoBinary::parse(&data) {
    println!("Go version: {}", bin.go_version().unwrap_or("unknown"));
    println!("Functions:  {}", bin.function_count().unwrap_or(0));

    for f in bin.functions() {
        println!("  {}", f.name);
    }
}
```

## What it parses

- **Format detection** for ELF, Mach-O, PE, and WebAssembly binaries, and the slices of universal (fat) Mach-O files
- **Build ID** extraction (ELF note + raw text-segment marker)
- **Build info** blob: Go version, module path, dependencies, build settings (GOOS, GOARCH, VCS info)
- **pclntab** (PC/line table): function names, entry offsets, each function's own source file and lines (code inlined into it left out), the per-PC inlining tree with each call site, and the per-function data blocks: argument layouts, open-coded defers, stack objects, GC pointer maps, wrapper targets
- **Type descriptors**: `abi.Type` structs via `.typelink` section or moduledata walking, with resolved parameter/field type names and methods resolved to their functions, plus a scan of the type region for descriptors only code reaches (closure contexts)
- **Interface tables** (itabs): every `(interface, concrete type)` pair the linker proved, each method resolved to the function it binds
- **Runtime hooks**: the runtime entries `go`, channel, `select`, `defer`, `panic`, cgo and system-call operations compile to, for matching call sites
- **Container symbols**: the functions and globals the linker named (ELF / Mach-O / PE), with addresses, sizes and kinds
- **Coverage metadata** of `-cover` builds: each instrumented package's functions and the source blocks their counters count, with decoders for stripped builds that work from a disassembler's findings
- **Build attribution**: `GOEXPERIMENT` changes, and the GOROOT, module cache, GOPATH, main directory and home an untrimmed build records
- **`//go:embed` assets**: embedded file paths and bytes (works stripped, all formats)
- **Package init order** from `moduledata.inittasks`
- **FIPS-140 mode** (`GOFIPS140`) and the `__go_fipsinfo` integrity sum
- **Module supply-chain detail**: `replace` directives and `go.sum` hashes
- **Architecture inference** from pclntab header fields (`minLC`, `ptrSize`)
- **Confidence scoring**: High (structural proof), Medium (version string), Low (heuristic)

Tested against binaries from Go 1.2 through Go 1.28 (tip), including the Go
1.27 ("V5") moduledata layout that drops the `typelinks`/`itablinks` slices and
stores interface tables inline. Type descriptors and itabs are read from Go 1.7.

## Example tool

The included `dump` example produces a full metadata dump of a Go binary:

```sh
cargo run --example dump -- path/to/go_binary
```

## Fuzzing

`fuzz/` holds three [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
targets (nightly toolchain; run locally, not in CI). Each one calls every
public accessor on what it parses:

- `parse`: arbitrary bytes through detection and parsing.
- `decoders`: the decoders that take a standalone blob (coverage metadata,
  FUNCDATA blocks, names, build info strings, wasm sections, GC programs).
- `mutate`: fixtures from `tests/samples` with byte patches aimed at their Go
  structures (pclntab, moduledata, type descriptors, build info, coverage
  blobs), so the container stays valid and the damage reaches the Go decoders.

```sh
cd fuzz
cargo +nightly fuzz run parse -- -max_len=65536 -timeout=10
cargo +nightly fuzz run decoders -- -max_len=65536 -timeout=10
# gobin has no unsafe code; without a sanitizer `mutate` runs about 4x faster.
cargo +nightly fuzz run -s none mutate -- -timeout=15
```

## Disclaimer

The Go binary format is defined by the Go compiler and runtime source code
(`src/runtime/`, `src/internal/abi/`, `src/cmd/link/`). Structure layouts and
field semantics in this crate are derived from the Go source tree across
releases, including the Go 1.27 development tree for the V5 moduledata layout.
The pclntab format has been stable across versions with well-defined magic
numbers for version detection, but future Go releases may introduce changes.

## License

Copyright 2026 ATRAPS LLC. Licensed under the Apache License,
Version 2.0. See `LICENSE` and `NOTICE`.
