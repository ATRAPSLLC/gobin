# Test samples

Reproducible binary fixtures for the integration suite. This directory is
excluded from the published crate (`exclude = ["tests/samples/"]` in
`Cargo.toml`), so size is not a concern.

The corpus sweeps **every parser-relevant Go version from 1.2 through 1.27**,
plus the unreleased Go 1.28 (`go128`, built from a tip toolchain), across
formats (ELF / Mach-O / PE / Wasm) and a set of feature harnesses. The
integration suite's `mod matrix` discovers fixtures by filename, so editing the
matrix in `build.sh` automatically extends test coverage.

## Naming

```
<prog>_go<minor>_<goos>_<goarch>[_variant][.exe]
```

`variant` ∈ `stripped` (`-ldflags="-s -w"`), `cover` (`-cover`; `basic_go120`
is the coverage format's first release), `fips`
(`GOFIPS140`), `pie` (`-buildmode=pie`), `cgobindings`
(`CGO_ENABLED=bindings`), `noversion` (a post-processed copy with the Go version
string overwritten); variants combine (`_cover_stripped`).
`basic_go128_darwin_universal` is a universal Mach-O file of
`basic_go128_darwin_amd64` and `basic_go128_darwin_arm64`, assembled by
`make_universal` in `build.sh` as `lipo` would (lipo needs a darwin host);
the corpus scan skips it, as it holds two images. `.exe` = PE/Windows. Every backbone fixture is
`linux/amd64`; the `go116/go120/go124/go126/go127/go128` anchors additionally
get cross-compiled `darwin/arm64` (Mach-O), `windows/amd64` (PE), and
`wasip1/wasm`. `go121`, `go123` and `go128` add `linux/386`, and `go128` the
only `js/wasm`.

## Version → layout

The Go minor version maps to a pclntab + moduledata layout the parser must
detect (one `basic_go<minor>_linux_amd64` fixture per row, plus the variants):

| Tags                | pclntab | Moduledata | Boundary the version pins                         |
|---------------------|---------|------------|---------------------------------------------------|
| `go12`, `go14`      | Go12    | none       | pre-moduledata (added 1.5), pre-types (added 1.7) |
| `go15`              | Go12    | V1         | V1 head with no `types`/`itablinks` (`[]*_type`)  |
| `go17`, `go18`      | Go12    | V1         | +types/typelinks/typemap (1.7); +plugin/textsect (1.8) |
| `go19`              | Go12    | V1         | V1 tail without `hasmain`/`bad`                   |
| `go110`,`go111`,`go112`,`go113`,`go115` | Go12 | V1 | full V1 (+hasmain/bad 1.10; +funcID 1.12)  |
| `go116`, `go117`    | Go116   | V2         | new pcHeader / functab / `_func`                  |
| `go118`             | Go118   | V3         | u32 functab offsets, `_func` +flag; +rodata/gofunc |
| `go120`,`go121`,`go123`,`go124`,`go125` | Go120 | V3 | `_func` +startLine; +covctrs (1.20), +inittasks (1.21) |
| `go126`             | Go120   | V4         | +epclntab, `.go.module` section                   |
| `go127`             | Go120   | V5         | inline itabs, no typelinks, `.go.type`/`.go.func` sections |
| `go128` (tip)       | Go120   | V5         | wasm PCs at `1<<63`; `CGO_ENABLED=bindings`         |


The corpus separately pins the `abi.MapType` layout, which has changed **six**
times and is not tied to the moduledata version - so each era needs its own
fixture. The integration test `types::map_descriptors_use_the_layout_of_their_go_version`
sweeps the whole corpus and additionally asserts that all six eras are present,
so this coverage cannot be lost silently:

| Tags                        | Map layout         | What changed at the boundary               |
|-----------------------------|--------------------|--------------------------------------------|
| `go17`, `go110`             | `HmapWithHmapType` | `Key, Elem, Bucket, Hmap` + a bool tail    |
| `go111`                     | `HmapBools`        | Go 1.11 drops the `Hmap` type pointer      |
| `go112`, `go113`            | `HmapFlags`        | Go 1.12 folds the bools into `flags uint32`|
| `go115`…`go123`             | `HmapHasher`       | Go 1.14 adds the `Hasher` pointer          |
| `go124`, `go125`, `go126`   | `Swiss`            | Go 1.24 replaces buckets with Swiss tables |
| `go127`                     | `SwissSplitGroup`  | Go 1.27 adds explicit key/elem strides     |

The flag *bits* were renumbered at the Swiss boundary too, so `MapTypeExtra`
normalizes them; `go120` (`hashMightPanic` on an interface-keyed map) and
`go126` exercise both encodings.

## Programs (sources under `src/`)

- `src/basic/` - the primary fixture, **byte-for-byte source-identical across
  every Go release from 1.2**: `main.main`, `main.worker`,
  `main.(*TestStruct).DoSomething` (both `//go:noinline` so the symbols survive
  every version), interfaces with multiple implementors (itabs), a goroutine +
  channel, `defer`, a closure, struct tags, `fmt`/`reflect`/`strings`. Also the
  source for the `_cover`, `_fips`, and wasm fixtures.
- `src/types/` - the full type-descriptor zoo: every `TypeDetail` kind
  (struct/map/chan-all-directions/slice/array/pointer/func-variadic) funnelled
  through `reflect.TypeOf` so each descriptor is reachable.
- `src/generics/` - Go generics (≥1.18): generic functions and types
  instantiated at multiple concrete types (`//go:noinline`), so the
  shape-stenciled instantiations (`main.Sum[go.shape.int]`,
  `main.(*Stack[…]).Push`, `main.Pair[string,int]`) are emitted.
- `src/cgo/` - a CGO build (`CGO_ENABLED=1`, needs host `gcc`), exercising the
  `_cgo_*` / `_Cfunc_*` shim symbols and the `CGO_ENABLED` build setting.
- `src/embed/` - `//go:embed assets/*` (multi-file `embed.FS` with a nested dir
  and a binary blob) plus a single-file `//go:embed` string.
- `src/minimal/` - smallest useful program (no `fmt`); near-empty metadata.
- `src/deps/` (with the module it imports, `src/greet/`) - the one fixture
  built without `-trimpath`, in module mode, so its source paths name where
  the build ran (`deps_go128_linux_amd64`, from `build_deps` in `build.sh`).
  The dependency is served from a local file proxy (no network). The
  compiler's `-trimpath=old=>new` rewrite places the build at `/home/gobin`
  and GOROOT at `/usr/local/go`, so the recorded paths are
  `/usr/local/go/src/...`, `/home/gobin/go/pkg/mod/example.com/greet@v1.0.0/`
  and `/home/gobin/src/deps/`; the build info records that rewrite, which
  names only the script's cache directory. Built with
  `GOEXPERIMENT=arenas,nogreenteagc`, so its version ends
  ` X:arenas,nogreenteagc`. `deps_go128_linux_amd64_cover` instruments both of
  its packages (`-cover -coverpkg=example.com/...`), and
  `deps_go128_linux_amd64_cover_stripped` is the same build with `-s -w`: the
  same layout, with the coverage metadata reachable only from code.
- `src/plugin/` - a `-buildmode=plugin` Go plugin. Built natively on darwin
  (CGO) it is a Mach-O dylib using **chained fixups**
  (`plugin_go126_darwin_arm64.so`); see below.

## Adversarial variants

These fixtures cover inputs a triage pipeline actually sees, where the
parser cannot fall back on the usual markers:

- **`basic_go127_linux_amd64_pie`** - `-buildmode=pie` prefixes every
  read-only-relocatable Go section with `.data.rel.ro`
  (`.data.rel.ro.go.type`, and pre-1.27 `.data.rel.ro.typelink`). Without the
  prefix stripping in `formats::classify_section`, a PIE binary looks like it
  has no type sections at all.
- **`embed_go127_wasip1_wasm`** - the only fixture where the address-space
  view is not the file. `embed.FS` recovery searches the reconstructed
  linear-memory image, so any attempt to narrow that search with file-offset
  section ranges finds nothing - silently, because a binary with no embeds
  legitimately returns an empty list.
- **`basic_go124_windows_amd64_noversion.exe`** - a byte-identical copy of
  `basic_go124_windows_amd64.exe` with every `go1.24` literal zeroed, the way an
  obfuscator leaves one. PE never carries a `.typelink` section at any Go
  version, so with no version string the only layout hint points at the Go 1.27
  moduledata; the fixture pins the structural arbitration that stops the parser
  acting on it. Generated by `build.sh` from the intact binary, not by a
  toolchain.
- **`basic_go121_linux_386_noversion`** - `basic_go121_linux_386` with its
  `go1.21` literals zeroed. Without a version, the parser tells a Go 1.10-1.22
  itab (padded) from a Go 1.23+ one by the word after `hash`: zero padding in
  the first, the first method word in the second.

## Rebuilding

`build.sh` is the single, self-contained builder. It runs on a **linux/amd64
host** (e.g. `ssh dev-linux`) and downloads each Go toolchain from go.dev on
demand - no system Go, no container engine, no `golang.org/dl` helpers. A linux
host is required because the pre-1.16 toolchains have no darwin/arm64 build (and
crash under qemu user-emulation), while every modern format cross-compiles
cleanly from linux.

```sh
./build.sh                 # build the whole matrix
./build.sh go12 go126      # only these version tags
./build.sh --list          # print the planned fixture set and exit
GOTIP_ROOT=~/go-tip ./build.sh go128   # the unreleased tag, from a tip checkout
```

The `go128` tag is built from a local tip toolchain: `$GOTIP_ROOT` (a Go
checkout after `src/make.bash`), else `$HOME/sdk/gotip` (`gotip download`).
Without one it is skipped. The checked-in `go128` fixtures were built at tip
commit `2dbf8b413a` (2026-11-20); once Go 1.28 ships they are rebuilt from the
release and the tag pinned to it like the others.

One fixture needs a host the script cannot assume:

- **`plugin_go126_darwin_arm64.so`** needs CGO + a darwin C toolchain for the
  Mach-O chained-fixup test, so it is built on a mac:
  ```sh
  ( cd src/plugin && CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
      go build -trimpath -buildmode=plugin -o ../../plugin_go126_darwin_arm64.so . )
  ```

Embedded source paths are trimmed so no build-host paths leak in: Go ≥1.13 uses
the `-trimpath` build flag, and Go 1.4-1.12 use `-gcflags=-trimpath=<dir>` (the
fixture programs are pure Go), both reducing the path to `main.go` /
`command-line-arguments/main.go` / `./main.go`. Only **Go 1.2** (`go12`) embeds
the build-cache path - its `6g` compiler predates path trimming entirely.
Tests match source files by basename, so the exact form is irrelevant.
