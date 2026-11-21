#!/usr/bin/env bash
#
# Rebuild every test fixture under tests/samples/ from the sources in src/.
#
# ONE script for the whole corpus. It runs on a linux/amd64 host and is fully
# self-contained: it downloads each released Go toolchain from go.dev on demand
# - no system Go, no container engine, no gotip bootstrap. A linux host is used
# because the pre-1.16 toolchains
# have no darwin/arm64 build (and crash under qemu user-emulation), while every
# modern format (Mach-O / PE / Wasm) cross-compiles cleanly from linux. The cgo
# harness needs a host C compiler (gcc), which a linux/amd64 box has.
#
# The primary fixture program (`src/basic/main.go`) compiles unchanged on every
# Go release from 1.2 onward, so a single program anchors uniform assertions
# across the whole version matrix. Additional harnesses exercise advanced,
# extractable features (see src/): `types` (the full type-descriptor zoo),
# `generics` (type parameters, >=1.18), `cgo` (a CGO build), plus `embed`,
# `minimal`, and `plugin`.
#
# Fixtures are named  <prog>_go<minor>_<goos>_<goarch>[_variant][.exe].
# The integration suite's `mod matrix` discovers them by filename, so editing
# the matrix below automatically extends test coverage.
#
# Usage:
#   ./build.sh                 # build the whole matrix
#   ./build.sh go12 go126      # only these version tags
#   ./build.sh --list          # print the planned fixture set and exit
#
# One fixture is NOT produced here: plugin_go126_darwin_arm64.so. A Go plugin
# needs CGO and -buildmode=plugin, and a darwin/arm64 plugin requires a darwin
# C toolchain (for the Mach-O chained-fixup test). Build it on a mac with:
#   ( cd src/plugin && CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
#       go build -trimpath -buildmode=plugin -o ../../plugin_go126_darwin_arm64.so . )
#
set -uo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT_DIR:-$SELF_DIR}"
SRC="$SELF_DIR/src"
CACHE="${GO_DL_CACHE:-${TMPDIR:-/tmp}/gobin-toolchains}"
WORK="$CACHE/work"
DL_BASE="https://go.dev/dl"

mkdir -p "$OUT" "$CACHE" "$WORK"

# ---------------------------------------------------------------------------
# Version matrix: tag -> full toolchain version. Every tag is built as
# linux/amd64 (the backbone that exercises the version-gated parsing).
#
# Why each version earns a slot (parser-relevant boundaries):
#   go12  1.2.2   Go12 pclntab; pre-moduledata, pre-types, pre-funcID
#   go14  1.4.3   last pre-moduledata
#   go15  1.5.4   moduledata (V1) introduced; pre-types (typelinks []*_type)
#   go17  1.7.6   +types/etypes, typelinks []int32, typemap
#   go18  1.8.7   +textsectmap, ptab, pluginpath, pkghashes
#   go19  1.9.7   V1 tail without hasmain/bad
#   go110 1.10.8  +hasmain, +bad
#   go111 1.11.13 maptype drops the `hmap` type pointer
#   go112 1.12.17 _func gains funcID; maptype bools collapse into `flags`
#   go113 1.13.15 last maptype without `hasher` (added in 1.14)
#   go115 1.15.15 last Go12-pclntab release
#   go116 1.16.15 new pcHeader (magic Go116); moduledata V2
#   go117 1.17.13 last Go116-magic
#   go118 1.18.10 magic Go118; _func +flag; moduledata V3; generics
#   go120 1.20.14 magic Go120; _func +startLine; +covctrs
#   go121 1.21.13 +inittasks; wasip1
#   go123 1.23.12 interior V3 sample
#   go124 1.24.13 GOFIPS140 available
#   go125 1.25.11 interior V3 sample
#   go126 1.26.4  moduledata V4 (+epclntab)
#   go127 1.27.1  moduledata V5 (-typelinks/-itablinks, +typedesclen,
#                 +itaboffset/itabsize); `.go.type`/`.go.func` sections;
#                 abi.MapType gains the split-group stride fields; newest
#                 stable anchor
#   go128 tip     unreleased Go 1.28, built from a local tip toolchain (see
#                 fetch_toolchain; skipped without one): wasm PCs move to
#                 1<<63 (text no longer overlaps linear memory),
#                 CGO_ENABLED=bindings, darwin records -buildmode=pie. The
#                 checked-in go128 fixtures were built at tip commit
#                 2dbf8b413a (2026-11-20); rebuild them from go1.28.0 once
#                 it ships and pin the release here.
# ---------------------------------------------------------------------------
VERSIONS=(
  "go12:1.2.2"   "go14:1.4.3"   "go15:1.5.4"   "go17:1.7.6"   "go18:1.8.7"
  "go19:1.9.7"   "go110:1.10.8" "go111:1.11.13" "go112:1.12.17" "go113:1.13.15"
  "go115:1.15.15"
  "go116:1.16.15" "go117:1.17.13" "go118:1.18.10" "go120:1.20.14"
  "go121:1.21.13" "go123:1.23.12" "go124:1.24.13" "go125:1.25.11" "go126:1.26.4"
  "go127:1.27.1" "go128:tip"
)

# Anchor versions that get cross-compiled format variants. Mach-O/PE build from
# any toolchain; darwin/arm64 needs >= 1.16; wasip1 needs >= 1.21.
FORMAT_ANCHORS=("go116" "go120" "go124" "go126" "go127" "go128")
WASIP1_ANCHORS=("go121" "go124" "go126" "go127" "go128")
# Versions that get a `types` harness (the type system arrived in Go 1.7).
# `go123` and `go126` bracket the two `abi.MapType` layout changes (buckets ->
# Swiss in 1.24, Swiss -> split-group strides in 1.27), which the map-descriptor
# stride assertions in `mod matrix` depend on.
TYPES_VERSIONS=(
  "go17" "go110" "go111" "go112" "go113" "go116" "go120" "go123" "go126" "go127"
  "go128"
)
# Versions that get a `generics` harness (type parameters arrived in Go 1.18).
GENERICS_VERSIONS=("go118" "go120" "go124" "go126" "go127" "go128")
# Versions that get a `cgo` harness (linux/amd64, CGO_ENABLED=1 + host gcc).
CGO_VERSIONS=("go116" "go126" "go127")

# Minor version of a tag/full-version string ("1.9.7" -> 9, "go116" -> 16).
minor_of() {
  local v="${1#go1}"; v="${v#1.}"; echo "${v%%.*}"
}
in_list() { local x=$1; shift; local e; for e in "$@"; do [[ "$e" == "$x" ]] && return 0; done; return 1; }

list_only=0; SELECT=()
for a in "$@"; do
  case "$a" in --list) list_only=1 ;; *) SELECT+=("$a") ;; esac
done
selected() {
  [[ ${#SELECT[@]} -eq 0 ]] && return 0
  local t; for t in "${SELECT[@]}"; do [[ "$t" == "$1" ]] && return 0; done; return 1
}

# Download + extract a toolchain into the cache (idempotent); echo its GOROOT.
fetch_toolchain() {  # fetch_toolchain <full-version>
  local v="$1"
  # An unreleased dev toolchain (the *next* Go, tracked ahead of its release)
  # is taken from $GOTIP_ROOT, else $HOME/sdk/gotip. Bootstrap one with
  # `go install golang.org/dl/gotip@latest && gotip download`, or build a Go
  # checkout's `src/make.bash` and point GOTIP_ROOT at the checkout.
  if [[ "$v" == "tip" ]]; then
    local tip="${GOTIP_ROOT:-$HOME/sdk/gotip}"
    [[ -x "$tip/bin/go" ]] && echo "$tip" || return 1
    return 0
  fi
  local root="$CACHE/go$v"
  if [[ ! -x "$root/go/bin/go" ]]; then
    local tgz="$CACHE/go$v.linux-amd64.tar.gz"
    [[ -s "$tgz" ]] || { echo "  ↓ go$v" >&2; curl -fsSL -o "$tgz" "$DL_BASE/go$v.linux-amd64.tar.gz" || return 1; }
    mkdir -p "$root"; tar -C "$root" -xzf "$tgz" || return 1
  fi
  [[ -x "$root/go/bin/go" ]] && echo "$root/go"
}

ok=0; fail=()
# build <tag> <ver> <prog> <goos> <goarch> <variant> [build args / KEY=VAL env]…
build() {
  local tag=$1 ver=$2 prog=$3 goos=$4 goarch=$5 variant=$6; shift 6
  local m
  if [[ "$ver" == "tip" ]]; then m="$(minor_of "$tag")"; else m="$(minor_of "$ver")"; fi
  local name="${prog}_${tag}_${goos}_${goarch}${variant}"
  [[ "$goos" == "windows" ]] && name="${name}.exe"
  if [[ $list_only -eq 1 ]]; then echo "  $name"; return 0; fi

  local goroot; goroot="$(fetch_toolchain "$ver")"
  if [[ -z "$goroot" ]]; then echo "  !! $name: no go$ver toolchain"; fail+=("$name"); return 0; fi

  local bdir="$WORK/$prog"
  # Keep build-host paths out of the committed fixtures. The `-trimpath` build
  # flag exists from Go 1.13; Go 1.4-1.12 predate it but their gc compiler
  # accepts `-gcflags=-trimpath=<dir>`, which strips the build dir so embedded
  # source paths reduce to "main.go" (the fixture programs are pure Go, so no
  # `-asmflags` is needed). Only Go 1.2's `6g` has neither and embeds the
  # (fixed, build-cache) path - a single fixture, by necessity.
  local flags=()
  if [[ "$m" -ge 13 ]]; then
    flags+=("-trimpath")
  elif [[ "$m" -ge 4 ]]; then
    flags+=("-gcflags=-trimpath=$bdir")
  fi
  # GOTOOLCHAIN=local (>=1.21) pins the build to the invoked toolchain.
  local pin=(); [[ "$m" -ge 21 ]] && pin+=("GOTOOLCHAIN=local")

  local args=() envs=() a
  for a in "$@"; do
    if [[ "$a" == *=* && "$a" != -* ]]; then envs+=("$a"); else args+=("$a"); fi
  done

  # Copy the whole program dir (so go:embed assets travel with main.go), but
  # drop go.mod - every build runs in GOPATH mode (GO111MODULE=off) and a stray
  # module file would only confuse the older toolchains.
  rm -rf "$bdir"; mkdir -p "$bdir"
  cp -r "$SRC/$prog/." "$bdir/"; rm -f "$bdir/go.mod"
  echo "  $name"
  # Hardcoded defaults come first; per-call envs (e.g. CGO_ENABLED=1) override.
  if ( cd "$bdir" && env \
        GOROOT="$goroot" GOPATH="$CACHE/gopath" GOCACHE="$CACHE/gocache" \
        GO111MODULE=off CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        "${pin[@]}" "${envs[@]}" \
        "$goroot/bin/go" build "${flags[@]}" "${args[@]}" -o "$OUT/$name" main.go ) \
      && [[ -s "$OUT/$name" ]]; then
    ok=$((ok + 1))
  else
    echo "    !! build failed"; rm -f "$OUT/$name"; fail+=("$name")
  fi
}

[[ $list_only -eq 0 ]] && echo "Building fixtures into $OUT (linux host, go.dev toolchains)…"

for entry in "${VERSIONS[@]}"; do
  tag="${entry%%:*}"; ver="${entry##*:}"
  if [[ "$ver" == "tip" ]]; then m="$(minor_of "$tag")"; else m="$(minor_of "$ver")"; fi
  selected "$tag" || continue
  # The unreleased tag needs a local tip toolchain; without one it is skipped
  # rather than failed, so a plain rebuild works on any host.
  if [[ "$ver" == "tip" && $list_only -eq 0 ]] && ! fetch_toolchain tip >/dev/null; then
    echo "  (skipping $tag: no tip toolchain; set GOTIP_ROOT)"
    continue
  fi

  # Backbone: every version as linux/amd64.
  build "$tag" "$ver" basic linux amd64 ""

  # Format variants on anchor versions.
  if in_list "$tag" "${FORMAT_ANCHORS[@]}"; then
    [[ "$m" -ge 16 ]] && build "$tag" "$ver" basic darwin arm64 ""
    build "$tag" "$ver" basic windows amd64 ""
  fi
  in_list "$tag" "${WASIP1_ANCHORS[@]}" && build "$tag" "$ver" basic wasip1 wasm ""

  # Advanced-feature harnesses.
  in_list "$tag" "${TYPES_VERSIONS[@]}"    && build "$tag" "$ver" types    linux amd64 ""
  in_list "$tag" "${GENERICS_VERSIONS[@]}" && build "$tag" "$ver" generics linux amd64 ""
  in_list "$tag" "${CGO_VERSIONS[@]}"      && build "$tag" "$ver" cgo      linux amd64 "" CGO_ENABLED=1

  # Feature / stripped variants.
  case "$tag" in
    go110) build "$tag" "$ver" basic linux amd64 "_stripped" -ldflags "-s -w" ;;  # stripped legacy
    go116) build "$tag" "$ver" basic linux amd64 "_stripped" -ldflags "-s -w" ;;
    # 32-bit itabs bracket Go 1.23's move to `abi.ITab`: go121 has the
    # explicit `_ [4]byte` after `hash` (fun at 16), go123 does not (fun at
    # 12). On 64-bit both put fun at 24, so only a 32-bit fixture pins it.
    # The first coverage-redesign release: its metadata blobs pin the
    # format's oldest shape.
    go120) build "$tag" "$ver" basic linux amd64 "_cover" -cover ;;
    go121) build "$tag" "$ver" basic linux 386 "" ;;
    go123) build "$tag" "$ver" basic linux 386 "" ;;
    go124) build "$tag" "$ver" embed linux amd64 ""
           build "$tag" "$ver" basic linux amd64 "_fips" GOFIPS140=v1.0.0 ;;
    go126) build "$tag" "$ver" basic   darwin  arm64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" basic   windows amd64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" basic   linux   amd64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" minimal darwin  arm64 ""
           build "$tag" "$ver" minimal darwin  arm64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" embed   darwin  arm64 ""
           build "$tag" "$ver" embed   linux   amd64 ""
           build "$tag" "$ver" embed   darwin  arm64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" basic   linux   amd64 "_cover" -cover
           build "$tag" "$ver" basic   darwin  arm64 "_fips" GOFIPS140=v1.0.0 ;;
    go127) build "$tag" "$ver" basic   darwin  arm64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" basic   windows amd64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" basic   linux   amd64 "_stripped" -ldflags "-s -w"
           build "$tag" "$ver" basic   linux   amd64 "_cover" -cover
           build "$tag" "$ver" basic   linux   amd64 "_fips" GOFIPS140=v1.0.0
           # -buildmode=pie moves every read-only-relocatable Go section under
           # a `.data.rel.ro` prefix (`.data.rel.ro.go.type`, and pre-1.27
           # `.data.rel.ro.typelink`). Without a PIE fixture the section
           # classifier's prefix stripping is untested, and an unprefixed
           # lookup makes a PIE binary look like it has no typelink section at
           # all - which the moduledata arbitration reads as a Go 1.27 signal.
           build "$tag" "$ver" basic   linux   amd64 "_pie" -buildmode=pie
           build "$tag" "$ver" minimal linux   amd64 ""
           build "$tag" "$ver" embed   linux   amd64 ""
           build "$tag" "$ver" embed   linux   amd64 "_stripped" -ldflags "-s -w"
           # A wasm embed fixture pins the one case where the address-space
           # view is not the file: `embed.FS` recovery searches the
           # reconstructed linear-memory image, so any attempt to narrow that
           # search with file-offset section ranges silently finds nothing.
           build "$tag" "$ver" embed   wasip1  wasm  "" ;;
    go128) build "$tag" "$ver" basic   linux   amd64 "_stripped" -ldflags "-s -w"
           # The second slice of the universal fixture (see make_universal).
           build "$tag" "$ver" basic   darwin  amd64 ""
           # js/wasm and wasip1/wasm both moved their PCs to 1<<63; js is the
           # original wasm port and the only fixture of it.
           build "$tag" "$ver" basic   js      wasm  ""
           build "$tag" "$ver" embed   wasip1  wasm  ""
           # A 4-byte-pointer target on a current toolchain.
           build "$tag" "$ver" basic   linux   386   ""
           # CGO_ENABLED=bindings records a third cgo mode; it needs no C
           # compiler (GOEXPERIMENT=cgobindings while it is experimental).
           build "$tag" "$ver" basic   linux   amd64 "_cgobindings" \
             CGO_ENABLED=bindings GOEXPERIMENT=cgobindings ;;
  esac
done

# A universal ("fat") Mach-O file, as `lipo -create` builds one from thin
# images: a big-endian header (magic 0xcafebabe, slice count, and per slice
# CPU type and subtype, offset, size and alignment), then each image at an
# offset aligned to 2^align (2^14 for arm64, 2^12 for the others). lipo needs a
# darwin host, so the header is written here.
make_universal() {  # make_universal <dst> <thin...>
  local dst=$1; shift
  if [[ $list_only -eq 1 ]]; then echo "  $dst"; return 0; fi
  local src; for src in "$@"; do
    if [[ ! -s "$OUT/$src" ]]; then echo "  !! $dst: missing $src"; fail+=("$dst"); return 0; fi
  done
  echo "  $dst"
  if ( cd "$OUT" && python3 - "$dst" "$@" <<'PYEOF'
import struct, sys
dst, srcs = sys.argv[1], sys.argv[2:]
images = [open(s, "rb").read() for s in srcs]
entries, offset = [], 8 + 20 * len(images)
for image in images:
    cputype, subtype = struct.unpack_from("<iI", image, 4)
    align = 14 if cputype == 0x0100000C else 12
    offset = (offset + (1 << align) - 1) & ~((1 << align) - 1)
    entries.append((cputype, subtype, offset, len(image), align))
    offset += len(image)
out = bytearray(struct.pack(">II", 0xCAFEBABE, len(images)))
for e in entries:
    out += struct.pack(">iIIII", *e)
for (_, _, off, _, _), image in zip(entries, images):
    out += b"\0" * (off - len(out))
    out += image
open(dst, "wb").write(out)
PYEOF
  ); then ok=$((ok + 1)); else echo "    !! failed"; fail+=("$dst"); fi
}
if selected go128; then
  make_universal basic_go128_darwin_universal basic_go128_darwin_amd64 basic_go128_darwin_arm64
fi

# A module-mode build without -trimpath, to record where a build ran: GOROOT,
# the module cache, GOPATH and the user's home. The dependency (src/greet) is
# served from a local file proxy, so no network is needed. The compiler's
# `-trimpath=old=>new` rewrite places the work tree at /home/gobin and GOROOT
# at /usr/local/go, the paths a build in that home records, so the fixture
# does not carry this host's paths. GOEXPERIMENT adds an ` X:` suffix to the
# version string: one experiment on, one default turned off.
build_deps() {  # build_deps <tag> <ver> [<variant> [go build args...]]
  local tag=$1 ver=$2 variant=${3:-} name="deps_${1}_linux_amd64${3:-}"
  shift 2; [[ $# -gt 0 ]] && shift
  if [[ $list_only -eq 1 ]]; then echo "  $name"; return 0; fi
  local goroot; goroot="$(fetch_toolchain "$ver")"
  if [[ -z "$goroot" ]]; then echo "  !! $name: no go$ver toolchain"; fail+=("$name"); return 0; fi
  # The build info records the -gcflags setting verbatim, rewrite included,
  # so GOROOT is reached through a link in the cache: the fixture then names
  # only cache paths, never where this host keeps its toolchains.
  local link="$CACHE/deps-goroot"; ln -sfn "$goroot" "$link"; goroot="$link"
  local root="$WORK/deps-root" home="$WORK/deps-root/home/gobin" proxy="$WORK/deps-proxy"
  # Go writes the module cache read-only; make it removable first.
  [[ -d "$root" ]] && chmod -R u+w "$root"
  rm -rf "$root" "$proxy"; mkdir -p "$home/src/deps" "$home/go" "$proxy"
  cp -r "$SRC/deps/." "$home/src/deps/"
  python3 - "$SRC/greet" "$proxy" <<'PYEOF'
import os, sys, zipfile
src, proxy = sys.argv[1], sys.argv[2]
mod, ver = "example.com/greet", "v1.0.0"
d = os.path.join(proxy, mod, "@v")
os.makedirs(d)
open(os.path.join(d, "list"), "w").write(ver + "\n")
open(os.path.join(d, ver + ".info"), "w").write('{"Version":"%s","Time":"2026-01-01T00:00:00Z"}' % ver)
open(os.path.join(d, ver + ".mod"), "wb").write(open(os.path.join(src, "go.mod"), "rb").read())
with zipfile.ZipFile(os.path.join(d, ver + ".zip"), "w") as z:
    for f in sorted(os.listdir(src)):
        z.write(os.path.join(src, f), "%s@%s/%s" % (mod, ver, f))
PYEOF
  local rewrite="$root/home=>/home;$goroot=>/usr/local/go"
  echo "  $name"
  if ( cd "$home/src/deps" && env \
        HOME="$home" GOPATH="$home/go" GOMODCACHE="$home/go/pkg/mod" \
        GOROOT="$goroot" GOCACHE="$CACHE/gocache" GOPROXY="file://$proxy" \
        GOSUMDB=off GOFLAGS=-mod=mod GO111MODULE=on GOTOOLCHAIN=local \
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOEXPERIMENT=arenas,nogreenteagc \
        "$goroot/bin/go" build "-gcflags=all=-trimpath=$rewrite" \
          "-asmflags=all=-trimpath=$rewrite" "$@" -o "$OUT/$name" . ) \
      && [[ -s "$OUT/$name" ]]; then
    ok=$((ok + 1))
  else
    echo "    !! build failed"; rm -f "$OUT/$name"; fail+=("$name")
  fi
}
if selected go128 && fetch_toolchain tip >/dev/null 2>&1; then
  build_deps go128 tip
  # Coverage over the module's two packages (the main package and the
  # dependency), and a stripped twin: the same layout with no symbol table,
  # which leaves the metadata blobs reachable only from the code.
  build_deps go128 tip "_cover" -cover -coverpkg=example.com/...
  build_deps go128 tip "_cover_stripped" -cover -coverpkg=example.com/... -ldflags "-s -w"
fi

# ---------------------------------------------------------------------------
# Derived fixtures: produced by post-processing a built binary rather than by
# invoking a toolchain.
# ---------------------------------------------------------------------------

# A Go binary with every occurrence of its version string overwritten, the way
# an obfuscator (garble) or a repacker leaves one. With no version to key on,
# the moduledata parser has to pick its layout from structural evidence alone -
# and on PE, which never carries a `.typelink` section, the only hint points at
# the Go 1.27 layout. Guessing wrong there silently empties the types, itabs,
# init tasks and inline tree, so this fixture pins the arbitration.
scrub_version() {  # scrub_version <src-name> <dst-name> <version-literal>
  local src="$OUT/$1" dst="$OUT/$2" lit="$3"
  if [[ $list_only -eq 1 ]]; then echo "  $2"; return 0; fi
  if [[ ! -s "$src" ]]; then echo "  !! $2: missing source $1"; fail+=("$2"); return 0; fi
  echo "  $2"
  if python3 - "$src" "$dst" "$lit" <<'PYEOF'
import sys

src, dst, lit = sys.argv[1], sys.argv[2], sys.argv[3].encode()
data = bytearray(open(src, "rb").read())
n = 0
i = data.find(lit)
while i >= 0:
    data[i : i + len(lit)] = b"\x00" * len(lit)
    n += 1
    i = data.find(lit, i + len(lit))
if n == 0:
    sys.exit(f"no occurrence of {lit!r} in {src}")
open(dst, "wb").write(bytes(data))
print(f"    scrubbed {n} occurrence(s)")
PYEOF
  then ok=$((ok + 1)); else echo "    !! scrub failed"; rm -f "$dst"; fail+=("$2"); fi
}

if [[ ${#SELECT[@]} -eq 0 ]] || selected go124; then
  scrub_version basic_go124_windows_amd64.exe basic_go124_windows_amd64_noversion.exe go1.24
fi
# With no version, a 32-bit itab's layout comes from its first record: the
# word after `hash` is Go 1.10-1.22's zero padding or Go 1.23's `fun[0]`.
if [[ ${#SELECT[@]} -eq 0 ]] || selected go121; then
  scrub_version basic_go121_linux_386 basic_go121_linux_386_noversion go1.21
fi

if [[ $list_only -eq 1 ]]; then exit 0; fi
echo "Done. Built $ok fixtures into $OUT."
if [[ ${#fail[@]} -gt 0 ]]; then printf 'Failed:\n'; printf '  %s\n' "${fail[@]}"; fi
