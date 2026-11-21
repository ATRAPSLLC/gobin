//! High-level metadata extracted from Go binaries.
//!
//! This module defines the data types returned by [`GoBinary`](crate::GoBinary) methods
//! and provides the extraction logic that transforms raw pclntab structures into
//! user-friendly function lists, file paths, and type information.
//!
//! ## What's Extractable
//!
//! | Data                  | Source Structure       | Survives Stripping? |
//! |-----------------------|------------------------|---------------------|
//! | Function names        | pclntab `funcnametab`  | Yes                 |
//! | Source file paths     | pclntab `filetab`      | Yes                 |
//! | Function boundaries   | pclntab `functab`      | Yes                 |
//! | Line numbers          | pclntab `pctab`        | Yes                 |
//! | Go version            | build info blob        | Yes                 |
//! | Module dependencies   | build info blob        | Yes                 |
//! | Build settings        | build info blob        | Yes                 |
//! | Build ID              | ELF note / raw marker  | Yes                 |
//! | Type names            | type descriptors       | Yes                 |
//! | DWARF debug info      | `.debug_*` sections    | **No** (`-w` flag)  |
//! | Symbol table          | `.symtab` / `.strtab`  | **No** (`-s` flag)  |
//!
//! ## Why Everything Survives
//!
//! Go's `-ldflags="-s -w"` only removes DWARF debug info (`-w`) and the ELF/PE
//! symbol table (`-s`). The pclntab, build info, and type descriptors are in separate
//! sections that the runtime accesses at execution time:
//!
//! - **pclntab**: needed for `runtime.Caller`, panic stack traces, GC stack scanning
//! - **Build info**: accessed by `runtime/debug.ReadBuildInfo()`
//! - **Types**: needed for `reflect`, interface dispatch, `fmt.Printf("%T", x)`

use crate::{
    detection::Confidence,
    names::{is_cgo_stub, package_boundary, package_of},
    structures::pclntab::{FuncData, FuncEntryIter, FuncId, OwnCode, ParsedPclntab},
};

/// Whether `pkg` is a Go runtime package.
///
/// Covers all three spellings the runtime has used: `runtime` itself,
/// `runtime/<sub>` (e.g. `runtime/cgo`, and the pre-1.24 `runtime/internal/*`
/// tree), and `internal/runtime/<sub>` - the home the runtime's internal
/// packages (`internal/runtime/atomic`, `internal/runtime/maps`,
/// `internal/runtime/sys`, …) moved to in Go 1.24 and where they still live in
/// 1.27. Without the third form, half the runtime of a modern binary
/// classifies as ordinary internal library code.
///
/// Shared with [`crate::structures::types::GoType::is_runtime`] so type-side
/// and function-side classifications agree on one canonical rule.
pub fn is_runtime_path(pkg: &str) -> bool {
    pkg == "runtime"
        || pkg.starts_with("runtime/")
        || pkg == "internal/runtime"
        || pkg.starts_with("internal/runtime/")
}

/// Whether `pkg` is a Go-internal package (runtime, `internal/*`, `vendor/*`,
/// or compiler-emitted pseudo-paths like `type:*`).
///
/// Shared between [`FunctionInfo::is_internal`] and
/// [`crate::structures::types::GoType::is_internal`].
pub fn is_internal_path(pkg: &str) -> bool {
    is_runtime_path(pkg)
        || pkg.starts_with("internal/")
        || pkg.starts_with("vendor/")
        || pkg.starts_with("type:")
}

/// Whether `pkg` is a Go standard-library package.
///
/// Stdlib package paths never contain `.` (third-party dependencies use
/// domain-shaped paths like `github.com/...`, `golang.org/x/...`,
/// `gopkg.in/...`). Internal/runtime packages are excluded so this answers
/// "user-visible stdlib" rather than "anything Google ships."
pub fn is_stdlib_path(pkg: &str) -> bool {
    !is_internal_path(pkg) && !pkg.contains('.')
}

/// Which Go toolchain produced the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compiler {
    /// The standard `gc` compiler (the default Go toolchain).
    Gc,
    /// TinyGo - produces small embedded/wasm binaries with a different runtime.
    /// TinyGo binaries do not carry a stdlib pclntab.
    TinyGo,
    /// Gccgo - GCC's Go front-end. Produces no pclntab.
    Gccgo,
    /// Could not determine (no `-compiler` setting and no distinguishing
    /// markers were found).
    Unknown,
}

/// One module dependency entry, including its checksum and any active replacement.
///
/// All string fields borrow from the underlying buildinfo blob via the
/// lifetime `'a`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DepEntry<'a> {
    /// Module import path, e.g. `"github.com/spf13/cobra"`.
    pub path: &'a str,
    /// Module version, if recorded (`v1.2.3`, `(devel)`, etc.).
    pub version: Option<&'a str>,
    /// Module sum hash from `go.sum`, e.g. `"h1:abc...="`.
    pub sum: Option<&'a str>,
    /// `replace` directive that overrode this dependency at build time, if any.
    pub replacement: Option<DepReplacement<'a>>,
}

/// Replacement target for a [`DepEntry`].
///
/// Records what the original module was substituted with - either a forked
/// module (`=> github.com/forked/foo v1.2.3 h1:xyz=`) or a local path
/// (`=> ./local/foo`, in which case `version` is typically `None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepReplacement<'a> {
    /// Replacement path or import (could be a local relative path).
    pub path: &'a str,
    /// Replacement version, if recorded.
    pub version: Option<&'a str>,
    /// Replacement sum hash, if recorded.
    pub sum: Option<&'a str>,
}

/// Result of automated obfuscation/protection detection on a Go binary.
///
/// **Sealed**: not marked `#[non_exhaustive]`. Adding a variant is a breaking
/// API change so callers can rely on exhaustive match.
///
/// # Stability
///
/// Consumers persist this enum into long-lived schemas (database columns,
/// structured logs). The contract:
///
/// - **Variants** - append-only. New obfuscators appear as new variants;
///   existing variants are never renamed or removed.
/// - **`Display` strings** (and [`Self::kind_str`]) - fixed forever once
///   shipped. Treat them as serialization keys.
/// - **`Debug` strings** - *not* a stability surface. Use `Display` /
///   `kind_str` for anything that lands in a database column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObfuscationKind {
    /// No obfuscation indicators detected.
    None,
    /// Binary appears to have been processed with `garble`. The
    /// confidence tier reflects how strong the signal is (number of
    /// obfuscated names, missing buildinfo, scrubbed deps).
    Garble {
        /// How confident the heuristic is in this verdict.
        confidence: Confidence,
    },
    /// Some other / custom obfuscation pattern was observed.
    Other {
        /// Short reason describing what was observed.
        reason: String,
    },
}

impl ObfuscationKind {
    /// Stable lowercase identifier for this verdict
    /// (`"none"` / `"garble"` / `"other"`).
    ///
    /// Drops the inner `confidence` and `reason` payloads - read those off
    /// the matched variant directly. See the `# Stability` section on
    /// [`ObfuscationKind`] for the durability contract.
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Garble { .. } => "garble",
            Self::Other { .. } => "other",
        }
    }
}

impl std::fmt::Display for ObfuscationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Garble { confidence } => write!(f, "garble({confidence})"),
            Self::Other { reason } => write!(f, "other({reason})"),
        }
    }
}

/// FIPS-140 mode information for a Go 1.24+ binary.
///
/// The authoritative "is this a FIPS build?" signal is the `GOFIPS140` build
/// setting, recorded in build info. The `__go_fipsinfo` section's integrity
/// sum (the `go:fipsinfo` symbol, `struct { Magic [16]byte; Sum [32]byte }`)
/// is present in *every* crypto-linked binary, so it alone does **not**
/// indicate FIPS mode - it's exposed here only as a content identifier for
/// the embedded crypto module.
///
/// [`crate::GoBinary::fips_info`] returns this only when `GOFIPS140` is set;
/// it is therefore `None` when build info is absent (e.g. stripped by
/// `garble`), even if the integrity section survives.
///
/// Source: `src/crypto/internal/fips140/check/check.go`,
/// `src/runtime/debug/mod.go` (`GOFIPS140`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FipsInfo<'a> {
    /// The `GOFIPS140` build-setting value (e.g. `"v1.0.0"` or
    /// `"v1.0.0-c2097c7c"`).
    pub version: &'a str,
    /// Whether `fips140=on` appears in `DefaultGODEBUG` - i.e. FIPS
    /// enforcement is active by default at runtime (vs. `fips140=only`/opt-in).
    pub enforced_by_default: bool,
    /// The 32-byte integrity sum from `__go_fipsinfo`, when the section is
    /// present and carries the expected magic. A content identifier for the
    /// embedded FIPS crypto module.
    pub module_sum: Option<[u8; 32]>,
}

/// One package-initialization task from `moduledata.inittasks` (Go 1.24+).
///
/// Each task runs an ordered list of init functions at program startup. See
/// [`crate::GoBinary::init_order`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitTask<'a> {
    /// Package this task initializes, derived from the first init function's
    /// name (e.g. `"runtime"`, `"main"`). `None` when no function name could
    /// be resolved.
    pub package: Option<&'a str>,
    /// The init functions, in execution order.
    pub functions: Vec<InitFunc<'a>>,
}

/// A single init function within an [`InitTask`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitFunc<'a> {
    /// Virtual address of the function entry point.
    pub entry_va: u64,
    /// Resolved package-qualified name (e.g. `"main.init.0"`), if the entry VA
    /// maps to a known pclntab function. `None` for stripped/unmapped entries.
    pub name: Option<&'a str>,
}

/// Structural description of a method receiver type parsed from a function name.
///
/// For `net/http.(*Client).Do` the receiver is `(*Client)` which decodes as
/// `ReceiverSpec { name: "Client", pointer: true, generic_args: None }`.
/// For `pkg.(*Map[K, V]).Len` the spec is
/// `ReceiverSpec { name: "Map", pointer: true, generic_args: Some("[K, V]") }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverSpec<'a> {
    /// Receiver type name, with leading `*` and any `[...]` generics stripped.
    pub name: &'a str,
    /// Whether the receiver is a pointer (`*T`).
    pub pointer: bool,
    /// Generic type arguments on the receiver, e.g. `"[int]"` or `"[K, V]"`.
    pub generic_args: Option<&'a str>,
}

/// Split a function's short name into `(receiver_text, method_name)` if it
/// has a method shape; otherwise `None`.
///
/// Handles four receiver shapes:
/// - Parenthesized pointer: `(*T).Method` / `(*T[args]).Method`
/// - Parenthesized value: `(T).Method` / `(T[args]).Method`
/// - Bare identifier: `T.Method`
/// - Bare identifier with generics: `T[args].Method`
fn split_receiver_and_method(short: &str) -> Option<(&str, &str)> {
    let bytes = short.as_bytes();
    if bytes.first() == Some(&b'(') {
        let mut depth: i32 = 0;
        let mut close = None;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'(' => depth = depth.checked_add(1)?,
                b')' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close?;
        let next_idx = close.checked_add(1)?;
        if bytes.get(next_idx) != Some(&b'.') {
            return None;
        }
        let method_start = close.checked_add(2)?;
        let recv = short.get(..=close)?;
        let method = short.get(method_start..)?;
        if method.is_empty() {
            return None;
        }
        return Some((recv, method));
    }

    let mut bracket_depth: i32 = 0;
    for (i, ch) in short.char_indices() {
        match ch {
            '[' => bracket_depth = bracket_depth.checked_add(1)?,
            ']' => bracket_depth = bracket_depth.checked_sub(1)?,
            '.' if bracket_depth == 0 => {
                let method_start = i.checked_add(1)?;
                let recv = short.get(..i)?;
                let method = short.get(method_start..)?;
                if recv.is_empty() || method.is_empty() {
                    return None;
                }
                if !is_receiver_ident(recv) {
                    return None;
                }
                return Some((recv, method));
            }
            _ => {}
        }
    }
    None
}

/// Whether `s` looks like a receiver type identifier (plus optional generic args).
fn is_receiver_ident(s: &str) -> bool {
    let core = s.split('[').next().unwrap_or(s);
    let mut chars = core.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse the receiver text (e.g. `"(*Client)"`, `"Time"`, `"Map[K, V]"`) into a
/// [`ReceiverSpec`].
fn parse_receiver_spec(recv: &str) -> ReceiverSpec<'_> {
    let mut s = recv;
    if let Some(stripped) = s.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
        s = stripped;
    }
    let pointer = if let Some(rest) = s.strip_prefix('*') {
        s = rest;
        true
    } else {
        false
    };
    let (name, generic_args) = match s.find('[') {
        Some(open) => (s.get(..open).unwrap_or(""), s.get(open..)),
        None => (s, None),
    };
    ReceiverSpec {
        name,
        pointer,
        generic_args,
    }
}

/// Return the last top-level (bracket-depth-0) `[...]` segment in `s`, or `None`.
fn last_top_level_bracket_segment(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    let mut depth: i32 = 0;
    let mut last_open = None;
    let mut last_close = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' => {
                if depth == 0 {
                    last_open = Some(i);
                }
                depth = depth.checked_add(1)?;
            }
            b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    last_close = Some(i);
                }
            }
            _ => {}
        }
    }
    match (last_open, last_close) {
        (Some(o), Some(c)) if c > o => s.get(o..=c),
        _ => None,
    }
}

/// Whether `name` ends with a closure-style `.funcN` or `.gowrapN` suffix
/// (where `N` is one or more digits, possibly nested through further closure
/// scopes like `.func1.func2`).
fn has_closure_suffix(name: &str) -> bool {
    has_numeric_suffix_after(name, ".func") || has_numeric_suffix_after(name, ".gowrap")
}

/// True if `name` contains `marker` followed immediately by one or more digits
/// (and either ends or is followed by another `.`).
fn has_numeric_suffix_after(name: &str, marker: &str) -> bool {
    let mut search_from: usize = 0;
    while let Some(slice) = name.get(search_from..) {
        let rel = match slice.find(marker) {
            Some(r) => r,
            None => return false,
        };
        let after = match search_from
            .checked_add(rel)
            .and_then(|x| x.checked_add(marker.len()))
        {
            Some(a) => a,
            None => return false,
        };
        let trailing = match name.get(after..) {
            Some(t) => t,
            None => return false,
        };
        let digit_end = trailing.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digit_end > 0 {
            let next_byte = trailing.as_bytes().get(digit_end).copied();
            if next_byte.is_none() || next_byte == Some(b'.') {
                return true;
            }
        }
        search_from = after;
    }
    false
}

/// The Go `-buildmode` value the binary was compiled with.
///
/// Source: `src/cmd/go/internal/work/init.go` (`-buildmode` flag definitions).
///
/// The build info records the mode the linker was given. Before Go 1.28 an
/// unset or `default` mode is recorded as `exe` even where the default is
/// position-independent (darwin, ios, android, windows without `-race`); from
/// Go 1.28 it is recorded as `pie` there.
///
/// # Stability
///
/// Consumers persist this enum into long-lived schemas (database columns,
/// structured logs). The contract:
///
/// - **Variants** - append-only. New build modes appear as new variants;
///   existing variants are never renamed or removed.
/// - **`Display` strings** (and [`Self::as_str`]) - fixed forever once
///   shipped. They round-trip through [`Self::parse`]; treat them as
///   serialization keys.
/// - **`Debug` strings** - *not* a stability surface. Use `Display` /
///   `as_str` for anything that lands in a database column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildMode<'a> {
    /// Default executable (`-buildmode=exe` or unset).
    Exe,
    /// Position-independent executable (`-buildmode=pie`).
    Pie,
    /// Linkable C shared library (`-buildmode=c-shared`).
    CShared,
    /// Linkable C archive (`-buildmode=c-archive`).
    CArchive,
    /// Go plugin (`-buildmode=plugin`).
    Plugin,
    /// Compiled archive (`-buildmode=archive`).
    Archive,
    /// Shared library of multiple Go packages (`-buildmode=shared`).
    Shared,
    /// Any other / future build mode value, verbatim from the build info.
    Other(&'a str),
}

impl<'a> BuildMode<'a> {
    /// Parse a raw `-buildmode` setting value into a [`BuildMode`].
    pub fn parse(value: &'a str) -> Self {
        match value {
            "exe" | "" => Self::Exe,
            "pie" => Self::Pie,
            "c-shared" => Self::CShared,
            "c-archive" => Self::CArchive,
            "plugin" => Self::Plugin,
            "archive" => Self::Archive,
            "shared" => Self::Shared,
            other => Self::Other(other),
        }
    }

    /// The canonical `-buildmode` flag string, suitable for round-tripping
    /// through [`Self::parse`].
    ///
    /// Returns the same kebab-case identifiers the Go toolchain accepts
    /// (`"exe"`, `"pie"`, `"c-shared"`, `"c-archive"`, `"plugin"`,
    /// `"archive"`, `"shared"`). For [`BuildMode::Other`] the inner verbatim
    /// string. See the `# Stability` section on [`BuildMode`] for the
    /// durability contract.
    pub fn as_str(&self) -> &'a str {
        match self {
            Self::Exe => "exe",
            Self::Pie => "pie",
            Self::CShared => "c-shared",
            Self::CArchive => "c-archive",
            Self::Plugin => "plugin",
            Self::Archive => "archive",
            Self::Shared => "shared",
            Self::Other(s) => s,
        }
    }
}

impl std::fmt::Display for BuildMode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a build enabled cgo: the `CGO_ENABLED` build setting.
///
/// Source: `src/cmd/go/internal/load/pkg.go` (`setBuildInfo`), which records
/// the value the build ran with.
///
/// # Stability
///
/// The same contract as [`BuildMode`]: variants are append-only, and the
/// `Display` strings (and [`Self::as_str`]) are the recorded setting values,
/// fixed forever and round-tripping through [`Self::parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgoMode<'a> {
    /// cgo disabled (`CGO_ENABLED=0`).
    Disabled,
    /// cgo enabled with a C toolchain (`CGO_ENABLED=1`).
    Enabled,
    /// cgo bindings (`CGO_ENABLED=bindings`, Go 1.28; first behind
    /// `GOEXPERIMENT=cgobindings`): packages that declare `//cgo:func` and
    /// related pragmas call C without a C compiler, while the `cgo` build tag
    /// is off.
    Bindings,
    /// Any other / future value, verbatim from the build info.
    Other(&'a str),
}

impl<'a> CgoMode<'a> {
    /// Parse a raw `CGO_ENABLED` setting value into a [`CgoMode`].
    pub fn parse(value: &'a str) -> Self {
        match value {
            "0" => Self::Disabled,
            "1" => Self::Enabled,
            "bindings" => Self::Bindings,
            other => Self::Other(other),
        }
    }

    /// The recorded setting value, suitable for round-tripping through
    /// [`Self::parse`]. See the `# Stability` section on [`CgoMode`].
    pub fn as_str(&self) -> &'a str {
        match self {
            Self::Disabled => "0",
            Self::Enabled => "1",
            Self::Bindings => "bindings",
            Self::Other(s) => s,
        }
    }
}

impl std::fmt::Display for CgoMode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Build metadata embedded in the Go binary.
///
/// Extracted from the build info blob (see [`crate::structures::buildinfo`]).
/// Contains everything `go version -m <binary>` would print.
///
/// ## Build Setting Keys
///
/// Common keys found in `build_settings` (from `src/runtime/debug/mod.go:69-95`):
///
/// | Key              | Example Value | Description                    |
/// |------------------|---------------|--------------------------------|
/// | `-buildmode`     | `exe`         | Build mode                     |
/// | `-compiler`      | `gc`          | Compiler toolchain             |
/// | `-mod`           | `vendor`      | Vendored build (Go 1.28+)      |
/// | `CGO_ENABLED`    | `0`/`1`/`bindings` | CGo enablement ([`CgoMode`]) |
/// | `GOOS`           | `linux`       | Target OS                      |
/// | `GOARCH`         | `amd64`       | Target architecture            |
/// | `GOAMD64`        | `v1`          | AMD64 microarch level          |
/// | `GOARM`          | `7`           | ARM version                    |
/// | `vcs`            | `git`         | Version control system         |
/// | `vcs.revision`   | `abc123...`   | Commit hash                    |
/// | `vcs.time`       | `2024-...`    | Commit timestamp (RFC3339)     |
/// | `vcs.modified`   | `true`        | Working tree dirty flag        |
#[derive(Debug, Clone, Default)]
pub struct BuildInfo<'a> {
    /// Go toolchain version (e.g. `"go1.26.1"`).
    pub go_version: Option<&'a str>,
    /// Main package import path (e.g. `"github.com/user/project/cmd/tool"`).
    pub main_path: Option<&'a str>,
    /// Main module name (e.g. `"github.com/user/project"`).
    pub main_module: Option<&'a str>,
    /// Main module version (e.g. `"(devel)"` or `"v1.2.3"`).
    pub main_version: Option<&'a str>,
    /// Main module `go.sum` hash (`h1:…`), present when the binary was built
    /// from a released, checksummed module (absent for `(devel)` builds).
    pub main_module_sum: Option<&'a str>,
    /// Module dependencies, including sums and any active replacements.
    pub deps: Vec<DepEntry<'a>>,
    /// Build settings as `(key, value)` pairs (borrowed from the modinfo blob).
    pub build_settings: Vec<(&'a str, &'a str)>,
}

impl<'a> BuildInfo<'a> {
    /// Look up a build setting by key name.
    pub fn setting(&self, key: &str) -> Option<&'a str> {
        self.build_settings
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| *v)
    }

    /// Target operating system (`GOOS` build setting).
    pub fn goos(&self) -> Option<&'a str> {
        self.setting("GOOS")
    }

    /// Target architecture (`GOARCH` build setting).
    pub fn goarch(&self) -> Option<&'a str> {
        self.setting("GOARCH")
    }

    /// How the build enabled cgo (`CGO_ENABLED` build setting): off, on with
    /// a C toolchain, or the cgo bindings of Go 1.28 that need none.
    ///
    /// `None` when the build info records no `CGO_ENABLED` (before Go 1.18).
    pub fn cgo_mode(&self) -> Option<CgoMode<'a>> {
        self.setting("CGO_ENABLED").map(CgoMode::parse)
    }

    /// Whether the build used the module's `vendor` directory
    /// (`-mod=vendor`), which Go records from Go 1.28 on: the dependency
    /// versions listed are then those vendored, which the go command cannot
    /// check against their sums.
    ///
    /// `false` when the setting is absent, as it is for every other `-mod`
    /// value and for every binary built before Go 1.28.
    pub fn vendored(&self) -> bool {
        self.setting("-mod") == Some("vendor")
    }

    /// VCS commit hash, if the binary was built from a VCS checkout.
    pub fn vcs_revision(&self) -> Option<&'a str> {
        self.setting("vcs.revision")
    }

    /// Commit time of the VCS revision (`vcs.time`), RFC 3339 in UTC as the
    /// go command writes it (e.g. `2024-05-01T12:34:56Z`).
    pub fn vcs_time(&self) -> Option<&'a str> {
        self.setting("vcs.time")
    }

    /// Whether the VCS working tree was dirty at build time.
    pub fn vcs_modified(&self) -> Option<bool> {
        self.setting("vcs.modified").map(|v| v == "true")
    }

    /// Build tags supplied via `-tags` at compile time, split on commas.
    ///
    /// Yields zero items if the binary was built without explicit tags
    /// (the `-tags` build setting is absent or empty).
    pub fn build_tags(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.setting("-tags")
            .into_iter()
            .flat_map(|v| v.split(',').filter(|s| !s.is_empty()))
    }

    /// Iterate over `(path, version)` pairs for module dependencies.
    ///
    /// For full structural detail (sums, replacements) use [`Self::deps_full`]
    /// or iterate [`Self::deps`] directly.
    pub fn dependencies(&self) -> impl Iterator<Item = (&'a str, Option<&'a str>)> + '_ {
        self.deps.iter().map(|d| (d.path, d.version))
    }

    /// Iterate over full [`DepEntry`] records, including `go.sum` hashes and
    /// any active `replace` directive (`=> path[ version][ h1:sum]`).
    ///
    /// This surfaces the supply-chain detail that [`Self::dependencies`]
    /// collapses - e.g. answering "is this binary using the official
    /// `golang.org/x/crypto` or a forked/replaced one?".
    pub fn deps_full(&self) -> impl Iterator<Item = &DepEntry<'a>> + '_ {
        self.deps.iter()
    }

    /// The main module's `go.sum` hash (`h1:…`), if the build recorded one.
    ///
    /// Present for binaries built from a released, checksummed module; absent
    /// for `(devel)` / local builds.
    pub fn module_sum(&self) -> Option<&'a str> {
        self.main_module_sum
    }

    /// Iterate over `(key, value)` build setting pairs.
    pub fn build_settings_iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> + '_ {
        self.build_settings.iter().copied()
    }

    /// The `-buildmode` value as a typed enum (default: [`BuildMode::Exe`]).
    ///
    /// Returns `None` only if the binary lacks build settings entirely
    /// (unparseable build info). A binary built without explicit `-buildmode`
    /// returns `Some(BuildMode::Exe)`.
    pub fn build_mode(&self) -> Option<BuildMode<'a>> {
        if self.build_settings.is_empty() {
            return None;
        }
        Some(BuildMode::parse(self.setting("-buildmode").unwrap_or("")))
    }
}

/// Metadata for a single function extracted from the pclntab.
///
/// Function names in Go are package-qualified and follow a consistent naming scheme:
///
/// | Pattern                        | Example                          |
/// |--------------------------------|----------------------------------|
/// | `pkg.Function`                 | `fmt.Println`                    |
/// | `pkg.(*Type).Method`           | `net/http.(*Client).Do`          |
/// | `pkg.Type.Method`              | `time.Time.String`               |
/// | `pkg.function.closureN`        | `main.main.func1`               |
/// | `pkg.function.gowrapN`         | `main.main.gowrap1`             |
///
/// These names survive stripping because they're stored in the pclntab's `funcnametab`,
/// not in the ELF/PE symbol table.
#[derive(Debug, Clone)]
pub struct FunctionInfo<'a> {
    /// Full package-qualified function name (borrowed from pclntab funcnametab).
    pub name: &'a str,
    /// The function's `_func` record: its entry offset, argument size, start
    /// line, raw ID and flags, and the offsets of its per-PC tables.
    pub func: FuncData,
    /// What the record's funcID marks the function as, classified against
    /// the binary's wrapper ID ([`FuncId::classify`]).
    pub func_id: FuncId,
    /// Source file of the function's own code, leaving out code inlined into
    /// it ([`ParsedPclntab::own_code`]).
    pub source_file: Option<&'a str>,
    /// Last source line of the function's own code, leaving out code inlined
    /// into it ([`ParsedPclntab::own_code`]); `0` when the line table is empty.
    pub end_line: i32,
    /// Maximum stack frame size in bytes (decoded from the pcsp table).
    pub frame_size: i32,
}

impl<'a> FunctionInfo<'a> {
    /// The function described by the `_func` record `func` of `pclntab`: its
    /// name, the source file and last line of its own code, and the largest
    /// frame its tables record.
    pub fn from_func(pclntab: &ParsedPclntab<'a>, func: FuncData) -> Self {
        let name = pclntab
            .func_name(func.name_off as u32)
            .unwrap_or("<unknown>");
        let own = pclntab.own_code(&func);
        Self {
            name,
            func_id: pclntab.func_id(&func, name),
            source_file: own
                .file_index
                .and_then(|index| pclntab.resolve_file_index(func.cu_offset, index)),
            end_line: own.lines.map_or(0, |(_, end)| end),
            frame_size: pclntab.max_frame_size(&func).unwrap_or(0),
            func,
        }
    }
}

impl FunctionInfo<'_> {
    /// Extract the package path from the function name.
    ///
    /// Go function names are `"<package-path>.<function>"` where the package
    /// path may itself contain `.` characters (third-party deps with domain
    /// names: `github.com/...`, `golang.org/...`, `gopkg.in/...`). The
    /// boundary is the first `.` **after the last `/`** in the name, plus a
    /// special-case extension for `gopkg.in`-style `.vN` version segments
    /// which are part of the package path.
    ///
    /// ```
    /// # use gobin::{metadata::FunctionInfo, structures::pclntab::{FuncData, FuncId}};
    /// # fn f(name: &str) -> FunctionInfo<'_> {
    /// #     let func = FuncData { func_off: 0, entry_off: 0, name_off: 0, args: 0, deferreturn: 0, pcsp: 0, pcfile: 0, pcln: 0, npcdata: 0, cu_offset: 0, start_line: 0, func_id: 0, flag: 0, nfuncdata: 0 };
    /// #     FunctionInfo { name, func, func_id: FuncId::Normal, source_file: None, end_line: 0, frame_size: 0 }
    /// # }
    /// assert_eq!(f("net/http.(*Client).Do").package(), Some("net/http"));
    /// assert_eq!(f("github.com/spf13/cobra.(*Command).Run").package(), Some("github.com/spf13/cobra"));
    /// assert_eq!(f("gopkg.in/yaml.v3.Marshal").package(), Some("gopkg.in/yaml.v3"));
    /// ```
    pub fn package(&self) -> Option<&str> {
        package_of(self.name)
    }

    /// Whether this is a Go runtime function (`"runtime."` prefix).
    pub fn is_runtime(&self) -> bool {
        self.name.starts_with("runtime.")
    }

    /// The short name (without package prefix).
    ///
    /// Mirrors [`Self::package`] - both use the same boundary computation.
    /// E.g. `"github.com/spf13/cobra.(*Command).Run"` -> `"(*Command).Run"`,
    /// `"gopkg.in/yaml.v3.Marshal"` -> `"Marshal"`.
    pub fn short_name(&self) -> &str {
        match package_boundary(self.name).and_then(|b| b.checked_add(1)) {
            Some(start) => self.name.get(start..).unwrap_or(self.name),
            None => self.name,
        }
    }

    /// Whether this function is a method (has a receiver type).
    ///
    /// A method has the form `<package>.<receiver>.<method>` where
    /// `<receiver>` is either `(*?Type[generics?])` (parenthesized - pointer
    /// or complex receiver) or a bare identifier with optional generic args.
    /// This parses the structure rather than using a substring heuristic, so
    /// it correctly identifies value-receiver methods like `time.Time.String`
    /// that the old `".("` heuristic missed.
    ///
    /// Closures (`pkg.parent.funcN`) and gowrap stubs (`pkg.parent.gowrapN`)
    /// look structurally like methods but are excluded - see [`Self::is_closure`].
    pub fn is_method(&self) -> bool {
        if self.is_closure() {
            return false;
        }
        split_receiver_and_method(self.short_name()).is_some()
    }

    /// Parsed receiver type for methods, e.g.
    /// `net/http.(*Client).Do` -> `Some(ReceiverSpec { name: "Client", pointer: true, ... })`.
    ///
    /// Returns `None` for non-method functions and for names that don't
    /// match a recognizable receiver shape.
    pub fn receiver_type(&self) -> Option<ReceiverSpec<'_>> {
        if self.is_closure() {
            return None;
        }
        let short = self.short_name();
        let (recv, _method) = split_receiver_and_method(short)?;
        Some(parse_receiver_spec(recv))
    }

    /// The method name portion for methods, e.g.
    /// `net/http.(*Client).Do` -> `Some("Do")`.
    ///
    /// Returns `None` for non-method functions.
    pub fn method_name(&self) -> Option<&str> {
        if self.is_closure() {
            return None;
        }
        let short = self.short_name();
        let (_recv, method) = split_receiver_and_method(short)?;
        Some(method)
    }

    /// Generic type arguments on the receiver (for methods on generic types) or
    /// on the function name itself (for generic functions).
    ///
    /// Returns the bracketed string including the brackets, e.g. `"[int]"` or
    /// `"[K, V]"`. Returns `None` if no top-level `[...]` is present.
    pub fn generic_args(&self) -> Option<&str> {
        let short = self.short_name();
        last_top_level_bracket_segment(short)
    }

    /// Whether this function uses `defer` (nonzero `deferreturn` offset).
    pub fn uses_defer(&self) -> bool {
        self.func.deferreturn != 0
    }

    /// Strongly-typed view of the `_func.flag` byte.
    pub fn func_flags(&self) -> FuncFlags {
        FuncFlags(self.func.flag)
    }

    /// Whether the compiler marked this function a wrapper
    /// ([`FuncId::Wrapper`]): compiler-generated code (method value and
    /// interface wrappers, hash and equality algorithms) and the few runtime
    /// functions tracebacks hide alike.
    pub fn is_wrapper(&self) -> bool {
        self.func_id == FuncId::Wrapper
    }

    /// Whether this function is marked top-of-stack (e.g. `runtime.goexit`).
    ///
    /// Bit 0 of the `_func.flag` byte (`FuncFlagTopFrame`).
    /// Source: `src/internal/abi/symtab.go` (`FuncFlag` constants).
    pub fn is_top_frame(&self) -> bool {
        self.func_flags().is_top_frame()
    }

    /// Whether this function writes the SP register itself (rare; assembly
    /// stubs and the runtime context-switch helpers).
    ///
    /// Bit 1 of the `_func.flag` byte (`FuncFlagSPWrite`).
    pub fn is_sp_write(&self) -> bool {
        self.func_flags().is_sp_write()
    }

    /// Whether this function is hand-written assembly (not Go-source compiled).
    ///
    /// Bit 2 of the `_func.flag` byte (`FuncFlagAsm`). Useful for closure
    /// detection: real closures are emitted as Go and never set this bit.
    pub fn is_asm(&self) -> bool {
        self.func_flags().is_asm()
    }

    /// Whether this is `runtime.systemstack` or `runtime.systemstack_switch`,
    /// the functions that switch to the system stack ([`FuncId::Systemstack`],
    /// [`FuncId::SystemstackSwitch`]). The runtime marks them by ID, not by a
    /// flag bit.
    pub fn is_systemstack(&self) -> bool {
        matches!(
            self.func_id,
            FuncId::Systemstack | FuncId::SystemstackSwitch
        )
    }

    /// Whether this is a compiler-generated closure or `gowrap` stub.
    ///
    /// The Go compiler emits closures with names of the form
    /// `parent.funcN` (and similarly `parent.gowrapN` for goroutine wrappers
    /// around method calls), where `N` is a positive integer. This checks
    /// the structural suffix shape - not the substring `.func` - and excludes
    /// hand-written assembly (which never produces closures and could
    /// otherwise share textual patterns).
    pub fn is_closure(&self) -> bool {
        if self.is_asm() {
            return false;
        }
        has_closure_suffix(self.name)
    }

    /// Whether this is a Go internal package (runtime, internal/*, vendor/*).
    pub fn is_internal(&self) -> bool {
        is_internal_path(self.package().unwrap_or(""))
    }

    /// Whether this is a standard library function (not user code, not runtime internals).
    pub fn is_stdlib(&self) -> bool {
        self.package().is_some_and(is_stdlib_path)
    }
}

/// Where a binary was built, read off the source paths its pclntab records
/// ([`crate::GoBinary::build_paths`]): the attribution a build without
/// `-trimpath` leaves. A field is `None` when the paths are trimmed (Go
/// records them relative, `runtime/proc.go`) or name no such place.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BuildPaths<'a> {
    /// GOROOT: the root of the runtime package's files,
    /// `<goroot>/src/runtime/` (`<goroot>/src/pkg/runtime/` in Go 1.2-1.3).
    pub goroot: Option<&'a str>,
    /// The module cache (`GOMODCACHE`): the root of a module's files,
    /// `<cache>/<module path>@<version>/`.
    pub module_cache: Option<&'a str>,
    /// GOPATH: the root of a package's files in GOPATH mode,
    /// `<gopath>/src/<import path>/`, or the module cache's parent when it is
    /// the default `<gopath>/pkg/mod`.
    pub gopath: Option<&'a str>,
    /// The directory of the main package's files.
    pub main_dir: Option<&'a str>,
    /// The home directory those paths are under: `/home/<user>`,
    /// `/Users/<user>`, `/root` or `<drive>:/Users/<user>`.
    pub home: Option<&'a str>,
}

impl<'a> BuildPaths<'a> {
    /// Read the paths off `(package path, source file)` pairs, one or more
    /// per package.
    pub fn from_files(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let files: Vec<(&str, &str)> = files
            .into_iter()
            .filter(|(_, file)| is_absolute(file))
            .collect();
        let mut paths = Self::default();
        for &(package, file) in &files {
            let dir = parent(file);
            match package {
                "main" => paths.main_dir = paths.main_dir.or(Some(dir)),
                "runtime" => {
                    paths.goroot = paths.goroot.or_else(|| {
                        strip_path_suffix(dir, "/src/runtime")
                            .or_else(|| strip_path_suffix(dir, "/src/pkg/runtime"))
                    });
                }
                _ => {}
            }
        }
        for &(package, file) in &files {
            if matches!(package, "main" | "runtime") {
                continue;
            }
            let dir = parent(file);
            if let Some(cache) = module_root(dir, package) {
                paths.module_cache = paths.module_cache.or(Some(cache));
                paths.gopath = paths
                    .gopath
                    .or_else(|| strip_path_suffix(cache, "/pkg/mod"));
                continue;
            }
            // A package under another root than GOROOT is a GOPATH one; one
            // whose path names no domain may be a GOROOT package itself, so
            // it counts only once GOROOT is known.
            let dotted = package
                .split('/')
                .next()
                .is_some_and(|first| first.contains('.'));
            let Some(root) = strip_path_suffix(dir, &format!("/src/{package}")) else {
                continue;
            };
            if dotted || paths.goroot.is_some_and(|goroot| goroot != root) {
                paths.gopath = paths.gopath.or(Some(root));
            }
        }
        paths.home = [
            paths.main_dir,
            paths.module_cache,
            paths.gopath,
            paths.goroot,
        ]
        .into_iter()
        .flatten()
        .chain(files.iter().map(|&(_, file)| file))
        .find_map(home_dir);
        paths
    }
}

/// Whether `path` is absolute: rooted at `/`, or at a Windows drive.
fn is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.first() == Some(&b'/')
        || (bytes.first().is_some_and(u8::is_ascii_alphabetic)
            && bytes.get(1) == Some(&b':')
            && matches!(bytes.get(2), Some(b'/' | b'\\')))
}

/// `path` up to its last separator (`/`, or `\` on Windows).
fn parent(path: &str) -> &str {
    path.rfind(['/', '\\'])
        .and_then(|end| path.get(..end))
        .unwrap_or("")
}

/// `path` less `suffix`, matching `/` in `suffix` against either separator.
fn strip_path_suffix<'p>(path: &'p str, suffix: &str) -> Option<&'p str> {
    let start = path.len().checked_sub(suffix.len())?;
    let tail = path.get(start..)?;
    let same = tail
        .bytes()
        .zip(suffix.bytes())
        .all(|(a, b)| a == b || (a == b'\\' && b == b'/'));
    same.then(|| path.get(..start)).flatten()
}

/// The module cache root of a file of package `package` in directory `dir`:
/// the prefix before `/<module path>@`, where the module path is a leading
/// part of the package path, written with the cache's escaping (an upper-case
/// letter becomes `!` and the letter in lower case).
fn module_root<'d>(dir: &'d str, package: &str) -> Option<&'d str> {
    let at = dir.find('@')?;
    let before = dir.get(..at)?;
    let mut cuts: Vec<usize> = package.match_indices('/').map(|(i, _)| i).collect();
    cuts.push(package.len());
    cuts.into_iter().rev().find_map(|cut| {
        let module = escape_module_path(package.get(..cut)?);
        strip_path_suffix(before, &format!("/{module}"))
    })
}

/// A module path as the module cache spells it (`golang.org/x/mod/module`,
/// `EscapePath`).
fn escape_module_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The home directory `path` lies under, if it names one.
fn home_dir(path: &str) -> Option<&str> {
    if path == "/root" || path.starts_with("/root/") {
        return path.get(..5);
    }
    let drive = is_absolute(path) && !path.starts_with('/');
    let users = if path.starts_with("/home/") {
        6
    } else if path.starts_with("/Users/") {
        7
    } else if drive && matches!(path.get(3..9), Some("Users/" | "Users\\")) {
        9
    } else {
        return None;
    };
    let rest = path.get(users..)?;
    let user = rest.find(['/', '\\']).unwrap_or(rest.len());
    if user == 0 {
        return None;
    }
    path.get(..users.checked_add(user)?)
}

/// What a call to a runtime hook does ([`crate::GoBinary::runtime_hooks`]).
///
/// The compiler lowers these Go operations to calls of fixed runtime (and
/// `syscall`) functions, so a call to one of them in the code marks the
/// operation at that call site. Finding the call sites takes a disassembler;
/// the hooks are their targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookKind {
    /// A call into C: `runtime.cgocall`, and each stub cgo generates for a C
    /// function (`pkg._Cfunc_<name>`), named for the C function it calls.
    CgoCall,
    /// The entry C code calls Go through (`runtime.cgocallback`), also used
    /// by Windows system callbacks.
    CgoCallback,
    /// A `go` statement (`runtime.newproc`).
    Spawn,
    /// `make(chan T)` (`runtime.makechan`, `makechan64`).
    ChanMake,
    /// A channel send (`runtime.chansend1`), or a non-blocking one in a
    /// `select` with one case and a default (`runtime.selectnbsend`).
    ChanSend,
    /// A channel receive (`runtime.chanrecv1`, `chanrecv2` for `v, ok`), or a
    /// non-blocking one (`runtime.selectnbrecv`, and `selectnbrecv2` before
    /// Go 1.17).
    ChanRecv,
    /// `close(ch)` (`runtime.closechan`).
    ChanClose,
    /// A `select` statement (`runtime.selectgo`; before Go 1.11 built up by
    /// `runtime.newselect`, `selectsend`, `selectrecv`, `selectrecv2` and
    /// `selectdefault` first), or an empty `select {}` (`runtime.block`).
    Select,
    /// A `defer` statement the compiler did not open-code
    /// (`runtime.deferproc`, `deferprocStack` from Go 1.13, `deferprocat` from
    /// Go 1.23). Open-coded defers (Go 1.14+) call nothing; see
    /// [`crate::GoBinary::open_defers`].
    Defer,
    /// `panic(v)` (`runtime.gopanic`; `runtime.panic` before Go 1.4).
    Panic,
    /// `recover()` (`runtime.gorecover`; `runtime.recover` before Go 1.4).
    Recover,
    /// The registration of a package's coverage metadata
    /// (`runtime.addCovMeta`, Go 1.20+ `-cover` builds), the first call of
    /// each instrumented package's init function. Its arguments are the
    /// metadata blob's address, length and hash, the package path, its id,
    /// and the counter mode and granularity: see
    /// [`crate::structures::coverage`].
    CoverageRegistration,
    /// A raw system call through package `syscall` or the runtime's
    /// (`syscall.Syscall`, `Syscall6`, `SyscallN`, `RawSyscall`, the darwin
    /// `syscall.syscall` family, `internal/runtime/syscall.Syscall6`, ...).
    Syscall,
}

/// The runtime and `syscall` functions each [`HookKind`] names, across Go
/// versions: a function a release lacks is simply not found.
///
/// Source: `src/cmd/compile/internal/walk` and
/// `src/cmd/compile/internal/ssagen/ssa.go` (the calls the compiler emits),
/// `src/syscall/syscall_*.go`.
const RUNTIME_HOOKS: &[(&str, HookKind)] = &[
    ("runtime.cgocall", HookKind::CgoCall),
    ("runtime.cgocallback", HookKind::CgoCallback),
    ("runtime.newproc", HookKind::Spawn),
    ("runtime.makechan", HookKind::ChanMake),
    ("runtime.makechan64", HookKind::ChanMake),
    ("runtime.chansend1", HookKind::ChanSend),
    ("runtime.selectnbsend", HookKind::ChanSend),
    ("runtime.chanrecv1", HookKind::ChanRecv),
    ("runtime.chanrecv2", HookKind::ChanRecv),
    ("runtime.selectnbrecv", HookKind::ChanRecv),
    ("runtime.selectnbrecv2", HookKind::ChanRecv),
    ("runtime.closechan", HookKind::ChanClose),
    ("runtime.selectgo", HookKind::Select),
    ("runtime.newselect", HookKind::Select),
    ("runtime.selectsend", HookKind::Select),
    ("runtime.selectrecv", HookKind::Select),
    ("runtime.selectrecv2", HookKind::Select),
    ("runtime.selectdefault", HookKind::Select),
    ("runtime.block", HookKind::Select),
    ("runtime.deferproc", HookKind::Defer),
    ("runtime.deferprocStack", HookKind::Defer),
    ("runtime.deferprocat", HookKind::Defer),
    ("runtime.gopanic", HookKind::Panic),
    ("runtime.panic", HookKind::Panic),
    ("runtime.gorecover", HookKind::Recover),
    ("runtime.addCovMeta", HookKind::CoverageRegistration),
    ("runtime.recover", HookKind::Recover),
    ("syscall.Syscall", HookKind::Syscall),
    ("syscall.Syscall6", HookKind::Syscall),
    ("syscall.Syscall9", HookKind::Syscall),
    ("syscall.Syscall12", HookKind::Syscall),
    ("syscall.Syscall15", HookKind::Syscall),
    ("syscall.Syscall18", HookKind::Syscall),
    ("syscall.SyscallN", HookKind::Syscall),
    ("syscall.RawSyscall", HookKind::Syscall),
    ("syscall.RawSyscall6", HookKind::Syscall),
    ("syscall.syscall", HookKind::Syscall),
    ("syscall.syscall6", HookKind::Syscall),
    ("syscall.syscall6X", HookKind::Syscall),
    ("syscall.syscall9", HookKind::Syscall),
    ("syscall.rawSyscall", HookKind::Syscall),
    ("syscall.rawSyscall6", HookKind::Syscall),
    ("internal/runtime/syscall.Syscall6", HookKind::Syscall),
    ("runtime/internal/syscall.Syscall6", HookKind::Syscall),
];

impl HookKind {
    /// The hook the function named `name` is, if any.
    pub fn of(name: &str) -> Option<Self> {
        if is_cgo_stub(name) {
            return Some(Self::CgoCall);
        }
        RUNTIME_HOOKS
            .iter()
            .find(|(hook, _)| *hook == name)
            .map(|&(_, kind)| kind)
    }
}

/// One function a [`HookKind`] names, found in the binary.
#[derive(Debug, Clone)]
pub struct RuntimeHook<'a> {
    /// What a call to it does.
    pub kind: HookKind,
    /// The function: its entry is where such calls land
    /// ([`crate::GoBinary::entry_va`]).
    pub function: FunctionInfo<'a>,
}

/// Strongly-typed view of the `_func.flag` byte.
///
/// Source: `src/internal/abi/symtab.go` - three flag bits are defined as of
/// Go 1.26:
///
/// | Bit | Constant            | Meaning                                  |
/// |-----|---------------------|------------------------------------------|
/// | 0   | `FuncFlagTopFrame`  | Treat as top of stack (e.g. `goexit`)    |
/// | 1   | `FuncFlagSPWrite`   | Function writes the SP register itself   |
/// | 2   | `FuncFlagAsm`       | Hand-written assembly, not Go-compiled   |
///
/// Source pragmas like `//go:nosplit` are not encoded here; they affect
/// codegen but are not exposed at runtime via this byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FuncFlags(pub u8);

impl FuncFlags {
    /// `FuncFlagTopFrame` (bit 0).
    pub const TOP_FRAME: u8 = 1 << 0;
    /// `FuncFlagSPWrite` (bit 1).
    pub const SP_WRITE: u8 = 1 << 1;
    /// `FuncFlagAsm` (bit 2).
    pub const ASM: u8 = 1 << 2;

    /// Raw underlying byte.
    pub fn bits(self) -> u8 {
        self.0
    }

    /// Whether `FuncFlagTopFrame` is set.
    pub fn is_top_frame(self) -> bool {
        self.0 & Self::TOP_FRAME != 0
    }

    /// Whether `FuncFlagSPWrite` is set.
    pub fn is_sp_write(self) -> bool {
        self.0 & Self::SP_WRITE != 0
    }

    /// Whether `FuncFlagAsm` is set.
    pub fn is_asm(self) -> bool {
        self.0 & Self::ASM != 0
    }
}

/// Borrowed per-function PC-value tables, populated by
/// [`for_each_function`] using shared reusable buffers.
///
/// All slices borrow from buffers owned by the iteration loop, so they are
/// only valid for the duration of a single callback invocation. If you need
/// to keep them across iterations, copy via `.to_vec()`.
#[derive(Debug)]
pub struct FunctionTables<'a> {
    /// `(pc_end, line)` steps ([`ParsedPclntab::decode_pcln`]).
    pub pcln: &'a [(u32, i32)],
    /// `(pc_end, stack pointer delta)` steps.
    pub pcsp: &'a [(u32, i32)],
    /// `(pc_end, file index)` steps. Resolve an index via
    /// [`ParsedPclntab::resolve_file_index`] using `FuncData::cu_offset`.
    pub pcfile: &'a [(u32, u32)],
}

/// Walk every function in the pclntab and invoke `f` once per function with
/// a [`FunctionInfo`] and its decoded per-PC tables.
///
/// Bulk equivalent of [`FunctionIter`] paired with per-function table
/// decoding - but using three reusable buffers shared across the whole walk
/// instead of allocating fresh `Vec`s for each function. For binaries with
/// tens of thousands of functions this avoids `O(nfunc)` allocations.
///
/// ```no_run
/// use gobin::{GoBinary, metadata::for_each_function};
/// # let data = vec![];
/// let bin = GoBinary::parse(&data).unwrap();
/// let pcl = bin.pclntab().unwrap();
/// for_each_function(&pcl, |info, tables| {
///     println!("{}: {} pcln entries", info.name, tables.pcln.len());
/// });
/// ```
pub fn for_each_function<F>(pclntab: &ParsedPclntab<'_>, mut f: F)
where
    F: FnMut(&FunctionInfo<'_>, &FunctionTables<'_>),
{
    let mut pcln_buf: Vec<(u32, i32)> = Vec::new();
    let mut pcsp_buf: Vec<(u32, i32)> = Vec::new();
    let mut pcfile_buf: Vec<(u32, u32)> = Vec::new();

    for (_entry_off, func_off) in pclntab.func_entries() {
        let func_data: FuncData = match pclntab.parse_func(func_off) {
            Some(fd) => fd,
            None => continue,
        };

        let name = pclntab
            .func_name(func_data.name_off as u32)
            .unwrap_or("<unknown>");

        pcln_buf.clear();
        pcln_buf.extend(pclntab.decode_pcln(&func_data));
        pcsp_buf.clear();
        pcsp_buf.extend(pclntab.decode_pcvalue(func_data.pcsp));
        pcfile_buf.clear();
        pcfile_buf.extend(pclntab.decode_pcfile(&func_data));

        let own = OwnCode::walk(
            pcln_buf.iter().copied(),
            pcfile_buf.iter().copied(),
            pclntab.inline_index_table(&func_data),
        );
        let source_file = own
            .file_index
            .and_then(|index| pclntab.resolve_file_index(func_data.cu_offset, index));
        let end_line = own.lines.map_or(0, |(_, end)| end);
        let frame_size = pcsp_buf.iter().map(|e| e.1).max().unwrap_or(0);

        let info = FunctionInfo {
            name,
            func_id: pclntab.func_id(&func_data, name),
            func: func_data,
            source_file,
            end_line,
            frame_size,
        };

        let tables = FunctionTables {
            pcln: &pcln_buf,
            pcsp: &pcsp_buf,
            pcfile: &pcfile_buf,
        };

        f(&info, &tables);
    }
}

/// Streaming iterator over [`FunctionInfo`] entries for a binary.
///
/// Yields functions one at a time without allocating a `Vec` up-front. Backs
/// [`crate::GoBinary::functions`].
///
/// Two lifetimes:
/// - `'p`: how long the borrow on the [`ParsedPclntab`] lives (typically tied
///   to a `&self` on `GoBinary`).
/// - `'a`: lifetime of the underlying binary bytes; yielded
///   [`FunctionInfo`] structs borrow strings from there.
///
/// Skips functions whose `_func` struct fails to parse - adversarial pclntab
/// data cannot panic the iteration. Yields zero items for binaries without a
/// recoverable pclntab.
pub struct FunctionIter<'a> {
    inner: Option<FunctionIterInner<'a>>,
}

struct FunctionIterInner<'a> {
    pclntab: ParsedPclntab<'a>,
    entries: FuncEntryIter<'a>,
}

impl<'a> FunctionIter<'a> {
    /// Build an iterator that yields one [`FunctionInfo`] per function in the
    /// pclntab. Pass `None` (or an unparsed binary) to get an empty iterator.
    ///
    /// Takes the [`ParsedPclntab`] by value because the struct is `Copy` and
    /// the iterator needs to outlive any temporary borrow the caller might
    /// have constructed (e.g. on-demand reconstruction from
    /// [`crate::structures::pclntab::PclntabMeta::attach`]).
    pub fn new(pclntab: Option<ParsedPclntab<'a>>) -> Self {
        Self {
            inner: pclntab.map(|p| FunctionIterInner {
                entries: p.func_entries(),
                pclntab: p,
            }),
        }
    }
}

impl<'a> Iterator for FunctionIter<'a> {
    type Item = FunctionInfo<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let inner = self.inner.as_mut()?;
        loop {
            let (_entry_off, func_off) = inner.entries.next()?;
            let func_data = match inner.pclntab.parse_func(func_off) {
                Some(fd) => fd,
                None => continue,
            };
            return Some(FunctionInfo::from_func(&inner.pclntab, func_data));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(name: &'static str) -> FunctionInfo<'static> {
        FunctionInfo {
            name,
            func_id: FuncId::Normal,
            func: FuncData {
                func_off: 0,
                entry_off: 0,
                name_off: 0,
                args: 0,
                deferreturn: 0,
                pcsp: 0,
                pcfile: 0,
                pcln: 0,
                npcdata: 0,
                cu_offset: 0,
                start_line: 0,
                func_id: 0,
                flag: 0,
                nfuncdata: 0,
            },
            source_file: None,
            end_line: 0,
            frame_size: 0,
        }
    }

    /// Sample of well-known Go function-name shapes covering stdlib,
    /// third-party (domain-prefixed) packages, methods, generics, closures,
    /// and runtime internals.
    const NAME_CORPUS: &[&str] = &[
        "runtime.gcStart",
        "runtime.main",
        "fmt.Println",
        "net/http.(*Client).Do",
        "encoding/json.Marshal",
        "github.com/spf13/cobra.(*Command).Run",
        "github.com/spf13/cobra.OnInitialize",
        "golang.org/x/crypto/aes.NewCipher",
        "gopkg.in/yaml.v3.Marshal",
        "k8s.io/client-go/rest.(*Config).TransportConfig",
        "main.main",
        "main.main.func1",
        "main.run.func2.gowrap1",
        "sync.(*Mutex).Lock",
        "time.Time.String",
        "sort.Slice[...]",
    ];

    #[test]
    fn property_package_short_name_roundtrip() {
        for &name in NAME_CORPUS {
            let f = make(name);
            let pkg = f
                .package()
                .unwrap_or_else(|| panic!("no package for {name}"));
            let short = f.short_name();
            assert_eq!(
                format!("{pkg}.{short}"),
                name,
                "package + '.' + short_name must round-trip for {name}",
            );
        }
    }

    #[test]
    fn package_handles_third_party_domains() {
        assert_eq!(make("runtime.gcStart").package(), Some("runtime"));
        assert_eq!(make("net/http.(*Client).Do").package(), Some("net/http"));
        assert_eq!(
            make("github.com/spf13/cobra.(*Command).Run").package(),
            Some("github.com/spf13/cobra"),
        );
        assert_eq!(
            make("golang.org/x/crypto/aes.NewCipher").package(),
            Some("golang.org/x/crypto/aes"),
        );
        assert_eq!(
            make("gopkg.in/yaml.v3.Marshal").package(),
            Some("gopkg.in/yaml.v3"),
        );
    }

    #[test]
    fn short_name_handles_third_party_domains() {
        assert_eq!(make("runtime.gcStart").short_name(), "gcStart");
        assert_eq!(make("net/http.(*Client).Do").short_name(), "(*Client).Do");
        assert_eq!(
            make("github.com/spf13/cobra.(*Command).Run").short_name(),
            "(*Command).Run",
        );
        assert_eq!(
            make("golang.org/x/crypto/aes.NewCipher").short_name(),
            "NewCipher",
        );
        assert_eq!(make("gopkg.in/yaml.v3.Marshal").short_name(), "Marshal");
    }

    #[test]
    fn package_returns_none_when_no_dot_after_path() {
        assert_eq!(make("noslash").package(), None);
        assert_eq!(make("github.com/user/pkg").package(), None);
    }

    #[test]
    fn deps_full_and_module_sum_surface_parsed_detail() {
        let info = BuildInfo {
            main_module: Some("example.com/app"),
            main_version: Some("v1.2.3"),
            main_module_sum: Some("h1:mainsum="),
            deps: vec![DepEntry {
                path: "golang.org/x/crypto",
                version: Some("v0.1.0"),
                sum: Some("h1:depsum="),
                replacement: Some(DepReplacement {
                    path: "github.com/forked/crypto",
                    version: Some("v0.1.1"),
                    sum: Some("h1:repl="),
                }),
            }],
            ..Default::default()
        };
        assert_eq!(info.module_sum(), Some("h1:mainsum="));
        let deps: Vec<&DepEntry<'_>> = info.deps_full().collect();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].sum, Some("h1:depsum="));
        assert_eq!(
            deps[0].replacement.as_ref().map(|r| r.path),
            Some("github.com/forked/crypto")
        );
        // The lossy convenience iterator still yields just (path, version).
        let simple: Vec<_> = info.dependencies().collect();
        assert_eq!(simple, vec![("golang.org/x/crypto", Some("v0.1.0"))]);
    }

    #[test]
    fn func_flags_bit_accessors() {
        assert!(!FuncFlags(0).is_top_frame());
        assert!(FuncFlags(FuncFlags::TOP_FRAME).is_top_frame());
        assert!(FuncFlags(FuncFlags::SP_WRITE).is_sp_write());
        assert!(FuncFlags(FuncFlags::ASM).is_asm());
        let all = FuncFlags(FuncFlags::TOP_FRAME | FuncFlags::SP_WRITE | FuncFlags::ASM);
        assert!(all.is_top_frame() && all.is_sp_write() && all.is_asm());
        assert_eq!(all.bits(), 0b111);
    }

    #[test]
    fn build_mode_parses_known_values() {
        assert_eq!(BuildMode::parse("exe"), BuildMode::Exe);
        assert_eq!(BuildMode::parse(""), BuildMode::Exe);
        assert_eq!(BuildMode::parse("pie"), BuildMode::Pie);
        assert_eq!(BuildMode::parse("c-shared"), BuildMode::CShared);
        assert_eq!(BuildMode::parse("c-archive"), BuildMode::CArchive);
        assert_eq!(BuildMode::parse("plugin"), BuildMode::Plugin);
        assert_eq!(
            BuildMode::parse("future-mode"),
            BuildMode::Other("future-mode")
        );
    }

    #[test]
    fn build_tags_parses_comma_separated() {
        let info = BuildInfo {
            build_settings: vec![("-tags", "netgo,osusergo,static_build")],
            ..Default::default()
        };
        let tags: Vec<&str> = info.build_tags().collect();
        assert_eq!(tags, vec!["netgo", "osusergo", "static_build"]);
    }

    #[test]
    fn build_tags_empty_when_unset() {
        let info = BuildInfo {
            build_settings: vec![("GOOS", "linux")],
            ..Default::default()
        };
        assert_eq!(info.build_tags().count(), 0);
    }

    #[test]
    fn build_mode_defaults_to_exe() {
        let info = BuildInfo {
            build_settings: vec![("GOOS", "linux")],
            ..Default::default()
        };
        assert_eq!(info.build_mode(), Some(BuildMode::Exe));
    }

    #[test]
    fn build_mode_none_for_empty_settings() {
        let info = BuildInfo::default();
        assert_eq!(info.build_mode(), None);
    }

    #[test]
    fn is_method_handles_value_and_pointer_receivers() {
        assert!(make("net/http.(*Client).Do").is_method());
        assert!(make("time.Time.String").is_method());
        assert!(make("sync.(*Mutex).Lock").is_method());
        assert!(make("github.com/spf13/cobra.(*Command).Run").is_method());
    }

    #[test]
    fn is_method_excludes_plain_functions() {
        assert!(!make("fmt.Println").is_method());
        assert!(!make("runtime.gcStart").is_method());
        assert!(!make("encoding/json.Marshal").is_method());
    }

    #[test]
    fn is_method_excludes_closures() {
        assert!(!make("main.main.func1").is_method());
        assert!(!make("main.run.func2.gowrap1").is_method());
    }

    #[test]
    fn is_method_handles_generic_receivers() {
        assert!(make("pkg.(*Map[K, V]).Len").is_method());
        assert!(make("pkg.Map[int, string].Get").is_method());
    }

    #[test]
    fn is_closure_strict_requires_numeric_suffix() {
        assert!(make("main.main.func1").is_closure());
        assert!(make("main.main.func1.func2").is_closure());
        assert!(make("main.run.gowrap1").is_closure());
        // Just `.func` without a digit - not a closure
        assert!(!make("pkg.Func").is_closure());
        // A type literally named `Func` with a method
        assert!(!make("pkg.Func.Method").is_closure());
    }

    #[test]
    fn is_closure_excludes_asm_funcs() {
        let mut f = make("runtime.x.func1");
        f.func.flag = FuncFlags::ASM;
        assert!(!f.is_closure(), "asm-flagged functions are never closures");
    }

    #[test]
    fn receiver_type_pointer_no_generics() {
        let f = make("net/http.(*Client).Do");
        let recv = f.receiver_type().unwrap();
        assert_eq!(recv.name, "Client");
        assert!(recv.pointer);
        assert_eq!(recv.generic_args, None);
    }

    #[test]
    fn receiver_type_value_no_generics() {
        let f = make("time.Time.String");
        let recv = f.receiver_type().unwrap();
        assert_eq!(recv.name, "Time");
        assert!(!recv.pointer);
        assert_eq!(recv.generic_args, None);
    }

    #[test]
    fn receiver_type_pointer_with_generics() {
        let f = make("pkg.(*Map[K, V]).Len");
        let recv = f.receiver_type().unwrap();
        assert_eq!(recv.name, "Map");
        assert!(recv.pointer);
        assert_eq!(recv.generic_args, Some("[K, V]"));
    }

    #[test]
    fn method_name_returns_method_portion() {
        assert_eq!(make("net/http.(*Client).Do").method_name(), Some("Do"));
        assert_eq!(make("time.Time.String").method_name(), Some("String"));
        assert_eq!(make("fmt.Println").method_name(), None);
        assert_eq!(make("main.main.func1").method_name(), None);
    }

    #[test]
    fn generic_args_handles_top_level_brackets() {
        assert_eq!(make("sort.Slice[int]").generic_args(), Some("[int]"));
        assert_eq!(make("pkg.(*Map[K, V]).Len").generic_args(), Some("[K, V]"),);
        assert_eq!(make("fmt.Println").generic_args(), None);
    }

    #[test]
    fn build_paths_follow_package_roots() {
        let paths = BuildPaths::from_files([
            ("runtime", "/usr/local/go/src/runtime/proc.go"),
            ("fmt", "/usr/local/go/src/fmt/print.go"),
            ("main", "/home/dev/src/app/main.go"),
            (
                "github.com/BurntSushi/toml",
                "/home/dev/go/pkg/mod/github.com/!burnt!sushi/toml@v1.3.2/decode.go",
            ),
            (
                "example.com/m/sub",
                "/home/dev/go/pkg/mod/example.com/m@v1.0.0/sub/x.go",
            ),
            ("internal/abi", "internal/abi/type.go"),
        ]);
        assert_eq!(paths.goroot, Some("/usr/local/go"));
        assert_eq!(paths.module_cache, Some("/home/dev/go/pkg/mod"));
        assert_eq!(paths.gopath, Some("/home/dev/go"));
        assert_eq!(paths.main_dir, Some("/home/dev/src/app"));
        assert_eq!(paths.home, Some("/home/dev"));
    }

    #[test]
    fn build_paths_unescape_module_paths() {
        // The cache writes an upper-case letter as `!` and the lower case.
        let paths = BuildPaths::from_files([(
            "github.com/BurntSushi/toml",
            "/home/dev/go/pkg/mod/github.com/!burnt!sushi/toml@v1.3.2/decode.go",
        )]);
        assert_eq!(paths.module_cache, Some("/home/dev/go/pkg/mod"));
    }

    #[test]
    fn build_paths_read_gopath_mode_and_old_layouts() {
        let paths = BuildPaths::from_files([
            ("runtime", "/opt/go/src/pkg/runtime/proc.c"),
            ("mytool/util", "/Users/ana/work/src/mytool/util/u.go"),
            ("fmt", "/opt/go/src/pkg/fmt/print.go"),
        ]);
        assert_eq!(paths.goroot, Some("/opt/go"));
        assert_eq!(paths.gopath, Some("/Users/ana/work"));
        assert_eq!(paths.home, Some("/Users/ana"));
        assert_eq!(paths.module_cache, None);
    }

    #[test]
    fn build_paths_read_windows_paths() {
        let paths = BuildPaths::from_files([
            ("runtime", "C:/Program Files/Go/src/runtime/proc.go"),
            ("main", "C:\\Users\\bob\\proj\\main.go"),
        ]);
        assert_eq!(paths.goroot, Some("C:/Program Files/Go"));
        assert_eq!(paths.main_dir, Some("C:\\Users\\bob\\proj"));
        assert_eq!(paths.home, Some("C:\\Users\\bob"));
    }

    #[test]
    fn build_paths_ignore_trimmed_paths() {
        let paths = BuildPaths::from_files([
            ("runtime", "runtime/proc.go"),
            ("main", "./main.go"),
            ("example.com/m", "example.com/m@v1.0.0/m.go"),
        ]);
        assert_eq!(paths, BuildPaths::default());
        assert_eq!(home_dir("/root"), Some("/root"));
        assert_eq!(home_dir("/rootfs/x"), None);
        assert_eq!(home_dir("/home/"), None);
    }
}
