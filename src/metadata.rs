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

use std::borrow::Cow;

use crate::{
    detection::Confidence,
    structures::pclntab::{FuncData, FuncEntryIter, ParsedPclntab},
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

/// Package path portion of a fully-qualified function name, or `None` if the
/// name has no package boundary. Mirrors [`FunctionInfo::package`] for callers
/// that hold a bare `&str`.
pub(crate) fn package_of(name: &str) -> Option<&str> {
    let boundary = package_boundary(name)?;
    name.get(..boundary)
}

/// Locate the package/short-name boundary in a Go function name.
///
/// Returns the byte index of the `.` that separates package path from the
/// trailing identifier(s). Both [`FunctionInfo::package`] and
/// [`FunctionInfo::short_name`] dispatch to this so they always agree.
///
/// The base rule is "first `.` after the last `/`". Path segments use `/`
/// and identifiers do not, so this correctly distinguishes
/// `github.com/spf13/cobra.(*Command).Run` (package `github.com/spf13/cobra`)
/// from `runtime.gcStart` (package `runtime`).
///
/// On top of that we extend past `gopkg.in`-style `.vN` segments: a package
/// path like `gopkg.in/yaml.v3` ends with a `.vN` version that the base rule
/// would split incorrectly. If the segment immediately after the candidate
/// boundary matches `v<digits>.`, the boundary moves to the next `.`.
fn package_boundary(name: &str) -> Option<usize> {
    let last_slash = name.rfind('/').and_then(|p| p.checked_add(1)).unwrap_or(0);
    let segment = name.get(last_slash..)?;
    let first_dot = segment.find('.')?;
    let mut boundary = last_slash.checked_add(first_dot)?;

    let after_start = boundary.checked_add(1)?;
    if let Some(after) = name.get(after_start..)
        && let Some(rest) = after.strip_prefix('v')
    {
        let digit_end = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digit_end > 0 && rest.as_bytes().get(digit_end) == Some(&b'.') {
            // boundary advances by '.' + 'v' + N digits = 2 + digit_end
            boundary = boundary.checked_add(2)?.checked_add(digit_end)?;
        }
    }
    Some(boundary)
}

/// The Go `-buildmode` value the binary was compiled with.
///
/// Source: `src/cmd/go/internal/work/init.go` (`-buildmode` flag definitions).
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildMode {
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
    /// Any other / future build mode value as a verbatim string.
    Other(String),
}

impl BuildMode {
    /// Parse a raw `-buildmode` setting value into a [`BuildMode`].
    pub fn parse(value: &str) -> Self {
        match value {
            "exe" | "" => Self::Exe,
            "pie" => Self::Pie,
            "c-shared" => Self::CShared,
            "c-archive" => Self::CArchive,
            "plugin" => Self::Plugin,
            "archive" => Self::Archive,
            "shared" => Self::Shared,
            other => Self::Other(other.to_string()),
        }
    }

    /// The canonical `-buildmode` flag string, suitable for round-tripping
    /// through [`Self::parse`].
    ///
    /// Returns the same kebab-case identifiers the Go toolchain accepts
    /// (`"exe"`, `"pie"`, `"c-shared"`, `"c-archive"`, `"plugin"`,
    /// `"archive"`, `"shared"`). For [`BuildMode::Other`] the inner verbatim
    /// string is returned as a borrowed `Cow`. See the `# Stability` section
    /// on [`BuildMode`] for the durability contract.
    pub fn as_str(&self) -> Cow<'static, str> {
        match self {
            Self::Exe => Cow::Borrowed("exe"),
            Self::Pie => Cow::Borrowed("pie"),
            Self::CShared => Cow::Borrowed("c-shared"),
            Self::CArchive => Cow::Borrowed("c-archive"),
            Self::Plugin => Cow::Borrowed("plugin"),
            Self::Archive => Cow::Borrowed("archive"),
            Self::Shared => Cow::Borrowed("shared"),
            Self::Other(s) => Cow::Owned(s.clone()),
        }
    }
}

impl std::fmt::Display for BuildMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_str())
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
/// | `CGO_ENABLED`    | `1`           | CGo enablement                 |
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

    /// Whether CGo was enabled at build time.
    pub fn cgo_enabled(&self) -> Option<bool> {
        self.setting("CGO_ENABLED").map(|v| v == "1")
    }

    /// VCS commit hash, if the binary was built from a VCS checkout.
    pub fn vcs_revision(&self) -> Option<&'a str> {
        self.setting("vcs.revision")
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
    pub fn build_mode(&self) -> Option<BuildMode> {
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
    /// PC offset from `runtime.text` (the start of executable code).
    pub entry_offset: u32,
    /// Total argument size in bytes (input + output parameters).
    pub args_size: i32,
    /// Source line number where the `func` keyword appears.
    pub start_line: i32,
    /// Special function ID (0 = normal). See [`crate::structures::pclntab::FuncData`]
    /// for the FuncID value table.
    pub func_id: u8,
    /// Function flags (top-frame, SP-write, asm).
    pub flags: u8,
    /// Offset from function entry to the `deferreturn` call (0 if no defer).
    pub deferreturn: u32,
    /// Offset into `pctab` for the stack-pointer delta table.
    pub pcsp: u32,
    /// Offset into `pctab` for the PC-to-file mapping table.
    pub pcfile: u32,
    /// Offset into `pctab` for the PC-to-line mapping table.
    pub pcln: u32,
    /// Number of PCDATA entries (metadata tables per PC range).
    pub npcdata: u32,
    /// Compilation unit offset in `cutab`.
    pub cu_offset: u32,
    /// Number of FUNCDATA entries (per-function data blobs like stack maps).
    pub nfuncdata: u8,
    /// Source file path for this function's entry point (resolved from pcfile + cutab).
    pub source_file: Option<&'a str>,
    /// Last source line in the function (decoded from the pcln table).
    pub end_line: i32,
    /// Maximum stack frame size in bytes (decoded from the pcsp table).
    pub frame_size: i32,
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
    /// # use gobin::metadata::FunctionInfo;
    /// # fn f(name: &str) -> FunctionInfo<'_> { FunctionInfo { name, entry_offset: 0, args_size: 0, start_line: 0, func_id: 0, flags: 0, deferreturn: 0, pcsp: 0, pcfile: 0, pcln: 0, npcdata: 0, cu_offset: 0, nfuncdata: 0, source_file: None, end_line: 0, frame_size: 0 } }
    /// assert_eq!(f("net/http.(*Client).Do").package(), Some("net/http"));
    /// assert_eq!(f("github.com/spf13/cobra.(*Command).Run").package(), Some("github.com/spf13/cobra"));
    /// assert_eq!(f("gopkg.in/yaml.v3.Marshal").package(), Some("gopkg.in/yaml.v3"));
    /// ```
    pub fn package(&self) -> Option<&str> {
        let boundary = package_boundary(self.name)?;
        Some(&self.name[..boundary])
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
        self.deferreturn != 0
    }

    /// Strongly-typed view of the [`Self::flags`] byte.
    pub fn func_flags(&self) -> FuncFlags {
        FuncFlags(self.flags)
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

    /// Whether this function runs on the system stack (`FuncIDsystemstack` /
    /// `FuncIDsystemstack_switch`).
    ///
    /// Inferred from [`Self::func_id`], not from `flag` - the runtime tracks
    /// systemstack by ID rather than a flag bit.
    pub fn is_systemstack(&self) -> bool {
        matches!(self.func_id, 98 | 99)
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

    /// Human-readable FuncID label, if this is a special runtime function.
    pub fn func_id_name(&self) -> Option<&'static str> {
        match self.func_id {
            0 => None,
            80 => Some("abort"),
            81 => Some("asmcgocall"),
            82 => Some("asyncPreempt"),
            83 => Some("cgocallback"),
            84 => Some("debugCallV2"),
            85 => Some("gcBgMarkWorker"),
            86 => Some("goexit"),
            87 => Some("gogo"),
            88 => Some("gopanic"),
            89 => Some("handleAsyncEvent"),
            90 => Some("mcall"),
            91 => Some("morestack"),
            92 => Some("mstart"),
            93 => Some("panicwrap"),
            94 => Some("rt0_go"),
            95 => Some("runfinq"),
            96 => Some("runtime_main"),
            97 => Some("sigpanic"),
            98 => Some("systemstack"),
            99 => Some("systemstack_switch"),
            100 => Some("wrapper"),
            _ => Some("unknown_special"),
        }
    }
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
    /// PC -> absolute line number.
    pub pcln: &'a [(u32, i32)],
    /// PC -> stack pointer delta.
    pub pcsp: &'a [(u32, i32)],
    /// PC -> file index. Resolve via
    /// [`ParsedPclntab::resolve_file_via_cu`] using `FuncData::cu_offset`.
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

        let source_file = pcfile_buf
            .first()
            .and_then(|(_, idx)| pclntab.resolve_file_via_cu(func_data.cu_offset, *idx));

        let end_line = pcln_buf.iter().map(|e| e.1).max().unwrap_or(0);
        let frame_size = pcsp_buf.iter().map(|e| e.1).max().unwrap_or(0);

        let info = FunctionInfo {
            name,
            entry_offset: func_data.entry_off,
            args_size: func_data.args,
            start_line: func_data.start_line,
            func_id: func_data.func_id,
            flags: func_data.flag,
            deferreturn: func_data.deferreturn,
            pcsp: func_data.pcsp,
            pcfile: func_data.pcfile,
            pcln: func_data.pcln,
            npcdata: func_data.npcdata,
            cu_offset: func_data.cu_offset,
            nfuncdata: func_data.nfuncdata,
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
            let name = inner
                .pclntab
                .func_name(func_data.name_off as u32)
                .unwrap_or("<unknown>");
            let source_file = inner.pclntab.resolve_source_file(&func_data);
            let end_line = inner
                .pclntab
                .line_range(&func_data)
                .map(|(_, end)| end)
                .unwrap_or(0);
            let frame_size = inner.pclntab.max_frame_size(&func_data).unwrap_or(0);
            return Some(FunctionInfo {
                name,
                entry_offset: func_data.entry_off,
                args_size: func_data.args,
                start_line: func_data.start_line,
                func_id: func_data.func_id,
                flags: func_data.flag,
                deferreturn: func_data.deferreturn,
                pcsp: func_data.pcsp,
                pcfile: func_data.pcfile,
                pcln: func_data.pcln,
                npcdata: func_data.npcdata,
                cu_offset: func_data.cu_offset,
                nfuncdata: func_data.nfuncdata,
                source_file,
                end_line,
                frame_size,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(name: &'static str) -> FunctionInfo<'static> {
        FunctionInfo {
            name,
            entry_offset: 0,
            args_size: 0,
            start_line: 0,
            func_id: 0,
            flags: 0,
            deferreturn: 0,
            pcsp: 0,
            pcfile: 0,
            pcln: 0,
            npcdata: 0,
            cu_offset: 0,
            nfuncdata: 0,
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
            BuildMode::Other("future-mode".into())
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
        f.flags = FuncFlags::ASM;
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
}
