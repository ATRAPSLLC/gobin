//! Go binary detection via heuristic string matching.
//!
//! This module provides the lowest-confidence detection layer. When a binary's format
//! cannot be parsed (corrupted headers, unknown format) and no structural markers are
//! found (no pclntab magic, no build ID), we fall back to scanning for strings that
//! appear in virtually every Go binary.
//!
//! ## Why These Strings Survive
//!
//! The Go runtime references these function names and error messages at runtime for
//! stack traces, panic output, and goroutine management. Even heavily stripped or
//! obfuscated Go binaries retain them in the pclntab's `funcnametab` (which is
//! separate from the ELF/PE symbol table).
//!
//! ## Confidence Levels
//!
//! The [`Confidence`] enum represents how certain we are that a binary is Go-compiled:
//!
//! | Level    | Meaning                                                     |
//! |----------|-------------------------------------------------------------|
//! | `None`   | No Go indicators found                                      |
//! | `Low`    | Heuristic string matches only (could be false positive)     |
//! | `Medium` | Build info or version string found                          |
//! | `High`   | Structural proof: pclntab magic, section names, or build ID |

use crate::structures::{
    PclntabVersion, itab::ItabLayout, locate::ModuledataSource, maptype::MapLayout,
    moduledata::ModuledataVersion,
};
use crate::{formats::FatSlice, util::find_bytes};

/// Confidence level for Go binary identification.
///
/// Ordered from lowest to highest, so you can use comparison operators:
/// ```
/// # use gobin::detection::Confidence;
/// assert!(Confidence::Low < Confidence::High);
/// ```
///
/// # Stability
///
/// Consumers persist this enum into long-lived schemas (database columns,
/// structured logs). The contract:
///
/// - **Variants** - append-only. New tiers appear as new variants; existing
///   variants are never renamed or removed.
/// - **`Display` strings** (and [`Self::as_str`]) - fixed forever once
///   shipped. Treat them as serialization keys.
/// - **`Debug` strings** - *not* a stability surface. Use `Display` /
///   `as_str` for anything that lands in a database column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// No Go-specific indicators were found.
    None,
    /// Only heuristic string patterns matched (e.g. `"runtime.main"` in binary).
    /// May produce false positives for binaries that embed Go-like strings.
    Low,
    /// A Go version string (`"go1.XX"`) or build info blob was found, but no
    /// structural proof (pclntab, section names) could be verified.
    Medium,
    /// Definitive structural markers confirmed: pclntab magic bytes, Go-specific
    /// section names (`.gopclntab`, `.go.buildinfo`), or ELF build ID notes.
    High,
}

impl Confidence {
    /// Stable lowercase identifier for this confidence tier
    /// (`"none"` / `"low"` / `"medium"` / `"high"`).
    ///
    /// See the `# Stability` section on [`Confidence`] for the durability
    /// contract these strings carry.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Structured detection report produced during [`crate::GoBinary::parse`] /
/// [`crate::GoBinary::try_parse`].
///
/// Wraps the headline [`Confidence`] tier with a list of individual signals
/// observed during analysis, so callers can answer "*why* did this score
/// Medium?" without re-running detection. Used for analyst-facing diagnostics
/// (the `examples/dump --explain` mode) and for upstream bug reports.
#[derive(Debug, Clone)]
pub struct ConfidenceReport {
    /// Final confidence tier.
    pub tier: Confidence,
    /// Individual signals collected during detection, in the order observed.
    pub signals: Vec<ConfidenceSignal>,
}

impl ConfidenceReport {
    /// Construct an empty report at [`Confidence::None`].
    pub fn empty() -> Self {
        Self {
            tier: Confidence::None,
            signals: Vec::new(),
        }
    }

    /// Append a signal to the report.
    pub fn push(&mut self, signal: ConfidenceSignal) {
        self.signals.push(signal);
    }

    /// Raise the tier if the new tier is strictly higher.
    pub fn raise_to(&mut self, tier: Confidence) {
        if tier > self.tier {
            self.tier = tier;
        }
    }
}

/// One observation made during Go-binary detection.
///
/// **Sealed**: this enum is exhaustively defined and not marked
/// `#[non_exhaustive]`. Adding a variant is a breaking API change so callers
/// can rely on exhaustive match without `_ =>` arms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfidenceSignal {
    /// `.gopclntab` / `__gopclntab` section was present in the binary headers.
    GopclntabSectionPresent,
    /// `.go.buildinfo` / `__go_buildinfo` section was present.
    BuildinfoSectionPresent,
    /// ELF `.note.go.buildid` (or `Go\0\0` note marker) was present.
    BuildidNotePresent,
    /// A Go type-metadata section was present. These names are unique to the
    /// Go linker, so any of them is structural proof on its own - useful on
    /// stripped binaries where `.gopclntab` was renamed away.
    TypeSectionPresent {
        /// Which section matched, in its ELF spelling (`".typelink"`,
        /// `".itablink"`, `".go.type"`, `".go.func"`). Mach-O spellings map
        /// onto the same values.
        section: &'static str,
    },
    /// Build ID raw marker (`\xff Go build ID:`) was found.
    BuildIdMarkerFound,
    /// Build info blob was successfully parsed.
    BuildinfoParsed,
    /// Build info parse failed for the given reason.
    BuildinfoMissing {
        /// Short, static reason string.
        reason: &'static str,
    },
    /// pclntab was successfully parsed; carries the format version and function count.
    PclntabParsed {
        /// Detected pclntab format version.
        version: PclntabVersion,
        /// Number of functions decoded from the pclntab.
        nfunc: usize,
    },
    /// pclntab could not be parsed for the given reason.
    PclntabMissing {
        /// Short, static reason string.
        reason: &'static str,
    },
    /// A Go version string was located; [`crate::GoBinary::go_version`]
    /// holds it.
    GoVersionString {
        /// Where the version was sourced from.
        source: VersionSource,
    },
    /// Heuristic runtime string patterns matched at low confidence.
    HeuristicStringsMatched {
        /// Number of distinct patterns matched.
        hits: usize,
    },
    /// The moduledata was found: the layout it was read with, and how.
    ModuledataLocated {
        /// Its layout.
        version: ModuledataVersion,
        /// How it was found.
        source: ModuledataSource,
    },
    /// No moduledata was found (Go 1.2-1.4 have none): types, itabs, init
    /// tasks and code addresses are unavailable.
    ModuledataMissing,
    /// The layouts the version-dependent records are read with, and what
    /// fixed them.
    LayoutsChosen {
        /// The itab record's.
        itab: ItabLayout,
        /// The map type descriptor's; `None` without a pclntab.
        map: Option<MapLayout>,
        /// Whether a text offset names a function by its index (wasm from
        /// Go 1.25) rather than by its PC offset.
        text_offsets_indexed: bool,
        /// What fixed them.
        decided_by: LayoutEvidence,
    },
    /// The container's symbol table defines symbols
    /// ([`crate::GoBinary::symbols`] reads them).
    SymbolTable,
    /// The container's symbol table defines no symbol: linked with
    /// `-ldflags=-s`, or stripped after (a stripped Mach-O keeps only its
    /// imports). Not reported for wasm, which has no such table.
    SymbolTableStripped,
}

/// What fixed the layouts gobin reads a binary's version-dependent records
/// with ([`ConfidenceSignal::LayoutsChosen`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutEvidence {
    /// The Go version the binary records.
    VersionString,
    /// The binary's structure (the pclntab, `_func` and moduledata layouts),
    /// for a binary whose version is unknown.
    Structure,
}

/// Where a Go version string was extracted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSource {
    /// Parsed from the structured build info blob.
    BuildInfoBlob,
    /// Read from a wasm module's `producers` custom section, which records
    /// the toolchain version in full
    /// ([`crate::structures::wasm::go_producer_version`]).
    WasmProducers,
    /// Found by scanning binary data for `go1.<digits>` patterns.
    StringScan,
}

/// Reason a binary could not be parsed as Go.
///
/// **Sealed** for the same reason as [`ConfidenceSignal`].
#[derive(Debug, Clone)]
pub enum ParseError {
    /// No Go-specific indicators were found above the [`Confidence::None`]
    /// threshold. The attached report records every signal that *was* checked,
    /// useful for surfacing "what was missing" to an analyst.
    NotAGoBinary {
        /// The detection report at the point of failure.
        report: ConfidenceReport,
    },
    /// A universal ("fat") Mach-O file: several thin images, one per
    /// architecture, which [`crate::GoBinary`] reads one at a time. Parse
    /// each slice's bytes, `&data[slice.range.clone()]`
    /// ([`crate::formats::macho_slices`]).
    Universal {
        /// The slices, in the order the header lists them.
        slices: Vec<FatSlice>,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAGoBinary { report } => {
                write!(
                    f,
                    "not a Go binary: no Go indicators found ({} signals checked)",
                    report.signals.len()
                )
            }
            Self::Universal { slices } => write!(
                f,
                "a universal Mach-O file of {} slices: parse each slice",
                slices.len()
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Strings that appear in virtually every Go binary.
///
/// These are function names stored in the pclntab `funcnametab` and runtime error
/// strings compiled into the `.rodata` section. They survive both stripping and
/// the removal of the ELF/PE symbol table.
///
/// Source: `runtime/proc.go` (runtime.main), `runtime/panic.go` (fatal errors),
/// `runtime/asm_*.s` (rt0_go, mstart, goexit), `runtime/proc.go` (newproc).
const HEURISTIC_PATTERNS: &[&[u8]] = &[
    b"runtime.main",
    b"runtime.goexit",
    b"runtime.mstart",
    b"runtime.rt0_go",
    b"fatal error: all goroutines are asleep",
    b"runtime.gopanic",
    b"runtime.newproc",
];

/// Threshold: how many distinct patterns must match before we declare "Go binary".
const HEURISTIC_THRESHOLD: usize = 3;

/// Perform heuristic string-based detection.
///
/// Scans the entire binary for known Go runtime strings. Returns `true` if at least
/// 3 distinct patterns are found, which makes false positives
/// unlikely (a non-Go binary would need to embed multiple Go-specific error messages).
pub fn heuristic_check(data: &[u8]) -> bool {
    heuristic_hits(data) >= HEURISTIC_THRESHOLD
}

/// Count how many heuristic patterns match in `data`.
///
/// Used by [`crate::GoBinary::try_parse`] to attach an exact hit count to the
/// [`ConfidenceSignal::HeuristicStringsMatched`] signal.
pub fn heuristic_hits(data: &[u8]) -> usize {
    HEURISTIC_PATTERNS
        .iter()
        .filter(|p| find_bytes(data, p).is_some())
        .count()
}
