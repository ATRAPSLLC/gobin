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

use crate::structures::PclntabVersion;

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
    /// A Go version string was located.
    GoVersionString {
        /// The version string (e.g. `"go1.26.1"`).
        version: String,
        /// Where the version was sourced from.
        source: VersionSource,
    },
    /// Heuristic runtime string patterns matched at low confidence.
    HeuristicStringsMatched {
        /// Number of distinct patterns matched.
        hits: usize,
    },
}

/// Where a Go version string was extracted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSource {
    /// Parsed from the structured build info blob.
    BuildInfoBlob,
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

/// Find the first occurrence of `needle` in `haystack`.
///
/// Uses a simple sliding-window scan. For the sizes we deal with (binaries up to
/// ~100MB, needles of 10-40 bytes), this is fast enough and avoids pulling in a
/// heavier substring search dependency.
pub(crate) fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let (first, rest) = needle.split_first()?;
    // Anchor on the first byte, then compare the tail only at candidates.
    // `windows(n).position` compares every candidate window in full, which is
    // the dominant cost of the whole-image searches PE and wasm binaries force
    // when there is no section to narrow them to.
    let last_start = haystack.len().checked_sub(needle.len())?;
    let mut from = 0usize;
    while from <= last_start {
        let window = haystack.get(from..)?;
        let hit = find_byte(window, *first)?;
        let start = from.checked_add(hit)?;
        if start > last_start {
            return None;
        }
        let tail_start = start.checked_add(1)?;
        let tail_end = tail_start.checked_add(rest.len())?;
        if haystack.get(tail_start..tail_end) == Some(rest) {
            return Some(start);
        }
        from = tail_start;
    }
    None
}

/// Index of the first occurrence of `byte` in `haystack`.
///
/// Eight bytes are tested per iteration with the classic SWAR zero-byte trick:
/// XOR-ing the word against a broadcast of the target turns "contains `byte`"
/// into "contains a zero byte", which `(x - 0x01..01) & !x & 0x80..80` answers
/// in three instructions. A byte-at-a-time `position` is roughly an order of
/// magnitude slower over the megabyte-scale buffers this crate searches, and
/// pulling in a `memchr` dependency for it is not worth the supply-chain
/// surface on a crate that otherwise depends only on `goblin`.
fn find_byte(haystack: &[u8], byte: u8) -> Option<usize> {
    const LANES: usize = 8;
    const LOW: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;

    let broadcast = u64::from_ne_bytes([byte; LANES]);
    let (words, tail) = haystack.as_chunks::<LANES>();
    for (i, chunk) in words.iter().enumerate() {
        let x = u64::from_ne_bytes(*chunk) ^ broadcast;
        if x.wrapping_sub(LOW) & !x & HIGH == 0 {
            continue;
        }
        let base = i.checked_mul(LANES)?;
        let hit = chunk.iter().position(|&b| b == byte)?;
        return base.checked_add(hit);
    }
    let consumed = haystack.len().checked_sub(tail.len())?;
    tail.iter()
        .position(|&b| b == byte)
        .and_then(|hit| consumed.checked_add(hit))
}
