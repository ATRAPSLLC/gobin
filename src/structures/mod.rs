//! Parsers for Go runtime structures embedded in compiled binaries.
//!
//! Every Go binary contains several metadata structures that the runtime needs at
//! execution time. These are defined in the Go source tree and populated by the
//! linker (`cmd/link`). This module provides parsers for three key structures:
//!
//! - [`buildid`] -- The Go build ID, a SHA256-derived fingerprint
//! - [`buildinfo`] -- Version, module path, dependencies, and build settings
//! - [`pclntab`] -- The PC/line table: function names, source files, line numbers
//!
//! [`moduledata`] parses the linker-generated master record that ties the rest
//! together, and [`locate`] finds it - by section where the toolchain emits
//! one, and by scanning for its `pcHeader` pointer everywhere else.
//!
//! ## Why These Structures Exist
//!
//! The Go runtime is more self-aware than a typical C runtime. It needs metadata for:
//!
//! - **Stack traces**: function names and line numbers for `panic` output
//! - **Garbage collection**: pointer maps and stack layouts per function
//! - **Goroutine preemption**: safe-point information per PC value
//! - **Interface dispatch**: type descriptors and method tables
//! - **Reflection**: full type information for `reflect.TypeOf` etc.
//!
//! All of this is compiled into the binary and referenced by the `moduledata` struct
//! (defined in `src/runtime/symtab.go:402-450`), which is the linker-generated master
//! record tying everything together.

pub mod abitype;
pub mod arraytype;
pub mod buildid;
pub mod buildinfo;
pub mod chantype;
pub mod descriptor;
pub mod elemtype;
pub mod embed;
pub mod fixups;
pub mod functype;
pub mod gcprog;
pub mod goslice;
pub mod gostring;
pub mod inittask;
pub mod inline;
pub mod interfacetype;
pub mod itab;
pub mod kind;
pub mod locate;
pub mod maptype;
pub mod method;
pub mod moduledata;
pub mod name;
pub mod pclntab;
pub mod strings;
pub mod structtype;
pub mod types;
pub mod uncommon;
pub(crate) mod util;
pub mod wasm;

/// Target architecture, inferred from the pclntab header's `minLC` and `ptrSize` fields.
///
/// The Go pclntab header (see [`pclntab::ParsedPclntab`]) stores two bytes that together
/// identify the target architecture:
///
/// - `minLC` (minimum instruction size, aka "PC quantum"): the smallest possible
///   instruction length. `1` for x86 (variable-length), `2` for s390x, `4` for
///   ARM/MIPS/PPC/RISC-V (fixed-width 32-bit instructions).
/// - `ptrSize`: pointer width in bytes. `4` for 32-bit, `8` for 64-bit.
///
/// ## Mapping Table
///
/// | `minLC` | `ptrSize` | Architecture                    |
/// |---------|-----------|----------------------------------|
/// | 1       | 4         | x86 (32-bit)                     |
/// | 1       | 8         | x86_64 / AMD64                   |
/// | 4       | 4         | ARM, MIPS32                      |
/// | 4       | 8         | ARM64, MIPS64, PPC64, RISC-V 64  |
/// | 2       | 8         | s390x                            |
/// | 1       | 8         | WebAssembly (wasm)               |
///
/// Note: `(4, 8)` is ambiguous between ARM64, MIPS64, PPC64, and RISC-V64.
/// Use build info's `GOARCH` setting for disambiguation.
///
/// Source: `src/internal/abi/symtab.go` (PCQuantum), `src/cmd/internal/obj/link.go`
///
/// # Stability
///
/// Consumers persist this enum into long-lived schemas (database columns,
/// structured logs). The contract:
///
/// - **Variants** - append-only. New architectures appear as new variants;
///   existing variants are never renamed or removed.
/// - **`Display` strings** (and [`Self::as_str`]) - fixed forever once
///   shipped, matching the canonical `GOARCH` values where applicable.
/// - **`Debug` strings** - *not* a stability surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// x86 32-bit (`minLC=1, ptrSize=4`)
    X86,
    /// x86_64 / AMD64 (`minLC=1, ptrSize=8`)
    X86_64,
    /// ARM 32-bit (`minLC=4, ptrSize=4`). Could also be MIPS32.
    Arm,
    /// ARM64 / AArch64 (`minLC=4, ptrSize=8`). Could also be MIPS64, PPC64, RISC-V64.
    Arm64,
    /// MIPS 32-bit (`minLC=4, ptrSize=4`)
    Mips32,
    /// MIPS 64-bit (`minLC=4, ptrSize=8`)
    Mips64,
    /// PowerPC 64-bit (`minLC=4, ptrSize=8`)
    Ppc64,
    /// RISC-V (`minLC=4, ptrSize=4 or 8`)
    RiscV,
    /// IBM s390x (`minLC=2, ptrSize=8`)
    S390x,
    /// WebAssembly (`minLC=1, ptrSize=8`)
    Wasm,
    /// Could not determine architecture from the available information.
    Unknown,
}

/// The pclntab format version, which directly identifies the Go compiler version range.
///
/// The Go toolchain has changed the pclntab format four times. Each change is signaled
/// by a different 4-byte magic number at the start of the `pcHeader` struct. The magic
/// values are intentionally designed to be endianness-invariant: reading them as either
/// little-endian or big-endian produces distinct values, enabling automatic byte-order
/// detection.
///
/// ## Version History
///
/// | Magic (`uint32`)  | LE Bytes            | Go Versions   | Key Changes                    |
/// |-------------------|---------------------|---------------|--------------------------------|
/// | `0xFFFF_FFFB`     | `fb ff ff ff`       | 1.2 -- 1.15   | Original format                |
/// | `0xFFFF_FFFA`     | `fa ff ff ff`       | 1.16 -- 1.17  | Added `cutab`, header fields   |
/// | `0xFFFF_FFF0`     | `f0 ff ff ff`       | 1.18 -- 1.19  | Entry PC -> offset from text   |
/// | `0xFFFF_FFF1`     | `f1 ff ff ff`       | 1.20+         | Colon in generated symbol names|
///
/// Source: `src/internal/abi/symtab.go:14-34`
///
/// Design doc: `golang.org/s/go12symtab` (referenced at `src/runtime/runtime2.go:1071`)
///
/// # Stability
///
/// Consumers persist this enum into long-lived schemas (database columns,
/// structured logs). The contract:
///
/// - **Variants** - append-only. New format versions appear as new variants;
///   existing variants are never renamed or removed.
/// - **`Display` strings** (and [`Self::as_str`]) - fixed forever once
///   shipped.
/// - **`Debug` strings** - *not* a stability surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PclntabVersion {
    /// Go 1.2 through 1.15 (magic `0xFFFFFFFB`).
    /// The original format defined in the Go 1.2 symtab design document.
    Go12,
    /// Go 1.16 through 1.17 (magic `0xFFFFFFFA`).
    /// Added the compilation unit table (`cutab`) and additional header fields
    /// for `funcnameOffset`, `cuOffset`, `filetabOffset`, `pctabOffset`, `pclnOffset`.
    Go116,
    /// Go 1.18 through 1.19 (magic `0xFFFFFFF0`).
    /// Changed function entry PCs from absolute addresses to offsets from
    /// `runtime.text`, making the functab entries fixed-size 8 bytes.
    Go118,
    /// Go 1.20 and later (magic `0xFFFFFFF1`).
    /// Added colons to generated symbol names (issue #37762).
    Go120,
}

impl PclntabVersion {
    /// The 4-byte magic value as it appears in a little-endian binary.
    pub fn magic_le(self) -> [u8; 4] {
        match self {
            Self::Go12 => [0xfb, 0xff, 0xff, 0xff],
            Self::Go116 => [0xfa, 0xff, 0xff, 0xff],
            Self::Go118 => [0xf0, 0xff, 0xff, 0xff],
            Self::Go120 => [0xf1, 0xff, 0xff, 0xff],
        }
    }

    /// The 4-byte magic value as it appears in a big-endian binary.
    pub fn magic_be(self) -> [u8; 4] {
        match self {
            Self::Go12 => [0xff, 0xff, 0xff, 0xfb],
            Self::Go116 => [0xff, 0xff, 0xff, 0xfa],
            Self::Go118 => [0xff, 0xff, 0xff, 0xf0],
            Self::Go120 => [0xff, 0xff, 0xff, 0xf1],
        }
    }

    /// Human-readable Go version range string.
    pub fn go_version_range(self) -> &'static str {
        match self {
            Self::Go12 => "Go 1.2 - 1.15",
            Self::Go116 => "Go 1.16 - 1.17",
            Self::Go118 => "Go 1.18 - 1.19",
            Self::Go120 => "Go 1.20+",
        }
    }

    /// Stable identifier for this pclntab format version
    /// (`"go12"` / `"go116"` / `"go118"` / `"go120"`). See the `# Stability`
    /// section on [`PclntabVersion`] for the durability contract.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go12 => "go12",
            Self::Go116 => "go116",
            Self::Go118 => "go118",
            Self::Go120 => "go120",
        }
    }
}

impl std::fmt::Display for PclntabVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Arch {
    /// Stable lowercase identifier for this architecture, matching the
    /// canonical `GOARCH` values where applicable
    /// (`"386"`, `"amd64"`, `"arm"`, `"arm64"`, `"mips"`, `"mips64"`,
    /// `"ppc64"`, `"riscv"`, `"s390x"`, `"wasm"`, `"unknown"`). See the
    /// `# Stability` section on [`Arch`] for the durability contract.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::X86 => "386",
            Self::X86_64 => "amd64",
            Self::Arm => "arm",
            Self::Arm64 => "arm64",
            Self::Mips32 => "mips",
            Self::Mips64 => "mips64",
            Self::Ppc64 => "ppc64",
            Self::RiscV => "riscv",
            Self::S390x => "s390x",
            Self::Wasm => "wasm",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
