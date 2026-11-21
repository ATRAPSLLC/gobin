//! Coverage metadata of a `-cover` build (Go 1.20+).
//!
//! `cmd/cover` gives each package it instruments a read-only metadata blob:
//! the package's name, path and module, and for each function its name,
//! source file and coverable units (the source extent and statement count of
//! each block a counter counts). The blob is an ordinary Go variable,
//! `<pkg>.goCover_<id>_M`, which only the package's init function references:
//! its first statement, prepended by the compiler, registers it with the
//! runtime (`cmd/compile/internal/coverage/cover.go`, `registerMeta`):
//!
//! ```text
//! runtime.addCovMeta(&blob, len, hash, pkgpath, pkgid, cmode, cgran)
//! ```
//!
//! Nothing else points at a blob; the runtime collects them as the inits run.
//! [`crate::GoBinary::coverage`] finds them through the symbol table. In a
//! stripped binary a disassembler finds the registration calls (the
//! [`crate::metadata::HookKind::CoverageRegistration`] hook) and reads their
//! arguments: [`crate::GoBinary::coverage_meta_at`] decodes the blob at the
//! first, whose length and hash must equal the second and third;
//! [`CounterMode::from_raw`] and [`CounterGranularity::from_raw`] read the
//! last two.
//!
//! ## Counters
//!
//! Each function counts into its own `[`[`FIRST_COUNTER_SLOT`]` + units]uint32`
//! variable in the `[covctrs, ecovctrs)` region
//! ([`crate::structures::moduledata::Moduledata::covctrs`]), zero in the
//! binary. On each call the function writes its unit count, package id and
//! function id ([`NUM_COUNTERS_SLOT`], [`PACKAGE_ID_SLOT`],
//! [`FUNCTION_ID_SLOT`]; the function id is its index in
//! [`CoveragePackage::functions`]) and counts unit `i` in slot
//! [`FIRST_COUNTER_SLOT`]` + i`. So the immediate a function stores into slot
//! 2 of a counter variable names the function that variable belongs to.
//!
//! ## Layout
//!
//! ```text
//! 0   u32 length       u32 package name     u32 package path   u32 module path
//!     (string table indices for the three names)
//! 16  [16]u8 hash
//! 32  u8 unused, [3]u8 padding
//! 36  u32 string count u32 function count
//! 44  u32 offset of each function record, from the blob's start
//!     string table: uleb count, then each string as uleb length + bytes
//!     function records: uleb units, name index, file index; per unit uleb
//!     start line, start column, end line, end column, statements; uleb
//!     literal flag
//! ```
//!
//! The layout is the same from Go 1.20 to 1.28.
//!
//! Source: `src/internal/coverage/defs.go` (`MetaSymbolHeader`),
//! `src/internal/coverage/encodemeta` and `decodemeta`, `src/cmd/cover`.

use crate::util::{read_u32, read_uvarint};

/// Size of a metadata blob's header (`coverage.CovMetaHeaderSize`).
pub const META_HEADER_SIZE: usize = 44;

/// Counter-variable slot holding the function's unit count.
pub const NUM_COUNTERS_SLOT: usize = 0;
/// Counter-variable slot holding the package's registration id.
pub const PACKAGE_ID_SLOT: usize = 1;
/// Counter-variable slot holding the function's index in its package's
/// metadata.
pub const FUNCTION_ID_SLOT: usize = 2;
/// Counter-variable slot of the first unit's counter.
pub const FIRST_COUNTER_SLOT: usize = 3;

/// One instrumented package's coverage metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveragePackage<'a> {
    /// The blob's length in bytes: the registration call's second argument.
    pub length: u32,
    /// The package name (`greet`).
    pub package_name: &'a str,
    /// The package path (`example.com/greet`).
    pub package_path: &'a str,
    /// The path of the module the package is in.
    pub module_path: &'a str,
    /// The hash `cmd/cover` gave the metadata: the registration call's third
    /// argument.
    pub hash: [u8; 16],
    /// The instrumented functions, in function-id order.
    pub functions: Vec<CoverageFunction<'a>>,
}

/// One instrumented function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageFunction<'a> {
    /// Its name as `cmd/cover` writes it: `Hello`, `T.Method`,
    /// `*T.Method`, or `func.L<line>.C<column>` for a function literal at
    /// package level (one inside a function belongs to that function).
    pub name: &'a str,
    /// Its source file: `<package path>/<file name>`, or the file's full path
    /// for a package named by a local path (`go test -cover ./pkg`).
    pub file: &'a str,
    /// Whether it is a function literal.
    pub is_literal: bool,
    /// Its coverable units, in counter order.
    pub units: Vec<CoverableUnit>,
}

impl CoverageFunction<'_> {
    /// The length of its counter variable, in `u32` slots.
    pub fn counter_slots(&self) -> usize {
        FIRST_COUNTER_SLOT.saturating_add(self.units.len())
    }

    /// The unit a counter-variable slot counts; `None` for the three header
    /// slots and past the end.
    pub fn unit_for_slot(&self, slot: usize) -> Option<&CoverableUnit> {
        self.units.get(slot.checked_sub(FIRST_COUNTER_SLOT)?)
    }
}

/// A block of source one counter counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverableUnit {
    /// Line it starts on.
    pub start_line: u32,
    /// Column it starts at.
    pub start_column: u32,
    /// Line it ends on.
    pub end_line: u32,
    /// Column it ends at.
    pub end_column: u32,
    /// Statements in it.
    pub statements: u32,
}

/// How a build counts (`-covermode`): the registration call's sixth
/// argument (`coverage.CounterMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterMode {
    /// `set`: whether a block ran.
    Set,
    /// `count`: how many times.
    Count,
    /// `atomic`: how many times, counted atomically.
    Atomic,
    /// Registration only: the package is registered but not counted.
    RegistrationOnly,
    /// The pseudo-mode of a test's main package.
    TestMain,
}

impl CounterMode {
    /// The mode a raw value names; `None` for the invalid `0` and unknown
    /// values.
    pub fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::Set,
            2 => Self::Count,
            3 => Self::Atomic,
            4 => Self::RegistrationOnly,
            5 => Self::TestMain,
            _ => return None,
        })
    }
}

/// What a counter counts: the registration call's seventh argument
/// (`coverage.CounterGranularity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterGranularity {
    /// One counter per block (the default).
    PerBlock,
    /// One counter per function (`-coverpkg` with `perfunc`).
    PerFunc,
}

impl CounterGranularity {
    /// The granularity a raw value names; `None` for the invalid `0` and
    /// unknown values.
    pub fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            1 => Self::PerBlock,
            2 => Self::PerFunc,
            _ => return None,
        })
    }
}

impl<'a> CoveragePackage<'a> {
    /// Decode a metadata blob. `data` starts at the blob and may run past
    /// it; the header's length bounds the read. `None` unless every part is
    /// well formed: the length within `data`, each function record inside
    /// the blob past the offset table, each string valid UTF-8 and each
    /// string index in the table.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let length = read_u32(data, 0)?;
        let blob = data.get(..usize::try_from(length).ok()?)?;
        let field = |at: usize| read_u32(blob, at).and_then(|v| usize::try_from(v).ok());
        let (name_index, path_index, module_index) = (field(4)?, field(8)?, field(12)?);
        let hash: [u8; 16] = blob.get(16..32)?.try_into().ok()?;
        let num_funcs = field(40)?;
        let offsets_end = num_funcs.checked_mul(4)?.checked_add(META_HEADER_SIZE)?;
        let mut cursor = Cursor {
            data: blob,
            pos: offsets_end,
        };
        let count = cursor.uleb()?;
        // Each string takes at least its one-byte length.
        let mut strings = Vec::with_capacity(count.min(blob.len()));
        for _ in 0..count {
            let len = cursor.uleb()?;
            strings.push(std::str::from_utf8(cursor.take(len)?).ok()?);
        }
        let string = |index: usize| strings.get(index).copied();
        let mut functions = Vec::with_capacity(num_funcs.min(blob.len()));
        for index in 0..num_funcs {
            let at = META_HEADER_SIZE.checked_add(index.checked_mul(4)?)?;
            let offset = field(at)?;
            if offset < at || offset >= blob.len() {
                return None;
            }
            let mut cursor = Cursor {
                data: blob,
                pos: offset,
            };
            let num_units = cursor.uleb()?;
            let name = string(cursor.uleb()?)?;
            let file = string(cursor.uleb()?)?;
            // Each unit takes at least five one-byte fields.
            let mut units = Vec::with_capacity(num_units.min(blob.len() / 5));
            for _ in 0..num_units {
                let mut next = || cursor.uleb().and_then(|v| u32::try_from(v).ok());
                units.push(CoverableUnit {
                    start_line: next()?,
                    start_column: next()?,
                    end_line: next()?,
                    end_column: next()?,
                    statements: next()?,
                });
            }
            functions.push(CoverageFunction {
                name,
                file,
                is_literal: cursor.uleb()? != 0,
                units,
            });
        }
        Some(Self {
            length,
            package_name: string(name_index)?,
            package_path: string(path_index)?,
            module_path: string(module_index)?,
            hash,
            functions,
        })
    }

    /// The source files its functions are in, each once, in order of first
    /// appearance.
    pub fn files(&self) -> Vec<&'a str> {
        let mut files: Vec<&'a str> = Vec::new();
        for function in &self.functions {
            if !files.contains(&function.file) {
                files.push(function.file);
            }
        }
        files
    }
}

/// A read position in a blob.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn uleb(&mut self) -> Option<usize> {
        let (value, len) = read_uvarint(self.data.get(self.pos..)?)?;
        self.pos = self.pos.checked_add(len)?;
        usize::try_from(value).ok()
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let bytes = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blob as `encodemeta` writes it: one function `F` in `p/f.go` with
    /// one unit, in package `p` of module `m`.
    fn blob() -> Vec<u8> {
        let strings: [&[u8]; 4] = [b"m", b"p", b"F", b"p/f.go"];
        let mut table = vec![strings.len() as u8];
        for s in strings {
            table.push(s.len() as u8);
            table.extend_from_slice(s);
        }
        let func_offset = META_HEADER_SIZE + 4 + table.len();
        // units, name, file; unit: 3:1 to 5:2 with 2 statements; literal no
        let record = [1u8, 2, 3, 3, 1, 5, 2, 2, 0];
        let length = func_offset + record.len();
        let mut b = Vec::new();
        for v in [length as u32, 1, 1, 0] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&[7u8; 16]);
        b.extend_from_slice(&[0u8; 4]);
        b.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&(func_offset as u32).to_le_bytes());
        b.extend_from_slice(&table);
        b.extend_from_slice(&record);
        b
    }

    #[test]
    fn decodes_a_blob() {
        let mut data = blob();
        data.extend_from_slice(b"trailing bytes past the blob");
        let p = CoveragePackage::parse(&data).unwrap();
        assert_eq!(
            (p.package_name, p.package_path, p.module_path),
            ("p", "p", "m")
        );
        assert_eq!(p.hash, [7; 16]);
        assert_eq!(p.files(), ["p/f.go"]);
        let f = &p.functions[0];
        assert_eq!((f.name, f.file, f.is_literal), ("F", "p/f.go", false));
        assert_eq!(
            f.units,
            [CoverableUnit {
                start_line: 3,
                start_column: 1,
                end_line: 5,
                end_column: 2,
                statements: 2
            }]
        );
        assert_eq!(f.counter_slots(), 4);
        // The record's last field is the literal flag.
        let mut literal = blob();
        *literal.last_mut().unwrap() = 1;
        assert!(CoveragePackage::parse(&literal).unwrap().functions[0].is_literal);
        assert_eq!(f.unit_for_slot(3), Some(&f.units[0]));
        assert_eq!(f.unit_for_slot(2), None);
    }

    #[test]
    fn rejects_malformed_blobs() {
        let good = blob();
        // Truncated anywhere.
        for len in 0..good.len() {
            assert_eq!(CoveragePackage::parse(&good[..len]), None, "length {len}");
        }
        // A function offset into the offset table.
        let mut bad = good.clone();
        bad[44..48].copy_from_slice(&40u32.to_le_bytes());
        assert_eq!(CoveragePackage::parse(&bad), None);
        // A string index past the table.
        let mut bad = good.clone();
        bad[8..12].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(CoveragePackage::parse(&bad), None);
        // A huge function count.
        let mut bad = good;
        bad[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(CoveragePackage::parse(&bad), None);
    }

    #[test]
    fn raw_modes() {
        assert_eq!(CounterMode::from_raw(1), Some(CounterMode::Set));
        assert_eq!(CounterMode::from_raw(3), Some(CounterMode::Atomic));
        assert_eq!(CounterMode::from_raw(0), None);
        assert_eq!(
            CounterGranularity::from_raw(2),
            Some(CounterGranularity::PerFunc)
        );
        assert_eq!(CounterGranularity::from_raw(9), None);
    }
}
