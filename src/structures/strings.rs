//! Go-style string literal scanner.
//!
//! Go strings are stored as `(ptr, len)` headers - *not* NUL-terminated -
//! with the actual UTF-8 bytes living in `.rodata` (or equivalent for
//! non-ELF). A generic strings extractor either misses them entirely or
//! splits them at internal NULs. This module provides a precise scanner:
//! it walks pointer-aligned positions in the binary, reads candidate
//! `(ptr, len)` pairs, validates that the pointer resolves to in-binary
//! data and that the bytes are valid UTF-8, and yields each as a
//! [`GoString<'a>`].
//!
//! ## Heuristics
//!
//! False positives are inherent to a `(u64, u64)` scan - any random pair
//! that happens to look like `(in-segment ptr, plausible len)` and points
//! to UTF-8 bytes will match. We minimize them by:
//!
//! - Requiring the candidate pointer to translate via [`BinaryContext::va_to_file`].
//! - Bounding `len` to `[MIN_LEN, MAX_LEN]` (default 2..=4096).
//! - Excluding pointers that fall inside `[moduledata.text, moduledata.etext)`
//!   (string data never lives in the code segment).
//!
//! UTF-8 is **not** required: malware regularly stashes non-UTF-8 payloads
//! (encoded shellcode, blobs, encrypted strings) in rodata as Go-style
//! length-prefixed entries, and a UTF-8 filter would silently drop them.
//! Consumers decide whether to interpret bytes as text via [`GoString::as_bytes`],
//! [`GoString::try_as_str`], or the convenience [`GoString::as_str`].
//!
//! Duplicate yields are *not* filtered - a string referenced from N
//! different positions yields N times. Consumers that want unique results
//! can `.collect::<HashSet<_>>()`.

use crate::{
    formats::BinaryContext,
    structures::{moduledata::Moduledata, util::read_uintptr},
};

/// Minimum length we treat as a plausible string. Below this, the noise
/// floor of false matches dominates.
const MIN_LEN: usize = 2;

/// Maximum length we treat as a plausible string. Real Go literals are
/// typically <1KB; 4KB gives generous headroom while filtering the
/// "random `len` happens to look small" case.
const MAX_LEN: usize = 4096;

/// One Go string literal recovered by the scanner.
///
/// All fields borrow from the underlying binary data via the lifetime `'a`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoString<'a> {
    /// Virtual address of the string data (the value of the `ptr` field of
    /// the `(ptr, len)` header that referenced this string).
    pub va: u64,
    /// Byte length of the string.
    pub len: usize,
    /// The string's UTF-8 bytes, borrowed from the binary.
    pub bytes: &'a [u8],
}

impl<'a> GoString<'a> {
    /// Raw bytes of the string, borrowed from the binary.
    ///
    /// Always succeeds - this is the canonical view for callers that want
    /// to handle arbitrary byte content (hex-dump, base64-encode, MinHash,
    /// etc.). Unlike [`Self::as_str`] / [`Self::try_as_str`], no UTF-8
    /// validation is performed.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Try to view the bytes as `&str`, returning the underlying
    /// [`std::str::Utf8Error`] on failure.
    ///
    /// Use this when you need to distinguish "not valid UTF-8" from "valid
    /// but empty"; otherwise [`Self::as_str`] is the more ergonomic choice.
    pub fn try_as_str(&self) -> Result<&'a str, std::str::Utf8Error> {
        std::str::from_utf8(self.bytes)
    }

    /// Convenience accessor: view the bytes as `&str`, or `None` for non-UTF-8
    /// content. Equivalent to `self.try_as_str().ok()`.
    pub fn as_str(&self) -> Option<&'a str> {
        std::str::from_utf8(self.bytes).ok()
    }
}

/// Streaming iterator over Go string literals discovered in a binary.
///
/// Walks the binary's bytes at `ps`-aligned offsets, treating each pair of
/// adjacent ptr-sized words as a candidate `(ptr, len)` header. Yields one
/// [`GoString`] per validated header.
pub struct GoStringIter<'a> {
    ctx: &'a BinaryContext<'a>,
    pos: usize,
    ps: usize,
    /// `[text_start, text_end)`. Pointers into this range are skipped (string
    /// data never lives in code).
    text_start: u64,
    text_end: u64,
}

impl<'a> GoStringIter<'a> {
    fn empty(ctx: &'a BinaryContext<'a>) -> Self {
        Self {
            ctx,
            pos: 0,
            ps: 0,
            text_start: 0,
            text_end: 0,
        }
    }
}

impl<'a> Iterator for GoStringIter<'a> {
    type Item = GoString<'a>;

    fn next(&mut self) -> Option<GoString<'a>> {
        let ps = self.ps;
        if ps == 0 {
            return None;
        }
        let ps_u8 = u8::try_from(ps).ok()?;
        // Walk the address space the runtime would see - for wasm the
        // reconstructed linear-memory image, otherwise the file bytes.
        let data = self.ctx.structure_search_data();

        loop {
            // Need ps + ps bytes for the (ptr, len) header.
            let header_end = self.pos.checked_add(ps.checked_mul(2)?)?;
            if header_end > data.len() {
                return None;
            }
            let header_pos = self.pos;
            self.pos = self.pos.checked_add(ps)?;

            let va = match read_uintptr(data, header_pos, ps_u8) {
                Some(v) if v != 0 => v,
                _ => continue,
            };
            // Skip pointers into the text segment.
            if va >= self.text_start && va < self.text_end {
                continue;
            }
            let len_u64 = match read_uintptr(data, header_pos.checked_add(ps)?, ps_u8) {
                Some(l) => l,
                None => continue,
            };
            let len = match usize::try_from(len_u64) {
                Ok(l) if (MIN_LEN..=MAX_LEN).contains(&l) => l,
                _ => continue,
            };

            let bytes = match self.ctx.slice_at_va(va).and_then(|s| s.get(..len)) {
                Some(b) => b,
                None => continue,
            };
            // No UTF-8 filter here - see the module-level docs. Callers that
            // need text use `GoString::try_as_str` / `as_str`; callers that
            // want raw rodata bytes (malware payloads, MinHash signal) use
            // `GoString::as_bytes`.
            return Some(GoString { va, len, bytes });
        }
    }
}

/// Construct a streaming string-literal scanner.
///
/// Returns an empty iterator when the binary lacks VA mapping (no goblin
/// parse succeeded) or has no recoverable moduledata to bound the text
/// segment.
pub fn extract_iter<'a>(
    ctx: &'a BinaryContext<'a>,
    moduledata: Option<&Moduledata>,
    ptr_size: u8,
) -> GoStringIter<'a> {
    let ps = ptr_size as usize;
    if ps == 0 || !ctx.has_va_mapping() {
        return GoStringIter::empty(ctx);
    }
    let (text_start, text_end) = match moduledata {
        Some(m) => (m.text, m.etext),
        // Without moduledata we can't filter text pointers; everything is a
        // candidate. That's acceptable - the UTF-8 + length filters still
        // cut most noise.
        None => (0, 0),
    };
    GoStringIter {
        ctx,
        pos: 0,
        ps,
        text_start,
        text_end,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_max_len_constants() {
        // Sanity check: defaults reflect the documented invariants.
        assert_eq!(MIN_LEN, 2);
        assert_eq!(MAX_LEN, 4096);
    }

    #[test]
    fn as_str_round_trips_utf8() {
        let s = GoString {
            va: 0x1000,
            len: 5,
            bytes: b"hello",
        };
        assert_eq!(s.as_str(), Some("hello"));
    }

    #[test]
    fn as_str_rejects_invalid_utf8() {
        let s = GoString {
            va: 0,
            len: 2,
            bytes: &[0xff, 0xfe],
        };
        assert_eq!(s.as_str(), None);
    }
}
