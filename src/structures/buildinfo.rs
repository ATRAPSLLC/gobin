//! Go build info extraction (version, module path, dependencies, build settings).
//!
//! The build info blob is a structured header embedded in every Go binary since Go 1.13.
//! It contains the Go toolchain version, the main module path, all dependency module
//! versions, and build settings (GOOS, GOARCH, VCS info, compiler flags, etc.).
//!
//! ## Binary Layout
//!
//! The blob lives in a dedicated section (`.go.buildinfo` on ELF, `__go_buildinfo`
//! on Mach-O, first writable PE section). It starts with a 32-byte header:
//!
//! ```text
//! Offset  Size   Field
//! 0       14     Magic: "\xff Go buildinf:" (literal bytes)
//! 14      1      ptrSize: pointer size (4 or 8)
//! 15      1      flags:
//!                  bit 0: endianness (0=little, 1=big)
//!                  bit 1: version format (0=pointer-based, 1=inline varint)
//! 16      16     Padding (zeros, to reach 32-byte total)
//! 32      var    Inline strings (Go 1.18+): varint-length-prefixed version,
//!                then varint-length-prefixed modinfo
//! ```
//!
//! The header requires 16-byte alignment in the binary.
//!
//! ## Module Info Format
//!
//! The modinfo string is framed by 16-byte binary sentinels:
//!
//! ```text
//! Start sentinel: 30 77 af 0c 92 74 08 02 41 e1 c1 07 e6 d6 18 e6
//! End sentinel:   f9 32 43 31 86 18 20 72 00 82 42 10 41 16 d8 f2
//! ```
//!
//! Between sentinels, a tab-delimited text block:
//! ```text
//! path\t<main_package_path>
//! mod\t<module_name>\t<version>
//! dep\t<dep_path>\t<version>\t<hash>
//! build\t<key>=<value>
//! ```
//!
//! ## Source References
//!
//! - Header format: `src/debug/buildinfo/buildinfo.go:58-203`
//! - Sentinel bytes: `src/cmd/go/internal/modload/build.go:29-30`
//! - Linker creation: `src/cmd/link/internal/ld/data.go:2609-2656`
//! - Modinfo parsing: `src/runtime/debug/mod.go:40-95`

use crate::{
    detection::find_bytes,
    formats::BinaryContext,
    metadata::{BuildInfo, DepEntry, DepReplacement},
    structures::util::read_uvarint,
};

/// Build info magic prefix: `"\xff Go buildinf:"` (14 bytes).
///
/// Source: `src/debug/buildinfo/buildinfo.go:58`
const BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";

/// The header must be placed at a 16-byte aligned address.
///
/// Source: `src/debug/buildinfo/buildinfo.go:61`
const BUILDINFO_ALIGN: usize = 16;

/// Total size of the build info header (magic + ptrSize + flags + padding).
///
/// Source: `src/debug/buildinfo/buildinfo.go:62`
const BUILDINFO_HEADER_SIZE: usize = 32;

/// Module info start sentinel (16 bytes).
///
/// Source: `src/cmd/go/internal/modload/build.go:29`
const MOD_INFO_START: &[u8] = &[
    0x30, 0x77, 0xaf, 0x0c, 0x92, 0x74, 0x08, 0x02, 0x41, 0xe1, 0xc1, 0x07, 0xe6, 0xd6, 0x18, 0xe6,
];

/// Module info end sentinel (16 bytes).
///
/// Source: `src/cmd/go/internal/modload/build.go:30`
const MOD_INFO_END: &[u8] = &[
    0xf9, 0x32, 0x43, 0x31, 0x86, 0x18, 0x20, 0x72, 0x00, 0x82, 0x42, 0x10, 0x41, 0x16, 0xd8, 0xf2,
];

/// Flags byte, bit 0: endianness (`0` = little-endian, `1` = big-endian).
const FLAG_ENDIAN: u8 = 0x01;

/// Flags byte, bit 1: string format (`0` = pointer-based pre-1.18, `1` = inline varint 1.18+).
///
/// Source: `src/debug/buildinfo/buildinfo.go:196-203`
const FLAG_VERSION_INL: u8 = 0x02;

/// Extract build info from binary data.
///
/// If the build info section location is known (from [`GoSections`](crate::formats::GoSections)), it's used
/// directly; otherwise the function falls back to scanning the entire binary for
/// the magic header.
///
/// For the inline format (Go 1.18+), the version and modinfo strings are decoded
/// from varint-length-prefixed data immediately after the 32-byte header.
/// For the pointer format (Go < 1.18), only a version string scan is attempted.
pub fn extract<'a>(ctx: &BinaryContext<'a>) -> Option<BuildInfo<'a>> {
    let data = ctx.data();
    let header_start = find_magic(ctx, data)?;

    let header_end = header_start.checked_add(BUILDINFO_HEADER_SIZE)?;
    let header = data.get(header_start..header_end)?;
    let ptr_size = (*header.get(14)?) as usize;
    let flags = *header.get(15)?;
    let _is_big_endian = (flags & FLAG_ENDIAN) != 0;
    let is_inline = (flags & FLAG_VERSION_INL) != 0;

    if ptr_size != 4 && ptr_size != 8 {
        return None;
    }

    let mut info = BuildInfo::default();

    if is_inline {
        // Go 1.18+: varint-length-prefixed strings after the 32-byte header
        let payload = data.get(header_end..)?;
        let (version, rest) = read_varint_string(payload)?;
        info.go_version = Some(version);

        // The modinfo blob contains binary sentinel bytes (not valid UTF-8)
        let (modinfo_bytes, _) = read_varint_bytes(rest)?;
        if let Some(text) = extract_modinfo_text(modinfo_bytes) {
            parse_modinfo(text, &mut info);
        }
    } else {
        // Pre-1.18: version stored via pointers (base address unknown in static analysis)
        info.go_version = find_version_string(data);
    }

    Some(info)
}

/// Locate the build-info header's offset within `data`.
///
/// `go:buildinfo` is a writable-data symbol (`sym.SBUILDINFO`), so the search
/// narrows to the regions that can hold it before falling back to the whole
/// image:
///
/// 1. the dedicated `.go.buildinfo` / `__go_buildinfo` section - exact, and
///    the usual case for ELF and Mach-O;
/// 2. the `.data` / `.noptrdata` sections - PE merges every Go data symbol
///    into `.data`, which is a small fraction of a Go binary (tens of KB
///    against megabytes of `.text` and `.rdata`);
/// 3. the data regions of the image
///    ([`BinaryContext::data_regions`]), so a stripped or unusual section
///    table still works.
fn find_magic(ctx: &BinaryContext<'_>, data: &[u8]) -> Option<usize> {
    let sections = ctx.sections();
    let candidates = [
        sections.go_buildinfo.as_ref(),
        sections.data_section.as_ref(),
        sections.noptrdata.as_ref(),
    ];
    for range in candidates.into_iter().flatten() {
        let end = range.offset.checked_add(range.size)?.min(data.len());
        if let Some(region) = data.get(range.offset..end)
            && let Some(pos) = find_aligned_magic(region)
        {
            return range.offset.checked_add(pos);
        }
    }
    // Fall back to a sweep, but only over the regions that can hold data: the
    // blob is a `sym.SBUILDINFO` symbol, so the executable section and the
    // pclntab are excluded. That matters most for wasm, which names no
    // sections at all and would otherwise sweep the whole module - twice, once
    // per candidate list above - to prove a blob it never carries is absent.
    for (from, to) in ctx.data_regions() {
        if let Some(region) = data.get(from..to)
            && let Some(pos) = find_aligned_magic(region)
        {
            return from.checked_add(pos);
        }
    }
    None
}

/// Find the build-info magic within `data`, preferring a 16-byte-aligned hit.
///
/// The Go linker aligns the symbol to [`BUILDINFO_ALIGN`] (a macOS
/// requirement), so an aligned occurrence is the real one; an unaligned hit is
/// still returned as a fallback in case a section offset shifted the
/// alignment. Both are answered in a **single** sweep - the previous
/// aligned-then-unaligned pair walked the buffer twice, which on PE and wasm
/// (neither of which has a `.go.buildinfo` section to narrow the search) meant
/// scanning the whole image twice over.
fn find_aligned_magic(data: &[u8]) -> Option<usize> {
    let mut first_unaligned: Option<usize> = None;
    let mut from: usize = 0;
    while let Some(rel) = data
        .get(from..)
        .and_then(|d| find_bytes(d, BUILDINFO_MAGIC))
    {
        let at = from.checked_add(rel)?;
        // A hit with no room for the full header cannot be the build info.
        if at
            .checked_add(BUILDINFO_HEADER_SIZE)
            .is_none_or(|e| e > data.len())
        {
            break;
        }
        if at.checked_rem(BUILDINFO_ALIGN) == Some(0) {
            return Some(at);
        }
        first_unaligned.get_or_insert(at);
        from = at.checked_add(1)?;
    }
    first_unaligned
}

/// Read a varint-length-prefixed UTF-8 string, returning the string (borrowed)
/// and the remaining data.
fn read_varint_string(data: &[u8]) -> Option<(&str, &[u8])> {
    let (len, consumed) = read_uvarint(data)?;
    let len = len as usize;
    let end = consumed.checked_add(len)?;
    let bytes = data.get(consumed..end)?;
    let s = std::str::from_utf8(bytes).ok()?;
    let rest = data.get(end..)?;
    Some((s, rest))
}

/// Read a varint-length-prefixed byte slice (may contain non-UTF-8 sentinel bytes).
fn read_varint_bytes(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, consumed) = read_uvarint(data)?;
    let len = len as usize;
    let end = consumed.checked_add(len)?;
    let payload = data.get(consumed..end)?;
    let rest = data.get(end..)?;
    Some((payload, rest))
}

/// Strip the 16-byte sentinels and return the UTF-8 text between them.
fn extract_modinfo_text(data: &[u8]) -> Option<&str> {
    let start = if data.len() >= 16 && data.get(..16) == Some(MOD_INFO_START) {
        16
    } else {
        0
    };
    let end = if data.len() >= 16 {
        let tail_start = data.len().checked_sub(16)?;
        if data.get(tail_start..) == Some(MOD_INFO_END) {
            tail_start
        } else {
            data.len()
        }
    } else {
        data.len()
    };
    if start >= end {
        return None;
    }
    std::str::from_utf8(data.get(start..end)?).ok()
}

/// Parse the tab-delimited modinfo text into [`BuildInfo`] fields.
///
/// ## Line Formats
///
/// ```text
/// path\t<import_path>
/// mod\t<module>\t<version>[\t<sum>]
/// dep\t<module>\t<version>[\t<sum>]
/// =>\t<replacement_path>[\t<version>][\t<sum>]
/// build\t<key>=<value>
/// ```
///
/// A `=>` line modifies the dependency on the immediately preceding `dep`
/// line (or the `mod` line, if no `dep` came first). Source:
/// `src/runtime/debug/mod.go:97-130` (`modinfo` writer).
///
/// Known build setting keys (from `src/runtime/debug/mod.go:69-95`):
/// `-buildmode`, `-compiler`, `CGO_ENABLED`, `GOARCH`, `GOOS`, `GOAMD64`,
/// `GOARM`, `GO386`, `GOFIPS140`, `vcs`, `vcs.revision`, `vcs.time`, `vcs.modified`
fn parse_modinfo<'a>(text: &'a str, info: &mut BuildInfo<'a>) {
    for line in text.lines() {
        let parts: Vec<&'a str> = line.splitn(4, '\t').collect();
        match parts.first() {
            Some(&"path") => {
                if let Some(p) = parts.get(1) {
                    info.main_path = Some(*p);
                }
            }
            Some(&"mod") => {
                if let Some(m) = parts.get(1) {
                    info.main_module = Some(*m);
                }
                if let Some(v) = parts.get(2) {
                    info.main_version = Some(*v);
                }
                if let Some(s) = parts.get(3) {
                    info.main_module_sum = Some(*s);
                }
            }
            Some(&"dep") => {
                if let Some(p) = parts.get(1) {
                    info.deps.push(DepEntry {
                        path: p,
                        version: parts.get(2).copied(),
                        sum: parts.get(3).copied(),
                        replacement: None,
                    });
                }
            }
            Some(&"=>") => {
                if let Some(p) = parts.get(1) {
                    let replacement = DepReplacement {
                        path: p,
                        version: parts.get(2).copied(),
                        sum: parts.get(3).copied(),
                    };
                    if let Some(last) = info.deps.last_mut() {
                        last.replacement = Some(replacement);
                    }
                }
            }
            Some(&"build") => {
                let setting = match parts.get(1) {
                    Some(s) => *s,
                    None => continue,
                };
                if let Some((key, value)) = setting.split_once('=') {
                    info.build_settings.push((key, value));
                } else {
                    info.build_settings.push((setting, ""));
                }
            }
            _ => {}
        }
    }
}

/// Scan binary data for a Go version string matching `"go1.XX"` or `"go1.XX.X"`.
///
/// Used as a fallback when the structured build info is unavailable (pre-1.18 binaries
/// or when the header is corrupted). Finds the first plausible match.
pub fn find_version_string(data: &[u8]) -> Option<&str> {
    let pattern = b"go1.";
    let mut pos: usize = 0;
    loop {
        let cutoff = pos.checked_add(8)?;
        if cutoff >= data.len() {
            return None;
        }
        let window = data.get(pos..)?;
        let found = find_bytes(window, pattern)?;
        let start = pos.checked_add(found)?;
        let scan_start = start.checked_add(4)?;
        let scan_limit = start.checked_add(20)?.min(data.len());
        let mut end = scan_start;
        while end < scan_limit {
            let ch = match data.get(end) {
                Some(c) => *c,
                None => break,
            };
            if ch.is_ascii_digit() || ch == b'.' {
                end = end.checked_add(1)?;
            } else {
                break;
            }
        }
        if let Some(slice) = data.get(start..end)
            && let Ok(s) = std::str::from_utf8(slice)
            && s.len() >= 5
            && s.get(4..)
                .is_some_and(|tail| tail.starts_with(|c: char| c.is_ascii_digit()))
        {
            return Some(s);
        }
        pos = scan_start;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_varint_string() {
        let data = [0x05, b'h', b'e', b'l', b'l', b'o', 0x00];
        let (s, rest) = read_varint_string(&data).unwrap();
        assert_eq!(s, "hello");
        assert_eq!(rest.len(), 1);
    }

    #[test]
    fn test_find_version_string() {
        let mut data = vec![0u8; 100];
        data[50..58].copy_from_slice(b"go1.26.1");
        data[58] = 0;
        assert_eq!(find_version_string(&data), Some("go1.26.1"));
    }

    #[test]
    fn test_parse_modinfo() {
        let text = "path\texample.com/app\nmod\texample.com/app\t(devel)\ndep\texample.com/dep\tv1.0.0\nbuild\t-compiler=gc\nbuild\tGOOS=linux\n";
        let mut info = BuildInfo::default();
        parse_modinfo(text, &mut info);
        assert_eq!(info.main_path, Some("example.com/app"));
        assert_eq!(info.main_module, Some("example.com/app"));
        assert_eq!(info.deps.len(), 1);
        assert_eq!(info.deps[0].path, "example.com/dep");
        assert_eq!(info.deps[0].version, Some("v1.0.0"));
        assert_eq!(info.deps[0].sum, None);
        assert!(info.deps[0].replacement.is_none());
        assert_eq!(info.build_settings.len(), 2);
    }

    #[test]
    fn test_parse_modinfo_with_sum_and_replace() {
        let text = "\
path\texample.com/app
dep\texample.com/lib\tv1.0.0\th1:abc=
=>\texample.com/forked\tv1.0.1\th1:def=
dep\texample.com/local\tv0.0.0
=>\t./vendored
";
        let mut info = BuildInfo::default();
        parse_modinfo(text, &mut info);
        assert_eq!(info.deps.len(), 2);
        assert_eq!(info.deps[0].sum, Some("h1:abc="));
        let r0 = info.deps[0].replacement.as_ref().unwrap();
        assert_eq!(r0.path, "example.com/forked");
        assert_eq!(r0.version, Some("v1.0.1"));
        assert_eq!(r0.sum, Some("h1:def="));
        let r1 = info.deps[1].replacement.as_ref().unwrap();
        assert_eq!(r1.path, "./vendored");
        assert_eq!(r1.version, None);
    }
}
