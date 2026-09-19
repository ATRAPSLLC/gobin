//! `//go:embed` asset extractor.
//!
//! `embed.FS` is a struct with a single field `files *[]file`. The compiler
//! lays down a generated `[]file` array in read-only data, and the runtime's
//! `file` struct is:
//!
//! ```text
//! type file struct {
//!     name string   // virtual path, e.g. "assets/x.txt" ("dir/" for directories)
//!     data string   // backing bytes in rodata (empty for directories)
//!     hash [16]byte // truncated SHA-256 (zero for directories)
//! }
//! ```
//!
//! On 64-bit that is `16 + 16 + 16 = 48` bytes per entry; on 32-bit, `32`.
//! Source: `src/embed/embed.go` (`FS`, `file`).
//!
//! ## Locating the array without symbols
//!
//! Stripped binaries carry no symbol for the embed variable, so we scan the
//! address space for the `*[]file` **slice header** `(ptr, len, cap)`: a
//! pointer-aligned triple where `len == cap`, `len` is small, and the array at
//! `ptr` parses as exactly `len` well-formed `file` entries (each with a
//! resolvable, path-shaped name; files with resolvable backing bytes; dirs
//! with a trailing `/` and empty data). Requiring the *whole* array to
//! validate makes false positives vanishingly unlikely.
//!
//! ## Limitation
//!
//! The single-file `//go:embed` forms (`embed.String` / `embed.Bytes`) compile
//! to an ordinary `string` / `[]byte` variable with no `files` anchor and are
//! **not** recoverable by this scanner. Only the `embed.FS` (multi-file) form
//! is supported.

use crate::{formats::BinaryContext, structures::util::read_uintptr};

/// One asset recovered from an `embed.FS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedAsset<'a> {
    /// Virtual path within the `embed.FS` (e.g. `"assets/logo.png"`).
    /// Directories keep their trailing `/`.
    pub path: &'a str,
    /// Whether this entry is a directory (no backing bytes).
    pub is_dir: bool,
    /// The embedded file contents, borrowed from read-only data. Empty for
    /// directories.
    pub data: &'a [u8],
}

/// Upper bounds so adversarial `len` / `name_len` fields cannot blow up memory
/// or wall-clock.
const MAX_ENTRIES_PER_FS: u64 = 1_000_000;
const MAX_NAME_LEN: u64 = 4096;
const MAX_DATA_LEN: u64 = 1 << 31; // 2 GiB per embedded file is already absurd

/// Scan the binary for `embed.FS` assets.
///
/// Returns every asset across all embed filesystems found, de-duplicated by
/// backing array. Empty when the binary embeds nothing (or only uses the
/// unsupported single-file form).
pub fn extract<'a>(ctx: &'a BinaryContext<'a>, ptr_size: u8) -> Vec<EmbeddedAsset<'a>> {
    let p = ptr_size as usize;
    if p != 4 && p != 8 {
        return Vec::new();
    }
    let data = ctx.structure_search_data();
    // file entry = name(string) + data(string) + hash[16] = 4*ptr + 16.
    let entry_size = match p.checked_mul(4).and_then(|x| x.checked_add(16)) {
        Some(s) => s,
        None => return Vec::new(),
    };

    let mut out = Vec::new();
    let mut seen_arrays: Vec<u64> = Vec::new();

    for (from, to) in ctx.search_regions() {
        scan_region(
            ctx,
            data,
            from,
            to,
            ptr_size,
            entry_size,
            &mut out,
            &mut seen_arrays,
        );
    }
    out
}

/// Scan `[start, end)` for `[]file` slice headers, appending every asset of
/// every array that validates.
///
/// The three words of a `(ptr, len, cap)` header are consecutive, so the walk
/// keeps a rolling window and reads each word once rather than once per
/// candidate position, and tests `len`/`cap` - by far the more selective
/// fields - before looking at the pointer.
#[allow(clippy::too_many_arguments)]
fn scan_region<'a>(
    ctx: &'a BinaryContext<'a>,
    data: &'a [u8],
    start: usize,
    end: usize,
    ptr_size: u8,
    entry_size: usize,
    out: &mut Vec<EmbeddedAsset<'a>>,
    seen_arrays: &mut Vec<u64>,
) {
    let p = ptr_size as usize;
    let Some(start) = start.checked_next_multiple_of(p) else {
        return;
    };
    let end = end.min(data.len());
    // Need three words to form a header.
    let Some(last) = end.checked_sub(p.saturating_mul(3)) else {
        return;
    };

    let read = |off: usize| read_uintptr(data, off, ptr_size);
    let (Some(mut ptr), Some(mut len)) = (read(start), read(start.saturating_add(p))) else {
        return;
    };

    let mut off = start;
    while off <= last {
        let Some(cap) = read(off.saturating_add(p.saturating_mul(2))) else {
            return;
        };
        if len != 0
            && len == cap
            && len <= MAX_ENTRIES_PER_FS
            && ptr != 0
            && (len as usize).checked_mul(entry_size).is_some()
            && !seen_arrays.contains(&ptr)
            && let Some(mut assets) = parse_file_array(ctx, ptr, len, ptr_size, entry_size)
        {
            seen_arrays.push(ptr);
            out.append(&mut assets);
        }
        ptr = len;
        len = cap;
        off = match off.checked_add(p) {
            Some(o) => o,
            None => return,
        };
    }
}

/// Parse exactly `count` `file` entries at array VA `arr_va`. Returns `None`
/// (rejecting the candidate) if any entry fails strict validation or the array
/// is not in `embed`'s canonical sort order.
fn parse_file_array<'a>(
    ctx: &'a BinaryContext<'a>,
    arr_va: u64,
    count: u64,
    ps: u8,
    entry_size: usize,
) -> Option<Vec<EmbeddedAsset<'a>>> {
    let p = ps as usize;
    // Deliberately un-reserved: nearly every candidate the scan offers is
    // rejected on its first entry, and reserving up front would allocate for
    // each of those only to drop it unused.
    let mut assets = Vec::new();
    // The embed `files` list is sorted by (dir, base); enforcing strictly
    // increasing order is the decisive filter that rejects the many unrelated
    // `[]string`-shaped tables a blind scan would otherwise match.
    let mut prev_key: Option<(&str, &str)> = None;
    for i in 0..count {
        let entry_off = (i as usize).checked_mul(entry_size)?;
        let entry_va = arr_va.checked_add(entry_off as u64)?;
        let entry = ctx.slice_at_va(entry_va)?;
        if entry.len() < entry_size {
            return None;
        }
        // name string (ptr,len) @ 0; data string (ptr,len) @ 2*ps; hash @ 4*ps.
        let name_ptr = read_uintptr(entry, 0, ps)?;
        let name_len = read_uintptr(entry, p, ps)?;
        let data_ptr = read_uintptr(entry, p.checked_mul(2)?, ps)?;
        let data_len = read_uintptr(entry, p.checked_mul(3)?, ps)?;
        let hash = entry.get(p.checked_mul(4)?..p.checked_mul(4)?.checked_add(16)?)?;
        let hash_is_zero = hash.iter().all(|&b| b == 0);

        let path = read_path(ctx, name_ptr, name_len)?;
        let is_dir = path.ends_with('/');

        let asset_data: &[u8] = if is_dir {
            // Directories: no backing bytes, zero hash.
            if data_ptr != 0 || data_len != 0 || !hash_is_zero {
                return None;
            }
            &[]
        } else {
            // Files: a real truncated-SHA256 hash (non-zero) and resolvable
            // backing bytes.
            if hash_is_zero || data_len == 0 || data_len > MAX_DATA_LEN {
                return None;
            }
            let bytes = ctx.slice_at_va(data_ptr)?;
            bytes.get(..data_len as usize)?
        };

        // Enforce the canonical embed ordering.
        let key = embed_sort_key(path);
        if prev_key.is_some_and(|prev| prev >= key) {
            return None;
        }
        prev_key = Some(key);

        assets.push(EmbeddedAsset {
            path,
            is_dir,
            data: asset_data,
        });
    }
    if assets.is_empty() {
        return None;
    }
    Some(assets)
}

/// The `(dir, base)` sort key `embed` orders its file list by.
///
/// Mirrors `embed.split`: strip a trailing `/`, then split at the last
/// remaining `/` (a missing dir becomes `"."`). Borrowed from `name` rather
/// than owned - the key exists only to be compared against its predecessor,
/// and the blind scan evaluates it for every candidate entry it examines, so
/// owning it allocated twice per rejected entry.
fn embed_sort_key(name: &str) -> (&str, &str) {
    let n = name.strip_suffix('/').unwrap_or(name);
    match n.rfind('/') {
        Some(i) => (
            n.get(..i).unwrap_or("."),
            n.get(i.saturating_add(1)..).unwrap_or(""),
        ),
        None => (".", n),
    }
}

/// Resolve and validate a `file.name`: a non-empty, path-shaped UTF-8 string
/// with no control characters.
fn read_path<'a>(ctx: &'a BinaryContext<'a>, name_ptr: u64, name_len: u64) -> Option<&'a str> {
    if name_ptr == 0 || name_len == 0 || name_len > MAX_NAME_LEN {
        return None;
    }
    let bytes = ctx.slice_at_va(name_ptr)?;
    let slice = bytes.get(..name_len as usize)?;
    let s = std::str::from_utf8(slice).ok()?;
    // embed paths are clean, relative, forward-slash virtual paths. Rejecting
    // control chars, leading slashes, backslashes, and spaces filters the bulk
    // of coincidental `[]string` matches a blind scan would otherwise hit.
    if s.is_empty()
        || s.starts_with('/')
        || s.contains('\\')
        || s.chars().any(|c| c.is_control() || c == ' ')
    {
        return None;
    }
    Some(s)
}
