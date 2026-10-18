//! Go build ID extraction.
//!
//! Every Go binary contains a build ID: a string derived from SHA256 hashes of the
//! compilation inputs and outputs. For executables, the format is:
//!
//! ```text
//! actionID/actionID/contentID/contentID
//! ```
//!
//! where each part is 20 characters of URL-safe base64 (alphabet:
//! `A-Za-z0-9-_`, encoding the first 120 bits of a SHA256 hash).
//!
//! ## Embedding Formats
//!
//! The build ID is stored differently depending on the binary format:
//!
//! ### ELF: PT_NOTE segment
//!
//! ```text
//! Section: .note.go.buildid
//! Note name:  "Go\x00\x00"  (4 bytes)
//! Note tag:   4              (ELF_NOTE_GOBUILDID_TAG)
//! Note desc:  <build ID string bytes>
//! ```
//!
//! Additional ELF note tags defined in `src/cmd/link/internal/ld/elf.go:965-973`:
//! - Tag 1: `GOPKGLIST` (package list)
//! - Tag 2: `GOABIHASH` (ABI hash)
//! - Tag 3: `GODEPS` (dependencies)
//! - Tag 4: `GOBUILDID` (build ID)
//!
//! ### Mach-O / PE / Plan9: Raw text-segment marker
//!
//! ```text
//! \xff Go build ID: "<build_id_string>"\n \xff
//! ```
//!
//! Placed at the very beginning of the text segment as symbol `go:buildid`.
//!
//! Source: `src/cmd/internal/buildid/buildid.go:241-242` (marker constants),
//! `src/cmd/link/internal/ld/data.go:2590-2607` (linker embedding).

use std::ops::Range;

use crate::{
    detection::find_bytes,
    formats::BinaryContext,
    structures::util::{align_up, slice_at},
};

/// Raw build ID prefix in non-ELF binaries.
///
/// Byte sequence: `ff 20 47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22`
///
/// Source: `src/cmd/internal/buildid/buildid.go:241`
const BUILD_ID_PREFIX: &[u8] = b"\xff Go build ID: \"";

/// Raw build ID suffix in non-ELF binaries.
///
/// Byte sequence: `22 0a 20 ff`
///
/// Source: `src/cmd/internal/buildid/buildid.go:242`
const BUILD_ID_SUFFIX: &[u8] = b"\"\n \xff";

/// ELF note name for Go notes: `"Go\x00\x00"` (4 bytes, null-padded).
///
/// Source: `src/cmd/internal/buildid/note.go:73`
const ELF_GO_NOTE_NAME: &[u8] = b"Go\x00\x00";

/// ELF note tag value for the Go build ID.
///
/// Source: `src/cmd/link/internal/ld/elf.go:970`
const ELF_NOTE_GOBUILDID_TAG: u32 = 4;

/// Maximum number of bytes to scan for the raw build ID marker.
///
/// The linker places `go:buildid` at the very start of the text segment, so 64KB
/// is more than enough to cover the initial headers + text start on any format.
const RAW_SEARCH_LIMIT: usize = 65536;

/// A Go build ID and where the binary records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildId<'a> {
    /// The build ID string.
    pub id: &'a str,
    /// Where the binary records it.
    pub source: BuildIdSource,
}

/// Where a binary records its Go build ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildIdSource {
    /// The descriptor of the Go build ID note in an ELF `PT_NOTE` segment, where
    /// the Go linker puts it on ELF.
    ElfNote,
    /// A raw marker blob: the `go:buildid` symbol at or near the start of the
    /// text on Mach-O and PE, or the `go:buildid` custom section of a wasm
    /// module.
    Marker {
        /// File-offset extent of the blob, from the first byte of
        /// `\xff Go build ID: "` through the last byte of `"\n \xff`.
        blob: Range<usize>,
    },
}

/// Extract the Go build ID from a binary.
///
/// The ELF `PT_NOTE` segments are tried first (structured, and where the Go
/// linker puts the ID on ELF; non-ELF images have none), then a scan for the
/// raw marker.
pub fn extract<'a>(ctx: &BinaryContext<'a>) -> Option<BuildId<'a>> {
    ctx.elf_note_segments()
        .find_map(find_note)
        .or_else(|| find_marker(ctx.data()))
}

/// Find the raw marker `\xff Go build ID: "..."\n \xff` near the start of
/// `data`.
///
/// The build ID string between the quotes is extracted verbatim. It may contain
/// Go string escape sequences (the Go toolchain uses `strconv.Quote`), but in
/// practice build IDs are pure ASCII base64 characters.
fn find_marker(data: &[u8]) -> Option<BuildId<'_>> {
    let search_end = data.len().min(RAW_SEARCH_LIMIT);
    let head = data.get(..search_end)?;
    let prefix_pos = find_bytes(head, BUILD_ID_PREFIX)?;
    let id_start = prefix_pos.checked_add(BUILD_ID_PREFIX.len())?;

    // Look for the suffix within 1KB of the prefix (build IDs are ~83 chars)
    let window_end = id_start.checked_add(1024)?.min(data.len());
    let search_window = data.get(id_start..window_end)?;
    let suffix_pos = find_bytes(search_window, BUILD_ID_SUFFIX)?;

    let id_end = id_start.checked_add(suffix_pos)?;
    let bytes = data.get(id_start..id_end)?;
    let id = std::str::from_utf8(bytes).ok()?;
    let blob_end = id_end.checked_add(BUILD_ID_SUFFIX.len())?;
    Some(BuildId {
        id,
        source: BuildIdSource::Marker {
            blob: prefix_pos..blob_end,
        },
    })
}

/// Walk one ELF `PT_NOTE` segment for the Go build ID note.
///
/// ## ELF Note Layout (per note entry)
///
/// ```text
/// Offset  Size  Field
/// 0       4     namesz  (name length including null padding)
/// 4       4     descsz  (descriptor/value length)
/// 8       4     type    (note tag)
/// 12      N     name    (null-padded to 4-byte alignment)
/// 12+N    M     desc    (null-padded to 4-byte alignment)
/// ```
fn find_note(data: &[u8]) -> Option<BuildId<'_>> {
    let mut pos: usize = 0;
    loop {
        let header_end = pos.checked_add(12)?;
        if header_end > data.len() {
            return None;
        }
        let namesz = u32::from_le_bytes(slice_at::<4>(data, pos)?) as usize;
        let descsz_off = pos.checked_add(4)?;
        let descsz = u32::from_le_bytes(slice_at::<4>(data, descsz_off)?) as usize;
        let type_off = pos.checked_add(8)?;
        let note_type = u32::from_le_bytes(slice_at::<4>(data, type_off)?);

        let name_start = header_end;
        let name_padded = align_up(namesz, 4)?;
        let desc_start = name_start.checked_add(name_padded)?;
        let desc_padded = align_up(descsz, 4)?;

        let desc_end = desc_start.checked_add(descsz)?;
        if desc_end > data.len() {
            return None;
        }

        if namesz == 4
            && note_type == ELF_NOTE_GOBUILDID_TAG
            && data.get(name_start..name_start.checked_add(4)?) == Some(ELF_GO_NOTE_NAME)
        {
            let bytes = data.get(desc_start..desc_end)?;
            let id = std::str::from_utf8(bytes).ok()?;
            return Some(BuildId {
                id,
                source: BuildIdSource::ElfNote,
            });
        }

        pos = desc_start.checked_add(desc_padded)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_frames_the_build_id() {
        let mut data = vec![0u8; 0x1000];
        let marker = b"\xff Go build ID: \"abc123/def456\"\n \xff";
        data[0x20..0x20 + marker.len()].copy_from_slice(marker);

        let found = find_marker(&data).unwrap();
        assert_eq!(found.id, "abc123/def456");
        assert_eq!(
            found.source,
            BuildIdSource::Marker {
                blob: 0x20..0x20 + marker.len()
            }
        );
    }

    #[test]
    fn marker_not_found() {
        let data = vec![0u8; 0x1000];
        assert!(find_marker(&data).is_none());
    }

    /// An opening marker with no closing one is not a framed blob.
    #[test]
    fn marker_without_closing_is_not_found() {
        let mut data = vec![0u8; 0x1000];
        let open = b"\xff Go build ID: \"abc123/def456\"\n";
        data[..open.len()].copy_from_slice(open);
        assert!(find_marker(&data).is_none());
    }

    /// The Go note is found past an unrelated note, and states its source.
    #[test]
    fn note_is_found_past_another_note() {
        let mut data = Vec::new();
        for (name, tag, desc) in [
            (&b"GNU\0"[..], 3u32, &b"0123"[..]),
            (ELF_GO_NOTE_NAME, ELF_NOTE_GOBUILDID_TAG, &b"abc/def"[..]),
        ] {
            data.extend_from_slice(&4u32.to_le_bytes());
            data.extend_from_slice(&(desc.len() as u32).to_le_bytes());
            data.extend_from_slice(&tag.to_le_bytes());
            data.extend_from_slice(name);
            data.extend_from_slice(desc);
            data.resize(data.len().next_multiple_of(4), 0);
        }
        assert_eq!(
            find_note(&data),
            Some(BuildId {
                id: "abc/def",
                source: BuildIdSource::ElfNote,
            })
        );
        assert_eq!(find_note(&data[..20]), None, "truncated");
    }
}
