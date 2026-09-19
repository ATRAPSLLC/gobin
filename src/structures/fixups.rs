//! Mach-O chained-fixups (`LC_DYLD_CHAINED_FIXUPS`) rebaser.
//!
//! Externally-linked Mach-O objects (CGO, `-buildmode=plugin`, c-shared) store
//! every data pointer not as a plain VA but as a link in a *fixup chain*: the
//! 64-bit slot packs the real target into low bits plus chain-walk metadata
//! (`next`, `bind`) in the high bits, to be applied by `dyld` at load time.
//! Until they are applied, reading such a slot as a pointer yields garbage -
//! so type / itab / moduledata pointer resolution fails on these objects.
//!
//! This module walks the fixup chains and produces a **rebased copy** of the
//! file bytes in which every rebase slot holds its resolved virtual address,
//! so the rest of the crate can read pointers exactly as it does for an
//! ordinary (internally-linked) binary. It mirrors the wasm linear-memory
//! image: the copy has the same byte layout as the file, only pointer *values*
//! change, so existing VA→file translation keeps working.
//!
//! Source: Apple `dyld` `mach-o/fixup-chains.h`.

use crate::structures::util::{read_u16, read_u32, read_uintptr};

/// `DYLD_CHAINED_PTR_64` - 8-byte slots, `target` is an unslid vmaddr.
const PTR_64: u16 = 2;
/// `DYLD_CHAINED_PTR_64_OFFSET` - 8-byte slots, `target` is an offset from the
/// image base. This is what the Go/clang toolchain emits.
const PTR_64_OFFSET: u16 = 6;
/// Sentinel page-start value meaning "no fixups on this page".
const START_NONE: u16 = 0xffff;

/// Read a little-endian `u64` at `off`.
fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    read_uintptr(data, off, 8)
}

/// Apply the chained fixups described at `data[fixups_off..]` and return a
/// rebased copy of `data`. `seg_vmaddr_fileoff` is `(vmaddr, fileoff)` for each
/// Mach-O segment in load-command order (the fixup chains index segments by
/// that order). `image_base` is the lowest segment vmaddr.
///
/// Returns `None` if there are no applicable (64-bit) fixups or the blob is
/// malformed - the caller then uses the original bytes unchanged. Never
/// panics; bounded against malformed offsets and chain cycles.
pub fn rebase(
    data: &[u8],
    fixups_off: usize,
    seg_vmaddr_fileoff: &[(u64, u64)],
    image_base: u64,
) -> Option<Vec<u8>> {
    // dyld_chained_fixups_header: fixups_version, starts_offset, ...
    let version = read_u32(data, fixups_off)?;
    if version != 0 {
        return None;
    }
    let starts_offset = read_u32(data, fixups_off.checked_add(4)?)? as usize;
    let starts_in_image = fixups_off.checked_add(starts_offset)?;

    // dyld_chained_starts_in_image: seg_count, seg_info_offset[seg_count].
    let seg_count = read_u32(data, starts_in_image)? as usize;
    if seg_count > 4096 {
        return None;
    }

    let mut out = data.to_vec();
    let mut applied = false;

    for seg in 0..seg_count {
        let so_pos = starts_in_image
            .checked_add(4)?
            .checked_add(seg.checked_mul(4)?)?;
        let seg_info_offset = match read_u32(data, so_pos) {
            Some(v) if v != 0 => v as usize,
            _ => continue, // no fixups in this segment
        };
        let (_seg_vmaddr, seg_fileoff) = match seg_vmaddr_fileoff.get(seg) {
            Some(&pair) => pair,
            None => continue,
        };
        apply_segment(
            data,
            &mut out,
            starts_in_image.checked_add(seg_info_offset)?,
            seg_fileoff,
            image_base,
            &mut applied,
        );
    }

    if applied { Some(out) } else { None }
}

/// Walk every fixup chain in one segment, writing resolved VAs into `out`.
fn apply_segment(
    data: &[u8],
    out: &mut [u8],
    starts: usize,
    seg_fileoff: u64,
    image_base: u64,
    applied: &mut bool,
) -> Option<()> {
    // dyld_chained_starts_in_segment:
    //   size u32, page_size u16, pointer_format u16, segment_offset u64,
    //   max_valid_pointer u32, page_count u16, page_start[page_count] u16
    let page_size = read_u16(data, starts.checked_add(4)?)? as usize;
    let pointer_format = read_u16(data, starts.checked_add(6)?)?;
    if !matches!(pointer_format, PTR_64 | PTR_64_OFFSET) || page_size == 0 {
        return None;
    }
    let page_count = read_u16(data, starts.checked_add(20)?)? as usize;
    let page_start_base = starts.checked_add(22)?;

    let seg_fileoff = usize::try_from(seg_fileoff).ok()?;

    for page in 0..page_count {
        let ps_pos = page_start_base.checked_add(page.checked_mul(2)?)?;
        let page_start = match read_u16(data, ps_pos) {
            Some(v) if v != START_NONE => v as usize,
            _ => continue,
        };
        let chain0 = seg_fileoff
            .checked_add(page.checked_mul(page_size)?)?
            .checked_add(page_start)?;
        walk_chain(data, out, chain0, pointer_format, image_base, applied);
    }
    Some(())
}

/// Walk one fixup chain starting at file offset `start`, rebasing each link.
fn walk_chain(
    data: &[u8],
    out: &mut [u8],
    start: usize,
    pointer_format: u16,
    image_base: u64,
    applied: &mut bool,
) {
    // Cap iterations so a malformed `next` cannot loop forever.
    const MAX_LINKS: usize = 50_000_000;
    let mut off = start;
    let mut links = 0usize;
    while links < MAX_LINKS {
        links = links.saturating_add(1);
        let raw = match read_u64(data, off) {
            Some(v) => v,
            None => return,
        };
        let bind = (raw >> 63) & 1;
        let next = ((raw >> 51) & 0xfff) as usize;

        if bind == 0 {
            // Rebase: target is bits 0..36, high8 bits 36..44.
            let target = raw & 0x000f_ffff_ffff;
            let high8 = (raw >> 36) & 0xff;
            let value = (high8 << 56) | target;
            let resolved = if pointer_format == PTR_64_OFFSET {
                image_base.wrapping_add(value)
            } else {
                value
            };
            if let Some(slot) = out.get_mut(off..off.saturating_add(8)) {
                slot.copy_from_slice(&resolved.to_le_bytes());
                *applied = true;
            }
        }
        // bind == 1: an external import; leave the slot as-is (Go runtime
        // pointers we care about are all rebases).

        if next == 0 {
            return; // end of chain
        }
        // `next` is a stride in 4-byte words for the 64-bit formats.
        off = match next.checked_mul(4).and_then(|d| off.checked_add(d)) {
            Some(v) => v,
            None => return,
        };
    }
}
