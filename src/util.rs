//! Low-level byte reading and offset arithmetic helpers shared across all
//! Go binary structure parsers.
//!
//! Two families of helpers live here:
//!
//! - **Bounds-checked readers** ([`slice_at`], [`read_uintptr`], [`read_u32`],
//!   [`read_i32`], [`read_u16`]) return `Option` for out-of-bounds reads, so
//!   adversarial input cannot cause panics.
//! - **Cursor / alignment helpers** ([`advance`], [`advance_n`], [`align_up`])
//!   for sequential parsers walking through a structure with overflow-checked
//!   arithmetic.
//! - **Variable-length integer decoder** ([`read_uvarint`]) for the Go
//!   pclntab and buildinfo formats which both use LEB128.
//! - **Byte search** ([`find_bytes`]) for the markers and magics the parsers
//!   scan for.
//!
//! All arithmetic uses `checked_*` / `saturating_*` so the
//! `clippy::arithmetic_side_effects` lint stays clean and parsers cannot
//! panic on hostile input.

/// Read a fixed-width slice at `offset`, returning `None` if out of bounds or
/// if `offset + N` overflows.
pub fn slice_at<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let s = data.get(offset..end)?;
    s.try_into().ok()
}

/// Read a little-endian `uintptr` (4 or 8 bytes depending on `ps`).
pub fn read_uintptr(data: &[u8], offset: usize, ps: u8) -> Option<u64> {
    match ps {
        4 => Some(u32::from_le_bytes(slice_at::<4>(data, offset)?) as u64),
        8 => Some(u64::from_le_bytes(slice_at::<8>(data, offset)?)),
        _ => None,
    }
}

/// Read a little-endian `u32`.
pub fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(slice_at::<4>(data, offset)?))
}

/// Read a little-endian `i32`.
pub fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_le_bytes(slice_at::<4>(data, offset)?))
}

/// Read a little-endian `u16`.
pub fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(slice_at::<2>(data, offset)?))
}

/// Advance a cursor `off` by `by` bytes, returning `None` on overflow.
///
/// Idiomatic shorthand for `off.checked_add(by)` - used by sequential parsers
/// like [`crate::structures::moduledata::Moduledata::parse`] that walk
/// fixed-layout records field by field.
#[inline]
pub fn advance(off: usize, by: usize) -> Option<usize> {
    off.checked_add(by)
}

/// Advance a cursor by `n_units * unit` bytes, returning `None` on overflow.
///
/// Used to skip past `[uintptr; N]`-style padding regions in structures whose
/// layout depends on pointer size.
#[inline]
pub fn advance_n(off: usize, n_units: usize, unit: usize) -> Option<usize> {
    n_units.checked_mul(unit).and_then(|t| off.checked_add(t))
}

/// Round `value` up to the nearest multiple of `align`, returning `None` on
/// overflow or when `align == 0`.
///
/// Equivalent to `(value + align - 1) & !(align - 1)` for power-of-two
/// alignments, but expressed via `checked_*` so the lint stays satisfied and
/// hostile inputs cannot wrap.
#[inline]
pub fn align_up(value: usize, align: usize) -> Option<usize> {
    if align == 0 {
        return None;
    }
    let mask = align.checked_sub(1)?;
    let raw = value.checked_add(mask)?;
    Some(raw & !mask)
}

/// `align_up` for `u64`, used when working with virtual addresses.
#[inline]
pub fn align_up_u64(value: u64, align: u64) -> Option<u64> {
    if align == 0 {
        return None;
    }
    let mask = align.checked_sub(1)?;
    let raw = value.checked_add(mask)?;
    Some(raw & !mask)
}

/// Decode an unsigned LEB128 / base-128 varint from a byte slice.
///
/// Each byte contributes 7 data bits (low 7) and 1 continuation bit (high
/// bit). Maximum 10 bytes (for `u64`). Returns `(value, bytes_consumed)` or
/// `None` on truncation, malformed continuation, or excessive shift.
///
/// This is the same encoding used by Go's `binary.Uvarint`, the pclntab
/// pcdata encoder, and the buildinfo blob.
///
/// Source: `src/encoding/binary/varint.go:63-82`.
pub fn read_uvarint(data: &[u8]) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return None;
        }
        let chunk = ((byte & 0x7f) as u64).checked_shl(shift)?;
        result |= chunk;
        if byte & 0x80 == 0 {
            return Some((result, i.checked_add(1)?));
        }
        shift = shift.checked_add(7)?;
    }
    None
}

/// Find the first occurrence of `needle` in `haystack`.
///
/// Uses a simple sliding-window scan. For the sizes we deal with (binaries up to
/// ~100MB, needles of 10-40 bytes), this is fast enough and avoids pulling in a
/// heavier substring search dependency.
pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_uintptr_32bit() {
        let data = 42u32.to_le_bytes();
        assert_eq!(read_uintptr(&data, 0, 4), Some(42));
    }

    #[test]
    fn read_uintptr_64bit() {
        let data = 0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes();
        assert_eq!(read_uintptr(&data, 0, 8), Some(0xDEAD_BEEF_CAFE_BABE));
    }

    #[test]
    fn read_uintptr_out_of_bounds() {
        let data = [0u8; 4];
        assert_eq!(read_uintptr(&data, 2, 4), None);
    }

    #[test]
    fn read_uintptr_invalid_ps() {
        let data = [0u8; 8];
        assert_eq!(read_uintptr(&data, 0, 3), None);
    }

    #[test]
    fn read_u32_basic() {
        let data = 0x12345678u32.to_le_bytes();
        assert_eq!(read_u32(&data, 0), Some(0x12345678));
    }

    #[test]
    fn read_u32_out_of_bounds() {
        let data = [0u8; 3];
        assert_eq!(read_u32(&data, 0), None);
    }

    #[test]
    fn read_i32_negative() {
        let data = (-100i32).to_le_bytes();
        assert_eq!(read_i32(&data, 0), Some(-100));
    }

    #[test]
    fn read_u16_basic() {
        let data = 0xABCDu16.to_le_bytes();
        assert_eq!(read_u16(&data, 0), Some(0xABCD));
    }

    #[test]
    fn read_at_offset() {
        let mut data = vec![0u8; 16];
        data[8..12].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(read_u32(&data, 8), Some(99));
    }

    #[test]
    fn advance_basic() {
        assert_eq!(advance(10, 4), Some(14));
        assert_eq!(advance(usize::MAX, 1), None);
    }

    #[test]
    fn advance_n_basic() {
        assert_eq!(advance_n(0, 3, 8), Some(24));
        assert_eq!(advance_n(usize::MAX, 1, 1), None);
        assert_eq!(advance_n(0, usize::MAX, 2), None);
    }

    #[test]
    fn align_up_powers_of_two() {
        assert_eq!(align_up(13, 4), Some(16));
        assert_eq!(align_up(16, 4), Some(16));
        assert_eq!(align_up(0, 8), Some(0));
        assert_eq!(align_up(1, 8), Some(8));
    }

    #[test]
    fn align_up_rejects_zero_align() {
        assert_eq!(align_up(10, 0), None);
        assert_eq!(align_up_u64(10, 0), None);
    }

    #[test]
    fn align_up_overflow() {
        assert_eq!(align_up(usize::MAX, 8), None);
    }

    #[test]
    fn align_up_u64_basic() {
        assert_eq!(align_up_u64(0x1003, 8), Some(0x1008));
        assert_eq!(align_up_u64(0x1000, 8), Some(0x1000));
    }

    #[test]
    fn read_uvarint_single_byte() {
        assert_eq!(read_uvarint(&[0x08]), Some((8, 1)));
    }

    #[test]
    fn read_uvarint_multi_byte() {
        assert_eq!(read_uvarint(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(read_uvarint(&[0xac, 0x02]), Some((300, 2)));
    }

    #[test]
    fn read_uvarint_empty() {
        assert_eq!(read_uvarint(&[]), None);
    }

    #[test]
    fn read_uvarint_truncated() {
        // continuation bit set but no following byte
        assert_eq!(read_uvarint(&[0x80]), None);
    }

    #[test]
    fn read_uvarint_too_long() {
        // 11 bytes of continuation should fail (max is 10)
        assert_eq!(read_uvarint(&[0x80; 11]), None);
    }
}
