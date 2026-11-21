//! Go array type extra fields (`abi.ArrayType`).
//!
//! The `ArrayType` follows the embedded `abi.Type` in the binary layout
//! for types of kind `Array`. It carries pointers to the element type,
//! the corresponding slice type, and the array length.
//!
//! Binary layout: 3 * pointer_size bytes.
//!
//! Fields:
//! - `Elem`  (uintptr) -- pointer to the element `abi.Type`
//! - `Slice` (uintptr) -- pointer to the `[]Elem` slice type
//! - `Len`   (uintptr) -- array length
//!
//! Source: `src/internal/abi/type.go:340-345`

use crate::util::read_uintptr;

/// Parsed extra fields for an array type descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct ArrayTypeExtra {
    /// Virtual address of the element type descriptor.
    pub elem: u64,
    /// Virtual address of the corresponding slice type descriptor.
    pub slice: u64,
    /// Array length.
    pub len: u64,
}

impl ArrayTypeExtra {
    /// Binary size: 3 * pointer_size.
    pub fn size(ps: u8) -> usize {
        (ps as usize).saturating_mul(3)
    }

    /// Parse from `data`. Data must start at the array type extra fields.
    ///
    /// Returns `None` if the buffer is too small.
    pub fn parse(data: &[u8], ps: u8) -> Option<Self> {
        let p = ps as usize;
        if data.len() < Self::size(ps) {
            return None;
        }

        Some(Self {
            elem: read_uintptr(data, 0, ps)?,
            slice: read_uintptr(data, p, ps)?,
            len: read_uintptr(data, p.saturating_mul(2), ps)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_64bit() {
        let mut buf = vec![0u8; 24];
        buf[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        buf[16..24].copy_from_slice(&10u64.to_le_bytes());

        let a = ArrayTypeExtra::parse(&buf, 8).unwrap();
        assert_eq!(a.elem, 0x1000);
        assert_eq!(a.slice, 0x2000);
        assert_eq!(a.len, 10);
    }

    #[test]
    fn parse_32bit() {
        let mut buf = vec![0u8; 12];
        buf[0..4].copy_from_slice(&0x3000u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0x4000u32.to_le_bytes());
        buf[8..12].copy_from_slice(&5u32.to_le_bytes());

        let a = ArrayTypeExtra::parse(&buf, 4).unwrap();
        assert_eq!(a.elem, 0x3000);
        assert_eq!(a.slice, 0x4000);
        assert_eq!(a.len, 5);
    }

    #[test]
    fn too_short_returns_none() {
        let buf = vec![0u8; 20];
        assert!(ArrayTypeExtra::parse(&buf, 8).is_none());
    }

    #[test]
    fn size_calculations() {
        assert_eq!(ArrayTypeExtra::size(4), 12);
        assert_eq!(ArrayTypeExtra::size(8), 24);
    }
}
