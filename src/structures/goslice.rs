//! Go slice header (`reflect.SliceHeader`) as stored in compiled binaries.
//!
//! A Go slice is `(ptr, len, cap)`, each `uintptr`-sized. The linker generates
//! slices in `moduledata` and type descriptor regions with `cap == len`.
//!
//! Source: `src/runtime/slice.go`, `src/reflect/value.go:2580-2584`

use crate::util::read_uintptr;

/// A Go slice header: `(ptr, len, cap)`, each pointer-sized.
#[derive(Debug, Clone, Copy, Default)]
pub struct GoSlice {
    /// Virtual address of the slice data.
    pub ptr: u64,
    /// Number of elements.
    pub len: u64,
    /// Capacity (usually == len for linker-generated slices).
    pub cap: u64,
}

/// A Go string header: `(ptr, len)`, each pointer-sized.
///
/// Go strings are `(data *byte, len int)`. Unlike a [`GoSlice`] there is no
/// capacity. Resolve `ptr`/`len` to bytes via the address-space view.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GoStr {
    /// Virtual address of the string bytes.
    pub ptr: u64,
    /// Length in bytes.
    pub len: u64,
}

impl GoStr {
    /// Binary size: 2 * pointer_size.
    pub fn size(ps: u8) -> usize {
        (ps as usize).saturating_mul(2)
    }

    /// Parse from raw bytes at the given offset.
    pub fn parse(data: &[u8], offset: usize, ps: u8) -> Option<Self> {
        let p = ps as usize;
        Some(Self {
            ptr: read_uintptr(data, offset, ps)?,
            len: read_uintptr(data, offset.checked_add(p)?, ps)?,
        })
    }

    /// Whether the string is empty (zero length).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl GoSlice {
    /// Binary size: 3 * pointer_size.
    pub fn size(ps: u8) -> usize {
        (ps as usize).saturating_mul(3)
    }

    /// Parse from raw bytes at the given offset.
    pub fn parse(data: &[u8], offset: usize, ps: u8) -> Option<Self> {
        let p = ps as usize;
        Some(Self {
            ptr: read_uintptr(data, offset, ps)?,
            len: read_uintptr(data, offset.checked_add(p)?, ps)?,
            cap: read_uintptr(data, offset.checked_add(p.saturating_mul(2))?, ps)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_64bit() {
        let mut data = vec![0u8; 24];
        data[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
        data[8..16].copy_from_slice(&10u64.to_le_bytes());
        data[16..24].copy_from_slice(&10u64.to_le_bytes());
        let s = GoSlice::parse(&data, 0, 8).unwrap();
        assert_eq!(s.ptr, 0x1000);
        assert_eq!(s.len, 10);
        assert_eq!(s.cap, 10);
    }

    #[test]
    fn parse_32bit() {
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(&0x2000u32.to_le_bytes());
        data[4..8].copy_from_slice(&5u32.to_le_bytes());
        data[8..12].copy_from_slice(&5u32.to_le_bytes());
        let s = GoSlice::parse(&data, 0, 4).unwrap();
        assert_eq!(s.ptr, 0x2000);
        assert_eq!(s.len, 5);
    }

    #[test]
    fn parse_at_offset() {
        let mut data = vec![0u8; 32];
        data[8..16].copy_from_slice(&0x3000u64.to_le_bytes());
        data[16..24].copy_from_slice(&7u64.to_le_bytes());
        data[24..32].copy_from_slice(&7u64.to_le_bytes());
        let s = GoSlice::parse(&data, 8, 8).unwrap();
        assert_eq!(s.ptr, 0x3000);
        assert_eq!(s.len, 7);
    }

    #[test]
    fn parse_too_short() {
        let data = vec![0u8; 20];
        assert!(GoSlice::parse(&data, 0, 8).is_none());
    }

    #[test]
    fn size_calculations() {
        assert_eq!(GoSlice::size(4), 12);
        assert_eq!(GoSlice::size(8), 24);
    }
}
