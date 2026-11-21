//! Go interface type extra fields (`abi.InterfaceType`).
//!
//! The `InterfaceType` follows the embedded `abi.Type` in the binary layout
//! for types of kind `Interface`. It carries the package path and a slice
//! of interface methods (`GoImethod` entries).
//!
//! Binary layout: pointer_size + GoSlice::size(ps) bytes.
//!
//! Fields:
//! - `PkgPath` (uintptr)  -- pointer to the package path name
//! - `Methods` (GoSlice)   -- slice of `abi.Imethod` entries
//!
//! Source: `src/internal/abi/type.go:370-377`

use crate::{structures::goslice::GoSlice, util::read_uintptr};

/// Parsed extra fields for an interface type descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct InterfaceTypeExtra {
    /// Virtual address of the package path name.
    pub pkg_path: u64,
    /// Slice header pointing to the `Imethod` array.
    pub methods: GoSlice,
}

impl InterfaceTypeExtra {
    /// Binary size: pointer_size + GoSlice::size(ps).
    pub fn size(ps: u8) -> usize {
        (ps as usize).saturating_add(GoSlice::size(ps))
    }

    /// Parse from `data`. Data must start at the interface type extra fields.
    ///
    /// Returns `None` if the buffer is too small.
    pub fn parse(data: &[u8], ps: u8) -> Option<Self> {
        let p = ps as usize;
        if data.len() < Self::size(ps) {
            return None;
        }

        let pkg_path = read_uintptr(data, 0, ps)?;
        let methods = GoSlice::parse(data, p, ps)?;

        Some(Self { pkg_path, methods })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_64bit() {
        // ps=8: size = 8 + 24 = 32 bytes
        let mut buf = vec![0u8; 32];
        // pkg_path
        buf[0..8].copy_from_slice(&0xAAAAu64.to_le_bytes());
        // methods.ptr
        buf[8..16].copy_from_slice(&0xBBBBu64.to_le_bytes());
        // methods.len
        buf[16..24].copy_from_slice(&3u64.to_le_bytes());
        // methods.cap
        buf[24..32].copy_from_slice(&3u64.to_le_bytes());

        let i = InterfaceTypeExtra::parse(&buf, 8).unwrap();
        assert_eq!(i.pkg_path, 0xAAAA);
        assert_eq!(i.methods.ptr, 0xBBBB);
        assert_eq!(i.methods.len, 3);
        assert_eq!(i.methods.cap, 3);
    }

    #[test]
    fn parse_32bit() {
        // ps=4: size = 4 + 12 = 16 bytes
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&0xCCCCu32.to_le_bytes());
        buf[4..8].copy_from_slice(&0xDDDDu32.to_le_bytes());
        buf[8..12].copy_from_slice(&2u32.to_le_bytes());
        buf[12..16].copy_from_slice(&2u32.to_le_bytes());

        let i = InterfaceTypeExtra::parse(&buf, 4).unwrap();
        assert_eq!(i.pkg_path, 0xCCCC);
        assert_eq!(i.methods.ptr, 0xDDDD);
        assert_eq!(i.methods.len, 2);
    }

    #[test]
    fn too_short_returns_none() {
        let buf = vec![0u8; 28];
        assert!(InterfaceTypeExtra::parse(&buf, 8).is_none());
    }

    #[test]
    fn size_calculations() {
        assert_eq!(InterfaceTypeExtra::size(4), 16);
        assert_eq!(InterfaceTypeExtra::size(8), 32);
    }
}
