//! Go uncommon type descriptor (`abi.UncommonType`).
//!
//! When a type has methods or a package path, an `UncommonType` struct is
//! appended after the type-specific extra fields. This struct records where
//! to find the method list.
//!
//! Binary layout: fixed 16 bytes (all architectures).
//!
//! Fields:
//! - `PkgPath` (NameOff / i32) -- offset to package path name
//! - `Mcount`  (u16)           -- number of methods
//! - `Xcount`  (u16)           -- number of exported methods
//! - `Moff`    (u32)           -- byte offset from this struct to the method array
//! - `_`       (4 bytes)       -- padding (not stored)
//!
//! Source: `src/internal/abi/type.go:230-236`

use crate::util::{read_i32, read_u16, read_u32};

/// Parsed `abi.UncommonType` -- method metadata appended to types with methods.
#[derive(Debug, Clone, Copy, Default)]
pub struct UncommonType {
    /// Offset into the names table for the package path.
    pub pkg_path: i32,
    /// Total number of methods (exported + unexported).
    pub mcount: u16,
    /// Number of exported methods.
    pub xcount: u16,
    /// Byte offset from this `UncommonType` to the `[mcount]Method` array.
    pub moff: u32,
}

impl UncommonType {
    /// Binary size: always 16 bytes (including 4 bytes of trailing padding).
    pub const SIZE: usize = 16;

    /// Parse an `UncommonType` from `data`. Data must start at the type.
    ///
    /// Returns `None` if the buffer is too small.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        let pkg_path = read_i32(data, 0)?;
        let mcount = read_u16(data, 4)?;
        let xcount = read_u16(data, 6)?;
        let moff = read_u32(data, 8)?;
        // bytes 12..16 are padding, not stored

        Some(Self {
            pkg_path,
            mcount,
            xcount,
            moff,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_buffer() {
        let mut buf = vec![0u8; 16];
        // pkg_path = 42
        buf[0..4].copy_from_slice(&42i32.to_le_bytes());
        // mcount = 5
        buf[4..6].copy_from_slice(&5u16.to_le_bytes());
        // xcount = 3
        buf[6..8].copy_from_slice(&3u16.to_le_bytes());
        // moff = 0x100
        buf[8..12].copy_from_slice(&0x100u32.to_le_bytes());
        // padding bytes 12..16 left as zero

        let u = UncommonType::parse(&buf).unwrap();
        assert_eq!(u.pkg_path, 42);
        assert_eq!(u.mcount, 5);
        assert_eq!(u.xcount, 3);
        assert_eq!(u.moff, 0x100);
    }

    #[test]
    fn too_short_returns_none() {
        let buf = vec![0u8; 15];
        assert!(UncommonType::parse(&buf).is_none());
    }

    #[test]
    fn parse_negative_pkg_path() {
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&(-10i32).to_le_bytes());
        buf[4..6].copy_from_slice(&7u16.to_le_bytes());
        buf[6..8].copy_from_slice(&2u16.to_le_bytes());
        buf[8..12].copy_from_slice(&0x200u32.to_le_bytes());

        let u = UncommonType::parse(&buf).unwrap();
        assert_eq!(u.pkg_path, -10);
        assert_eq!(u.mcount, 7);
        assert_eq!(u.xcount, 2);
        assert_eq!(u.moff, 0x200);
    }
}
