//! Go struct type extra fields (`abi.StructType`) and struct field descriptor.
//!
//! The `StructType` follows the embedded `abi.Type` in the binary layout
//! for types of kind `Struct`. It carries a package path and a slice of
//! struct field descriptors.
//!
//! ## StructTypeExtra
//!
//! Binary layout: pointer_size + GoSlice::size(ps) bytes.
//!
//! Fields:
//! - `PkgPath` (uintptr) -- pointer to the package path name
//! - `Fields`  (GoSlice) -- slice of `StructField` entries
//!
//! ## GoStructField
//!
//! Binary layout: 3 * pointer_size bytes.
//!
//! Fields:
//! - `Name`   (uintptr) -- pointer to the field name
//! - `Typ`    (uintptr) -- pointer to the field type descriptor
//! - `Offset` (uintptr) -- byte offset of the field within the struct
//!
//! Source: `src/internal/abi/type.go:437-461`

use crate::{structures::goslice::GoSlice, util::read_uintptr};

/// Parsed extra fields for a struct type descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct StructTypeExtra {
    /// Virtual address of the package path name.
    pub pkg_path: u64,
    /// Slice header pointing to the `StructField` array.
    pub fields: GoSlice,
}

impl StructTypeExtra {
    /// Binary size: pointer_size + GoSlice::size(ps).
    pub fn size(ps: u8) -> usize {
        (ps as usize).saturating_add(GoSlice::size(ps))
    }

    /// Parse from `data`. Data must start at the struct type extra fields.
    ///
    /// Returns `None` if the buffer is too small.
    pub fn parse(data: &[u8], ps: u8) -> Option<Self> {
        let p = ps as usize;
        if data.len() < Self::size(ps) {
            return None;
        }

        let pkg_path = read_uintptr(data, 0, ps)?;
        let fields = GoSlice::parse(data, p, ps)?;

        Some(Self { pkg_path, fields })
    }
}

/// Parsed Go struct field descriptor (`abi.StructField`).
#[derive(Debug, Clone, Copy, Default)]
pub struct GoStructField {
    /// Virtual address of the field name.
    pub name: u64,
    /// Virtual address of the field type descriptor.
    pub typ: u64,
    /// Byte offset of this field within the struct.
    pub offset: u64,
}

impl GoStructField {
    /// Binary size: 3 * pointer_size.
    pub fn size(ps: u8) -> usize {
        (ps as usize).saturating_mul(3)
    }

    /// Parse from `data`. Data must start at the struct field.
    ///
    /// Returns `None` if the buffer is too small.
    pub fn parse(data: &[u8], ps: u8) -> Option<Self> {
        let p = ps as usize;
        if data.len() < Self::size(ps) {
            return None;
        }

        Some(Self {
            name: read_uintptr(data, 0, ps)?,
            typ: read_uintptr(data, p, ps)?,
            offset: read_uintptr(data, p.saturating_mul(2), ps)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_struct_type_extra_64bit() {
        // ps=8: size = 8 + 24 = 32 bytes
        let mut buf = vec![0u8; 32];
        buf[0..8].copy_from_slice(&0x1111u64.to_le_bytes());
        buf[8..16].copy_from_slice(&0x2222u64.to_le_bytes());
        buf[16..24].copy_from_slice(&5u64.to_le_bytes());
        buf[24..32].copy_from_slice(&5u64.to_le_bytes());

        let s = StructTypeExtra::parse(&buf, 8).unwrap();
        assert_eq!(s.pkg_path, 0x1111);
        assert_eq!(s.fields.ptr, 0x2222);
        assert_eq!(s.fields.len, 5);
        assert_eq!(s.fields.cap, 5);
    }

    #[test]
    fn parse_struct_type_extra_32bit() {
        // ps=4: size = 4 + 12 = 16 bytes
        let mut buf = vec![0u8; 16];
        buf[0..4].copy_from_slice(&0x3333u32.to_le_bytes());
        buf[4..8].copy_from_slice(&0x4444u32.to_le_bytes());
        buf[8..12].copy_from_slice(&3u32.to_le_bytes());
        buf[12..16].copy_from_slice(&3u32.to_le_bytes());

        let s = StructTypeExtra::parse(&buf, 4).unwrap();
        assert_eq!(s.pkg_path, 0x3333);
        assert_eq!(s.fields.ptr, 0x4444);
        assert_eq!(s.fields.len, 3);
    }

    #[test]
    fn parse_go_struct_field_64bit() {
        let mut buf = vec![0u8; 24];
        buf[0..8].copy_from_slice(&0xAAAAu64.to_le_bytes());
        buf[8..16].copy_from_slice(&0xBBBBu64.to_le_bytes());
        buf[16..24].copy_from_slice(&16u64.to_le_bytes());

        let f = GoStructField::parse(&buf, 8).unwrap();
        assert_eq!(f.name, 0xAAAA);
        assert_eq!(f.typ, 0xBBBB);
        assert_eq!(f.offset, 16);
    }

    #[test]
    fn parse_go_struct_field_32bit() {
        let mut buf = vec![0u8; 12];
        buf[0..4].copy_from_slice(&0xCCCCu32.to_le_bytes());
        buf[4..8].copy_from_slice(&0xDDDDu32.to_le_bytes());
        buf[8..12].copy_from_slice(&8u32.to_le_bytes());

        let f = GoStructField::parse(&buf, 4).unwrap();
        assert_eq!(f.name, 0xCCCC);
        assert_eq!(f.typ, 0xDDDD);
        assert_eq!(f.offset, 8);
    }

    #[test]
    fn struct_type_extra_too_short() {
        let buf = vec![0u8; 28];
        assert!(StructTypeExtra::parse(&buf, 8).is_none());
    }

    #[test]
    fn go_struct_field_too_short() {
        let buf = vec![0u8; 20];
        assert!(GoStructField::parse(&buf, 8).is_none());
    }

    #[test]
    fn size_calculations() {
        assert_eq!(StructTypeExtra::size(4), 16);
        assert_eq!(StructTypeExtra::size(8), 32);
        assert_eq!(GoStructField::size(4), 12);
        assert_eq!(GoStructField::size(8), 24);
    }
}
