//! Go function type extra fields (`abi.FuncType`).
//!
//! The `FuncType` follows the embedded `abi.Type` in the binary layout
//! for types of kind `Func`. It encodes the input and output parameter
//! counts plus a variadic flag.
//!
//! Binary layout: 4 bytes (all architectures).
//!
//! Fields:
//! - `InCount`  (u16) -- number of input parameters
//! - `OutCount` (u16) -- output count in low 13 bits; bit 15 = variadic flag
//!
//! Source: `src/internal/abi/type.go:358-368`

use crate::util::read_u16;

/// Parsed extra fields for a function type descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct FuncTypeExtra {
    /// Number of input (parameter) types.
    pub in_count: u16,
    /// Raw output count field. Low 13 bits are the output count;
    /// bit 15 indicates variadic.
    pub out_count: u16,
}

impl FuncTypeExtra {
    /// Binary size: always 4 bytes.
    pub const SIZE: usize = 4;

    /// Parse from `data`. Data must start at the func type extra fields.
    ///
    /// Returns `None` if the buffer is too small.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }

        Some(Self {
            in_count: read_u16(data, 0)?,
            out_count: read_u16(data, 2)?,
        })
    }

    /// Number of output (return) types, masked to the low 13 bits.
    pub fn num_out(&self) -> u16 {
        self.out_count & 0x1fff
    }

    /// Whether this function is variadic (bit 15 of `out_count`).
    pub fn is_variadic(&self) -> bool {
        self.out_count & 0x8000 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let mut buf = vec![0u8; 4];
        buf[0..2].copy_from_slice(&3u16.to_le_bytes());
        buf[2..4].copy_from_slice(&2u16.to_le_bytes());

        let f = FuncTypeExtra::parse(&buf).unwrap();
        assert_eq!(f.in_count, 3);
        assert_eq!(f.out_count, 2);
        assert_eq!(f.num_out(), 2);
        assert!(!f.is_variadic());
    }

    #[test]
    fn variadic_flag() {
        let mut buf = vec![0u8; 4];
        buf[0..2].copy_from_slice(&1u16.to_le_bytes());
        // out_count = 0x8001 => variadic with 1 output
        buf[2..4].copy_from_slice(&0x8001u16.to_le_bytes());

        let f = FuncTypeExtra::parse(&buf).unwrap();
        assert!(f.is_variadic());
        assert_eq!(f.num_out(), 1);
    }

    #[test]
    fn output_count_masking() {
        let mut buf = vec![0u8; 4];
        buf[0..2].copy_from_slice(&0u16.to_le_bytes());
        // out_count = 0x9ABC => variadic, num_out = 0x1ABC = 7100
        buf[2..4].copy_from_slice(&0x9ABCu16.to_le_bytes());

        let f = FuncTypeExtra::parse(&buf).unwrap();
        assert!(f.is_variadic());
        assert_eq!(f.num_out(), 0x1ABC);
    }

    #[test]
    fn too_short_returns_none() {
        let buf = vec![0u8; 3];
        assert!(FuncTypeExtra::parse(&buf).is_none());
    }
}
