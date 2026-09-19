//! Minimal WebAssembly container support for Go-emitted binaries.
//!
//! WebAssembly modules are a sequence of length-prefixed sections following an
//! 8-byte header (`\0asm` + version). This module exposes only what gobin
//! needs to reach the Go runtime structures inside a `GOOS=js GOARCH=wasm`
//! binary:
//!
//! - [`walk`] enumerates top-level sections, surfacing custom-section names
//!   (`go:buildid`, `producers`, `name` - per `src/cmd/link/internal/wasm/asm.go`)
//!   and Data-section payload bounds. The Go linker does *not* emit a
//!   dedicated `.gopclntab` custom section for wasm; pclntab + buildinfo
//!   live inside the Data-section linear-memory payload, alongside the rest
//!   of the runtime's static data.
//!
//! - [`data_segments`] decodes the Data section into individual
//!   `(linear_memory_offset, file_offset, size)` triples, since wasm allows
//!   each segment to target a different linear-memory address.
//!
//! - [`build_linear_memory_image`] assembles those segments into one
//!   contiguous buffer with zero-fill gaps. Several Go runtime structures
//!   (the pcHeader, moduledata, type descriptors, …) span multiple disjoint
//!   data segments in linear memory; rebuilding the image lets downstream
//!   parsers address them by their runtime VA the same way they do on
//!   ELF/Mach-O/PE.
//!
//! This module is intentionally narrow - it does not understand wasm
//! function types, imports, exports, instructions, or linking metadata.
//! Anything more is the caller's job.
//!
//! Reference: WebAssembly Core Specification §5.5
//! ([webassembly.org/specs/core/2.0/binary/modules.html#sections]).

/// One walked section, expressed as file-offset ranges so the caller can
/// slice into the original byte buffer.
#[derive(Debug, Clone, Copy)]
pub struct WasmSection<'a> {
    /// Section ID (`0` = custom, `1` = type, `2` = import, …, `11` = data).
    pub id: u8,
    /// Custom-section name when `id == 0`, else `None`.
    pub name: Option<&'a str>,
    /// File-offset range covering just the section's payload (excludes the
    /// id byte, the LEB128 length prefix, and - for custom sections - the
    /// name header).
    pub payload_offset: usize,
    /// Length of the payload range.
    pub payload_size: usize,
}

/// Walk the sections of a wasm module, yielding one [`WasmSection`] per section.
///
/// Returns an empty iterator if `data` does not begin with the wasm magic +
/// version, or once any malformed length prefix is encountered.
pub fn walk(data: &[u8]) -> WasmSectionIter<'_> {
    if !data.starts_with(b"\x00asm\x01\x00\x00\x00") {
        return WasmSectionIter {
            data,
            pos: data.len(),
        };
    }
    WasmSectionIter { data, pos: 8 }
}

/// Iterator returned by [`walk`].
pub struct WasmSectionIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for WasmSectionIter<'a> {
    type Item = WasmSection<'a>;

    fn next(&mut self) -> Option<WasmSection<'a>> {
        if self.pos >= self.data.len() {
            return None;
        }
        let id = *self.data.get(self.pos)?;
        let after_id = self.pos.checked_add(1)?;
        let (size, after_len) = read_uleb128(self.data, after_id)?;
        let size = usize::try_from(size).ok()?;
        let payload_end = after_len.checked_add(size)?;
        if payload_end > self.data.len() {
            // Malformed section - abort the walk.
            self.pos = self.data.len();
            return None;
        }

        let (payload_offset, payload_size, name) = if id == 0 {
            // Custom section: payload is `<name_len:uleb128> <name:bytes> <body>`.
            let (name_len, after_name_len) = read_uleb128(self.data, after_len)?;
            let name_len = usize::try_from(name_len).ok()?;
            let name_end = after_name_len.checked_add(name_len)?;
            if name_end > payload_end {
                self.pos = self.data.len();
                return None;
            }
            let name_bytes = self.data.get(after_name_len..name_end)?;
            let name = std::str::from_utf8(name_bytes).ok();
            let body_size = payload_end.checked_sub(name_end)?;
            (name_end, body_size, name)
        } else {
            (after_len, size, None)
        };

        self.pos = payload_end;
        Some(WasmSection {
            id,
            name,
            payload_offset,
            payload_size,
        })
    }
}

/// One reconstructed wasm data segment: where in the file its payload sits and
/// where in the linear-memory image it should be placed.
#[derive(Debug, Clone, Copy)]
pub struct WasmDataSegment {
    /// Linear-memory address (`i32.const N` from the segment's offset
    /// expression).
    pub mem_offset: u64,
    /// File offset of the segment's payload bytes.
    pub file_offset: usize,
    /// Length of the payload.
    pub size: usize,
}

/// Walk the wasm Data section and extract every `(mem_offset, file_offset,
/// size)` segment triple.
///
/// Only handles the common case Go's linker emits: `flags == 0` (active,
/// memory index 0) with an `i32.const` offset expression. Segments using
/// other modes (passive, memidx ≠ 0) are skipped silently. A malformed
/// length prefix terminates the walk early without panicking.
pub fn data_segments(data: &[u8]) -> Vec<WasmDataSegment> {
    let mut out = Vec::new();
    for sec in walk(data) {
        if sec.id != 11 {
            continue;
        }
        // Section payload: vec(data_segment).
        let section_end = match sec.payload_offset.checked_add(sec.payload_size) {
            Some(e) => e,
            None => return out,
        };
        let mut pos = sec.payload_offset;
        let count = match read_uleb128(data, pos) {
            Some((c, p)) => {
                pos = p;
                c
            }
            None => return out,
        };

        for _ in 0..count {
            if pos >= section_end {
                break;
            }
            let flags = match read_uleb128(data, pos) {
                Some((f, p)) => {
                    pos = p;
                    f
                }
                None => return out,
            };

            let mem_offset = if flags == 0 {
                // Offset expression: typically `i32.const N; end`.
                match data.get(pos) {
                    Some(0x41) => {
                        pos = match pos.checked_add(1) {
                            Some(p) => p,
                            None => return out,
                        };
                        let (val, np) = match read_uleb128_signed(data, pos) {
                            Some(v) => v,
                            None => return out,
                        };
                        pos = np;
                        if data.get(pos) != Some(&0x0b) {
                            return out;
                        }
                        pos = match pos.checked_add(1) {
                            Some(p) => p,
                            None => return out,
                        };
                        u64::from(val as u32)
                    }
                    _ => {
                        // Unsupported offset expression - bail rather than
                        // silently miscompute.
                        return out;
                    }
                }
            } else {
                // Skip non-active segments (passive / memidx); the Go linker
                // doesn't emit these for runtime data.
                let (_, np) = match read_uleb128(data, pos) {
                    Some(v) => v,
                    None => return out,
                };
                pos = np;
                continue;
            };

            let payload_size = match read_uleb128(data, pos) {
                Some((s, p)) => {
                    pos = p;
                    s as usize
                }
                None => return out,
            };
            let payload_end = match pos.checked_add(payload_size) {
                Some(e) => e,
                None => return out,
            };
            if payload_end > section_end {
                return out;
            }
            out.push(WasmDataSegment {
                mem_offset,
                file_offset: pos,
                size: payload_size,
            });
            pos = payload_end;
        }
    }
    out
}

/// Build a linear-memory image from wasm data segments, copying each
/// segment's bytes to its target offset and zero-filling gaps.
///
/// Returns `None` if the resulting image would exceed `max_size_bytes` -
/// adversarial input could request gigabytes of zero-fill, so callers gate
/// this behind a sanity cap. The returned vector's length is exactly the
/// largest `mem_offset + size` across all segments.
pub fn build_linear_memory_image(data: &[u8], max_size_bytes: usize) -> Option<Vec<u8>> {
    let segs = data_segments(data);
    if segs.is_empty() {
        return None;
    }
    let mut max_end: u64 = 0;
    for s in &segs {
        let end = s.mem_offset.checked_add(s.size as u64)?;
        if end > max_end {
            max_end = end;
        }
    }
    let total = usize::try_from(max_end).ok()?;
    if total > max_size_bytes {
        return None;
    }
    let mut image = vec![0u8; total];
    for s in &segs {
        let dst_start = usize::try_from(s.mem_offset).ok()?;
        let dst_end = dst_start.checked_add(s.size)?;
        let src = data.get(s.file_offset..s.file_offset.checked_add(s.size)?)?;
        let dst = image.get_mut(dst_start..dst_end)?;
        dst.copy_from_slice(src);
    }
    Some(image)
}

/// Read an unsigned LEB128 at `offset`. Returns `(value, position_after)`.
///
/// Bounded to 5 bytes so adversarial input cannot make the loop run
/// indefinitely - five 7-bit chunks cover any `u32`, which is enough for
/// every wasm-format unsigned LEB128.
fn read_uleb128(data: &[u8], offset: usize) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut pos = offset;
    for _ in 0..5 {
        let byte = *data.get(pos)?;
        pos = pos.checked_add(1)?;
        let chunk = u32::from(byte & 0x7f);
        let shifted = chunk.checked_shl(shift)?;
        result = result.checked_add(shifted)?;
        if byte & 0x80 == 0 {
            return Some((result, pos));
        }
        shift = shift.checked_add(7)?;
    }
    None
}

/// Read a *signed* LEB128 integer at `offset`. Returns `(value, position_after)`.
///
/// Wasm `i32.const` data-segment offsets are encoded as signed LEBs even
/// though the value is non-negative in practice. The full 5-byte encoding
/// covers any `i32` the linker might emit.
fn read_uleb128_signed(data: &[u8], offset: usize) -> Option<(i32, usize)> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut pos = offset;
    let mut byte: u8;
    loop {
        byte = *data.get(pos)?;
        pos = pos.checked_add(1)?;
        let chunk = i64::from(byte & 0x7f);
        let shifted = chunk.checked_shl(shift)?;
        result = result.checked_add(shifted)?;
        shift = shift.checked_add(7)?;
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 35 {
            return None;
        }
    }
    // Sign-extend if the high bit of the final group is set and shift < 32.
    if shift < 32 && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    let v = i32::try_from(result).ok()?;
    Some((v, pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_minimal_module() {
        // Minimal wasm: header + one custom section "go:buildid" with body
        // [0xff, 0x42].
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
        // Custom section id (0), size (LEB128) = 1 + 10 + 2 = 13
        bytes.push(0);
        bytes.push(13);
        bytes.push(10); // name length
        bytes.extend_from_slice(b"go:buildid");
        bytes.extend_from_slice(&[0xff, 0x42]);
        let s = walk(&bytes).next().unwrap();
        assert_eq!(s.id, 0);
        assert_eq!(s.name, Some("go:buildid"));
        assert_eq!(
            &bytes[s.payload_offset..s.payload_offset + s.payload_size],
            &[0xff, 0x42]
        );
    }

    #[test]
    fn rejects_non_wasm() {
        assert!(walk(b"\x7fELF\x02\x01\x01\x00").next().is_none());
    }

    #[test]
    fn truncated_length_aborts() {
        // Header + section id but no length byte
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
        bytes.push(0);
        assert!(walk(&bytes).next().is_none());
    }

    #[test]
    fn malformed_length_aborts() {
        // Section claims length 1000 but only 1 byte follows.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
        bytes.push(0); // custom
        // LEB128 for 1000: 0xe8, 0x07
        bytes.extend_from_slice(&[0xe8, 0x07, 0x00]);
        assert!(walk(&bytes).next().is_none());
    }
}
