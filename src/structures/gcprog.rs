//! GC pointer-map (GC program) decoder.
//!
//! `moduledata.gcdata` / `moduledata.gcbss` point at **GC programs** - a
//! Lempel-Ziv-style bytecode the runtime expands (`runGCProg`) into a 1-bit
//! per pointer-sized word bitmap over the `[data, edata)` / `[bss, ebss)`
//! segments. Bit `i` set means the word at `segment_start + i*ptrSize` holds a
//! pointer.
//!
//! Decoding this gives a precise map of **where pointers live in global
//! memory** - function pointers, interface/`itab` pointers, string/slice
//! headers, global `*T` variables - without any disassembly.
//!
//! ## Bytecode
//!
//! ```text
//! 00000000:        stop
//! 0nnnnnnn:        emit n bits copied from the next (n+7)/8 bytes (LSB-first)
//! 10000000 n c:    repeat the previous n bits c times (n, c are uvarints)
//! 1nnnnnnn c:      repeat the previous n bits c times (c is a uvarint)
//! ```
//!
//! Source: `src/runtime/mbitmap.go` (`runGCProg`, "Packed GC pointer bitmaps").

use crate::structures::util::read_uvarint;

/// Safety bound on the number of decoded words, on top of the caller's
/// `max_words`, so a malformed `repeat` count cannot allocate unboundedly.
const HARD_WORD_CAP: usize = 64 * 1024 * 1024;

/// Decode a GC program into a per-word pointer bitmap.
///
/// `max_words` is the number of pointer-sized words the segment spans
/// (`(edata - data) / ptrSize`). The returned vector has length `<= max_words`;
/// element `i` is `true` when word `i` of the segment holds a pointer. Never
/// panics on malformed input - it stops early and returns what it decoded.
pub fn run_gc_prog(prog: &[u8], max_words: usize) -> Vec<bool> {
    let cap = max_words.min(HARD_WORD_CAP);
    let mut out: Vec<bool> = Vec::new();
    let mut p = 0usize;

    loop {
        if out.len() >= cap {
            break;
        }
        let inst = match prog.get(p) {
            Some(&b) => b,
            None => break,
        };
        p = match p.checked_add(1) {
            Some(v) => v,
            None => break,
        };

        if inst & 0x80 == 0 {
            // Literal: emit n bits from the following (n+7)/8 bytes.
            let n = (inst & 0x7f) as usize;
            if n == 0 {
                break; // stop
            }
            for i in 0..n {
                let Some(byte_idx) = p.checked_add(i.checked_div(8).unwrap_or(0)) else {
                    break;
                };
                let bit = i.checked_rem(8).unwrap_or(0);
                match prog.get(byte_idx) {
                    Some(&byte) => out.push((byte >> bit) & 1 == 1),
                    None => break,
                }
                if out.len() >= cap {
                    break;
                }
            }
            let nbytes = n.saturating_add(7).checked_div(8).unwrap_or(0);
            p = match p.checked_add(nbytes) {
                Some(v) => v,
                None => break,
            };
        } else {
            // Repeat the previous n bits c times.
            let mut n = (inst & 0x7f) as usize;
            if n == 0 {
                match read_uvarint(prog.get(p..).unwrap_or(&[])) {
                    Some((v, used)) => {
                        n = v as usize;
                        p = p.saturating_add(used);
                    }
                    None => break,
                }
            }
            let c = match read_uvarint(prog.get(p..).unwrap_or(&[])) {
                Some((v, used)) => {
                    p = p.saturating_add(used);
                    v as usize
                }
                None => break,
            };
            if n == 0 || n > out.len() {
                break;
            }
            let start = out.len().saturating_sub(n);
            let pattern: Vec<bool> = out.get(start..).map(<[bool]>::to_vec).unwrap_or_default();
            for _ in 0..c {
                if out.len() >= cap {
                    break;
                }
                out.extend_from_slice(&pattern);
            }
        }
    }

    out.truncate(max_words);
    out
}

/// A decoded pointer map over a contiguous moduledata memory segment
/// (`data` or `bss`): which pointer-sized words hold pointers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerMap {
    /// Virtual address of the first word the map covers (`data` or `bss`).
    pub base_va: u64,
    /// Pointer size in bytes (the word stride).
    pub ptr_size: u8,
    /// One flag per word: `words[i]` is `true` when the word at
    /// `base_va + i*ptr_size` holds a pointer.
    pub words: Vec<bool>,
}

impl PointerMap {
    /// Number of words that hold pointers.
    pub fn pointer_count(&self) -> usize {
        self.words.iter().filter(|&&b| b).count()
    }

    /// Virtual addresses of every word that holds a pointer.
    pub fn pointer_vas(&self) -> impl Iterator<Item = u64> + '_ {
        let stride = self.ptr_size as u64;
        let base = self.base_va;
        self.words
            .iter()
            .enumerate()
            .filter_map(move |(i, &is_ptr)| {
                if is_ptr {
                    base.checked_add((i as u64).checked_mul(stride)?)
                } else {
                    None
                }
            })
    }

    /// Whether the word at a (word-aligned) virtual address holds a pointer.
    /// Returns `None` if `va` is outside the mapped range or misaligned.
    pub fn is_pointer(&self, va: u64) -> Option<bool> {
        let stride = self.ptr_size as u64;
        if stride == 0 {
            return None;
        }
        let off = va.checked_sub(self.base_va)?;
        if off.checked_rem(stride)? != 0 {
            return None;
        }
        let idx = usize::try_from(off.checked_div(stride)?).ok()?;
        self.words.get(idx).copied()
    }
}
