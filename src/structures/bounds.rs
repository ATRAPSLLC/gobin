//! The words of a Go binary that state where its code begins and ends.
//!
//! The Go runtime keeps the bounds of its text in plain pointer-sized words:
//! the `moduledata` fields `minpc`, `maxpc`, `text` and `etext`, the base
//! address of each `textsectmap` entry, the `textStart` field of a Go 1.18-1.25
//! `pcHeader`, and the end sentinel of the function table of a Go 1.2-1.17
//! binary, whose entries hold absolute PCs. The linker writes each as an
//! address (a link-time value in a statically linked image, a relocated word
//! in a position-independent one), so a tool that collects every data word
//! holding a code address collects these too, although each one states a
//! boundary and points at no function: the words holding `etext` and `maxpc`
//! name the byte after the last Go function, which in an externally linked
//! image is alignment filler or the host linker's first C function.
//!
//! A [`BoundWord`] names one such word by its address, so a consumer judges the
//! word by what it is, not by what it points at. A function that starts at the
//! address a bound word holds is reached through other words, and any other
//! word holding that address is a legitimate code pointer.
//!
//! Not every word of the tables is a bound. The function table of a Go
//! 1.2-1.17 binary holds one absolute entry PC per function, and each of those
//! entries is a pointer to a function entry; only its final end sentinel is a
//! bound. From Go 1.18 on the table holds 32-bit offsets and has no pointer
//! words at all.

/// Name of the linker symbol at the first byte of Go code, the address
/// [`TextBound::Text`] and [`TextBound::HeaderTextStart`] state.
pub const TEXT_SYMBOL: &str = "runtime.text";

/// Name of the linker symbol one past the last byte of Go code, the address
/// [`TextBound::Etext`] states.
pub const ETEXT_SYMBOL: &str = "runtime.etext";

/// Which text bound a [`BoundWord`] states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TextBound {
    /// `moduledata.minpc`: the lowest function entry.
    MinPc,
    /// `moduledata.maxpc`: the end of the last function, which a Go 1.24+
    /// linker leaves short of `etext`.
    MaxPc,
    /// `moduledata.text`: `runtime.text`, the first byte of Go code.
    Text,
    /// `moduledata.etext`: `runtime.etext`, one past the last byte of Go code.
    Etext,
    /// `textsect.baseaddr` of one `moduledata.textsectmap` entry: the address
    /// its text section starts at. The entry's other two fields are offsets
    /// from `runtime.text`, not addresses, and are not bound words.
    SectionBase,
    /// `pcHeader.textStart` (Go 1.18-1.25): `runtime.text` again, recorded in
    /// the pclntab. Go 1.26 stopped writing it.
    HeaderTextStart,
    /// The final entry of a Go 1.2-1.17 function table: the absolute PC one
    /// past the last function.
    FunctabEnd,
}

/// One word of a Go binary that holds a text bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoundWord {
    /// The virtual address of the word itself (the site that holds the bound,
    /// not the bound it holds), in the binary's address space: for PE the
    /// image base is included, as for every address gobin returns.
    pub va: u64,
    /// Which bound the word states.
    pub bound: TextBound,
    /// The address the word holds.
    pub value: u64,
}
