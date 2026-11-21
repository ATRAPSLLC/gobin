//! The symbol table the Go linker writes into the container: ELF `.symtab`,
//! the Mach-O `LC_SYMTAB` and the PE COFF symbol table.
//!
//! Go names every function and global the program keeps, so an unstripped
//! binary names its variables (`os.Args`, `main.config`) with their addresses
//! and, on ELF, their sizes. `-ldflags=-s` drops the table; the function names
//! in the pclntab survive it, the variable names do not. A wasm module has no
//! such table.
//!
//! Since Go 1.20 the linker writes the data it generates (strings, type
//! descriptors, itabs, function metadata) as a few container symbols
//! (`go:string.*`, `type:*`, `go:func.*`) rather than one per item.

use goblin::{
    elf::{
        Elf,
        section_header::{SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS},
        sym::{STT_FILE, STT_SECTION},
    },
    mach::{
        MachO,
        symbols::{N_SECT, N_STAB, N_TYPE},
    },
    pe::{
        PE,
        options::ParseOptions,
        section_table::{
            IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_WRITE,
        },
    },
};

use crate::formats::BinaryFormat;

/// What a symbol's section holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// Code: a function, or a marker in the text (`runtime.text`).
    Text,
    /// Initialized writable data: a global with an initial value.
    Data,
    /// Zero-initialized writable data: a global without one.
    Bss,
    /// Read-only data: constants, and the linker's tables and descriptors.
    ReadOnly,
}

/// One defined symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol<'a> {
    /// The name, as the Go linker writes it (`main.main`, `os.Args`,
    /// `go:string.*`); Mach-O's leading `_` is removed.
    pub name: &'a str,
    /// Its virtual address.
    pub va: u64,
    /// Its size in bytes: recorded on ELF, otherwise the distance to the
    /// next symbol in its section or to the section's end
    /// ([`Self::size_recorded`]).
    pub size: u64,
    /// Whether the table recorded [`Self::size`] (ELF) or it was derived from
    /// the next symbol (Mach-O and PE record none).
    pub size_recorded: bool,
    /// What its section holds.
    pub kind: SymbolKind,
}

impl Symbol<'_> {
    /// Whether `va` lies in the symbol.
    pub fn contains(&self, va: u64) -> bool {
        va >= self.va && va.wrapping_sub(self.va) < self.size
    }
}

/// A binary's defined symbols, sorted by address.
#[derive(Debug, Clone, Default)]
pub struct Symbols<'a> {
    symbols: Vec<Symbol<'a>>,
}

impl<'a> Symbols<'a> {
    /// Read the symbol table of `data`, a `format` binary. Empty for a
    /// stripped binary, a wasm module, or a table goblin cannot parse.
    pub fn read(data: &'a [u8], format: BinaryFormat) -> Self {
        let mut symbols = match format {
            BinaryFormat::Elf => {
                Elf::parse(data).map_or_else(|_| Vec::new(), |elf| elf_symbols(&elf).collect())
            }
            BinaryFormat::MachO => MachO::parse(data, 0).map_or_else(
                |_| Vec::new(),
                |macho| with_derived_sizes(macho_placed(&macho).collect()),
            ),
            BinaryFormat::Pe => PE::parse_with_opts(data, &pe_options()).map_or_else(
                |_| Vec::new(),
                |pe| with_derived_sizes(pe_placed(&pe, data).collect()),
            ),
            BinaryFormat::Wasm | BinaryFormat::Unknown => Vec::new(),
        };
        symbols.sort_by(|a, b| a.va.cmp(&b.va).then_with(|| a.name.cmp(b.name)));
        Self { symbols }
    }

    /// The symbols, in address order.
    pub fn as_slice(&self) -> &[Symbol<'a>] {
        &self.symbols
    }

    /// Iterate the symbols in address order.
    pub fn iter(&self) -> std::slice::Iter<'_, Symbol<'a>> {
        self.symbols.iter()
    }

    /// The number of symbols.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Whether there are none: a stripped binary, or a wasm module.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// The symbol that holds address `va`, the one starting nearest below
    /// it when symbols nest. `None` when `va` falls between symbols.
    pub fn at(&self, va: u64) -> Option<&Symbol<'a>> {
        let end = self.symbols.partition_point(|s| s.va <= va);
        self.symbols
            .get(..end)?
            .iter()
            .rev()
            .find(|s| s.contains(va))
    }

    /// The first symbol named `name`.
    pub fn named(&self, name: &str) -> Option<&Symbol<'a>> {
        self.symbols.iter().find(|s| s.name == name)
    }
}

impl<'s, 'a> IntoIterator for &'s Symbols<'a> {
    type Item = &'s Symbol<'a>;
    type IntoIter = std::slice::Iter<'s, Symbol<'a>>;

    fn into_iter(self) -> Self::IntoIter {
        self.symbols.iter()
    }
}

/// A section a Mach-O or PE symbol may sit in: where it ends and what it
/// holds.
#[derive(Debug, Clone, Copy)]
struct Section {
    end: u64,
    kind: SymbolKind,
}

/// Whether a parsed ELF image defines any symbol [`Symbols::read`] would
/// yield. Stops at the first.
pub fn elf_defines_symbols(elf: &Elf<'_>) -> bool {
    elf_symbols(elf).next().is_some()
}

/// Whether a parsed Mach-O image defines any symbol [`Symbols::read`] would
/// yield; a stripped one keeps only its imports. Stops at the first.
pub fn macho_defines_symbols(macho: &MachO<'_>) -> bool {
    macho_placed(macho).next().is_some()
}

/// Whether a parsed PE image defines any symbol [`Symbols::read`] would
/// yield. Stops at the first.
pub fn pe_defines_symbols(pe: &PE<'_>, data: &[u8]) -> bool {
    pe_placed(pe, data).next().is_some()
}

/// The PE parse the symbols need: the section table and the COFF header,
/// none of the directories.
pub fn pe_options() -> ParseOptions {
    ParseOptions::default()
        .with_parse_resources(false)
        .with_parse_imports(false)
        .with_parse_tls_data(false)
}

fn elf_symbols<'e, 'a>(elf: &'e Elf<'a>) -> impl Iterator<Item = Symbol<'a>> + 'e {
    // Section indices from `SHN_LORESERVE` up name no section (absolute and
    // common symbols); 0 is an undefined one.
    const SHN_LORESERVE: usize = 0xff00;
    elf.syms.iter().filter_map(move |sym| {
        let index = sym.st_shndx;
        if index == 0 || index >= SHN_LORESERVE || matches!(sym.st_type(), STT_SECTION | STT_FILE) {
            return None;
        }
        let name = elf.strtab.get_at(sym.st_name).filter(|n| !n.is_empty())?;
        let section = elf.section_headers.get(index)?;
        let kind = if section.sh_flags & u64::from(SHF_EXECINSTR) != 0 {
            SymbolKind::Text
        } else if section.sh_type == SHT_NOBITS {
            SymbolKind::Bss
        } else if section.sh_flags & u64::from(SHF_WRITE) != 0 {
            SymbolKind::Data
        } else {
            SymbolKind::ReadOnly
        };
        Some(Symbol {
            name,
            va: sym.st_value,
            size: sym.st_size,
            size_recorded: true,
            kind,
        })
    })
}

fn macho_placed<'a>(macho: &MachO<'a>) -> impl Iterator<Item = (&'a str, u64, Section)> {
    // `n_sect` numbers the sections from 1 across all segments in load
    // order, so a segment whose sections do not parse ends the numbering.
    const SECTION_TYPE: u32 = 0xff;
    const ZEROFILL: [u32; 3] = [0x1, 0xc, 0x12]; // S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL
    const INSTRUCTIONS: u32 = 0x8000_0400; // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
    const VM_PROT_WRITE: u32 = 0x2;
    let mut sections = Vec::new();
    for segment in &macho.segments {
        let Ok(list) = segment.sections() else {
            break;
        };
        for (section, _) in list {
            let kind = if ZEROFILL.contains(&(section.flags & SECTION_TYPE)) {
                SymbolKind::Bss
            } else if section.flags & INSTRUCTIONS != 0 {
                SymbolKind::Text
            } else if segment.initprot & VM_PROT_WRITE != 0 {
                SymbolKind::Data
            } else {
                SymbolKind::ReadOnly
            };
            sections.push(Section {
                end: section.addr.saturating_add(section.size),
                kind,
            });
        }
    }
    macho
        .symbols()
        .map_while(Result::ok)
        .filter_map(move |(name, nlist)| {
            if nlist.n_type & N_STAB != 0 || nlist.n_type & N_TYPE != N_SECT {
                return None;
            }
            let name = name.strip_prefix('_').unwrap_or(name);
            let section = sections.get(nlist.n_sect.checked_sub(1)?)?;
            (!name.is_empty()).then_some((name, nlist.n_value, *section))
        })
}

fn pe_placed<'p, 'a>(
    pe: &'p PE<'a>,
    data: &'a [u8],
) -> impl Iterator<Item = (&'a str, u64, Section)> + 'p {
    let coff = pe.header.coff_header;
    let table = coff.symbols(data).ok().flatten();
    // The string table follows the 18-byte symbol records; names are read
    // from it as they are needed, not parsed all at once.
    let strings = (coff.number_of_symbol_table as usize)
        .checked_mul(18)
        .and_then(|records| records.checked_add(coff.pointer_to_symbol_table as usize))
        .and_then(|start| data.get(start..))
        .unwrap_or(&[]);
    table
        .map(|table| table.iter())
        .into_iter()
        .flatten()
        .filter_map(move |(_, inline, symbol)| {
            // A long name is an offset into the string table, which starts
            // with its own 4-byte length.
            let name = inline.or_else(|| {
                let n = symbol.name;
                let offset = u32::from_le_bytes([n[4], n[5], n[6], n[7]]) as usize;
                let rest = strings.get(offset..)?;
                let end = rest.iter().position(|&b| b == 0)?;
                std::str::from_utf8(rest.get(..end)?).ok()
            });
            let name = name.filter(|n| !n.is_empty() && !n.starts_with('.'))?;
            let section = usize::try_from(symbol.section_number)
                .ok()
                .and_then(|number| number.checked_sub(1))
                .and_then(|index| pe.sections.get(index))?;
            let start = pe
                .image_base
                .saturating_add(u64::from(section.virtual_address));
            let flags = section.characteristics;
            let writable = flags & IMAGE_SCN_MEM_WRITE != 0;
            // The Go linker folds the zero-initialized data into the end of
            // `.data`, past its raw bytes.
            let kind = if flags & IMAGE_SCN_CNT_CODE != 0 {
                SymbolKind::Text
            } else if flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
                || (writable && symbol.value >= section.size_of_raw_data)
            {
                SymbolKind::Bss
            } else if writable {
                SymbolKind::Data
            } else {
                SymbolKind::ReadOnly
            };
            let size = section.virtual_size.max(section.size_of_raw_data);
            let section = Section {
                end: start.saturating_add(u64::from(size)),
                kind,
            };
            Some((name, start.saturating_add(u64::from(symbol.value)), section))
        })
}

/// Symbols from a table that records no sizes: each runs to the next symbol
/// at a higher address in its section, or to the section's end.
fn with_derived_sizes<'a>(mut placed: Vec<(&'a str, u64, Section)>) -> Vec<Symbol<'a>> {
    placed.sort_by_key(|&(_, va, _)| va);
    let ends: Vec<u64> = placed
        .iter()
        .map(|&(_, va, section)| {
            let next = placed
                .iter()
                .skip(placed.partition_point(|&(_, v, _)| v <= va))
                .map(|&(_, v, _)| v)
                .next()
                .filter(|&next| next < section.end);
            next.unwrap_or(section.end)
        })
        .collect();
    placed
        .into_iter()
        .zip(ends)
        .map(|((name, va, section), end)| Symbol {
            name,
            va,
            size: end.saturating_sub(va),
            size_recorded: false,
            kind: section.kind,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(end: u64) -> Section {
        Section {
            end,
            kind: SymbolKind::Data,
        }
    }

    #[test]
    fn derived_sizes_run_to_the_next_symbol_or_the_section_end() {
        let s = with_derived_sizes(vec![
            ("b", 0x110, section(0x140)),
            ("a", 0x100, section(0x140)),
            ("alias", 0x100, section(0x140)),
            ("c", 0x200, section(0x208)),
        ]);
        let sizes: Vec<(&str, u64)> = s.iter().map(|s| (s.name, s.size)).collect();
        assert_eq!(sizes, [("a", 0x10), ("alias", 0x10), ("b", 0x30), ("c", 8)]);
        assert!(s.iter().all(|s| !s.size_recorded));
    }

    #[test]
    fn at_finds_the_holding_symbol() {
        let symbols = Symbols {
            symbols: vec![
                Symbol {
                    name: "a",
                    va: 0x100,
                    size: 0x10,
                    size_recorded: true,
                    kind: SymbolKind::Data,
                },
                Symbol {
                    name: "marker",
                    va: 0x110,
                    size: 0,
                    size_recorded: true,
                    kind: SymbolKind::Data,
                },
                Symbol {
                    name: "b",
                    va: 0x110,
                    size: 8,
                    size_recorded: true,
                    kind: SymbolKind::Data,
                },
            ],
        };
        assert_eq!(symbols.at(0x100).map(|s| s.name), Some("a"));
        assert_eq!(symbols.at(0x10f).map(|s| s.name), Some("a"));
        assert_eq!(symbols.at(0x110).map(|s| s.name), Some("b"));
        assert_eq!(symbols.at(0x118), None);
        assert_eq!(symbols.at(0xff), None);
    }
}
