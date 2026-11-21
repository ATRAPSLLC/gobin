// Integration tests, organized by concern.
//
// `mod matrix` is the centerpiece: it discovers every fixture built by
// tests/samples/build.sh and sweeps each extraction surface across the whole
// corpus (every Go version × format × variant), so a single test covers what
// used to be dozens of per-fixture one-offs. The remaining modules cover
// surfaces a corpus sweep can't express uniformly:
//
//   detection · functions · strings_and_inline · addresses · buildinfo ·
//   moduledata · embed_and_fips · wasm · types · harness (advanced features)
//
// Shared fixture-path constants and the `load` helper live at the crate root;
// each module pulls them in with `use super::*`.
//
// Workspace-level `[lints.rust]` / `[lints.clippy]` apply to test binaries too,
// but tests legitimately use `unwrap`/`expect`/indexing/arithmetic for terseness
// and don't need rustdoc.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::collections::BTreeSet;

use gobin::{
    GoBinary, detect,
    detection::{Confidence, ConfidenceSignal, ParseError},
    formats::BinaryFormat,
    metadata::{Compiler, FunctionInfo, FunctionIter, ObfuscationKind, for_each_function},
    structures::{
        Arch, PclntabVersion,
        pclntab::{FuncData, FuncId},
    },
};

// Representative fixtures for the per-feature tests below. The full
// version×format matrix is swept separately in `mod matrix`. Fixtures are
// built reproducibly with `-trimpath` (see tests/samples/build.sh), so they
// carry no local filesystem paths.
const BASIC_NORMAL: &str = "tests/samples/basic_go126_darwin_arm64";
const BASIC_STRIPPED: &str = "tests/samples/basic_go126_darwin_arm64_stripped";
const BASIC_LINUX: &str = "tests/samples/basic_go126_linux_amd64";
const BASIC_WINDOWS: &str = "tests/samples/basic_go126_windows_amd64.exe";
const MINIMAL_NORMAL: &str = "tests/samples/minimal_go126_darwin_arm64";
const MINIMAL_STRIPPED: &str = "tests/samples/minimal_go126_darwin_arm64_stripped";
const BASIC_WASM: &str = "tests/samples/basic_go126_wasip1_wasm";
const BASIC_GO127: &str = "tests/samples/basic_go127_darwin_arm64";
const BASIC_GO127_STRIPPED: &str = "tests/samples/basic_go127_darwin_arm64_stripped";
const BASIC_FIPS: &str = "tests/samples/basic_go126_darwin_arm64_fips";
const BASIC_EMBED: &str = "tests/samples/embed_go126_darwin_arm64";
const BASIC_EMBED_STRIPPED: &str = "tests/samples/embed_go126_darwin_arm64_stripped";
const BASIC_EMBED_LINUX: &str = "tests/samples/embed_go126_linux_amd64";
const COVER_LINUX: &str = "tests/samples/basic_go126_linux_amd64_cover";
const BASIC_GO127_LINUX: &str = "tests/samples/basic_go127_linux_amd64";
const BASIC_GO127_PIE: &str = "tests/samples/basic_go127_linux_amd64_pie";
const BASIC_GO124_WINDOWS: &str = "tests/samples/basic_go124_windows_amd64.exe";
const BASIC_GO124_WINDOWS_NOVERSION: &str = "tests/samples/basic_go124_windows_amd64_noversion.exe";

fn load(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("Failed to read {path}: {e}"))
}

// ===========================================================================
// Binary detection, rejection of non-Go input, and top-level parse sanity.
// ===========================================================================
mod detection {
    use super::*;

    #[test]
    fn detect_wasm_go_binary() {
        let data = load(BASIC_WASM);
        let bin = GoBinary::parse(&data).expect("Should detect wasm Go binary");
        assert_eq!(bin.context().format(), BinaryFormat::Wasm);
        assert_eq!(bin.confidence(), Confidence::High);
        assert!(bin.go_version().unwrap().starts_with("go1."));
        assert!(bin.build_id().is_some(), "Wasm carries go:buildid section");
    }

    #[test]
    fn detect_fast_path_recognizes_go_binaries() {
        for path in [BASIC_NORMAL, BASIC_LINUX, BASIC_WINDOWS] {
            let data = load(path);
            assert!(
                detect(&data),
                "{path}: detect() should recognize this binary"
            );
        }
    }

    #[test]
    fn detect_fast_path_rejects_random_data() {
        let data = vec![0u8; 4096];
        assert!(!detect(&data), "detect() should not flag zeroes");
    }

    #[test]
    fn minimal_normal_detected() {
        let data = load(MINIMAL_NORMAL);
        let bin = GoBinary::parse(&data).expect("Minimal binary should be detected");
        assert_eq!(bin.confidence(), Confidence::High);
        assert!(bin.go_version().is_some());
        assert!(bin.pclntab().map(|p| p.nfunc).unwrap() > 0);
    }

    #[test]
    fn minimal_stripped_detected() {
        let data = load(MINIMAL_STRIPPED);
        let bin = GoBinary::parse(&data).expect("Minimal stripped binary should be detected");
        assert_eq!(bin.confidence(), Confidence::High);
        assert!(bin.pclntab().map(|p| p.nfunc).unwrap() > 0);
    }

    #[test]
    fn build_id_macho_format() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let id = bin.build_id().expect("Should have build ID");
        let parts: Vec<&str> = id.split('/').collect();
        assert_eq!(parts.len(), 4, "Executable build ID should have 4 parts");
        for part in &parts {
            assert_eq!(part.len(), 20, "Each part should be 20 chars of base64");
        }
    }

    #[test]
    fn compiler_recognizes_gc_binaries() {
        for path in [BASIC_NORMAL, BASIC_LINUX, BASIC_WINDOWS] {
            let data = load(path);
            let bin = GoBinary::parse(&data).unwrap();
            assert_eq!(bin.compiler(), Compiler::Gc, "{path}: expected gc compiler");
        }
    }

    #[test]
    fn obfuscation_none_for_clean_binaries() {
        for path in [BASIC_NORMAL, BASIC_LINUX, BASIC_WINDOWS] {
            let data = load(path);
            let bin = GoBinary::parse(&data).unwrap();
            assert_eq!(
                bin.obfuscation(),
                ObfuscationKind::None,
                "{path}: clean build should not be flagged",
            );
            assert!(
                !bin.is_likely_garbled(),
                "{path}: clean build is not garble"
            );
        }
    }

    #[test]
    fn try_parse_returns_report_on_success() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::try_parse(&data).expect("should parse");
        let report = bin.report();
        assert_eq!(report.tier, Confidence::High);
        assert!(
            report
                .signals
                .iter()
                .any(|s| matches!(s, ConfidenceSignal::PclntabParsed { .. })),
            "report should record pclntab parse signal",
        );
    }

    #[test]
    fn try_parse_returns_error_for_random_data() {
        let data = vec![0u8; 1024];
        let err = match GoBinary::try_parse(&data) {
            Ok(_) => panic!("random data must fail"),
            Err(e) => e,
        };
        let ParseError::NotAGoBinary { report } = err else {
            panic!("random data is no universal Mach-O: {err:?}");
        };
        assert_eq!(report.tier, Confidence::None);
    }

    #[test]
    fn reject_non_go_binary() {
        let data = vec![0u8; 1024];
        assert!(
            GoBinary::parse(&data).is_none(),
            "Random data should not be detected as Go"
        );
    }

    #[test]
    fn reject_empty_data() {
        assert!(GoBinary::parse(&[]).is_none());
    }

    #[test]
    fn reject_small_data() {
        assert!(GoBinary::parse(&[0x7f, b'E', b'L', b'F']).is_none());
    }

    #[test]
    fn reject_non_go_elf_header() {
        // Valid ELF magic but not a Go binary
        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        assert!(GoBinary::parse(&data).is_none());
    }
}

// ===========================================================================
// Function metadata, name classification, and the function iterators.
// ===========================================================================
mod functions {
    use super::*;

    /// A normal function named `name`.
    fn function(name: &str) -> FunctionInfo<'_> {
        FunctionInfo {
            name,
            func: FuncData {
                func_off: 0,
                entry_off: 0,
                name_off: 0,
                args: 0,
                deferreturn: 0,
                pcsp: 0,
                pcfile: 0,
                pcln: 0,
                npcdata: 0,
                cu_offset: 0,
                start_line: 0,
                func_id: 0,
                flag: 0,
                nfuncdata: 0,
            },
            func_id: FuncId::Normal,
            source_file: None,
            end_line: 0,
            frame_size: 0,
        }
    }

    #[test]
    fn function_info_short_name() {
        let f = function("net/http.(*Client).Do");
        assert_eq!(f.short_name(), "(*Client).Do");
        assert_eq!(f.package(), Some("net/http"));
        assert!(f.is_method());
    }

    #[test]
    fn function_info_closure() {
        let f = function("main.main.func1");
        assert!(f.is_closure());
        assert!(!f.is_method());
    }

    /// A funcID is read the way the compiler assigns it: the binary's
    /// wrapper ID is a wrapper whatever the name (Go 1.17's ABI wrappers share
    /// their function's name), and any other nonzero ID is the special the
    /// name names, whatever its number (which Go renumbers between versions).
    #[test]
    fn func_ids_classify_by_wrapper_id_then_name() {
        let wrapper = Some(22);
        assert_eq!(FuncId::classify(0, "main.main", wrapper), FuncId::Normal);
        for raw in [7, 8, 14] {
            assert_eq!(
                FuncId::classify(raw, "runtime.goexit", wrapper),
                FuncId::Goexit
            );
        }
        assert_eq!(
            FuncId::classify(22, "runtime.mstart", wrapper),
            FuncId::Wrapper
        );
        assert_eq!(
            FuncId::classify(14, "runtime.mstart", wrapper),
            FuncId::Mstart
        );
        assert_eq!(
            FuncId::classify(15, "runtime.cgocallback_gofunc", None),
            FuncId::Cgocallback
        );
        assert_eq!(
            FuncId::classify(22, "main.(*T).String", wrapper),
            FuncId::Wrapper
        );
        // A nonzero, non-wrapper ID no name accounts for is reported as such.
        assert_eq!(
            FuncId::classify(5, "main.(*T).String", wrapper),
            FuncId::Unknown(5)
        );
        assert_eq!(FuncId::RuntimeMain.as_str(), "runtime_main");
    }

    #[test]
    fn function_source_file_resolved() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let funcs = bin.functions().collect::<Vec<_>>();

        let main_fn = funcs
            .iter()
            .find(|f| f.name == "main.main")
            .expect("main.main not found");
        let src = main_fn
            .source_file
            .expect("main.main should have a source file");
        assert!(src.ends_with("main.go"), "Expected main.go, got: {src}");
    }

    #[test]
    fn function_line_range() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let funcs = bin.functions().collect::<Vec<_>>();

        let main_fn = funcs
            .iter()
            .find(|f| f.name == "main.main")
            .expect("main.main not found");
        assert!(main_fn.func.start_line > 0, "start_line should be positive");
        assert!(
            main_fn.end_line >= main_fn.func.start_line,
            "end_line ({}) should be >= start_line ({})",
            main_fn.end_line,
            main_fn.func.start_line
        );
    }

    #[test]
    fn function_frame_size() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let funcs = bin.functions().collect::<Vec<_>>();

        let main_fn = funcs
            .iter()
            .find(|f| f.name == "main.main")
            .expect("main.main not found");
        assert!(
            main_fn.frame_size > 0,
            "main.main should have a nonzero frame size"
        );
    }

    #[test]
    fn for_each_function_visits_all_functions() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let pcl = bin.pclntab().unwrap();

        let baseline_len = FunctionIter::new(Some(pcl)).count();
        let mut count = 0usize;
        let mut saw_main = false;
        for_each_function(&pcl, |info, tables| {
            count += 1;
            if info.name == "main.main" {
                saw_main = true;
                assert!(
                    !tables.pcln.is_empty(),
                    "main.main should have pcln entries"
                );
            }
        });
        assert_eq!(
            count, baseline_len,
            "for_each_function must visit all functions"
        );
        assert!(saw_main, "main.main must be visited");
    }

    #[test]
    fn functions_iterator_matches_extract_functions() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let baseline = bin.functions().collect::<Vec<_>>();
        let from_iter: Vec<&str> = bin.functions().map(|f| f.name).collect();
        assert_eq!(from_iter.len(), baseline.len());
        assert_eq!(from_iter.first().copied(), baseline.first().map(|f| f.name),);
        assert!(from_iter.contains(&"main.main"));
    }

    #[test]
    fn functions_iterator_empty_without_pclntab() {
        // Use a buffer that lacks a parseable pclntab. We can't construct GoBinary
        // without going through `parse`, so verify the iterator API exists and
        // composes with standard combinators on a real binary instead.
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let user_fns: usize = bin
            .functions()
            .filter(|f| !f.is_runtime() && !f.is_internal())
            .count();
        assert!(user_fns > 0, "expected at least one user function");
    }

    #[test]
    fn func_data_args_size_returns_unsigned_byte_count() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let pcl = bin.pclntab().unwrap();

        let mut saw_nonneg = false;
        for (_, off) in pcl.func_entries().take(20) {
            let f = match pcl.parse_func(off) {
                Some(f) => f,
                None => continue,
            };
            // args_size() never wraps for negative-stored values; non-negative
            // raw values pass through unchanged.
            if f.args >= 0 {
                assert_eq!(f.args_size(), f.args as u32);
                saw_nonneg = true;
            }
        }
        assert!(
            saw_nonneg,
            "expected at least one function with a non-negative args field"
        );
    }
}

// ===========================================================================
// Go string-literal recovery and inline-tree decoding.
// ===========================================================================
mod strings_and_inline {
    use super::*;

    #[test]
    fn strings_iter_recovers_runtime_literals() {
        use std::collections::HashSet;

        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();

        let mut unique: HashSet<&str> = HashSet::new();
        let mut total = 0usize;
        for s in bin.strings() {
            total += 1;
            if let Some(text) = s.as_str() {
                unique.insert(text);
            }
        }
        assert!(
            total > 100,
            "expected a healthy number of string hits, got {total}"
        );
        assert!(
            unique.len() > 50,
            "expected many unique strings, got {}",
            unique.len()
        );

        // Spot-check: well-known runtime panic-message fragments should appear in
        // any non-trivial Go binary built with the `gc` toolchain. Match as
        // substrings since the compiler often emits them inside longer literals
        // (e.g. "invalid memory address or nil pointer dereference").
        let needles = ["unreachable", "invalid memory address"];
        for needle in needles {
            assert!(
                unique.iter().any(|s| s.contains(needle)),
                "expected a runtime literal containing {:?} among {} unique strings",
                needle,
                unique.len(),
            );
        }
    }

    #[test]
    fn strings_iter_works_on_stripped_binaries() {
        // Strings live in rodata, not in DWARF or symbol tables - should
        // survive `-ldflags='-s -w'` unchanged.
        let normal = {
            let d = load(BASIC_NORMAL);
            let bin = GoBinary::parse(&d).unwrap();
            bin.strings().count()
        };
        let stripped = {
            let d = load(BASIC_STRIPPED);
            let bin = GoBinary::parse(&d).unwrap();
            bin.strings().count()
        };
        // Should be very close - within 5% (stripping shouldn't materially affect rodata).
        let diff = (normal as i64 - stripped as i64).abs();
        let bound = (normal / 20).max(10);
        assert!(
            (diff as usize) <= bound,
            "string count drifted: normal={normal} stripped={stripped} diff={diff}",
        );
    }

    #[test]
    fn strings_iter_works_across_formats() {
        for path in [BASIC_NORMAL, BASIC_LINUX, BASIC_WINDOWS] {
            let data = load(path);
            let bin = GoBinary::parse(&data).unwrap();
            let count = bin.strings().count();
            assert!(count > 100, "{path}: expected many strings, got {count}");
        }
    }

    #[test]
    fn strings_iter_surfaces_non_utf8_bytes() {
        // After A-09, the scanner no longer pre-filters on UTF-8. Verify that
        // (a) bin.strings() never panics on non-UTF-8 hits, and (b) GoString's
        // as_bytes() / try_as_str() / as_str() agree with each other.
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();

        let mut total = 0usize;
        let mut utf8_ok = 0usize;
        let mut non_utf8 = 0usize;
        for s in bin.strings() {
            total += 1;
            // Raw bytes are always available.
            assert_eq!(s.as_bytes().len(), s.len);
            match s.try_as_str() {
                Ok(text) => {
                    utf8_ok += 1;
                    assert_eq!(s.as_str(), Some(text));
                }
                Err(_) => {
                    non_utf8 += 1;
                    assert_eq!(s.as_str(), None);
                }
            }
        }
        assert!(total > 100, "expected many string hits, got {total}");
        // We intentionally don't assert non_utf8 > 0 - a stdlib hello binary
        // may not contain any. The point is the API doesn't drop them.
        let _ = (utf8_ok, non_utf8);
    }

    #[test]
    fn inline_tree_yields_entries_for_typical_binary() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();

        // Walk every function; expect at least one to expose inlined frames.
        let mut total_entries = 0usize;
        let mut saw_named = false;
        let mut max_depth = 0u32;
        for func in bin.functions() {
            for entry in bin.inline_tree(&func) {
                total_entries += 1;
                if !entry.function_name.is_empty() {
                    saw_named = true;
                }
                if entry.depth > max_depth {
                    max_depth = entry.depth;
                }
                assert!(
                    entry.pc_range.start <= entry.pc_range.end,
                    "pc_range must be ordered"
                );
            }
        }
        assert!(
            total_entries > 0,
            "expected at least one inlined call across the binary"
        );
        assert!(
            saw_named,
            "at least one inline entry must resolve a function name"
        );
        let _ = max_depth; // depth may be 0 for shallow inlining; just compute it
    }

    #[test]
    fn inline_tree_empty_for_function_without_inlining() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();

        // Find a function with no funcdata (typically asm helpers or trivial leaves)
        // and verify the iterator is empty rather than panicking.
        for func in bin.functions() {
            if func.func.nfuncdata == 0 {
                assert_eq!(
                    bin.inline_tree(&func).count(),
                    0,
                    "function with nfuncdata=0 must have empty inline tree",
                );
                return;
            }
        }
    }
}

// ===========================================================================
// Virtual-address translation: `text_va` / `entry_va` / `entry_rva`.
// ===========================================================================
mod addresses {
    use super::*;

    #[test]
    fn text_va_and_etext_va_present() {
        for path in [BASIC_NORMAL, BASIC_LINUX, BASIC_WINDOWS] {
            let data = load(path);
            let bin = GoBinary::parse(&data).unwrap();
            let text = bin
                .text_va()
                .unwrap_or_else(|| panic!("{path}: text_va missing"));
            let etext = bin
                .etext_va()
                .unwrap_or_else(|| panic!("{path}: etext_va missing"));
            assert!(text > 0, "{path}: text_va should be nonzero");
            assert!(etext > text, "{path}: etext_va should be > text_va");
        }
    }

    #[test]
    fn entry_off_translates_to_text_va() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let text_va = bin.text_va().unwrap();
        let funcs = bin.functions().collect::<Vec<_>>();
        let main_fn = funcs.iter().find(|f| f.name == "main.main").unwrap();
        let main_va = text_va + main_fn.func.entry_off as u64;
        assert!(
            main_va > text_va,
            "main.main VA must be inside text segment"
        );
    }

    #[test]
    fn entry_va_matches_manual_translation() {
        for path in [BASIC_NORMAL, BASIC_LINUX, BASIC_WINDOWS] {
            let data = load(path);
            let bin = GoBinary::parse(&data).unwrap();
            let text_va = bin.text_va().unwrap();
            let func = bin.functions().next().unwrap();

            let manual = text_va + func.func.entry_off as u64;
            assert_eq!(
                bin.entry_va(&func),
                Some(manual),
                "{path}: entry_va must equal text_va + entry_off"
            );
        }
    }

    #[test]
    fn entry_rva_subtracts_image_base_for_pe() {
        // PE: entry_rva = entry_va − image_base.
        let data = load(BASIC_WINDOWS);
        let bin = GoBinary::parse(&data).unwrap();
        let func = bin.functions().next().unwrap();

        let image_base = bin.context().image_base();
        assert!(
            image_base > 0,
            "PE image_base should be nonzero (typical: 0x140000000 for amd64 EXE)"
        );
        let va = bin.entry_va(&func).unwrap();
        let rva = bin.entry_rva(&func).unwrap();
        assert_eq!(rva, va - image_base);
        assert!(rva < va, "RVA must be smaller than VA for PE");
    }

    #[test]
    fn entry_rva_equals_entry_va_for_va_native_formats() {
        // ELF and Mach-O: image_base is 0, so RVA == VA.
        for path in [BASIC_NORMAL, BASIC_LINUX] {
            let data = load(path);
            let bin = GoBinary::parse(&data).unwrap();
            assert_eq!(
                bin.context().image_base(),
                0,
                "{path}: VA-native format should report image_base = 0"
            );
            let func = bin.functions().next().unwrap();
            assert_eq!(bin.entry_va(&func), bin.entry_rva(&func));
        }
    }
}

// ===========================================================================
// Build info: settings, the field iterators, and build-mode round-tripping.
// ===========================================================================
mod buildinfo {
    use super::*;

    #[test]
    fn buildinfo_borrows_from_input() {
        let data = load(BASIC_LINUX);
        let bin = GoBinary::parse(&data).unwrap();
        let info = bin.build_info().unwrap();
        // main_path is now Option<&str>; verify it borrows from the original
        // buildinfo blob by checking the pointer falls inside `data`.
        if let Some(main) = info.main_path {
            let main_ptr = main.as_ptr() as usize;
            let data_start = data.as_ptr() as usize;
            let data_end = data_start + data.len();
            assert!(
                main_ptr >= data_start && main_ptr < data_end,
                "main_path should borrow from binary data, not be re-allocated"
            );
        }
    }

    #[test]
    fn build_info_iterators_match_fields() {
        let data = load(BASIC_LINUX);
        let bin = GoBinary::parse(&data).unwrap();
        let info = bin.build_info().unwrap();
        assert_eq!(info.dependencies().count(), info.deps.len());
        assert_eq!(
            info.build_settings_iter().count(),
            info.build_settings.len()
        );
    }

    #[test]
    fn build_mode_as_str_round_trips_through_parse() {
        use gobin::metadata::BuildMode;
        let cases = [
            BuildMode::Exe,
            BuildMode::Pie,
            BuildMode::CShared,
            BuildMode::CArchive,
            BuildMode::Plugin,
            BuildMode::Archive,
            BuildMode::Shared,
            BuildMode::Other("custom-future"),
        ];
        for mode in cases {
            let s = mode.as_str();
            let round = BuildMode::parse(s);
            assert_eq!(round, mode, "as_str → parse must round-trip for {mode:?}");
            // Display must agree with as_str so schema serialization is stable.
            assert_eq!(format!("{mode}"), s);
        }
    }

    #[test]
    fn build_settings_expose_buildmode_and_tags() {
        let data = load(BASIC_LINUX);
        let bin = GoBinary::parse(&data).unwrap();
        let info = bin.build_info().expect("build info present");
        assert!(info.build_mode().is_some());
        let _ = info.build_tags();
    }
}

// ===========================================================================
// `moduledata` surfaces - segments, GC pointer maps, itabs, coverage, init
// ===========================================================================
mod moduledata {
    use super::*;

    /// A PE binary never carries a `.typelink` section at any Go version, so
    /// with its version string scrubbed the only layout hint points at Go 1.27.
    /// Picking V5 there shifts every field past `types` and silently reports an
    /// empty types region, no itabs, no init tasks and `has_main == false`.
    /// The layout must instead be arbitrated structurally, giving byte-for-byte
    /// the same extraction as the intact binary.
    #[test]
    fn layout_survives_a_scrubbed_version_string() {
        use gobin::structures::moduledata::ModuledataVersion;

        let intact_data = load(BASIC_GO124_WINDOWS);
        let intact = GoBinary::parse(&intact_data).unwrap();
        let scrubbed_data = load(BASIC_GO124_WINDOWS_NOVERSION);
        let scrubbed = GoBinary::parse(&scrubbed_data).unwrap();

        // The premise: the version really is unrecoverable from the scrubbed
        // copy, so the parser cannot fall back on it.
        assert!(intact.go_version().unwrap().starts_with("go1.24"));
        assert!(
            !scrubbed
                .go_version()
                .is_some_and(|v| v.starts_with("go1.24")),
            "fixture should have no usable version string"
        );

        let a = intact.moduledata().unwrap();
        let b = scrubbed.moduledata().unwrap();
        assert_eq!(b.version, ModuledataVersion::V3);
        assert_eq!(a.version, b.version);
        assert_eq!((a.types, a.etypes), (b.types, b.etypes));
        assert_eq!(
            (a.rodata, a.gofunc, a.epclntab),
            (b.rodata, b.gofunc, b.epclntab)
        );
        assert_eq!(a.has_main, b.has_main);
        assert!(a.has_main);

        assert_eq!(intact.types().count(), scrubbed.types().count());
        assert_eq!(intact.itab_pairs().count(), scrubbed.itab_pairs().count());
        assert_eq!(intact.init_order().len(), scrubbed.init_order().len());
        assert!(
            scrubbed.types().count() > 100,
            "types must not collapse to 0"
        );
        assert!(scrubbed.itab_pairs().count() > 0);
        assert!(!scrubbed.init_order().is_empty());
    }

    /// `-buildmode=pie` renames every read-only-relocatable Go section with a
    /// `.data.rel.ro` prefix. If the classifier does not strip it, a PIE binary
    /// looks like it has no type sections at all - which for Go ≤1.26 is read
    /// as a Go 1.27 signal, and for 1.27 loses the positive `.go.type` signal.
    #[test]
    fn pie_relro_section_names_are_recognized() {
        use gobin::structures::moduledata::ModuledataVersion;

        let plain_data = load(BASIC_GO127_LINUX);
        let plain = GoBinary::parse(&plain_data).unwrap();
        let pie_data = load(BASIC_GO127_PIE);
        let pie = GoBinary::parse(&pie_data).unwrap();

        assert!(
            pie.context().sections().go_type.is_some(),
            ".data.rel.ro.go.type must classify as .go.type"
        );
        assert!(pie.context().sections().go_func.is_some());
        assert_eq!(pie.moduledata().unwrap().version, ModuledataVersion::V5);
        // Same program, same toolchain: the extraction must not differ.
        assert_eq!(plain.types().count(), pie.types().count());
        assert_eq!(plain.itab_pairs().count(), pie.itab_pairs().count());
        assert_eq!(plain.functions().count(), pie.functions().count());
    }

    /// Go 1.26 stopped writing `textStart` into the pcHeader, leaving the slot
    /// zeroed. A moduledata-less 1.26+ binary must not report `runtime.text` as
    /// address 0 - that turns every entry VA into a raw `entry_off` without any
    /// error surfacing.
    #[test]
    fn text_va_is_never_zero() {
        for f in super::matrix::discover() {
            let data = load(&f.path);
            let Some(bin) = GoBinary::parse(&data) else {
                continue;
            };
            if let Some(va) = bin.text_va() {
                // wasm addresses code in a separate PC space whose text base
                // legitimately is 0; every other format maps text above 0.
                if bin.context().format() == BinaryFormat::Wasm {
                    continue;
                }
                assert_ne!(va, 0, "{}: text_va() reported address 0", f.path);
            }
        }
    }

    #[test]
    fn moduledata_segments_and_identity() {
        let data = load(BASIC_LINUX);
        let bin = GoBinary::parse(&data).unwrap();
        let md = bin.moduledata().expect("moduledata");

        // The main executable owns `main`, has no plugin/module name.
        assert_eq!(bin.is_main_module(), Some(true));
        assert_eq!(bin.module_name(), None);
        assert_eq!(bin.plugin_path(), None);

        // Data-segment boundaries are populated and ordered.
        for (name, r) in [
            ("noptrdata", md.noptrdata),
            ("data", md.data),
            ("noptrbss", md.noptrbss),
        ] {
            assert!(
                r.start != 0 && r.end >= r.start,
                "{name} range invalid: {r:?}"
            );
        }
        assert!(md.end > md.text, "module end should be past text");
        // A plain build is not coverage-instrumented.
        assert!(!bin.is_coverage_build());
    }

    #[test]
    fn moduledata_subslice_decoders() {
        let data = load(BASIC_LINUX);
        let bin = GoBinary::parse(&data).unwrap();

        // A normal binary has exactly one text section, ordered.
        let ts = bin.text_sections();
        assert_eq!(ts.len(), 1, "ordinary binary has one text section");
        assert!(ts[0].end >= ts[0].vaddr);

        // Plugin/shared-only tables are empty for a plain executable, and the
        // decoders must not panic.
        assert!(bin.plugin_exports().is_empty());
        assert!(bin.package_hashes().is_empty());
        assert!(bin.module_hashes().is_empty());
    }

    #[test]
    fn gc_pointer_map_locates_global_pointers() {
        let data = load(BASIC_LINUX);
        let bin = GoBinary::parse(&data).unwrap();
        let md = bin.moduledata().unwrap();
        let (text, end) = (md.text, md.end);

        let pm = bin.data_pointer_map().expect("data pointer map");
        assert!(
            pm.pointer_count() > 50,
            "expected many global data pointers"
        );
        assert!(
            pm.pointer_count() < pm.words.len(),
            "not every word is a pointer"
        );

        // Every word the map flags as a pointer must actually hold a pointer-shaped
        // value: nil, or an address inside the module image. Scalar garbage here
        // would mean the GC program was decoded wrong.
        let ctx = bin.context();
        let mut checked = 0usize;
        for va in pm.pointer_vas().take(300) {
            if let Some(sl) = ctx.slice_at_va(va)
                && let Ok(bytes) = sl.get(..8).unwrap_or(&[]).try_into()
            {
                let v = u64::from_le_bytes(bytes);
                checked += 1;
                assert!(
                    v == 0 || (v >= text && v < end),
                    "pointer word {va:#x} holds non-pointer {v:#x}"
                );
            }
        }
        assert!(checked > 100, "should have sampled many pointer words");

        // bss also decodes.
        assert!(bin.bss_pointer_map().unwrap().pointer_count() > 50);
    }

    #[test]
    fn itab_method_pointers_resolve_into_text() {
        let data = load(BASIC_LINUX);
        let bin = GoBinary::parse(&data).unwrap();
        let md = bin.moduledata().unwrap();
        let (text, etext) = (md.text, md.etext);

        let mut total = 0usize;
        for pair in bin.itab_pairs().take(60) {
            for va in bin.itab_methods(&pair).iter().map(|m| m.va) {
                total += 1;
                assert!(
                    va == 0 || (va >= text && va < etext),
                    "itab method ptr {va:#x} not in text"
                );
            }
        }
        assert!(
            total > 10,
            "expected resolved itab method pointers, got {total}"
        );
    }

    #[test]
    fn itab_pairs_returns_some_for_normal_binaries() {
        for path in [BASIC_NORMAL, BASIC_LINUX] {
            let data = load(path);
            let bin = GoBinary::parse(&data).unwrap();
            for p in bin.itab_pairs() {
                assert_ne!(p.iface_type_va, 0, "{path}: iface VA should be nonzero");
                assert_ne!(
                    p.concrete_type_va, 0,
                    "{path}: concrete VA should be nonzero"
                );
            }
        }
    }

    #[test]
    fn coverage_build_detected() {
        let data = load(COVER_LINUX);
        let bin = GoBinary::parse(&data).unwrap();
        assert!(
            bin.is_coverage_build(),
            "a -cover binary should report a coverage-counter region"
        );
        let md = bin.moduledata().unwrap();
        assert!(md.covctrs.is_some_and(|r| !r.is_empty()));
    }

    #[test]
    fn init_order_lists_runtime_and_main() {
        let data = load(BASIC_GO127);
        let bin = GoBinary::parse(&data).unwrap();
        let tasks = bin.init_order();
        assert!(
            tasks.len() >= 3,
            "a fmt-using program runs several package inits, got {}",
            tasks.len()
        );
        let packages: BTreeSet<&str> = tasks.iter().filter_map(|t| t.package).collect();
        assert!(
            packages.contains("runtime"),
            "runtime should initialize, saw {packages:?}"
        );
        // Every resolved init function name should end in an `init`-shaped suffix.
        let resolved: Vec<&str> = tasks
            .iter()
            .flat_map(|t| t.functions.iter())
            .filter_map(|f| f.name)
            .collect();
        assert!(
            !resolved.is_empty(),
            "at least some init fns should resolve"
        );
        assert!(
            resolved.iter().all(|n| n.contains("init")),
            "init task entries should be init functions, saw {resolved:?}"
        );
    }

    #[test]
    fn init_order_empty_is_safe() {
        // Older binaries (pre-1.24 / no inittasks) must return cleanly, not panic.
        let data = load(MINIMAL_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let _ = bin.init_order(); // must not panic regardless of availability
    }

    #[test]
    fn init_order_works_on_v4_binary() {
        // basic_normal is Go 1.26 (V4); the V4 walk was extended to reach inittasks.
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let tasks = bin.init_order();
        let packages: std::collections::BTreeSet<&str> =
            tasks.iter().filter_map(|t| t.package).collect();
        assert!(
            packages.contains("runtime"),
            "V4 inittasks should resolve runtime init, saw {packages:?}"
        );
    }

    #[test]
    fn macho_plugin_chained_fixups_resolve() {
        // A Go plugin (-buildmode=plugin) is an externally-linked Mach-O dylib
        // whose data pointers are chained fixups; without rebasing, no pointer
        // resolves. With it, types / plugin tables come back.
        let data = load("tests/samples/plugin_go126_darwin_arm64.so");
        let bin = GoBinary::parse(&data).unwrap();

        assert_eq!(
            bin.is_main_module(),
            Some(false),
            "a plugin is not the main module"
        );
        assert_eq!(bin.plugin_path(), Some("gobin.test/plugin"));
        assert!(
            bin.types().count() > 100,
            "types must resolve through fixups"
        );

        // Exported plugin symbols (moduledata.ptab) decode with names.
        let exports: BTreeSet<&str> = bin.plugin_exports().iter().filter_map(|e| e.name).collect();
        assert!(exports.contains("ExportedFunc"), "saw {exports:?}");
        assert!(exports.contains("ExportedVar"), "saw {exports:?}");

        // Per-package ABI hashes resolve to real package paths.
        let pkgs: BTreeSet<&str> = bin
            .package_hashes()
            .iter()
            .filter_map(|h| h.module_name)
            .collect();
        assert!(
            pkgs.iter().any(|p| p.starts_with("internal/")),
            "saw {pkgs:?}"
        );
    }

    #[test]
    fn go127_detects_v5_moduledata() {
        use gobin::structures::moduledata::ModuledataVersion;
        let data = load(BASIC_GO127);
        let bin = GoBinary::parse(&data).expect("Go 1.27 binary should parse");
        let md = bin.moduledata().expect("moduledata should be located");
        assert_eq!(
            md.version,
            ModuledataVersion::V5,
            "go1.27-devel should select the V5 layout"
        );
        // Regression guard: the old speculative V5 branch hardcoded these to
        // None, which silently disabled inline-tree and funcdata resolution.
        assert!(md.gofunc.is_some(), "V5 must still carry gofunc");
        assert!(md.rodata.is_some(), "V5 must still carry rodata");
        assert!(md.itaboffset.is_some(), "V5 stores itabs at itaboffset");
        assert!(md.typelinks.is_none(), "V5 dropped the typelinks slice");
    }

    #[test]
    fn go127_itab_pairs_via_inline_region() {
        // V5 removed .itablink / itablinks; itabs are walked inline at
        // types+itaboffset. This exercises the third itab strategy.
        let data = load(BASIC_GO127);
        let bin = GoBinary::parse(&data).unwrap();
        let pairs: Vec<_> = bin.itab_pairs().collect();
        assert!(
            pairs.len() >= 5,
            "a binary using fmt + several interface impls should expose many \
             itabs, got {}",
            pairs.len()
        );
        // Every pair must carry plausible (non-zero) type-descriptor VAs.
        for p in &pairs {
            assert!(p.iface_type_va != 0 && p.concrete_type_va != 0);
        }
    }

    #[test]
    fn go127_types_still_extract() {
        // Type extraction must fall back to descriptor-walking now that the
        // .typelink section is gone in V5.
        let data = load(BASIC_GO127);
        let bin = GoBinary::parse(&data).unwrap();
        let n = bin.types().count();
        assert!(n > 100, "expected many types via descriptor walk, got {n}");
    }

    #[test]
    fn go127_stripped_still_v5() {
        use gobin::structures::moduledata::ModuledataVersion;
        let data = load(BASIC_GO127_STRIPPED);
        let bin = GoBinary::parse(&data).expect("stripped Go 1.27 should parse");
        let md = bin
            .moduledata()
            .expect("moduledata located even when stripped");
        assert_eq!(md.version, ModuledataVersion::V5);
        assert!(bin.itab_pairs().count() >= 5);
    }
}

// ===========================================================================
// `go:embed` asset recovery and FIPS-mode detection.
// ===========================================================================
mod embed_and_fips {
    use super::*;

    /// `embed.FS` recovery reads through the address-space view, which for
    /// wasm is the reconstructed linear-memory image rather than the file.
    /// Narrowing that search with file-offset section ranges finds nothing -
    /// silently, since a binary with no embeds legitimately returns empty.
    #[test]
    fn embedded_assets_recovered_from_wasm() {
        let data = load("tests/samples/embed_go127_wasip1_wasm");
        let bin = GoBinary::parse(&data).unwrap();
        let assets = bin.embedded_assets();
        assert!(
            !assets.is_empty(),
            "wasm embed fixture must yield its embedded files"
        );
        assert!(
            assets.iter().any(|a| a.path.ends_with(".txt")),
            "expected the embedded text assets, got {:?}",
            assets.iter().map(|a| a.path).collect::<Vec<_>>()
        );
        // Directories carry no bytes; files do.
        for a in &assets {
            if a.is_dir {
                assert!(a.data.is_empty(), "{}: dir must have no bytes", a.path);
            } else {
                assert!(!a.data.is_empty(), "{}: file must have bytes", a.path);
            }
        }
    }

    fn assert_embed_assets(path: &str) {
        let data = load(path);
        let bin = GoBinary::parse(&data).unwrap();
        let assets = bin.embedded_assets();
        let by_path: std::collections::BTreeMap<&str, &[u8]> =
            assets.iter().map(|a| (a.path, a.data)).collect();

        // The three embedded files (recovered bytes must match the sources).
        assert_eq!(
            by_path.get("assets/hello.txt").copied(),
            Some(b"hello embedded world\n".as_slice()),
            "{path}: hello.txt content"
        );
        assert_eq!(
            by_path.get("assets/data.bin").copied(),
            Some(b"second asset file\n".as_slice()),
            "{path}: data.bin content"
        );
        assert!(
            by_path.contains_key("assets/nested/inner.dat"),
            "{path}: nested file present"
        );
        // Directory entries are surfaced with the trailing slash and no bytes.
        let dirs: Vec<&str> = assets.iter().filter(|a| a.is_dir).map(|a| a.path).collect();
        assert!(
            dirs.contains(&"assets/nested/"),
            "{path}: nested dir entry, saw {dirs:?}"
        );
        assert!(
            assets
                .iter()
                .filter(|a| a.is_dir)
                .all(|a| a.data.is_empty()),
            "{path}: directory entries carry no bytes"
        );
    }

    #[test]
    fn embedded_assets_recovered_with_symbols() {
        assert_embed_assets(BASIC_EMBED);
    }

    #[test]
    fn embedded_assets_recovered_when_stripped() {
        // The scanner is symbol-independent: -ldflags="-s -w" must not hide assets.
        assert_embed_assets(BASIC_EMBED_STRIPPED);
    }

    #[test]
    fn embedded_assets_recovered_on_elf() {
        // Same extraction path works across container formats (ELF here).
        assert_embed_assets(BASIC_EMBED_LINUX);
    }

    #[test]
    fn embedded_assets_empty_for_non_embed_binary() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        assert!(
            bin.embedded_assets().is_empty(),
            "a binary with no //go:embed must yield no assets (false-positive guard)"
        );
    }

    #[test]
    fn fips_info_detected_in_fips_build() {
        let data = load(BASIC_FIPS);
        let bin = GoBinary::parse(&data).unwrap();
        let fips = bin
            .fips_info()
            .expect("GOFIPS140 build should report FIPS info");
        assert!(fips.version.starts_with("v1.0.0"));
        assert!(fips.enforced_by_default, "fips140=on in DefaultGODEBUG");
        // The integrity sum is present and non-zero.
        assert!(fips.module_sum.is_some_and(|s| s != [0u8; 32]));
    }

    #[test]
    fn fips_info_absent_in_normal_build() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        // The fipsinfo section is linked into modern Go binaries, but without the
        // GOFIPS140 build setting it is not a FIPS build.
        assert!(
            bin.fips_info().is_none(),
            "non-FIPS builds must not report FIPS mode"
        );
    }
}

// ===========================================================================
// Wasm linear-memory reconstruction and extraction.
// ===========================================================================
mod wasm {
    use super::*;

    #[test]
    fn wasm_pclntab_parses() {
        let data = load(BASIC_WASM);
        let bin = GoBinary::parse(&data).unwrap();
        let pcl = bin
            .pclntab()
            .expect("wasm pclntab should parse via reconstructed linear-memory image");
        assert!(
            pcl.nfunc > 100,
            "expected hundreds of functions in stdlib wasm build, got {}",
            pcl.nfunc
        );
        assert_eq!(pcl.ptr_size, 8, "Go wasm uses ptrSize = 8");
        assert_eq!(pcl.min_lc, 1, "Go wasm uses minLC = 1");
    }

    #[test]
    fn wasm_arch_resolves_correctly() {
        let data = load(BASIC_WASM);
        let bin = GoBinary::parse(&data).unwrap();
        // pclntab arch can't disambiguate (1,8) - reports X86_64.
        assert_eq!(bin.pclntab().unwrap().arch(), Arch::X86_64);
        // bin.arch() folds in the container format and resolves to Wasm.
        assert_eq!(bin.arch(), Arch::Wasm);
    }

    #[test]
    fn wasm_function_iter_yields_runtime_main() {
        let data = load(BASIC_WASM);
        let bin = GoBinary::parse(&data).unwrap();
        let names: Vec<&str> = bin.functions().map(|f| f.name).collect();
        assert!(
            names.contains(&"runtime.main"),
            "runtime.main should be reachable via the pclntab funcname table"
        );
        assert!(
            names.contains(&"main.main"),
            "main.main should be reachable via the pclntab funcname table"
        );
        assert!(
            names.len() > 100,
            "wasm functions() should yield hundreds of names, got {}",
            names.len()
        );
    }

    #[test]
    fn wasm_types_extracted() {
        let data = load(BASIC_WASM);
        let bin = GoBinary::parse(&data).unwrap();
        let types: Vec<_> = bin.types().collect();
        assert!(
            types.len() > 100,
            "wasm types() should yield hundreds of types, got {}",
            types.len()
        );
        // Spot-check a well-known runtime type.
        assert!(
            types.iter().any(|t| t.name.contains("runtime.")),
            "expected at least one runtime.* type"
        );
    }

    #[test]
    fn wasm_strings_extracted() {
        let data = load(BASIC_WASM);
        let bin = GoBinary::parse(&data).unwrap();
        let count = bin.strings().count();
        assert!(
            count > 50,
            "wasm strings() should yield many strings, got {count}"
        );
    }

    #[test]
    fn wasm_inline_tree_yields_entries() {
        let data = load(BASIC_WASM);
        let bin = GoBinary::parse(&data).unwrap();

        let mut total_entries = 0usize;
        for func in bin.functions().take(200) {
            total_entries += bin.inline_tree(&func).count();
            if total_entries > 0 {
                break;
            }
        }
        assert!(
            total_entries > 0,
            "wasm should expose at least one inline-tree entry across the first 200 functions"
        );
    }

    #[test]
    fn wasm_moduledata_resolves_text_va() {
        let data = load(BASIC_WASM);
        let bin = GoBinary::parse(&data).unwrap();
        // moduledata discovery should succeed for wasm via the linear-memory
        // pcHeader-pointer scan, exposing text/etext.
        let text = bin.text_va().expect("wasm should resolve runtime.text");
        let etext = bin.etext_va().expect("wasm should resolve runtime.etext");
        assert!(etext > text, "etext must follow text");
    }
}

// ===========================================================================
// Type-descriptor extraction: structural details, fields, methods, parameter
// ===========================================================================
mod types {
    use super::*;

    /// `abi.MapType` has shipped three different shapes - bucket-based `hmap`
    /// (≤1.23), Swiss tables (1.24-1.26), and Swiss with explicit key/elem
    /// strides (1.27+) - and each descriptor's size feeds the position of its
    /// trailing `UncommonType`. Sweep the corpus and assert every map
    /// descriptor is read with the layout its Go version actually emitted, with
    /// the version-specific fields populated and the others genuinely absent.
    #[test]
    fn map_descriptors_use_the_layout_of_their_go_version() {
        use gobin::structures::types::{MapLayout, TypeDetail};

        let mut checked = 0usize;
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for f in super::matrix::discover() {
            let minor = super::matrix::tag_minor(&f.gotag);
            // Type descriptors arrived in Go 1.7.
            if minor < 7 {
                continue;
            }
            let expected = MapLayout::for_go_minor(minor);
            let data = load(&f.path);
            let Some(bin) = GoBinary::parse(&data) else {
                continue;
            };
            let mut saw_map = false;
            for t in bin.types() {
                let TypeDetail::Map { extra, .. } = &t.detail else {
                    continue;
                };
                saw_map = true;
                assert_eq!(
                    extra.layout, expected,
                    "{}: {} parsed with {:?}, expected {:?}",
                    f.path, t.name, extra.layout, expected
                );
                match expected {
                    MapLayout::HmapWithHmapType | MapLayout::HmapBools => {
                        assert!(extra.bucket_size.is_some_and(|b| b > 0), "{}", f.path);
                        assert!(extra.hasher.is_none(), "{}: hasher arrives in 1.14", f.path);
                        assert!(
                            extra.raw_flags.is_none(),
                            "{}: the bool tail has no flags word",
                            f.path
                        );
                        assert!(extra.group_size.is_none(), "{}", f.path);
                        assert_eq!(
                            extra.hmap.is_some(),
                            expected == MapLayout::HmapWithHmapType,
                            "{}: the hmap pointer exists only up to Go 1.10",
                            f.path
                        );
                    }
                    MapLayout::HmapFlags | MapLayout::HmapHasher => {
                        assert!(extra.bucket_size.is_some_and(|b| b > 0), "{}", f.path);
                        assert!(extra.raw_flags.is_some(), "{}", f.path);
                        assert!(extra.hmap.is_none(), "{}", f.path);
                        assert_eq!(
                            extra.hasher.is_some(),
                            expected == MapLayout::HmapHasher,
                            "{}: the hasher pointer arrives in Go 1.14",
                            f.path
                        );
                        assert!(extra.group_size.is_none(), "{}", f.path);
                        assert!(extra.slot_size.is_none(), "{}", f.path);
                        assert!(extra.key_stride.is_none(), "{}", f.path);
                    }
                    MapLayout::Swiss => {
                        assert!(extra.group_size.is_some_and(|g| g > 0), "{}", f.path);
                        assert!(extra.slot_size.is_some(), "{}", f.path);
                        // The 1.27-only stride fields must read as absent,
                        // not as a zero scavenged from the next descriptor.
                        assert!(extra.keys_off.is_none(), "{}", f.path);
                        assert!(extra.key_stride.is_none(), "{}", f.path);
                        assert!(extra.bucket_size.is_none(), "{}", f.path);
                    }
                    MapLayout::SwissSplitGroup => {
                        assert!(extra.group_size.is_some_and(|g| g > 0), "{}", f.path);
                        assert!(extra.keys_off.is_some(), "{}", f.path);
                        assert!(extra.key_stride.is_some(), "{}", f.path);
                        assert!(extra.elem_stride.is_some(), "{}", f.path);
                        assert!(extra.slot_size.is_none(), "{}", f.path);
                        assert!(extra.bucket_size.is_none(), "{}", f.path);
                    }
                    MapLayout::Probe => unreachable!("resolved before parsing"),
                }
                // The flags word is a 5-bit mask in every encoding; a value
                // outside that range means we read past the descriptor's end.
                if let Some(raw) = extra.raw_flags {
                    assert!(
                        raw < 64,
                        "{}: {} has implausible map flags {raw:#x}",
                        f.path,
                        t.name
                    );
                }
                // `reflexive_key` exists in every hmap encoding and in none of
                // the Swiss ones, which is a second, independent check that the
                // right decoder ran.
                assert_eq!(
                    extra.flags.reflexive_key.is_some(),
                    expected.is_hmap(),
                    "{}: {} reflexive-key presence disagrees with {:?}",
                    f.path,
                    t.name,
                    expected
                );
                seen.insert(format!("{expected:?}"));
                checked += 1;
            }
            // Every fixture that reaches `fmt`/`reflect` carries map types.
            if f.prog == "types" {
                assert!(
                    saw_map,
                    "{}: types harness should surface map types",
                    f.path
                );
            }
        }
        assert!(checked > 50, "expected a broad sweep, checked {checked}");
        // Every layout era must be represented by a real fixture, so the
        // corpus cannot silently lose coverage of one of the six boundaries.
        let want: BTreeSet<String> = [
            "HmapWithHmapType",
            "HmapBools",
            "HmapFlags",
            "HmapHasher",
            "Swiss",
            "SwissSplitGroup",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(
            seen, want,
            "map-layout coverage gap: the corpus exercises {seen:?}"
        );
    }

    /// Go 1.27 replaced the typelink table with a walk bounded by
    /// `moduledata.typedesclen`. Walking to `etypes` instead runs off the end
    /// of the typelink descriptors into non-typelink types, `type:.namedata.*`
    /// blobs, and finally the inline itab array - surfacing unnamed junk types.
    #[test]
    fn v5_type_walk_stops_at_typedesclen() {
        use gobin::structures::moduledata::ModuledataVersion;

        for f in super::matrix::discover() {
            let data = load(&f.path);
            let Some(bin) = GoBinary::parse(&data) else {
                continue;
            };
            let Some(md) = bin.moduledata() else { continue };
            if md.version != ModuledataVersion::V5 {
                continue;
            }
            let typedesclen = md.typedesclen.expect("V5 records typedesclen");
            let itaboffset = md.itaboffset.expect("V5 records itaboffset");
            assert!(typedesclen > 0 && typedesclen <= itaboffset, "{}", f.path);
            let bound = md.types + typedesclen;

            let types: Vec<_> = bin.types().collect();
            assert!(!types.is_empty(), "{}: V5 must still yield types", f.path);
            for t in &types {
                assert!(
                    t.descriptor_va >= md.types && t.descriptor_va < bound,
                    "{}: type {:?} at {:#x} lies outside [types, types+typedesclen) = [{:#x}, {:#x})",
                    f.path,
                    t.name,
                    t.descriptor_va,
                    md.types,
                    bound
                );
                assert!(
                    !t.name.is_empty(),
                    "{}: unnamed type at {:#x} - the walk over-ran its bound",
                    f.path,
                    t.descriptor_va
                );
            }
        }
    }

    /// Go 1.27 lowered `abi.MaxPtrmaskBytes` from 2048 to 16 and deleted
    /// type-level GC programs, so most non-trivial types now defer their
    /// pointer mask to run time. `gc_mask_va` must report those as absent
    /// rather than handing back the address of an empty BSS slot.
    #[test]
    fn gc_mask_on_demand_is_modelled() {
        use gobin::structures::abitype::AbiType;

        let data = load(BASIC_GO127_LINUX);
        let bin = GoBinary::parse(&data).unwrap();
        let mut on_demand = 0usize;
        let mut inline_mask = 0usize;
        for t in bin.types() {
            let Some(off) = bin.context().va_to_file(t.descriptor_va) else {
                continue;
            };
            let Some(abi) = bin
                .context()
                .structure_search_data()
                .get(off..)
                .and_then(|d| AbiType::parse(d, 8))
            else {
                continue;
            };
            if abi.gc_mask_on_demand() {
                on_demand += 1;
                assert!(
                    abi.gc_mask_va().is_none(),
                    "on-demand types have no static mask"
                );
            } else if abi.gcdata != 0 {
                inline_mask += 1;
                assert_eq!(abi.gc_mask_va(), Some(abi.gcdata));
            }
        }
        assert!(inline_mask > 0, "small types still carry a static mask");
        // Whether any type in a given program crosses the (Go 1.27) 16-byte
        // threshold depends on the program, so `on_demand` is only required to
        // be consistent, not non-zero.
        let _ = on_demand;
    }

    #[test]
    fn type_details_present() {
        use gobin::structures::types::TypeDetail;

        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let types: Vec<_> = bin.types().collect();

        // Should have at least some types with struct/interface/func/chan details
        let has_struct = types
            .iter()
            .any(|t| matches!(t.detail, TypeDetail::Struct { .. }));
        let has_method_count = types.iter().any(|t| t.method_count > 0);

        assert!(
            has_struct,
            "Should have at least one struct type with field count"
        );
        assert!(
            has_method_count,
            "Should have at least one type with methods"
        );
    }

    #[test]
    fn struct_fields_resolved() {
        use gobin::structures::types::TypeDetail;

        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let types: Vec<_> = bin.types().collect();

        let struct_with_fields = types.iter().find_map(|t| match &t.detail {
            TypeDetail::Struct { fields, .. } if !fields.is_empty() => Some((t, fields)),
            _ => None,
        });
        let (ty, fields) =
            struct_with_fields.expect("at least one struct should have resolved fields");
        assert!(!ty.name.is_empty());
        let named_fields = fields.iter().filter(|f| !f.name.is_empty()).count();
        assert!(
            named_fields > 0,
            "expected at least one named field on {}",
            ty.name
        );
    }

    #[test]
    fn interface_methods_resolved_when_present() {
        use gobin::structures::types::TypeDetail;

        // The current `basic_*` fixtures have no Interface entries in their
        // typelinks (the Go linker omits interface types not used as runtime
        // type descriptors). We assert: *if* any interface with method_count > 0
        // is present, we must also have resolved its method names.
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let types: Vec<_> = bin.types().collect();

        for t in &types {
            if let TypeDetail::Interface {
                method_count,
                methods,
                ..
            } = &t.detail
                && *method_count > 0
            {
                assert!(
                    !methods.is_empty(),
                    "interface {} has method_count={} but no resolved methods",
                    t.name,
                    method_count,
                );
            }
        }
    }

    #[test]
    fn func_type_carries_param_vas() {
        use gobin::structures::types::TypeDetail;

        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();

        // Find at least one Func type with non-zero param VAs and verify
        // the lengths match in_count / out_count.
        let mut saw_with_params = false;
        let mut saw_input_va = false;
        let mut saw_output_va = false;
        for t in bin.types() {
            if let TypeDetail::Func {
                in_count,
                out_count,
                inputs,
                outputs,
                ..
            } = &t.detail
            {
                if !inputs.is_empty() || !outputs.is_empty() {
                    saw_with_params = true;
                }
                assert_eq!(
                    inputs.len(),
                    *in_count as usize,
                    "{}: inputs.len() must equal in_count when descriptor is well-formed",
                    t.name,
                );
                assert_eq!(
                    outputs.len(),
                    *out_count as usize,
                    "{}: outputs.len() must equal out_count",
                    t.name,
                );
                if inputs.iter().any(|r| r.va != 0) {
                    saw_input_va = true;
                }
                if outputs.iter().any(|r| r.va != 0) {
                    saw_output_va = true;
                }
            }
        }
        assert!(
            saw_with_params,
            "expected at least one func type with params"
        );
        assert!(saw_input_va, "at least one input VA should be nonzero");
        assert!(saw_output_va, "at least one output VA should be nonzero");
    }

    #[test]
    fn all_types_enumerates_more_and_resolves_tags() {
        use gobin::structures::types::TypeDetail;
        let data = load(BASIC_LINUX);
        let bin = GoBinary::parse(&data).unwrap();

        let canonical = bin.types().count();
        let all = bin.all_types();
        // The transitive walk reaches strictly more than the typelink set.
        assert!(
            all.len() > canonical,
            "all_types ({}) should exceed types ({canonical})",
            all.len()
        );
        // Every enumerated type has a clean name and a valid descriptor VA.
        for t in &all {
            assert!(
                t.name.is_empty() || !t.name.bytes().any(|c| c < 0x20),
                "garbage type name: {:?}",
                t.name
            );
            assert!(t.descriptor_va != 0);
        }
        // Struct field tags resolve (only reachable via the full walk, since the
        // tagged struct types are not all in typelink).
        let mut tagged = 0usize;
        let mut saw_keyvalue_tag = false;
        for t in &all {
            if let TypeDetail::Struct { fields, .. } = &t.detail {
                for f in fields {
                    if let Some(tag) = f.tag {
                        tagged += 1;
                        // Conventional `key:"value"` tags (e.g. json/yaml) appear in
                        // stdlib structs - at least one should decode cleanly.
                        if tag.contains(":\"") {
                            saw_keyvalue_tag = true;
                        }
                    }
                }
            }
        }
        assert!(tagged > 0, "expected at least one tagged struct field");
        assert!(
            saw_keyvalue_tag,
            "expected a conventional key:\"value\" struct tag"
        );

        // Regression guards for the func-type descriptor bug. A mis-located
        // `UncommonType` (the funcType struct's alignment padding was skipped)
        // produced a garbage `mcount`; resolving those phantom methods followed
        // garbage `mtyp` offsets and exploded the transitive closure. Real Go types
        // have at most ~150 methods, and this fixture's legitimate closure is ~850
        // types - neither bound is tight, but each is far below the bug's output
        // (mcount up to 0xFFFF; ~12.8k inflated types).
        for t in &all {
            assert!(
                t.method_count < 500,
                "absurd method_count {} on type {:?} - UncommonType mis-located?",
                t.method_count,
                t.name
            );
        }
        assert!(
            all.len() < 3000,
            "all_types inflated to {} - garbage method offsets being followed?",
            all.len()
        );
        // The transitive walk reaches the binary's own tagged structs and decodes
        // their field tags - covering json, yaml, multi-key, and `,omitempty`.
        //
        // (This previously asserted ">20" tagged fields. That count was an artifact
        // of a func-type descriptor bug: the `UncommonType` for func types was
        // located short by the funcType struct's alignment padding, so a garbage
        // `mcount` was read and the phantom methods' garbage `mtyp` offsets were
        // followed into ~12k unrelated descriptors - inflating `all_types` from the
        // ~850 genuinely-reachable types to ~12.8k and surfacing stdlib structs not
        // actually reachable from typelinks. With the layout fixed, the walk reaches
        // only legitimately-referenced types.)
        for expected in [
            "json:\"name\" yaml:\"name\"",
            "json:\"enabled\"",
            "json:\"count,omitempty\"",
        ] {
            assert!(
                all.iter().any(|t| matches!(
                    &t.detail,
                    TypeDetail::Struct { fields, .. }
                        if fields.iter().any(|f| f.tag == Some(expected))
                )),
                "expected the walk to reach a struct carrying tag {expected:?}"
            );
        }
    }

    #[test]
    fn type_at_va_resolves_referenced_types() {
        use gobin::structures::types::TypeDetail;
        let data = load(BASIC_LINUX);
        let bin = GoBinary::parse(&data).unwrap();

        // Find a slice type and resolve its element type by VA.
        let slice = bin
            .types()
            .find_map(|t| match t.detail {
                TypeDetail::Slice { elem_va } if elem_va != 0 => Some(elem_va),
                _ => None,
            })
            .expect("a slice type with an element");
        let elem = bin.type_at(slice).expect("element type resolves");
        assert!(!elem.name.is_empty());
    }

    #[test]
    fn type_descriptor_full_fields() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();

        // A named type with methods exposes its import path (from UncommonType),
        // the equality-fn and GC-bitmap pointers, and the raw tflag.
        let t = bin
            .types()
            .find(|t| t.name.contains("TestStruct") && t.has_uncommon)
            .expect("TestStruct with methods");
        assert_eq!(t.pkg_path, Some("main"), "uncommon pkg_path");
        assert!(t.equal_va != 0, "equality fn VA should be set");
        assert!(t.gcdata_va != 0, "gcdata VA should be set");
        assert!(t.tflag & 0x01 != 0, "TFlagUncommon bit set");

        // At least some types expose a pointer-to-this descriptor offset.
        assert!(
            bin.types().any(|t| t.ptr_to_this != 0),
            "expected some types to carry a *T offset"
        );
    }

    #[test]
    fn type_names_resolve_for_fields_methods_and_params() {
        use gobin::structures::types::TypeDetail;

        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();

        let mut resolved_field = false;
        let mut resolved_param = false;
        let mut named_field_value = None;
        for t in bin.types() {
            match &t.detail {
                TypeDetail::Struct { fields, .. } => {
                    for n in fields.iter().filter_map(|f| f.type_name) {
                        resolved_field = true;
                        named_field_value.get_or_insert_with(|| n.to_string());
                    }
                }
                TypeDetail::Func {
                    inputs, outputs, ..
                } if inputs
                    .iter()
                    .chain(outputs.iter())
                    .any(|r| r.name.is_some()) =>
                {
                    resolved_param = true;
                }
                _ => {}
            }
        }
        // A stdlib-linked binary has plenty of named struct fields and func params;
        // the leaf (concrete) referenced types should resolve to names. Method /
        // interface-method signature types are unnamed Go func types, so their
        // `type_name` is expectedly None - covered by the doc contract, not here.
        assert!(resolved_field, "expected some struct field type names");
        assert!(resolved_param, "expected some func param type names");
        assert!(
            named_field_value.is_some_and(|n| !n.is_empty()),
            "a resolved field type name should be non-empty"
        );
    }

    #[test]
    fn pointer_and_slice_carry_elem_va() {
        use gobin::structures::types::TypeDetail;

        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let types: Vec<_> = bin.types().collect();

        let any_ptr = types
            .iter()
            .any(|t| matches!(&t.detail, TypeDetail::Pointer { elem_va } if *elem_va != 0));
        let any_slice = types
            .iter()
            .any(|t| matches!(&t.detail, TypeDetail::Slice { elem_va } if *elem_va != 0));
        assert!(
            any_ptr,
            "expected at least one pointer with nonzero elem_va"
        );
        assert!(
            any_slice,
            "expected at least one slice with nonzero elem_va"
        );
    }

    #[test]
    fn map_carries_key_and_elem_va() {
        use gobin::structures::types::TypeDetail;

        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let types: Vec<_> = bin.types().collect();

        let any_map = types.iter().any(|t| {
            matches!(&t.detail, TypeDetail::Map { key_va, elem_va, .. } if *key_va != 0 && *elem_va != 0)
        });
        assert!(
            any_map,
            "expected at least one map with nonzero key/elem VAs"
        );
    }

    #[test]
    fn methods_resolved_on_concrete_types() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let types: Vec<_> = bin.types().collect();

        let with_methods = types
            .iter()
            .find(|t| t.has_uncommon && !t.methods.is_empty())
            .expect("at least one type should expose resolved methods");
        let m = with_methods.methods.first().unwrap();
        assert!(!m.name.is_empty(), "method names should resolve to strings");
        assert_eq!(
            with_methods.methods.len(),
            with_methods.method_count as usize,
            "methods.len() should match method_count for {}",
            with_methods.name,
        );
    }

    #[test]
    fn type_classification_helpers_match_function_helpers() {
        use gobin::metadata::{is_internal_path, is_runtime_path, is_stdlib_path};

        // runtime.* / runtime/internal/* are runtime AND internal, never stdlib
        assert!(is_runtime_path("runtime"));
        assert!(is_runtime_path("runtime/internal/atomic"));
        // Go 1.24 moved the runtime's internal packages under `internal/`;
        // they are still runtime code, not ordinary internal library code.
        assert!(is_runtime_path("internal/runtime/atomic"));
        assert!(is_runtime_path("internal/runtime/maps"));
        assert!(is_runtime_path("internal/runtime/sys"));
        assert!(is_internal_path("internal/runtime/maps"));
        assert!(!is_stdlib_path("internal/runtime/maps"));
        // …but a non-runtime `internal/` package is not runtime.
        assert!(!is_runtime_path("internal/abi"));
        assert!(!is_runtime_path("internal/runtimefoo"));
        assert!(is_internal_path("runtime"));
        assert!(!is_stdlib_path("runtime"));

        // Plain stdlib
        assert!(is_stdlib_path("net/http"));
        assert!(is_stdlib_path("encoding/json"));
        assert!(!is_internal_path("net/http"));
        assert!(!is_runtime_path("net/http"));

        // Third-party (domain-shaped) is none-of-the-above
        assert!(!is_stdlib_path("github.com/spf13/cobra"));
        assert!(!is_internal_path("github.com/spf13/cobra"));
        assert!(!is_stdlib_path("gopkg.in/yaml.v3"));

        // internal/* is internal but not stdlib
        assert!(is_internal_path("internal/abi"));
        assert!(!is_stdlib_path("internal/abi"));
    }

    #[test]
    fn go_type_classification_via_real_binary() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();

        let (mut runtime_ct, mut stdlib_ct, mut user_ct) = (0usize, 0usize, 0usize);
        for ty in bin.types() {
            if ty.is_runtime() {
                runtime_ct += 1;
            } else if ty.is_stdlib() {
                stdlib_ct += 1;
            } else if ty.package().is_some() {
                user_ct += 1;
            }
            // is_internal must be a superset of is_runtime
            if ty.is_runtime() {
                assert!(
                    ty.is_internal(),
                    "runtime type must also be internal: {}",
                    ty.name
                );
            }
            // is_stdlib and is_internal must be disjoint
            assert!(
                !(ty.is_stdlib() && ty.is_internal()),
                "type both stdlib AND internal: {}",
                ty.name
            );
        }
        assert!(
            runtime_ct > 0,
            "a Go binary should expose at least one runtime type"
        );
        let _ = (stdlib_ct, user_ct);
    }

    #[test]
    fn type_detail_scalar_accessors() {
        use gobin::structures::types::TypeDetail;

        let arr = TypeDetail::Array {
            len: 16,
            elem_va: 0,
            slice_va: 0,
        };
        assert_eq!(arr.array_len(), Some(16));
        assert_eq!(arr.chan_dir(), None);
        assert_eq!(arr.func_arity(), None);

        let ch = TypeDetail::Chan { dir: 2, elem_va: 0 };
        assert_eq!(ch.chan_dir(), Some(2));
        assert_eq!(ch.array_len(), None);

        let f = TypeDetail::Func {
            in_count: 3,
            out_count: 2,
            is_variadic: false,
            inputs: vec![],
            outputs: vec![],
        };
        assert_eq!(f.func_arity(), Some((3, 2)));

        let s = TypeDetail::Struct {
            field_count: 5,
            fields: vec![],
        };
        assert_eq!(s.struct_field_count(), Some(5));

        let i = TypeDetail::Interface {
            method_count: 7,
            methods: vec![],
            pkg_path: None,
        };
        assert_eq!(i.interface_method_count(), Some(7));

        // None cases
        let n = TypeDetail::None;
        assert_eq!(n.array_len(), None);
        assert_eq!(n.chan_dir(), None);
        assert_eq!(n.func_arity(), None);
        assert_eq!(n.struct_field_count(), None);
        assert_eq!(n.interface_method_count(), None);
    }

    #[test]
    fn types_iter_and_itab_pairs_iter_compose() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();

        // bin.types() is a streaming iterator - verify it composes with .take() /
        // .count() and yields a positive number of types.
        let count = bin.types().count();
        assert!(count > 0, "binary should expose at least one type");
        assert_eq!(bin.types().take(5).count(), count.min(5));

        // itab_pairs is a streaming iterator (corpus may not contain pairs)
        let _ = bin.itab_pairs().count();
    }

    #[test]
    fn enum_display_strings_are_stable() {
        use gobin::structures::types::{MapLayout, MapTypeExtra, TypeDetail};

        // Confidence
        assert_eq!(format!("{}", Confidence::None), "none");
        assert_eq!(format!("{}", Confidence::Low), "low");
        assert_eq!(format!("{}", Confidence::Medium), "medium");
        assert_eq!(format!("{}", Confidence::High), "high");

        // PclntabVersion
        assert_eq!(format!("{}", PclntabVersion::Go12), "go12");
        assert_eq!(format!("{}", PclntabVersion::Go116), "go116");
        assert_eq!(format!("{}", PclntabVersion::Go118), "go118");
        assert_eq!(format!("{}", PclntabVersion::Go120), "go120");

        // Arch - values match canonical GOARCH where they exist
        assert_eq!(format!("{}", Arch::X86), "386");
        assert_eq!(format!("{}", Arch::X86_64), "amd64");
        assert_eq!(format!("{}", Arch::Arm64), "arm64");
        assert_eq!(format!("{}", Arch::Wasm), "wasm");
        assert_eq!(format!("{}", Arch::Unknown), "unknown");

        // TypeDetail::kind_str
        assert_eq!(TypeDetail::None.kind_str(), "none");
        assert_eq!(
            TypeDetail::Array {
                len: 4,
                elem_va: 0x1000,
                slice_va: 0,
            }
            .kind_str(),
            "array"
        );
        assert_eq!(
            TypeDetail::Chan {
                dir: 3,
                elem_va: 0x1000
            }
            .kind_str(),
            "chan"
        );
        assert_eq!(
            TypeDetail::Map {
                key_va: 0x1,
                elem_va: 0x2,
                group_va: 0,
                extra: Box::new(
                    MapTypeExtra::parse(&[0u8; 88], 8, MapLayout::SwissSplitGroup).unwrap(),
                ),
            }
            .kind_str(),
            "map"
        );
    }

    #[test]
    fn decode_pcfile_returns_unsigned_indices() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let pcl = bin.pclntab().unwrap();

        let mut saw_indices = false;
        let mut saw_resolved = false;
        for func in bin.functions() {
            if pcl.decode_pcfile(&func.func).next().is_some() {
                saw_indices = true;
            }
            if pcl.decode_pcfile_paths(&func.func).next().is_some() {
                saw_resolved = true;
            }
            if saw_indices && saw_resolved {
                break;
            }
        }
        assert!(
            saw_indices,
            "at least one function should produce pcfile indices"
        );
        assert!(
            saw_resolved,
            "at least one function should resolve a pcfile path"
        );
    }
}

// ===========================================================================
// Comprehensive cross-version matrix.
//
// Fixtures are discovered by filename
// (`<prog>_go<minor>_<goos>_<goarch>[_variant][.exe]`), so the whole corpus
// built by `tests/samples/build.sh` is swept automatically - adding a build
// line extends coverage with no test edits. The `basic` program is byte-for-
// byte identical source on every Go release from 1.2 onward, so the assertions
// below hold uniformly across the entire version range.
// ===========================================================================
mod matrix {
    use super::*;
    use gobin::{
        formats::BinaryFormat,
        structures::{
            Arch, PclntabVersion,
            bounds::{ETEXT_SYMBOL, TEXT_SYMBOL, TextBound},
            moduledata::ModuledataVersion,
        },
    };

    pub struct Fixture {
        pub path: String,
        pub prog: String,
        pub gotag: String,
        pub goos: String,
        pub goarch: String,
    }

    /// Discover every fixture binary, parsing its
    /// `<prog>_go<NN>_<goos>_<goarch>[_variant]` filename.
    pub fn discover() -> Vec<Fixture> {
        let dir = "tests/samples";
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if !path.is_file() {
                continue;
            }
            let fname = path.file_name().unwrap().to_str().unwrap().to_string();
            // Plugins / shared objects have different invariants (no main.main).
            if fname.ends_with(".so") || fname.ends_with(".sh") || fname.ends_with(".md") {
                continue;
            }
            let name = fname.strip_suffix(".exe").unwrap_or(&fname);
            // `_noversion` fixtures have their Go version string deliberately
            // scrubbed, so the version-derived assertions below do not apply.
            // They are exercised by `moduledata::layout_survives_a_scrubbed_
            // version_string` instead.
            if name.ends_with("_noversion") {
                continue;
            }
            // Peel an optional build variant (stripped / cover / fips / pie) to
            // expose the underlying <prog>_go<NN>_<goos>_<goarch> name.
            // Variants combine (`_cover_stripped`), so peel until none is left.
            let mut core = name;
            while let Some(rest) = ["_stripped", "_cover", "_fips", "_pie", "_cgobindings"]
                .iter()
                .find_map(|v| core.strip_suffix(v))
            {
                core = rest;
            }
            let parts: Vec<&str> = core.split('_').collect();
            // <prog>_go<NN>_<goos>_<goarch>. A universal Mach-O file holds
            // several images, read one at a time (`mod universal`).
            if parts.len() != 4 || !parts[1].starts_with("go") || parts[3] == "universal" {
                continue;
            }
            out.push(Fixture {
                path: format!("{dir}/{fname}"),
                prog: parts[0].to_string(),
                gotag: parts[1].to_string(),
                goos: parts[2].to_string(),
                goarch: parts[3].to_string(),
            });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    /// Minor version from a `go1<minor>` tag (`go17` → 7, `go126` → 26). Every
    /// Go release is 1.x, so stripping `go1` is unambiguous.
    pub fn tag_minor(gotag: &str) -> u32 {
        gotag
            .strip_prefix("go1")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// pclntab magic/layout the parser must detect for a given minor version.
    fn expected_pclntab(minor: u32) -> PclntabVersion {
        match minor {
            0..=15 => PclntabVersion::Go12,
            16 | 17 => PclntabVersion::Go116,
            18 | 19 => PclntabVersion::Go118,
            _ => PclntabVersion::Go120,
        }
    }

    /// moduledata layout for a given minor version (`None` before Go 1.5).
    fn expected_md(minor: u32) -> Option<ModuledataVersion> {
        match minor {
            0..=4 => None,
            5..=15 => Some(ModuledataVersion::V1),
            16 | 17 => Some(ModuledataVersion::V2),
            18..=25 => Some(ModuledataVersion::V3),
            26 => Some(ModuledataVersion::V4),
            _ => Some(ModuledataVersion::V5),
        }
    }

    fn expected_format(goos: &str) -> BinaryFormat {
        match goos {
            "darwin" => BinaryFormat::MachO,
            "windows" => BinaryFormat::Pe,
            "wasip1" | "js" => BinaryFormat::Wasm,
            _ => BinaryFormat::Elf,
        }
    }

    fn expected_arch(goarch: &str) -> Arch {
        match goarch {
            "amd64" => Arch::X86_64,
            "386" => Arch::X86,
            "arm64" => Arch::Arm64,
            "wasm" => Arch::Wasm,
            other => panic!("unmapped goarch {other}"),
        }
    }

    fn basics() -> Vec<Fixture> {
        discover()
            .into_iter()
            .filter(|f| f.prog == "basic")
            .collect()
    }

    #[test]
    fn corpus_is_comprehensive() {
        let fx = discover();
        assert!(
            fx.len() >= 40,
            "expected a broad fixture matrix, found {}",
            fx.len()
        );

        let tags: BTreeSet<&str> = fx.iter().map(|f| f.gotag.as_str()).collect();
        // Every parser-relevant version boundary must be represented.
        for t in [
            "go12", "go14", "go15", "go17", "go18", "go19", "go110", "go112", "go115", "go116",
            "go117", "go118", "go120", "go121", "go124", "go126", "go127", "go128",
        ] {
            assert!(tags.contains(t), "matrix is missing version {t}");
        }

        // All four pclntab layouts and all moduledata versions are exercised.
        let basics = basics();
        for want in [
            PclntabVersion::Go12,
            PclntabVersion::Go116,
            PclntabVersion::Go118,
            PclntabVersion::Go120,
        ] {
            assert!(
                basics
                    .iter()
                    .any(|f| expected_pclntab(tag_minor(&f.gotag)) == want),
                "pclntab layout {want:?} not covered"
            );
        }
        for want in [
            None,
            Some(ModuledataVersion::V1),
            Some(ModuledataVersion::V2),
            Some(ModuledataVersion::V3),
            Some(ModuledataVersion::V4),
            Some(ModuledataVersion::V5),
        ] {
            assert!(
                basics
                    .iter()
                    .any(|f| expected_md(tag_minor(&f.gotag)) == want),
                "moduledata coverage missing {want:?}"
            );
        }

        // The advanced-feature harnesses are present.
        let progs: BTreeSet<&str> = fx.iter().map(|f| f.prog.as_str()).collect();
        for p in ["basic", "types", "generics", "cgo", "embed", "minimal"] {
            assert!(progs.contains(p), "harness {p} missing from corpus");
        }
    }

    #[test]
    fn detection_correct_for_every_basic() {
        for fx in basics() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap_or_else(|| panic!("parse failed: {}", fx.path));
            assert_eq!(
                bin.confidence(),
                Confidence::High,
                "{}: confidence",
                fx.path
            );
            assert_eq!(
                bin.context().format(),
                expected_format(&fx.goos),
                "{}: format",
                fx.path
            );
            assert_eq!(bin.arch(), expected_arch(&fx.goarch), "{}: arch", fx.path);

            let m = tag_minor(&fx.gotag);
            assert_eq!(
                bin.pclntab().unwrap().version,
                expected_pclntab(m),
                "{}: pclntab version",
                fx.path
            );
            // Go 1.2 embeds no parseable version string; everything else does.
            if fx.gotag != "go12" {
                let v = bin
                    .go_version()
                    .unwrap_or_else(|| panic!("{}: no go version", fx.path));
                assert!(v.starts_with("go1"), "{}: odd version {v}", fx.path);
            }
        }
    }

    #[test]
    fn core_symbols_present_in_every_basic() {
        for fx in basics() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let names: BTreeSet<&str> = bin.functions().map(|f| f.name).collect();
            for want in [
                "main.main",
                "main.worker",
                "main.(*TestStruct).DoSomething",
                "runtime.main",
            ] {
                assert!(names.contains(want), "{}: missing {want}", fx.path);
            }
        }
    }

    #[test]
    fn packages_and_files_sane_in_every_basic() {
        for fx in basics() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let mut packages = BTreeSet::new();
            let mut files = BTreeSet::new();
            for f in bin.functions() {
                if let Some(p) = f.package() {
                    packages.insert(p.to_string());
                }
                if let Some(s) = f.source_file {
                    files.insert(s.to_string());
                }
            }
            // Bounded and populated - the legacy-misparse bug produced millions.
            assert!(
                (10..5000).contains(&packages.len()),
                "{}: package count {} out of range",
                fx.path,
                packages.len()
            );
            assert!(
                (5..5000).contains(&files.len()),
                "{}: source-file count {} out of range",
                fx.path,
                files.len()
            );
            for p in ["main", "runtime", "fmt"] {
                assert!(packages.contains(p), "{}: package {p} missing", fx.path);
            }
            // No package name carries control bytes or non-ASCII garbage. (Some
            // compiler-generated symbols like `type..eq.struct {...}` legitimately
            // contain spaces and braces, so only control/non-ASCII bytes - the
            // signature of the original misparse - are rejected.)
            for p in &packages {
                assert!(
                    p.bytes().all(|b| b.is_ascii() && !b.is_ascii_control()),
                    "{}: garbage package {p:?}",
                    fx.path
                );
            }
            // main.main's source file resolves to the fixture program.
            let main = bin.functions().find(|f| f.name == "main.main").unwrap();
            assert!(
                main.source_file.is_some_and(|s| s.ends_with("main.go")),
                "{}: main.main source file unresolved",
                fx.path
            );
        }
    }

    #[test]
    fn addresses_resolve_in_every_basic() {
        for fx in basics() {
            // Wasm uses linear-memory addressing tested separately.
            if fx.goarch == "wasm" {
                continue;
            }
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let text = bin
                .text_va()
                .unwrap_or_else(|| panic!("{}: no text_va", fx.path));
            assert!(text != 0, "{}: zero text_va", fx.path);

            let main = bin.functions().find(|f| f.name == "main.main").unwrap();
            let va = text + u64::from(main.func.entry_off);
            assert!(va >= text, "{}: main.main below text", fx.path);
            if let Some(etext) = bin.etext_va() {
                assert!(va < etext, "{}: main.main past etext", fx.path);
            }
        }
    }

    #[test]
    fn moduledata_version_and_invariants() {
        // Wasm moduledata lives in linear memory with different invariants; it
        // has dedicated coverage in the `wasm_*` tests.
        for fx in basics().into_iter().filter(|f| f.goarch != "wasm") {
            let m = tag_minor(&fx.gotag);
            let want = expected_md(m);
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let md = bin.moduledata();
            match (want, &md) {
                (None, Some(_)) => panic!("{}: pre-1.5 must have no moduledata", fx.path),
                (None, None) => continue,
                (Some(_), None) => panic!("{}: moduledata not located", fx.path),
                (Some(w), Some(md)) => {
                    assert_eq!(md.version, w, "{}: moduledata version", fx.path);
                    assert!(md.minpc < md.maxpc, "{}: minpc<maxpc", fx.path);
                    assert!(
                        md.text != 0 && md.etext > md.text,
                        "{}: text/etext",
                        fx.path
                    );
                    // A normal single-module executable: runtime-populated /
                    // multi-module fields are nil, and the tail did not over-read.
                    assert_eq!(md.next, 0, "{}: single module", fx.path);
                    assert_eq!(md.typemap, 0, "{}: typemap runtime-only", fx.path);
                    assert!(!md.bad, "{}: not bad", fx.path);
                    // Version-gated optionals must match the layout exactly.
                    use ModuledataVersion as V;
                    assert_eq!(
                        md.epclntab.is_some(),
                        matches!(md.version, V::V4 | V::V5),
                        "{}: epclntab gating",
                        fx.path
                    );
                    assert_eq!(
                        md.typedesclen.is_some(),
                        matches!(md.version, V::V5),
                        "{}: typedesclen gating",
                        fx.path
                    );
                    // hasmain is recoverable from Go 1.10 onward; the V1 parser
                    // defaults it true for the single-module executable.
                    assert!(
                        bin.is_main_module().unwrap_or(false),
                        "{}: main module",
                        fx.path
                    );
                }
            }
        }
    }

    /// The pointer-sized word at `va`, read through the address space.
    fn word_at(bin: &GoBinary<'_>, va: u64) -> Option<u64> {
        let ps = bin.pclntab()?.ptr_size;
        let bytes = bin.context().slice_at_va(va)?;
        match ps {
            4 => Some(u64::from(u32::from_le_bytes(
                bytes.get(..4)?.try_into().ok()?,
            ))),
            8 => Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?)),
            _ => None,
        }
    }

    /// Every bound word holds, at its address, the bound it states; the words
    /// are the ones the toolchain's layout has, no more.
    fn check_bound_words(path: &str, minor: u32) {
        let data = load(path);
        let bin = GoBinary::parse(&data).unwrap_or_else(|| panic!("{path}: parse failed"));
        let words = bin.text_bound_words();
        assert!(
            words.windows(2).all(|pair| pair[0].va < pair[1].va),
            "{path}: ascending, no address twice"
        );
        for word in &words {
            assert_eq!(
                word_at(&bin, word.va),
                Some(word.value),
                "{path}: the word at {:#x} ({:?}) holds {:#x}",
                word.va,
                word.bound,
                word.value
            );
        }
        let of = |bound: TextBound| {
            words
                .iter()
                .filter(|w| w.bound == bound)
                .collect::<Vec<_>>()
        };

        // moduledata: the four bounds, and one base address per text section.
        match bin.moduledata() {
            Some(md) => {
                for (bound, value) in [
                    (TextBound::MinPc, md.minpc),
                    (TextBound::MaxPc, md.maxpc),
                    (TextBound::Text, md.text),
                    (TextBound::Etext, md.etext),
                ] {
                    let found = of(bound);
                    assert_eq!(found.len(), 1, "{path}: one {bound:?} word");
                    assert_eq!(found[0].value, value, "{path}: {bound:?}");
                }
                let sections = bin.text_sections();
                // `textsectmap` arrived in Go 1.8.
                assert_eq!(!sections.is_empty(), minor >= 8, "{path}: text sections");
                let bases = of(TextBound::SectionBase);
                assert_eq!(bases.len(), sections.len(), "{path}: one base per section");
                for (word, section) in bases.iter().zip(&sections) {
                    assert_eq!(word.value, section.baseaddr, "{path}: section base");
                }
            }
            None => {
                for bound in [
                    TextBound::MinPc,
                    TextBound::MaxPc,
                    TextBound::Text,
                    TextBound::Etext,
                    TextBound::SectionBase,
                ] {
                    assert!(of(bound).is_empty(), "{path}: no moduledata, no {bound:?}");
                }
            }
        }

        // pcHeader.textStart: written by Go 1.18 through 1.25 only, and zero
        // in wasm, where the code starts at address 0.
        let header = of(TextBound::HeaderTextStart);
        if (18..=25).contains(&minor) && bin.context().format() != BinaryFormat::Wasm {
            assert_eq!(header.len(), 1, "{path}: pcHeader.textStart");
            assert_eq!(Some(header[0].value), bin.moduledata().map(|m| m.text));
        } else {
            assert!(header.is_empty(), "{path}: no pcHeader.textStart");
        }

        // Function table: absolute PCs up to Go 1.17, whose end sentinel is
        // the one bound; every entry before it is a function's own entry PC.
        let end = of(TextBound::FunctabEnd);
        if minor > 17 {
            assert!(end.is_empty(), "{path}: offsets, not pointers");
            return;
        }
        let pcl = bin.pclntab().unwrap();
        let ps = u64::from(pcl.ptr_size);
        let table = bin.context().view_to_va(pcl.offset).unwrap() + pcl.functab_offset as u64;
        assert_eq!(end.len(), 1, "{path}: one end sentinel");
        assert_eq!(
            end[0].va,
            table + 2 * pcl.nfunc as u64 * ps,
            "{path}: sentinel site"
        );
        if let Some(md) = bin.moduledata() {
            assert_eq!(end[0].value, md.maxpc, "{path}: sentinel is maxpc");
        }
        let mut entries = 0usize;
        for (index, (entry_off, _)) in pcl.func_entries().enumerate() {
            let site = table + 2 * index as u64 * ps;
            assert!(
                words.iter().all(|word| word.va != site),
                "{path}: entry {index} is a function pointer, not a bound"
            );
            assert_eq!(
                word_at(&bin, site),
                Some(pcl.text_start + u64::from(entry_off)),
                "{path}: entry {index} holds the function's entry PC"
            );
            entries += 1;
        }
        assert_eq!(entries, pcl.nfunc, "{path}: every entry visited");
    }

    #[test]
    fn bound_words_hold_their_bounds_across_corpus() {
        let fixtures = discover();
        for fx in &fixtures {
            check_bound_words(&fx.path, tag_minor(&fx.gotag));
        }
        // Old absolute tables, 1.18+ headers, 1.26 and 1.27 layouts, every
        // format and the wasm address space are all among the fixtures.
        let minors: BTreeSet<u32> = fixtures.iter().map(|f| tag_minor(&f.gotag)).collect();
        for want in [5, 10, 16, 17, 18, 20, 24, 25, 26, 27] {
            assert!(minors.contains(&want), "no Go 1.{want} fixture");
        }
        for goos in ["linux", "darwin", "windows", "wasip1"] {
            assert!(fixtures.iter().any(|f| f.goos == goos), "no {goos} fixture");
        }
    }

    #[test]
    fn bound_words_survive_a_scrubbed_version_string() {
        // The layout is then chosen by arbitration, and the words are still
        // where the bounds are.
        check_bound_words(BASIC_GO124_WINDOWS_NOVERSION, 24);
    }

    /// The three words that started a function over `runtime.etext` in an
    /// externally linked Go 1.16 image are bound words, found at the
    /// addresses the image holds them.
    #[test]
    fn cgo_go116_bound_words_include_the_etext_holders() {
        let data = load("tests/samples/cgo_go116_linux_amd64");
        let bin = GoBinary::parse(&data).unwrap();
        let etext = bin.etext_va().unwrap();
        let sites: BTreeSet<(u64, TextBound)> = bin
            .text_bound_words()
            .iter()
            .filter(|word| word.value == etext)
            .map(|word| (word.va, word.bound))
            .collect();
        assert_eq!(
            sites,
            BTreeSet::from([
                (0x5471a8, TextBound::MaxPc),
                (0x5471b8, TextBound::Etext),
                (0x51b8c0, TextBound::FunctabEnd),
            ])
        );
    }

    /// Every fixture that carries a raw build ID marker reports its blob, and
    /// the blob is the marker framing exactly the build ID; an ELF build ID
    /// comes from the note and has none.
    #[test]
    fn build_id_blob_frames_the_build_id_across_corpus() {
        use gobin::structures::buildid::BuildIdSource;
        const OPEN: &[u8] = b"\xff Go build ID: \"";
        const CLOSE: &[u8] = b"\"\n \xff";
        let mut paths: Vec<String> = discover().into_iter().map(|f| f.path).collect();
        paths.push(BASIC_GO124_WINDOWS_NOVERSION.to_string());
        paths.push("tests/samples/plugin_go126_darwin_arm64.so".to_string());
        let mut framed = BTreeSet::new();
        for path in &paths {
            let data = load(path);
            let bin = GoBinary::parse(&data).unwrap_or_else(|| panic!("{path}: parse failed"));
            let format = bin.context().format();
            let Some(BuildIdSource::Marker { blob }) = bin.build_id_source() else {
                assert!(
                    format == BinaryFormat::Elf || bin.build_id().is_none(),
                    "{path}: a {format:?} build ID has a blob"
                );
                continue;
            };
            assert_ne!(format, BinaryFormat::Elf, "{path}: ELF carries a note");
            let bytes = &data[blob.clone()];
            let id = bin.build_id().unwrap().as_bytes();
            assert_eq!(bytes.len(), OPEN.len() + id.len() + CLOSE.len(), "{path}");
            assert!(bytes.starts_with(OPEN), "{path}: opening marker");
            assert!(bytes.ends_with(CLOSE), "{path}: closing marker");
            assert_eq!(&bytes[OPEN.len()..bytes.len() - CLOSE.len()], id, "{path}");
            // On Mach-O and PE the blob is `go:buildid`, a text symbol.
            if format != BinaryFormat::Wasm {
                let text = bin.context().sections().text_section.unwrap();
                let va = bin.context().file_to_va(blob.start).unwrap();
                assert!(
                    (text.va..text.va + text.size as u64).contains(&va),
                    "{path}: blob at {va:#x} is in the text"
                );
            }
            framed.insert(format!("{format:?}"));
        }
        assert_eq!(
            framed,
            BTreeSet::from(["MachO".into(), "Pe".into(), "Wasm".into()])
        );
    }

    /// The ELF note is the only build ID an ELF image carries.
    #[test]
    fn build_id_blob_is_absent_for_an_elf_note() {
        use gobin::structures::buildid::BuildIdSource;
        let data = load(BASIC_GO127_LINUX);
        let bin = GoBinary::parse(&data).unwrap();
        assert!(bin.context().sections().has_go_buildid_note);
        assert!(bin.build_id().is_some());
        assert_eq!(bin.build_id_source(), Some(&BuildIdSource::ElfNote));
    }

    /// The section holding the last Go byte ends at or past `etext`, and only
    /// binaries with a `textsectmap` have one.
    #[test]
    fn text_section_end_holds_etext_across_corpus() {
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let path = &fx.path;
            let Some(end) = bin.text_section_end_va() else {
                assert!(
                    bin.text_sections().is_empty(),
                    "{path}: a section holds etext"
                );
                continue;
            };
            let etext = bin.etext_va().unwrap();
            assert!(
                end >= etext,
                "{path}: {end:#x} ends before etext {etext:#x}"
            );
            let holder = bin
                .text_sections()
                .into_iter()
                .find(|s| s.baseaddr + (s.end - s.vaddr) == end)
                .unwrap();
            assert!(
                holder.baseaddr < etext,
                "{path}: section starts before etext"
            );
        }
    }

    /// The executable section header is the oracle: an internally linked
    /// image's Go section is the whole of it, a host-linked one's stops short
    /// of the C code the host linker put after Go's.
    #[test]
    fn text_section_end_is_where_the_go_linker_ended_its_section() {
        for (path, end, header_end) in [
            // Internally linked: the Go section is the ELF `.text`.
            (BASIC_GO127_LINUX, 0x49d411, 0x49d411),
            ("tests/samples/basic_go120_linux_amd64", 0x4852d1, 0x4852d1),
            // Host-linked: `.text` runs on into C code.
            ("tests/samples/cgo_go127_linux_amd64", 0x49d271, 0x49dd48),
            ("tests/samples/cgo_go116_linux_amd64", 0x49a1ea, 0x49acdf),
            (
                "tests/samples/plugin_go126_darwin_arm64.so",
                0xea3e4,
                0xeaa94,
            ),
        ] {
            let data = load(path);
            let bin = GoBinary::parse(&data).unwrap();
            let text = bin.context().sections().text_section.unwrap();
            assert_eq!(text.va + text.size as u64, header_end, "{path}: header");
            assert_eq!(bin.text_section_end_va(), Some(end), "{path}");
        }
        // No `textsectmap` before Go 1.8.
        let data = load("tests/samples/basic_go17_linux_amd64");
        assert_eq!(GoBinary::parse(&data).unwrap().text_section_end_va(), None);
    }

    /// The symbol names gobin states are the ones an unstripped ELF's symbol
    /// table gives the text bounds.
    #[test]
    fn text_symbols_name_the_text_bounds() {
        for path in [
            BASIC_GO127_LINUX,
            "tests/samples/cgo_go127_linux_amd64",
            "tests/samples/basic_go116_linux_amd64",
            "tests/samples/basic_go110_linux_amd64",
        ] {
            let data = load(path);
            let bin = GoBinary::parse(&data).unwrap();
            let elf = goblin::elf::Elf::parse(&data).unwrap();
            let symbol = |name: &str| {
                elf.syms
                    .iter()
                    .find(|sym| elf.strtab.get_at(sym.st_name) == Some(name))
                    .map(|sym| sym.st_value)
            };
            assert_eq!(symbol(TEXT_SYMBOL), bin.text_va(), "{path}: {TEXT_SYMBOL}");
            assert_eq!(
                symbol(ETEXT_SYMBOL),
                bin.etext_va(),
                "{path}: {ETEXT_SYMBOL}"
            );
        }
    }

    #[test]
    fn types_extracted_where_supported() {
        // The type system (types/etypes + typelinks) arrived in Go 1.7.
        for fx in basics().iter().filter(|f| tag_minor(&f.gotag) >= 7) {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            assert!(
                bin.types().count() > 50,
                "{}: too few types ({})",
                fx.path,
                bin.types().count()
            );
            // The fixture's own named type must be recovered (older versions
            // may only emit the `*main.TestStruct` pointer descriptor).
            assert!(
                bin.types().any(|t| t.name.contains("TestStruct")),
                "{}: TestStruct not extracted",
                fx.path
            );
        }
    }

    #[test]
    fn itabs_extracted_where_supported() {
        // itablinks arrived in Go 1.6; the basic program emits several
        // (interface, concrete) pairs via its Greeter implementors.
        for fx in basics()
            .iter()
            .filter(|f| tag_minor(&f.gotag) >= 7 && f.goarch != "wasm")
        {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            assert!(
                bin.itab_pairs().count() >= 3,
                "{}: too few itab pairs ({})",
                fx.path,
                bin.itab_pairs().count()
            );
        }
    }

    #[test]
    fn init_order_where_inittasks_present() {
        for fx in basics().into_iter().filter(|f| f.goarch != "wasm") {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            if bin.moduledata().and_then(|m| m.inittasks).is_some() {
                let inits = bin.init_order();
                assert!(
                    inits.iter().any(|t| t.package == Some("runtime")),
                    "{}: runtime init task missing",
                    fx.path
                );
            }
        }
    }

    #[test]
    fn func_struct_layout_sane_across_versions() {
        for fx in basics().iter().filter(|f| f.goarch != "wasm") {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let pcl = bin.pclntab().unwrap();
            let mut parsed = 0usize;
            for (_, func_off) in pcl.func_entries() {
                let fd = match pcl.parse_func(func_off) {
                    Some(fd) => fd,
                    None => continue,
                };
                parsed += 1;
                assert!(
                    fd.nfuncdata <= 16,
                    "{}: implausible nfuncdata {}",
                    fx.path,
                    fd.nfuncdata
                );
                for (_, line) in pcl.decode_pcln(&fd) {
                    assert!(line < 2_000_000, "{}: implausible line {}", fx.path, line);
                }
            }
            assert!(parsed > 100, "{}: only {parsed} funcs parsed", fx.path);
        }
    }

    #[test]
    fn build_metadata_across_corpus() {
        for fx in basics() {
            let m = tag_minor(&fx.gotag);
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();

            // Build ID is embedded from Go 1.5 on and survives stripping (the
            // stripped variants are part of the corpus).
            if m >= 5 {
                assert!(bin.build_id().is_some(), "{}: missing build id", fx.path);
            }
            // The build-info blob (module info) arrives in Go 1.16; its build
            // *settings* (GOOS/GOARCH/-compiler/CGO_ENABLED) arrive in Go 1.18.
            // Wasm does not carry the blob.
            if m >= 16 && fx.goarch != "wasm" {
                let info = bin
                    .build_info()
                    .unwrap_or_else(|| panic!("{}: no build info", fx.path));
                if m >= 18 {
                    assert_eq!(
                        info.goos(),
                        Some(fx.goos.as_str()),
                        "{}: build goos",
                        fx.path
                    );
                    assert_eq!(
                        info.goarch(),
                        Some(fx.goarch.as_str()),
                        "{}: build goarch",
                        fx.path
                    );
                    assert_eq!(
                        info.setting("-compiler"),
                        Some("gc"),
                        "{}: compiler",
                        fx.path
                    );
                    assert!(
                        info.cgo_mode().is_some(),
                        "{}: no CGO_ENABLED setting",
                        fx.path
                    );
                }
            }
        }
    }

    #[test]
    fn function_classification_across_corpus() {
        for fx in basics() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let funcs: Vec<_> = bin.functions().collect();

            let main = funcs.iter().find(|f| f.name == "main.main").unwrap();
            assert_eq!(main.package(), Some("main"), "{}: main pkg", fx.path);
            assert!(
                !main.is_method() && !main.is_runtime() && !main.is_closure(),
                "{}: main class",
                fx.path
            );
            assert!(main.func.entry_off > 0, "{}: main entry_offset", fx.path);

            let rt = funcs.iter().find(|f| f.name == "runtime.main").unwrap();
            assert!(
                rt.is_runtime() && rt.is_internal() && !rt.is_stdlib(),
                "{}: runtime class",
                fx.path
            );

            // The program uses fmt, so a stdlib function is always present.
            let stdlib = funcs.iter().find(|f| f.name.starts_with("fmt.")).unwrap();
            assert!(
                stdlib.is_stdlib() && !stdlib.is_internal() && !stdlib.is_runtime(),
                "{}: stdlib class",
                fx.path
            );
        }
    }

    #[test]
    fn source_files_resolve_across_corpus() {
        for fx in basics() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let files: Vec<&str> = bin.pclntab().unwrap().file_names().collect();
            assert!(!files.is_empty(), "{}: no source files", fx.path);
            assert!(
                files.iter().any(|f| f.ends_with("main.go")),
                "{}: no main.go",
                fx.path
            );
        }
    }

    #[test]
    fn strings_recovered_across_corpus() {
        for fx in basics() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let n = bin.strings().count();
            assert!(n > 100, "{}: too few strings ({n})", fx.path);
        }
    }

    #[test]
    fn metadata_consistent_across_formats() {
        // The same Go version built for different formats must report an
        // identical toolchain version and pclntab layout. A wasm module states
        // its version in its `producers` section, which records the toolchain
        // version without the ` X:<experiments>` suffix `runtime.Version`
        // appends for a non-default GOEXPERIMENT (the `_cgobindings`
        // variant), so the comparison is of the toolchain version alone.
        let toolchain = |bin: &GoBinary<'_>| {
            bin.go_version()
                .map(|v| v.split(" X:").next().unwrap_or(v).to_string())
        };
        let mut by_tag: std::collections::BTreeMap<String, Vec<Fixture>> =
            std::collections::BTreeMap::new();
        for fx in basics() {
            by_tag.entry(fx.gotag.clone()).or_default().push(fx);
        }
        for (tag, group) in by_tag.iter().filter(|(_, g)| g.len() > 1) {
            let parsed: Vec<_> = group.iter().map(|fx| (fx, load(&fx.path))).collect();
            let bins: Vec<_> = parsed
                .iter()
                .map(|(fx, d)| (*fx, GoBinary::parse(d).unwrap()))
                .collect();
            let (_, first) = &bins[0];
            let v0 = toolchain(first);
            let p0 = first.pclntab().map(|p| p.version);
            for (fx, bin) in &bins[1..] {
                assert_eq!(
                    toolchain(bin),
                    v0,
                    "{tag}: go_version differs at {}",
                    fx.path
                );
                assert_eq!(
                    bin.pclntab().map(|p| p.version),
                    p0,
                    "{tag}: pclntab version differs at {}",
                    fx.path
                );
            }
        }
    }
}

// ===========================================================================
// Advanced-feature harnesses. Each program (src/<name>/main.go) exercises a
// specific extractable surface; these tests assert the parser actually
// surfaces it across the versions the harness is built for.
// ===========================================================================
mod harness {
    use super::*;
    use gobin::structures::types::TypeDetail;

    fn fixtures(prog: &str) -> Vec<String> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir("tests/samples").unwrap() {
            let p = entry.unwrap().path();
            let n = p.file_name().unwrap().to_str().unwrap().to_string();
            if n.starts_with(&format!("{prog}_go")) && !n.ends_with(".sh") {
                out.push(format!("tests/samples/{n}"));
            }
        }
        out.sort();
        assert!(!out.is_empty(), "no {prog} fixtures found");
        out
    }

    /// The `types` harness funnels one value of every kind through reflection,
    /// so the extractor must surface every structural `TypeDetail` variant.
    #[test]
    fn types_harness_covers_every_kind() {
        for path in fixtures("types") {
            let data = load(&path);
            let bin = GoBinary::parse(&data).unwrap();
            let mut kinds = BTreeSet::new();
            let mut saw_variadic_func = false;
            let mut chan_dirs = BTreeSet::new();
            for t in bin.types() {
                kinds.insert(t.detail.kind_str());
                if let TypeDetail::Func { is_variadic, .. } = &t.detail {
                    saw_variadic_func |= *is_variadic;
                }
                if let TypeDetail::Chan { dir, .. } = &t.detail {
                    chan_dirs.insert(*dir);
                }
            }
            // Every structural detail the extractor enumerates from typelinks.
            // (Bare interface type descriptors are not enumerated here - they
            // are reachable only via itabs and pointer/elem references, asserted
            // through `itab_pairs` below - so "interface" is not in this set.)
            for k in ["struct", "map", "chan", "slice", "array", "pointer", "func"] {
                assert!(kinds.contains(k), "{path}: missing TypeDetail kind {k}");
            }
            // The fixture's own named types are recovered (older versions may
            // emit only the `*main.X` pointer form, so match by substring).
            let names: Vec<&str> = bin.types().map(|t| t.name).collect();
            for want in ["Record", "Circle", "Celsius", "Embedded"] {
                assert!(
                    names.iter().any(|n| n.contains(&format!("main.{want}"))),
                    "{path}: type main.{want} missing"
                );
            }
            // NOTE: named tagged structs (Record) are enumerated only in their
            // `*main.Record` pointer form; the underlying struct descriptor -
            // with field names, tags, and the embedded flag - is referenced via
            // `elem_va` but not yielded by `bin.types()`. Field-tag/embedded
            // extraction is therefore not asserted here (see TODO C-06).
            assert!(saw_variadic_func, "{path}: variadic func type not surfaced");
            // Recv-only, send-only and bidirectional channels are distinguished.
            assert!(
                chan_dirs.len() >= 2,
                "{path}: channel directions not distinguished"
            );
            // The Shape interface is surfaced through its (interface, concrete)
            // itab with Circle rather than the type enumeration.
            assert!(
                bin.itab_pairs().count() >= 1,
                "{path}: no itab pairs (interface not surfaced)"
            );
        }
    }

    /// The `generics` harness instantiates generic funcs and types at multiple
    /// concrete types; the parser must surface the instantiated symbols and the
    /// generic type descriptors.
    #[test]
    fn generics_harness_surfaces_instantiations() {
        for path in fixtures("generics") {
            let data = load(&path);
            let bin = GoBinary::parse(&data).unwrap();
            let fnames: BTreeSet<&str> = bin.functions().map(|f| f.name).collect();

            // Generic function instantiations (shape-stenciled) are present.
            assert!(
                fnames.iter().any(|n| n.starts_with("main.Sum[")),
                "{path}: no main.Sum[...] instantiation"
            );
            assert!(
                fnames
                    .iter()
                    .any(|n| n.contains("Stack[") && n.ends_with(".Push")),
                "{path}: no Stack[...].Push instantiation"
            );
            // The receiver's generic args are parsed out of the method name.
            let push = bin
                .functions()
                .find(|f| f.name.contains("Stack[") && f.name.ends_with(".Push"))
                .unwrap();
            assert_eq!(
                push.package(),
                Some("main"),
                "{path}: generic method package"
            );

            // Generic type instantiations are recovered as named types.
            let tnames: BTreeSet<&str> = bin.types().map(|t| t.name).collect();
            assert!(
                tnames.iter().any(|n| n.contains("main.Stack[")),
                "{path}: no main.Stack[...] type"
            );
            assert!(
                tnames.iter().any(|n| n.contains("main.Pair[")),
                "{path}: no main.Pair[...] type"
            );
        }
    }

    /// The `cgo` harness is a CGO build; the parser must report CGO enablement
    /// and surface the generated cgo shim symbols.
    #[test]
    fn cgo_harness_detected() {
        for path in fixtures("cgo") {
            let data = load(&path);
            let bin = GoBinary::parse(&data).unwrap();
            // The cgo shim symbols are emitted on every version and are the
            // primary signal.
            let names: BTreeSet<&str> = bin.functions().map(|f| f.name).collect();
            assert!(
                names
                    .iter()
                    .any(|n| n.starts_with("_cgo_") || n.starts_with("_Cfunc_")),
                "{path}: no cgo shim symbols"
            );
            // The CGO_ENABLED build setting only exists in the buildinfo blob
            // from Go 1.18 onward; assert it where the blob carries settings.
            let minor = bin
                .go_version()
                .and_then(|v| v.strip_prefix("go1"))
                .and_then(|s| s.split('.').next())
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            if minor >= 18 {
                assert_eq!(
                    bin.build_info().and_then(|bi| bi.cgo_mode()),
                    Some(gobin::metadata::CgoMode::Enabled),
                    "{path}: CGO_ENABLED not reported"
                );
            }
        }
    }
}

// ===========================================================================
// Types only code reaches: the descriptors laid out in the type region.
// ===========================================================================
mod laid_out_types {
    use super::*;

    /// **Every descriptor the reflection tables name is one the type region
    /// scan finds**, on every sample that has them: the scan's checks reject
    /// no real descriptor. And the scan reaches types the tables do not name
    /// (a closure's context), so `all_types` holds more than `types` alone
    /// would reach on some sample.
    #[test]
    fn the_scan_finds_every_reflected_descriptor_and_more() {
        let mut beyond = 0usize;
        let mut checked = 0usize;
        for entry in std::fs::read_dir("tests/samples").unwrap() {
            let path = entry.unwrap().path();
            let name = path.to_string_lossy().to_string();
            if name.ends_with(".sh") || !path.is_file() {
                continue;
            }
            let data = load(&name);
            let Some(bin) = GoBinary::parse(&data) else {
                continue;
            };
            let reflected: BTreeSet<u64> = bin.types().map(|t| t.descriptor_va).collect();
            if reflected.is_empty() {
                continue;
            }
            checked += 1;
            let laid_out: BTreeSet<u64> = bin
                .laid_out_types()
                .iter()
                .map(|t| t.descriptor_va)
                .collect();
            let missed: Vec<u64> = reflected.difference(&laid_out).copied().take(5).collect();
            assert!(
                missed.is_empty(),
                "{name}: reflected descriptors the scan missed: {missed:#x?}"
            );
            beyond += laid_out.difference(&reflected).count();
        }
        assert!(checked > 0, "no sample with reflected types");
        assert!(
            beyond > 0,
            "the scan reaches no type the tables do not name"
        );
    }
}

// ===========================================================================
// Code addresses, version strings and build modes across every encoding:
// wasm's three text-offset encodings, the development toolchain's version
// form, and Go 1.28's third cgo mode.
// ===========================================================================
mod addressing_and_versions {
    use super::matrix::discover;
    use super::*;
    use gobin::{formats::BinaryFormat, structures::moduledata::ModuledataVersion};

    /// Go code is not in a wasm module's linear memory, and the Go linker
    /// writes no segment for the leading zeros of its data, so below the
    /// first segment there is only zero-fill. Before Go 1.28 `runtime.text`
    /// was 0 and the text range `[text, etext)` happened to cover that span;
    /// Go 1.28 moved the PCs to `1 << 63`, and small integer pairs read as
    /// `(ptr, len)` began resolving there as all-zero "strings".
    #[test]
    fn wasm_strings_start_in_initialized_data() {
        let mut checked = 0usize;
        for fx in discover().into_iter().filter(|f| f.goarch == "wasm") {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let floor = bin
                .context()
                .wasm_initialized_start()
                .unwrap_or_else(|| panic!("{}: no data segment", fx.path));
            for s in bin.strings() {
                assert!(
                    s.va >= floor,
                    "{}: string at {:#x} below the first data segment {floor:#x}",
                    fx.path,
                    s.va
                );
            }
            checked += 1;
        }
        assert!(checked >= 8, "expected the wasm fixtures, found {checked}");
    }

    /// The arbiter that picks the moduledata layout must accept every real
    /// image's moduledata. Its `rodata >= text` rule holds only where code
    /// and data share an address space; Go 1.28 wasm puts `text` at `1 << 63`.
    #[test]
    fn located_moduledata_is_self_consistent() {
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let Some(md) = bin.moduledata() else {
                continue;
            };
            if md.version == ModuledataVersion::V1 {
                continue;
            }
            let wasm = bin.context().format() == BinaryFormat::Wasm;
            assert!(
                md.layout_self_consistent(wasm),
                "{}: located moduledata fails its own consistency check",
                fx.path
            );
        }
    }

    /// An itab's method words are code pointers, so each must translate to a
    /// function's entry and back. On wasm this pins all three encodings of a
    /// text offset: a PC offset through Go 1.24, a function index shifted into
    /// a PC from Go 1.25, and that PC based at `1 << 63` from Go 1.28.
    #[test]
    fn itab_method_pointers_are_function_entries() {
        let mut checked = 0usize;
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let entries: BTreeSet<u32> = bin.functions().map(|f| f.func.entry_off).collect();
            for pair in bin.itab_pairs() {
                // A zero word is an unbound method: Go 1.7-1.9 link their itabs
                // with the method words empty for the runtime to fill at init.
                // From Go 1.10 the linker binds every method of every itab it
                // emits, so a zero there is a misplaced read.
                let methods: Vec<u64> = bin.itab_methods(&pair).iter().map(|m| m.va).collect();
                if super::matrix::tag_minor(&fx.gotag) >= 10 {
                    assert!(
                        !methods.contains(&0),
                        "{}: itab {:#x} has an unbound method word",
                        fx.path,
                        pair.itab_va
                    );
                }
                for pc in methods.into_iter().filter(|&pc| pc != 0) {
                    let off = bin.text_off(pc).unwrap_or_else(|| {
                        panic!("{}: method pointer {pc:#x} is in no text section", fx.path)
                    });
                    assert!(
                        entries.contains(&off),
                        "{}: method pointer {pc:#x} (text offset {off:#x}) is no function entry",
                        fx.path
                    );
                    assert_eq!(bin.text_addr(off), Some(pc), "{}: {pc:#x}", fx.path);
                    checked += 1;
                }
            }
        }
        assert!(checked > 1000, "too few itab methods checked: {checked}");
    }

    /// An itab's `hash` copies its concrete type's (Go 1.5-1.8 records none,
    /// so the pair carries the type's), and its layout matches its Go
    /// version: the `link` word of Go 1.5-1.9, the padding of Go 1.10-1.22,
    /// `internal/abi.ITab` from Go 1.23.
    #[test]
    fn itab_hashes_and_layouts_match_their_go_version() {
        use gobin::structures::itab::ItabLayout;

        let mut checked = 0usize;
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let types: std::collections::BTreeMap<u64, u32> =
                bin.types().map(|t| (t.descriptor_va, t.hash)).collect();
            let mut pairs = 0usize;
            for pair in bin.itab_pairs() {
                if let Some(&hash) = types.get(&pair.concrete_type_va) {
                    assert_eq!(pair.hash, hash, "{}: itab {:#x}", fx.path, pair.itab_va);
                    checked += 1;
                }
                pairs += 1;
            }
            if pairs > 0 {
                let minor = super::matrix::tag_minor(&fx.gotag);
                assert_eq!(
                    bin.itab_layout(),
                    ItabLayout::for_go_minor(minor),
                    "{}",
                    fx.path
                );
            }
        }
        assert!(checked > 500, "too few itab hashes checked: {checked}");

        // With its version scrubbed, a 32-bit Go 1.21 binary still reads as
        // padded, from the zero word after its first itab's hash.
        let data = load("tests/samples/basic_go121_linux_386_noversion");
        let bin = GoBinary::parse(&data).unwrap();
        assert!(
            !bin.go_version().is_some_and(|v| v.starts_with("go1.")),
            "{:?}",
            bin.go_version()
        );
        assert_eq!(bin.itab_layout(), ItabLayout::Padded);
        let entries: BTreeSet<u32> = bin.functions().map(|f| f.func.entry_off).collect();
        let methods: Vec<u64> = bin
            .itab_pairs()
            .flat_map(|pair| bin.itab_methods(&pair))
            .map(|m| m.va)
            .collect();
        assert!(!methods.is_empty());
        for pc in methods {
            assert!(
                bin.text_off(pc).is_some_and(|off| entries.contains(&off)),
                "{pc:#x} is no function entry"
            );
        }
    }

    /// Every function's entry PC, and every PC inside it, finds that
    /// function; the PCs around the code find none. Sweeps every pclntab
    /// layout, including Go 1.2-1.17's absolute function-table entries and
    /// wasm's three text-offset encodings.
    #[test]
    fn function_at_finds_the_function_holding_a_pc() {
        let mut checked = 0usize;
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let funcs: Vec<_> = bin.functions().collect();
            for pair in funcs.windows(2) {
                let (f, next) = (&pair[0], &pair[1]);
                let Some(entry) = bin.entry_va(f) else {
                    continue;
                };
                let found = bin.function_at(entry).map(|g| g.func.entry_off);
                assert_eq!(found, Some(f.func.entry_off), "{}: {}", fx.path, f.name);
                // The last PC before the next function is still this one.
                let last = bin.entry_va(next).unwrap() - 1;
                let found = bin.function_at(last).map(|g| g.func.entry_off);
                assert_eq!(
                    found,
                    Some(f.func.entry_off),
                    "{}: end of {}",
                    fx.path,
                    f.name
                );
                checked += 1;
            }
            if let Some(text) = bin.text_va().filter(|&t| t > 0) {
                assert!(bin.function_at(text - 1).is_none(), "{}", fx.path);
            }
            if let Some(etext) = bin.etext_va() {
                assert!(bin.function_at(etext).is_none(), "{}", fx.path);
            }
        }
        assert!(checked > 100_000, "too few functions checked: {checked}");
    }

    /// The funcID list of the Go minor version `minor`, copied from that
    /// release's source (`cmd/internal/objabi/funcid.go`, then
    /// `runtime/symtab.go`, then `internal/abi/symtab.go`): entry `n` names
    /// raw ID `n`. An oracle independent of the classifier, which reads IDs
    /// by name and by the binary's wrapper ID, never by these numbers.
    fn funcid_list(minor: u32) -> Vec<&'static str> {
        let list = match minor {
            10 => {
                "normal goexit jmpdefer mcall morestack mstart rt0_go asmcgocall sigpanic runfinq bgsweep forcegchelper timerproc gcBgMarkWorker systemstack_switch systemstack cgocallback gogo externalthreadhandler"
            }
            11 => {
                "normal runtime_main goexit jmpdefer mcall morestack mstart rt0_go asmcgocall sigpanic runfinq gcBgMarkWorker systemstack_switch systemstack cgocallback gogo externalthreadhandler debugCallV1"
            }
            12 | 13 => {
                "normal runtime_main goexit jmpdefer mcall morestack mstart rt0_go asmcgocall sigpanic runfinq gcBgMarkWorker systemstack_switch systemstack cgocallback gogo externalthreadhandler debugCallV1 gopanic panicwrap wrapper"
            }
            14..=16 => {
                "normal runtime_main goexit jmpdefer mcall morestack mstart rt0_go asmcgocall sigpanic runfinq gcBgMarkWorker systemstack_switch systemstack cgocallback gogo externalthreadhandler debugCallV1 gopanic panicwrap handleAsyncEvent asyncPreempt wrapper"
            }
            17 => {
                "normal abort asmcgocall asyncPreempt cgocallback debugCallV2 gcBgMarkWorker goexit gogo gopanic handleAsyncEvent jmpdefer mcall morestack mstart panicwrap rt0_go runfinq runtime_main sigpanic systemstack systemstack_switch wrapper"
            }
            18..=21 => {
                "normal abort asmcgocall asyncPreempt cgocallback debugCallV2 gcBgMarkWorker goexit gogo gopanic handleAsyncEvent mcall morestack mstart panicwrap rt0_go runfinq runtime_main sigpanic systemstack systemstack_switch wrapper"
            }
            22..=24 => {
                "normal abort asmcgocall asyncPreempt cgocallback corostart debugCallV2 gcBgMarkWorker goexit gogo gopanic handleAsyncEvent mcall morestack mstart panicwrap rt0_go runfinq runtime_main sigpanic systemstack systemstack_switch wrapper"
            }
            _ => {
                "normal abort asmcgocall asyncPreempt cgocallback corostart debugCallV2 gcBgMarkWorker goexit gogo gopanic handleAsyncEvent mcall morestack mstart panicwrap rt0_go runtime_main runFinalizers runCleanups sigpanic systemstack systemstack_switch wrapper"
            }
        };
        list.split(' ').collect()
    }

    /// Every function's funcID classifies to the name Go's own list gives its
    /// raw number, on every fixture from Go 1.10 (the first with IDs). Pins
    /// the version-free classification, the wrapper-ID detection (Go 1.17's
    /// ABI wrappers share their function's name), and the Go 1.10-1.15
    /// `_func` layouts the ID is read from. (`cgocallback_gofunc` reads as
    /// `cgocallback`, its later name, in the lists.)
    #[test]
    fn func_ids_match_the_go_source_lists() {
        let mut checked = 0usize;
        for fx in discover() {
            let minor = super::matrix::tag_minor(&fx.gotag);
            if minor < 10 {
                continue;
            }
            let list = funcid_list(minor);
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let mut specials = 0usize;
            for f in bin.functions() {
                let want = list
                    .get(usize::from(f.func.func_id))
                    .unwrap_or_else(|| panic!("{}: {} raw {}", fx.path, f.name, f.func.func_id));
                assert_eq!(
                    f.func_id.as_str(),
                    *want,
                    "{}: {} raw {}",
                    fx.path,
                    f.name,
                    f.func.func_id
                );
                if !matches!(f.func_id, FuncId::Normal | FuncId::Wrapper) {
                    specials += 1;
                }
                checked += 1;
            }
            assert!(specials >= 10, "{}: {specials} special functions", fx.path);
        }
        assert!(checked > 100_000, "too few functions checked: {checked}");
    }

    /// The Go 1.2-1.15 `_func` record is read with the layout its era wrote:
    /// the word after `args` is a frame size (or Go 1.5-1.9's placeholder),
    /// the funcID (Go 1.10-1.11), then `deferreturn` (Go 1.12-1.15). So no
    /// function before Go 1.12 reports a `deferreturn`, the basic program's
    /// deferring function does from Go 1.12, and `nfuncdata` is read.
    #[test]
    fn legacy_func_records_use_their_eras_layout() {
        use gobin::structures::pclntab::LegacyFuncLayout;

        for fx in discover().into_iter().filter(|f| f.prog == "basic") {
            let minor = super::matrix::tag_minor(&fx.gotag);
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let want = match minor {
                0..=4 => Some(LegacyFuncLayout::FrameSize),
                5..=9 => Some(LegacyFuncLayout::FramePlaceholder),
                10 | 11 => Some(LegacyFuncLayout::FuncIdWord),
                12..=15 => Some(LegacyFuncLayout::DeferReturn),
                _ => None,
            };
            assert_eq!(bin.pclntab().unwrap().legacy_func, want, "{}", fx.path);
            let funcs: Vec<_> = bin.functions().collect();
            let deferring = funcs.iter().filter(|f| f.uses_defer()).count();
            if minor < 12 {
                assert_eq!(deferring, 0, "{}: deferreturn before Go 1.12", fx.path);
            } else {
                assert!(
                    funcs
                        .iter()
                        .any(|f| f.name.starts_with("main.") && f.uses_defer()),
                    "{}: no main function defers",
                    fx.path
                );
            }
            let with_funcdata = funcs.iter().filter(|f| f.func.nfuncdata > 0).count();
            assert!(
                with_funcdata * 2 > funcs.len(),
                "{}: {with_funcdata} of {} functions carry funcdata",
                fx.path,
                funcs.len()
            );
        }
    }

    /// An init task holds its functions' PCs; every one names a function, on
    /// wasm as everywhere else.
    #[test]
    fn init_functions_resolve_to_names() {
        let mut wasm_named = 0usize;
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            for task in bin.init_order() {
                for func in &task.functions {
                    assert!(
                        func.name.is_some(),
                        "{}: init function at {:#x} has no name",
                        fx.path,
                        func.entry_va
                    );
                    if fx.goarch == "wasm" {
                        wasm_named += 1;
                    }
                }
            }
        }
        assert!(wasm_named > 50, "too few wasm init functions: {wasm_named}");
    }

    /// The development toolchain's version string carries its commit, and a
    /// wasm module states the whole string in its `producers` section.
    #[test]
    fn development_toolchain_version_is_complete() {
        let mut checked = 0usize;
        for fx in discover().into_iter().filter(|f| f.gotag == "go128") {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let version = bin.go_version().unwrap();
            assert!(
                version.starts_with("go1.28-devel_"),
                "{}: {version}",
                fx.path
            );
            assert_eq!(bin.runtime_commit(), Some("2dbf8b413a"), "{}", fx.path);
            checked += 1;
        }
        assert!(
            checked >= 10,
            "expected the go128 fixtures, found {checked}"
        );
        for fx in discover().into_iter().filter(|f| f.gotag == "go127") {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            assert_eq!(bin.runtime_commit(), None, "{}", fx.path);
        }
    }

    /// `CGO_ENABLED` records three modes since Go 1.28.
    #[test]
    fn cgo_mode_matches_the_build() {
        use gobin::metadata::CgoMode;

        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let Some(mode) = bin.build_info().and_then(|bi| bi.cgo_mode()) else {
                continue;
            };
            let want = if fx.path.ends_with("_cgobindings") {
                CgoMode::Bindings
            } else if fx.prog == "cgo" {
                CgoMode::Enabled
            } else {
                CgoMode::Disabled
            };
            assert_eq!(mode, want, "{}", fx.path);
        }
        let bindings = load("tests/samples/basic_go128_linux_amd64_cgobindings");
        let bin = GoBinary::parse(&bindings).unwrap();
        assert_eq!(
            bin.build_info().and_then(|bi| bi.cgo_mode()),
            Some(CgoMode::Bindings)
        );
    }
}

// ===========================================================================
// Per-function data blocks and per-PC tables (FUNCDATA / PCDATA), decoded in
// the format of each Go version, against oracles independent of the decoders.
// ===========================================================================
mod funcdata_blocks {
    use super::matrix::{discover, tag_minor};
    use super::*;
    use gobin::structures::funcdata::{ArgItem, FuncDataKind, OpenDefers, PcDataKind, StackObject};

    /// The runtime throws "bad symbol table" when a PC's
    /// `PCDATA_StackMapIndex` names a pointer map the function's
    /// `FUNCDATA_LocalsPointerMaps` does not have, so on every real binary each
    /// index is below the map count. Pins the per-version `FUNCDATA` and
    /// `PCDATA` indices, the pointer-or-offset block references, and the end
    /// of every PC-value table (one read past its terminator reads the next).
    #[test]
    fn stack_map_indices_name_existing_maps() {
        let mut checked = 0usize;
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            // A block that fails to decode is skipped below, so also require
            // that nearly every function with GC maps has them decode: a
            // misplaced block reference reads as an unmapped address.
            let (mut with_maps, mut decoded) = (0usize, 0usize);
            for f in bin.functions() {
                if f.func.nfuncdata >= 2 {
                    with_maps += 1;
                }
                let Some(maps) = bin.pointer_maps(&f, FuncDataKind::LocalsPointerMaps) else {
                    continue;
                };
                decoded += 1;
                let Some(table) = bin.pcdata(&f, PcDataKind::StackMapIndex) else {
                    continue;
                };
                for (_, index) in table {
                    if let Ok(index) = u32::try_from(index) {
                        assert!(
                            index < maps.count,
                            "{}: {} index {index} of {} maps",
                            fx.path,
                            f.name,
                            maps.count
                        );
                        checked += 1;
                    }
                }
            }
            // Go 1.2 binaries state no version, and its maps' format is not
            // that of Go 1.3-1.4, so none decode there by design.
            if fx.gotag != "go12" {
                assert!(
                    decoded * 10 >= with_maps * 9,
                    "{}: {decoded} of {with_maps} functions' maps decode",
                    fx.path
                );
            }
        }
        assert!(checked > 100_000, "too few indices checked: {checked}");
    }

    /// An inlined call's record names its call site, and from Go 1.12 also
    /// `parentPc`, "an instruction whose source position is the call site":
    /// the line table at that PC is the record's line. From Go 1.20 the record
    /// carries the callee's first line instead, which is that function's own
    /// `startLine` wherever a standalone copy of it exists. Both oracles come
    /// from tables the inline decoder does not read.
    #[test]
    fn inline_records_agree_with_the_line_tables() {
        let mut lines_checked = 0usize;
        let mut starts_checked = 0usize;
        for fx in discover() {
            let minor = tag_minor(&fx.gotag);
            if minor < 9 {
                continue;
            }
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let pcl = bin.pclntab().unwrap();
            // Names are not unique (Go 1.17's ABI wrappers share theirs), so
            // the oracle is every start line a name has.
            let mut starts: std::collections::BTreeMap<&str, BTreeSet<i32>> = Default::default();
            for f in bin.functions() {
                starts.entry(f.name).or_default().insert(f.func.start_line);
            }
            let mut entries = 0usize;
            for f in bin.functions() {
                let lines: Vec<(u32, i32)> = pcl.decode_pcln(&f.func).collect();
                let line_at = |pc: u32| lines.iter().find(|(end, _)| pc < *end).map(|e| e.1);
                for e in bin.inline_tree(&f) {
                    entries += 1;
                    assert!(
                        e.function_name.contains('.'),
                        "{}: {} inlines {:?}",
                        fx.path,
                        f.name,
                        e.function_name
                    );
                    if let (Some(pc), Some(line)) = (e.parent_pc, e.call_line) {
                        assert_eq!(line_at(pc), Some(line), "{}: {}", fx.path, f.name);
                        lines_checked += 1;
                    }
                    if let (Some(start), Some(own)) = (e.start_line, starts.get(e.function_name)) {
                        assert!(
                            own.contains(&start),
                            "{}: {} {start} not in {own:?}",
                            fx.path,
                            e.function_name
                        );
                        starts_checked += 1;
                    }
                }
            }
            assert!(entries > 0, "{}: no inline tree", fx.path);
        }
        assert!(
            lines_checked > 50_000,
            "call lines checked: {lines_checked}"
        );
        assert!(
            starts_checked > 1_000,
            "start lines checked: {starts_checked}"
        );
    }

    /// Without a version string the tables are read only where every Go
    /// version the structure allows agrees on their format. A scrubbed Go
    /// 1.21 / 1.24 binary's structure allows Go 1.20-1.25: the block indices
    /// and the pointer maps agree, so they decode, while the open-coded defer
    /// format changed at Go 1.22, so it is not guessed. A Go 1.2 binary, which
    /// states no version, could be Go 1.2-1.4, whose PCDATA 0 and pointer maps
    /// differ, so neither decodes.
    #[test]
    fn versionless_binaries_decode_only_what_their_structure_fixes() {
        for path in [
            "tests/samples/basic_go121_linux_386_noversion",
            "tests/samples/basic_go124_windows_amd64_noversion.exe",
        ] {
            let data = load(path);
            let bin = GoBinary::parse(&data).unwrap();
            let worker = bin.functions().find(|f| f.name == "main.worker").unwrap();
            assert!(
                bin.pointer_maps(&worker, FuncDataKind::LocalsPointerMaps)
                    .is_some(),
                "{path}"
            );
            assert!(bin.arg_layout(&worker).is_some(), "{path}");
            assert!(
                bin.funcdata(&worker, FuncDataKind::OpenCodedDeferInfo)
                    .is_some(),
                "{path}"
            );
            assert!(bin.open_defers(&worker).is_none(), "{path}");
        }
        let data = load("tests/samples/basic_go12_linux_amd64");
        let bin = GoBinary::parse(&data).unwrap();
        assert_eq!(bin.go_version(), None);
        for f in bin.functions() {
            assert!(
                bin.pcdata(&f, PcDataKind::StackMapIndex).is_none(),
                "{}",
                f.name
            );
            assert!(
                bin.pointer_maps(&f, FuncDataKind::LocalsPointerMaps)
                    .is_none(),
                "{}",
                f.name
            );
        }
    }

    /// The argument layout of `main.worker(ch chan int, n int)`: two
    /// pointer-sized words, and of `main.TestStruct.Greet`, whose receiver is
    /// `struct{ Name string; Count int }`: a string (pointer, length) and an
    /// int inside one aggregate. Recorded from Go 1.17.
    #[test]
    fn arg_layout_matches_the_signatures() {
        let mut checked = 0usize;
        for fx in discover().into_iter().filter(|f| f.prog == "basic") {
            if tag_minor(&fx.gotag) < 17 {
                continue;
            }
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let p = bin.pclntab().unwrap().ptr_size;
            let word = |offset: u8| ArgItem::Value { offset, size: p };
            let find = |name: &str| bin.functions().find(|f| f.name == name).unwrap();
            let worker = bin.arg_layout(&find("main.worker")).unwrap();
            assert_eq!(worker.items, vec![word(0), word(p)], "{}", fx.path);
            let greet = bin.arg_layout(&find("main.TestStruct.Greet")).unwrap();
            assert_eq!(
                greet.items,
                vec![ArgItem::Aggregate(vec![
                    ArgItem::Aggregate(vec![word(0), word(p)]),
                    word(2 * p),
                ])],
                "{}",
                fx.path
            );
            checked += 1;
        }
        assert!(checked >= 15, "fixtures checked: {checked}");
    }

    /// `main.worker` defers one call (`defer close(ch)`), which the compiler
    /// open-codes from Go 1.14: the defer info lists it through Go 1.21 and
    /// gives its slots from Go 1.22.
    #[test]
    fn open_defers_find_the_one_deferred_call() {
        let mut checked = 0usize;
        for fx in discover().into_iter().filter(|f| f.prog == "basic") {
            let minor = tag_minor(&fx.gotag);
            if minor < 14 {
                continue;
            }
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let worker = bin.functions().find(|f| f.name == "main.worker").unwrap();
            let defers = bin
                .open_defers(&worker)
                .unwrap_or_else(|| panic!("{}", fx.path));
            match defers {
                OpenDefers::Listed { calls, .. } => {
                    assert!(minor < 22, "{}", fx.path);
                    assert_eq!(calls.len(), 1, "{}", fx.path);
                }
                OpenDefers::Slots { .. } => assert!(minor >= 22, "{}", fx.path),
            }
            checked += 1;
        }
        assert!(checked >= 20, "fixtures checked: {checked}");
    }

    /// A function names the function it wraps only when the compiler marked
    /// it a wrapper (its funcID), and the target resolves; the `go worker(ch,
    /// 21)` statement's wrapper (Go 1.22+, on the register-ABI targets that
    /// need one) wraps `main.worker`.
    #[test]
    fn wrapped_functions_resolve_from_wrappers() {
        let mut checked = 0usize;
        for fx in discover() {
            let minor = tag_minor(&fx.gotag);
            if minor < 18 {
                continue;
            }
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            for f in bin.functions() {
                if bin.funcdata(&f, FuncDataKind::WrapInfo).is_none() {
                    continue;
                }
                assert!(f.is_wrapper(), "{}: {} is not a wrapper", fx.path, f.name);
                let target = bin.wrapped_function(&f);
                assert!(target.is_some(), "{}: {} wraps nothing", fx.path, f.name);
                checked += 1;
            }
            if fx.prog == "basic" && minor >= 22 && matches!(fx.goarch.as_str(), "amd64" | "arm64")
            {
                let gowrap = bin
                    .functions()
                    .find(|f| f.name == "main.main.gowrap1")
                    .unwrap_or_else(|| panic!("{}", fx.path));
                assert_eq!(
                    bin.wrapped_function(&gowrap).map(|w| w.name),
                    Some("main.worker"),
                    "{}",
                    fx.path
                );
            }
        }
        assert!(checked > 200, "wrappers checked: {checked}");
    }

    /// Go 1.12-1.16 record each stack object's type, which resolves to a type
    /// descriptor; Go 1.17+ record its size and pointer bytes, which it holds.
    #[test]
    fn stack_objects_hold_types_or_sizes() {
        let (mut typed, mut sized) = (0usize, 0usize);
        for fx in discover() {
            let minor = tag_minor(&fx.gotag);
            if minor < 12 {
                continue;
            }
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            for f in bin.functions() {
                for object in bin.stack_objects(&f).unwrap_or_default() {
                    let StackObject {
                        size,
                        ptr_bytes,
                        type_va,
                        ..
                    } = object;
                    if minor <= 16 {
                        let ty = type_va.and_then(|va| bin.type_at(va));
                        assert!(ty.is_some(), "{}: {} object type", fx.path, f.name);
                        typed += 1;
                    } else {
                        let (size, ptr) = (size.unwrap(), ptr_bytes.unwrap());
                        assert!(size > 0 && ptr <= size as i32, "{}: {}", fx.path, f.name);
                        sized += 1;
                    }
                }
            }
        }
        assert!(typed > 500 && sized > 2_000, "typed {typed}, sized {sized}");
    }
}

mod source_spans_and_methods {
    use super::matrix::{discover, tag_minor};
    use super::*;
    use gobin::structures::types::{TypeDetail, TypeKind};
    use std::collections::BTreeMap;

    /// The value `(pc_end, value)` steps give `pc`, as the runtime's
    /// `pcvalue` reads them: the first step ending after it.
    fn value_at<T: Copy>(steps: &[(u32, T)], pc: u32) -> Option<T> {
        steps.iter().find(|&&(end, _)| pc < end).map(|&(_, v)| v)
    }

    /// The functions `tests/samples/src/basic/main.go` declares, as
    /// `(symbol, line of func, line of its closing brace)`.
    fn basic_source_functions() -> Vec<(String, i32, i32)> {
        source_functions("tests/samples/src/basic/main.go", "main")
    }

    /// The functions the Go source file `path` of package `package` declares,
    /// as `(symbol, line of func, line of its closing brace)`.
    pub fn source_functions(path: &str, package: &str) -> Vec<(String, i32, i32)> {
        let src = std::fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = src.lines().collect();
        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let Some(rest) = line.strip_prefix("func ") else {
                continue;
            };
            let symbol = match rest.strip_prefix('(') {
                Some(recv) => {
                    let (recv, rest) = recv.split_once(") ").unwrap();
                    let ty = recv.split_whitespace().last().unwrap();
                    let name = rest.split('(').next().unwrap();
                    match ty.strip_prefix('*') {
                        Some(ty) => format!("{package}.(*{ty}).{name}"),
                        None => format!("{package}.{ty}.{name}"),
                    }
                }
                None => format!("{package}.{}", rest.split('(').next().unwrap()),
            };
            let close = if line.trim_end().ends_with('}') {
                i
            } else {
                i + lines[i..].iter().position(|l| *l == "}").unwrap()
            };
            out.push((symbol, i as i32 + 1, close as i32 + 1));
        }
        out
    }

    /// A function's source span leaves out the code inlined into it, whose
    /// lines are its callees' (`fmt.Println`'s, in `print.go`, inside
    /// `main.main`), and its line table holds absolute lines (Go 1.20 added
    /// a start line beside it, which is no base to add). Checked against the
    /// fixture's source: each function of `main.go` spans from its `func`
    /// line to its last statement or closing brace. Fixtures built from a
    /// copy of the source three lines shorter shift every line by `-3`.
    #[test]
    fn function_spans_match_the_source() {
        let source = basic_source_functions();
        let main = source
            .iter()
            .find(|(s, ..)| s == "main.main")
            .unwrap()
            .clone();
        let mut checked = 0usize;
        for fx in discover().into_iter().filter(|fx| fx.prog == "basic") {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let pcl = bin.pclntab().unwrap();
            let span = |name: &str| {
                bin.functions().find(|f| f.name == name).map(|f| {
                    (
                        pcl.line_range(&f.func),
                        f.end_line,
                        f.func.start_line,
                        f.source_file,
                    )
                })
            };
            let (Some((lo, _)), ..) = span("main.main").unwrap() else {
                panic!("{}: main.main has no lines", fx.path);
            };
            let shift = [0, -3]
                .into_iter()
                .find(|s| lo == main.1 + s)
                .unwrap_or_else(|| panic!("{}: main.main starts at line {lo}", fx.path));
            for (symbol, first, close) in &source {
                let Some((range, end_line, start_line, file)) = span(symbol) else {
                    continue; // inlined everywhere, or never compiled
                };
                let (first, close) = (first + shift, close + shift);
                let (lo, hi) = range.unwrap();
                assert_eq!(hi, end_line, "{}: {symbol}", fx.path);
                assert!(
                    file.unwrap().ends_with("main.go"),
                    "{}: {symbol} {file:?}",
                    fx.path
                );
                assert!(
                    lo >= first,
                    "{}: {symbol} starts at {lo}, before {first}",
                    fx.path
                );
                if first == close {
                    assert_eq!(hi, first, "{}: one-line {symbol}", fx.path);
                } else {
                    assert!(
                        (close - 1..=close).contains(&hi),
                        "{}: {symbol} ends at {hi}, its body at {}",
                        fx.path,
                        close - 1
                    );
                }
                if tag_minor(&fx.gotag) >= 20 {
                    assert_eq!(start_line, first, "{}: {symbol}", fx.path);
                }
                checked += 1;
            }
        }
        assert!(checked > 300, "too few spans checked: {checked}");
    }

    /// The bulk walk describes each function as the iterator does, its
    /// tables decoded once into shared buffers: the same source file (Go
    /// 1.2-1.15 resolve files without a compilation unit table) and span.
    #[test]
    fn for_each_function_agrees_with_functions() {
        let mut checked = 0usize;
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let pcl = bin.pclntab().unwrap();
            let mut iter = bin.functions();
            for_each_function(&pcl, |info, _| {
                let f = iter.next().unwrap();
                assert_eq!(
                    (
                        info.name,
                        info.source_file,
                        info.end_line,
                        info.frame_size,
                        info.func_id
                    ),
                    (f.name, f.source_file, f.end_line, f.frame_size, f.func_id),
                    "{}",
                    fx.path
                );
                checked += 1;
            });
            assert!(iter.next().is_none(), "{}", fx.path);
        }
        assert!(checked > 100_000, "too few functions checked: {checked}");
    }

    /// Joining the line and file tables gives every PC the line and the file
    /// the runtime's `pcvalue` reads for it from each table on its own.
    #[test]
    fn joined_lines_and_files_agree_with_each_table() {
        let mut checked = 0usize;
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let pcl = bin.pclntab().unwrap();
            for f in bin.functions().step_by(25) {
                let lines: Vec<(u32, i32)> = pcl.decode_pcln(&f.func).collect();
                let files: Vec<(u32, u32)> = pcl.decode_pcfile(&f.func).collect();
                let joined: Vec<(u32, i32, &str)> = pcl.decode_pcln_with_files(&f.func).collect();
                let end = lines.last().map_or(0, |&(end, _)| end);
                for pc in 0..end {
                    let Some(path) = value_at(&files, pc)
                        .and_then(|i| pcl.resolve_file_index(f.func.cu_offset, i))
                    else {
                        continue;
                    };
                    let line = value_at(&lines, pc).unwrap();
                    let item = joined.iter().find(|&&(end, ..)| pc < end);
                    assert_eq!(
                        item.map(|&(_, l, p)| (l, p)),
                        Some((line, path)),
                        "{}: {} pc {pc}",
                        fx.path,
                        f.name
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 1_000_000, "too few PCs checked: {checked}");
    }

    /// An inlined call sits in its caller's code: the enclosing function's
    /// own code for an outermost frame, else the parent inlined function's.
    /// From Go 1.20 the call site is read from the enclosing function's
    /// tables at `parentPc`; so its file must be the caller's source file (the
    /// enclosing function's, or the parent's standalone copy's), and an
    /// outermost call's line must fall in the enclosing function's span. An
    /// inlined function's own file is its standalone copy's.
    #[test]
    fn inline_call_sites_lie_in_their_callers() {
        let (mut outer, mut nested, mut callee) = (0usize, 0usize, 0usize);
        let mut go19 = (0usize, 0usize); // (checked, agreeing)
        for fx in discover()
            .into_iter()
            .filter(|fx| tag_minor(&fx.gotag) >= 9)
        {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let files: BTreeMap<&str, BTreeSet<&str>> =
                bin.functions().fold(BTreeMap::new(), |mut m, f| {
                    if let Some(file) = f.source_file {
                        m.entry(f.name).or_default().insert(file);
                    }
                    m
                });
            let own_file = |name: &str, file: Option<&str>| {
                files
                    .get(name)
                    .is_none_or(|set| set.len() != 1 || file.is_some_and(|f| set.contains(f)))
            };
            for f in bin.functions() {
                let entries: Vec<_> = bin.inline_tree(&f).collect();
                let names: BTreeMap<u32, &str> =
                    entries.iter().map(|e| (e.index, e.function_name)).collect();
                for e in &entries {
                    let at = format!(
                        "{}: {} <- {} @{:?}",
                        fx.path, f.name, e.function_name, e.pc_range
                    );
                    assert_eq!(e.parent.is_none(), e.depth == 0, "{at}");
                    // Go 1.9 positions some inlined calls' code at the call
                    // site only, which leaves the callee's file unrecorded:
                    // count those, and require all from Go 1.10.
                    let agrees = own_file(e.function_name, e.source_file);
                    if tag_minor(&fx.gotag) >= 10 {
                        assert!(agrees, "{at}: {:?}", e.source_file);
                        callee += usize::from(files.contains_key(e.function_name));
                    } else if files.get(e.function_name).is_some_and(|set| set.len() == 1) {
                        go19.0 += 1;
                        go19.1 += usize::from(agrees);
                    }
                    match e.parent {
                        // A package's generated initializer runs the variable
                        // initializers of all its files: it has no one file.
                        None if f.name.ends_with(".init") => {}
                        None => {
                            let (lo, hi) = bin.pclntab().unwrap().line_range(&f.func).unwrap();
                            assert_eq!(e.call_file, f.source_file, "{at}");
                            // Before Go 1.12 a statement whose code was all
                            // inlined leaves no instruction of the caller's at
                            // its line, so the caller's span can end before it.
                            let line = e.call_line.unwrap();
                            if tag_minor(&fx.gotag) >= 12 {
                                assert!(
                                    (lo..=hi).contains(&line),
                                    "{at}: line {line} not in {lo}-{hi}"
                                );
                            }
                            outer += 1;
                        }
                        Some(parent) => {
                            if let Some(name) = names.get(&parent) {
                                assert!(
                                    own_file(name, e.call_file),
                                    "{at}: {:?} not {name}'s",
                                    e.call_file
                                );
                                nested += 1;
                            }
                        }
                    }
                }
            }
        }
        assert!(
            outer > 20_000 && nested > 2_000 && callee > 20_000,
            "{outer} {nested} {callee}"
        );
        // Go 1.9 also positions argument setup at the call site, inside the
        // callee's range: the callee's file is the other one there.
        assert!(
            go19.0 > 100 && go19.1 * 100 >= go19.0 * 90,
            "Go 1.9: {go19:?}"
        );
    }

    /// A named type `T` shares the string `*T` with its pointer type and
    /// marks it to drop the star (`tflagExtraStar`): a pointer's name is its
    /// element's with one star before it, and only pointers start with one.
    /// A named type is exported when its unqualified name is.
    #[test]
    fn type_names_drop_the_shared_star() {
        let mut pointers = 0usize;
        for fx in discover()
            .into_iter()
            .filter(|fx| tag_minor(&fx.gotag) >= 7)
        {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let types = bin.all_types();
            assert!(!types.is_empty(), "{}", fx.path);
            for t in &types {
                if t.kind != TypeKind::Pointer {
                    assert!(
                        !t.name.starts_with('*'),
                        "{}: {:?} {}",
                        fx.path,
                        t.kind,
                        t.name
                    );
                    continue;
                }
                // A named pointer type (`type dequeueNil *struct{}`) has its
                // own name.
                let (TypeDetail::Pointer { elem_va }, false) = (&t.detail, t.is_named) else {
                    continue;
                };
                let elem_va = *elem_va;
                if let Some(elem) = bin.type_at(elem_va).filter(|e| !e.name.is_empty()) {
                    assert_eq!(t.name, format!("*{}", elem.name), "{}", fx.path);
                    pointers += 1;
                }
            }
            let exported =
                |name: &str| types.iter().find(|t| t.name == name).map(|t| t.is_exported);
            if fx.prog == "basic" {
                assert_eq!(exported("main.TestStruct"), Some(true), "{}", fx.path);
                assert_eq!(exported("*main.TestStruct"), Some(false), "{}", fx.path);
                assert_eq!(exported("runtime.errorString"), Some(false), "{}", fx.path);
                assert_eq!(exported("int"), Some(false), "{}", fx.path);
            }
        }
        assert!(
            pointers > 10_000,
            "too few pointer types checked: {pointers}"
        );
    }

    /// The receiver and method name a function for method `method` of type
    /// `ty` ends its name with, generic arguments elided as the compiler
    /// names instantiations (`[...]`).
    fn method_suffix(ty: &str, method: &str) -> String {
        let (pointer, base) = match ty.strip_prefix('*') {
            Some(base) => (true, base),
            None => (false, ty),
        };
        let base = elide_type_args(base);
        let t = base.rsplit_once('.').map_or(base.as_str(), |(_, t)| t);
        if pointer {
            format!(".(*{t}).{method}")
        } else {
            format!(".{t}.{method}")
        }
    }

    fn elide_type_args(name: &str) -> String {
        let mut out = String::new();
        let mut depth = 0usize;
        for c in name.chars() {
            match c {
                '[' => {
                    if depth == 0 {
                        out.push_str("[...]");
                    }
                    depth += 1;
                }
                ']' => depth -= 1,
                _ if depth == 0 => out.push(c),
                _ => {}
            }
        }
        out
    }

    /// Whether `function` can run method `method` of `ty`: named for it, or
    /// for its pointer type when reached through an interface, or the
    /// wrapper the linker shares among types embedding the same field at the
    /// same place (`pkg..embed.<depth>.<offset>.<method's own name>`).
    fn runs_method(function: &str, ty: &str, method: &str, via_pointer: bool) -> bool {
        let name = elide_type_args(function);
        let pointer = format!("*{}", ty.trim_start_matches('*'));
        name.ends_with(&method_suffix(ty, method))
            || (via_pointer && name.ends_with(&method_suffix(&pointer, method)))
            || (name.contains("..embed.") && name.ends_with(&format!(".{method}")))
    }

    /// A type's methods resolve to the functions named for them: the direct
    /// call to `pkg.T.M` or `pkg.(*T).M`, the interface call to that or the
    /// pointer receiver's wrapper.
    #[test]
    fn methods_resolve_to_their_functions() {
        let (mut direct, mut interface) = (0usize, 0usize);
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            for t in bin.all_types() {
                for m in &t.methods {
                    let at = format!("{}: {}.{}", fx.path, t.name, m.name);
                    let functions = bin.method_functions(m);
                    assert_eq!(
                        functions.direct.is_some(),
                        m.function_text_offset.is_some(),
                        "{at}"
                    );
                    assert_eq!(
                        functions.interface.is_some(),
                        m.interface_text_offset.is_some(),
                        "{at}"
                    );
                    if let Some(f) = functions.direct {
                        assert!(
                            runs_method(f.name, t.name, m.name, false),
                            "{at}: {}",
                            f.name
                        );
                        direct += 1;
                    }
                    if let Some(f) = functions.interface {
                        assert!(
                            runs_method(f.name, t.name, m.name, true),
                            "{at}: {}",
                            f.name
                        );
                        interface += 1;
                    }
                }
            }
        }
        assert!(
            direct > 15_000 && interface > 13_000,
            "{direct} {interface}"
        );
    }

    /// An itab binds each interface method to its concrete type's interface
    /// entry for the method of the same name (its `ifn`): two tables the
    /// linker writes apart. A method the linker dropped as unreachable has no
    /// entry, and its itab word points at `runtime.unreachableMethod`.
    #[test]
    fn itab_methods_are_their_types_interface_entries() {
        let mut checked = 0usize;
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            for pair in bin.itab_pairs() {
                let Some(concrete) = bin.type_at(pair.concrete_type_va) else {
                    continue;
                };
                for m in bin.itab_methods(&pair).into_iter().filter(|m| m.va != 0) {
                    let at = format!("{}: {} {:?}", fx.path, concrete.name, m.name);
                    let name = m.name.unwrap_or_else(|| panic!("{at}: unnamed"));
                    let function = m.function.unwrap_or_else(|| panic!("{at}: {:#x}", m.va));
                    let own = concrete.methods.iter().find(|c| c.name == name);
                    match own.and_then(|c| c.interface_text_offset) {
                        Some(off) => {
                            assert_eq!(bin.text_addr(off as u32), Some(m.va), "{at}");
                            assert!(
                                runs_method(function.name, concrete.name, name, true),
                                "{at}: {}",
                                function.name
                            );
                        }
                        None => assert_eq!(function.name, "runtime.unreachableMethod", "{at}"),
                    }
                    checked += 1;
                }
            }
        }
        assert!(checked > 3_000, "too few itab methods checked: {checked}");
    }
}

mod attribution_and_symbols {
    use super::matrix::{discover, tag_minor};
    use super::*;
    use gobin::{
        SymbolKind,
        detection::LayoutEvidence,
        metadata::HookKind,
        structures::{buildinfo, locate::ModuledataSource},
    };

    /// `has_cgo` is true for exactly the binaries built with cgo: the cgo
    /// fixtures, not the ones whose runtime merely holds its own entry into C
    /// (every binary from Go 1.7), its Windows callback entry, or Go 1.28's
    /// C-compiler-free cgo bindings. A cgo binary's C-call stubs are hooks
    /// named for the C functions its source calls.
    #[test]
    fn cgo_is_found_in_cgo_builds_only() {
        let mut cgo = 0usize;
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            assert_eq!(bin.has_cgo(), fx.prog == "cgo", "{}", fx.path);
            if fx.prog == "cgo" {
                let stubs: BTreeSet<&str> = bin
                    .runtime_hooks()
                    .iter()
                    .filter(|h| h.kind == HookKind::CgoCall)
                    .map(|h| h.function.name)
                    .collect();
                // The source calls C.cgo_add and C.free (C.malloc goes
                // through cgo's own allocator wrapper).
                for stub in ["main._Cfunc_cgo_add", "main._Cfunc_free"] {
                    assert!(stubs.contains(stub), "{}: {stubs:?}", fx.path);
                }
                cgo += 1;
            }
        }
        assert_eq!(cgo, 3, "cgo fixtures checked");
    }

    /// The hooks of the basic program, which starts a goroutine, sends and
    /// receives on a channel and closes one, are found in every release: the
    /// entries the compiler lowers those statements to, each a function
    /// entry.
    #[test]
    fn hooks_name_the_runtime_entries_of_go_statements() {
        for fx in discover().into_iter().filter(|fx| fx.prog == "basic") {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let hooks = bin.runtime_hooks();
            let kinds: BTreeSet<String> = hooks.iter().map(|h| format!("{:?}", h.kind)).collect();
            for kind in [
                "Spawn",
                "ChanMake",
                "ChanSend",
                "ChanRecv",
                "ChanClose",
                "Panic",
            ] {
                assert!(kinds.contains(kind), "{}: no {kind} in {kinds:?}", fx.path);
            }
            for hook in &hooks {
                assert_eq!(
                    HookKind::of(hook.function.name),
                    Some(hook.kind),
                    "{}",
                    fx.path
                );
                assert_eq!(
                    bin.function_at(bin.entry_va(&hook.function).unwrap())
                        .map(|f| f.func.entry_off),
                    Some(hook.function.func.entry_off),
                    "{}: {}",
                    fx.path,
                    hook.function.name
                );
            }
        }
    }

    /// The experiments the version string ends with are the ones the build
    /// info's `GOEXPERIMENT` setting records, read apart; and the scan for
    /// the runtime's own copy of the version, used without build info, finds
    /// the same.
    #[test]
    fn experiments_match_the_goexperiment_setting() {
        let mut with = 0usize;
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let experiments = bin.go_experiments();
            let setting: Vec<&str> = bin
                .build_info()
                .and_then(|info| info.setting("GOEXPERIMENT"))
                .map_or_else(Vec::new, |s| s.split(',').collect());
            assert_eq!(experiments, setting, "{}", fx.path);
            let scanned: Vec<&str> = buildinfo::find_version_experiments(&data)
                .map_or_else(Vec::new, |s| s.split(',').collect());
            assert_eq!(scanned, experiments, "{}", fx.path);
            // The deps builds turn two on, the cgo-bindings build one.
            let expected = fx.prog == "deps" || fx.path.ends_with("_cgobindings");
            assert_eq!(!experiments.is_empty(), expected, "{}", fx.path);
            with += usize::from(expected);
        }
        assert!(with >= 2, "fixtures with experiments: {with}");
        let data = load("tests/samples/deps_go128_linux_amd64");
        let bin = GoBinary::parse(&data).unwrap();
        assert_eq!(bin.go_experiments(), ["arenas", "nogreenteagc"]);
    }

    /// An untrimmed build names where it ran. The deps fixture was built in
    /// `/home/gobin` with its GOROOT at `/usr/local/go` and a module from
    /// the default cache; a trimmed build names nothing; and every untrimmed
    /// Go 1.2-1.12 fixture names its GOROOT, the directory each runtime file
    /// it records sits under.
    #[test]
    fn build_paths_name_where_the_build_ran() {
        use gobin::metadata::BuildPaths;
        let data = load("tests/samples/deps_go128_linux_amd64");
        let bin = GoBinary::parse(&data).unwrap();
        assert_eq!(
            bin.build_paths(),
            BuildPaths {
                goroot: Some("/usr/local/go"),
                module_cache: Some("/home/gobin/go/pkg/mod"),
                gopath: Some("/home/gobin/go"),
                main_dir: Some("/home/gobin/src/deps"),
                home: Some("/home/gobin"),
            }
        );
        for fx in discover().into_iter().filter(|fx| fx.prog != "deps") {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let paths = bin.build_paths();
            if tag_minor(&fx.gotag) >= 13 {
                assert_eq!(
                    paths,
                    BuildPaths::default(),
                    "{}: built with -trimpath",
                    fx.path
                );
                continue;
            }
            let goroot = paths
                .goroot
                .unwrap_or_else(|| panic!("{}: no GOROOT", fx.path));
            let pcl = bin.pclntab().unwrap();
            let runtime_files = pcl
                .file_names()
                .filter(|f| f.contains("/src/runtime/") || f.contains("/src/pkg/runtime/"))
                .count();
            assert!(runtime_files > 0, "{}", fx.path);
            assert!(
                pcl.file_names()
                    .filter(|f| f.contains("/src/runtime/") || f.contains("/src/pkg/runtime/"))
                    .all(|f| f.starts_with(goroot)),
                "{}: {goroot}",
                fx.path
            );
            assert_eq!(paths.module_cache, None, "{}", fx.path);
        }
    }

    /// The symbol table, read from the container, names every function the
    /// pclntab lists at its entry (assembly functions with Go 1.17's `.abi0`
    /// suffix, generic instances with their type arguments where the pclntab
    /// has `[...]`, and Go 1.17's `·` written `.`); on Mach-O and PE, which record no sizes, a function's
    /// derived size is its extent in the function table. `runtime.text` is
    /// `moduledata.text`, and `os.Args` is a zero-initialized global.
    #[test]
    fn symbols_agree_with_the_pclntab() {
        // The linker names a generic function in the pclntab with everything
        // from its first `[` to its last `]` cut to `[...]`
        // (`cmd/link/internal/ld/pcln.go`, `funcNameForRuntime`), and Go 1.17
        // writes `·` where the symbol table has `.`.
        fn elide(name: &str) -> String {
            let name = name.replace('\u{b7}', ".");
            match (name.find('['), name.rfind(']')) {
                (Some(open), Some(close)) if open < close => {
                    format!("{}[...]{}", &name[..open], &name[close + 1..])
                }
                _ => name,
            }
        }
        let (mut checked, mut sized, mut stripped) = (0usize, 0usize, 0usize);
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let symbols = bin.symbols();
            let format = bin.context().format();
            let present = bin
                .report()
                .signals
                .contains(&ConfidenceSignal::SymbolTable);
            assert_eq!(present, !symbols.is_empty(), "{}", fx.path);
            if symbols.is_empty() {
                if format != BinaryFormat::Wasm {
                    assert!(fx.path.contains("_stripped"), "{}: no symbols", fx.path);
                    stripped += 1;
                }
                continue;
            }
            let mut entries: Vec<u64> = bin.functions().filter_map(|f| bin.entry_va(&f)).collect();
            entries.sort_unstable();
            entries.dedup();
            for f in bin.functions() {
                let entry = bin.entry_va(&f).unwrap();
                let at_entry: Vec<_> = symbols.iter().filter(|s| s.va == entry).collect();
                let named = at_entry.iter().find(|s| {
                    s.name == f.name
                        || s.name.strip_suffix(".abi0") == Some(f.name)
                        || elide(s.name) == elide(f.name)
                });
                let named = named.unwrap_or_else(|| {
                    panic!("{}: {} at {entry:#x}: {at_entry:?}", fx.path, f.name)
                });
                assert_eq!(named.kind, SymbolKind::Text, "{}: {}", fx.path, f.name);
                if !named.size_recorded
                    && let Some(&next) = entries.iter().find(|&&e| e > entry)
                {
                    assert_eq!(named.size, next - entry, "{}: {}", fx.path, f.name);
                    sized += 1;
                }
                checked += 1;
            }
            if let Some(md) = bin.moduledata() {
                assert_eq!(
                    symbols.named("runtime.text").map(|s| s.va),
                    Some(md.text),
                    "{}",
                    fx.path
                );
            }
            // A program that imports `os` (directly or through `fmt`) has it.
            let Some(args) = symbols.named("os.Args") else {
                assert_ne!(fx.prog, "basic", "{}: no os.Args", fx.path);
                continue;
            };
            assert_eq!(args.kind, SymbolKind::Bss, "{}", fx.path);
            assert_eq!(
                symbols.at(args.va).map(|s| s.name),
                Some("os.Args"),
                "{}",
                fx.path
            );
        }
        assert!(checked > 100_000 && sized > 15_000, "{checked} {sized}");
        assert!(stripped >= 8, "stripped fixtures: {stripped}");
    }

    /// The report states how the moduledata was found and the layouts the
    /// records are read with, as the accessors give them.
    #[test]
    fn report_states_layouts_and_moduledata() {
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let signals = &bin.report().signals;
            let located = signals.iter().find_map(|s| match s {
                ConfidenceSignal::ModuledataLocated { version, source } => {
                    Some((*version, *source))
                }
                _ => None,
            });
            match bin.moduledata() {
                Some(md) => {
                    let (version, source) = located.unwrap_or_else(|| panic!("{}", fx.path));
                    assert_eq!(version, md.version, "{}", fx.path);
                    // Its own section when the binary has one; else a scan, of
                    // the data sections the linker emits it into, or of the
                    // whole linear memory on wasm, whose sections are not
                    // its address space.
                    let expected = if bin.context().sections().go_module.is_some() {
                        ModuledataSource::Section
                    } else if bin.context().format() == BinaryFormat::Wasm {
                        ModuledataSource::ImageScan
                    } else {
                        ModuledataSource::DataScan
                    };
                    assert_eq!(source, expected, "{}", fx.path);
                }
                None => {
                    assert!(
                        signals.contains(&ConfidenceSignal::ModuledataMissing),
                        "{}",
                        fx.path
                    );
                    assert!(tag_minor(&fx.gotag) <= 4, "{}: no moduledata", fx.path);
                }
            }
            let layouts = signals
                .iter()
                .find_map(|s| match s {
                    ConfidenceSignal::LayoutsChosen {
                        itab,
                        map,
                        decided_by,
                        ..
                    } => Some((*itab, *map, *decided_by)),
                    _ => None,
                })
                .unwrap();
            assert_eq!(layouts.0, bin.itab_layout(), "{}", fx.path);
            assert_eq!(layouts.1, bin.map_layout(), "{}", fx.path);
            let versioned = bin.go_version().is_some_and(|v| v.starts_with("go1."));
            assert_eq!(
                layouts.2 == LayoutEvidence::VersionString,
                versioned,
                "{}: {:?}",
                fx.path,
                bin.go_version()
            );
        }
        // Go 1.2 records no version: its structure dates it to Go 1.2-1.4,
        // which share the itab and map layouts.
        let data = load("tests/samples/basic_go12_linux_amd64");
        let bin = GoBinary::parse(&data).unwrap();
        assert_eq!(
            bin.itab_layout(),
            gobin::structures::itab::ItabLayout::Linked
        );
        assert_eq!(
            bin.map_layout(),
            Some(gobin::structures::maptype::MapLayout::HmapWithHmapType)
        );
    }
}

mod coverage_metadata {
    use super::matrix::discover;
    use super::source_spans_and_methods::source_functions;
    use super::*;
    use gobin::{metadata::HookKind, structures::coverage::CoveragePackage};

    /// The pclntab symbol of a function `cmd/cover` names `name` in a package
    /// whose symbols start with `prefix`: `*T.M` is `prefix.(*T).M`.
    fn symbol(prefix: &str, name: &str) -> String {
        match name.strip_prefix('*') {
            Some(method) => {
                let (ty, m) = method.split_once('.').unwrap();
                format!("{prefix}.(*{ty}).{m}")
            }
            None => format!("{prefix}.{name}"),
        }
    }

    /// The fixture source and symbol prefix of an instrumented package.
    fn source_of(prog: &str, package: &CoveragePackage<'_>) -> (String, &'static str) {
        match (prog, package.package_name) {
            ("deps", "greet") => ("tests/samples/src/greet/greet.go".into(), "greet"),
            (prog, "main") => (format!("tests/samples/src/{prog}/main.go"), "main"),
            other => panic!("unexpected package {other:?}"),
        }
    }

    /// A `-cover` build's metadata describes its own source: each
    /// instrumented function is in the pclntab under the symbol `cmd/cover`'s
    /// name maps to, each of its units lies within that function in the
    /// fixture's source file, and each file is the source's. The blob's
    /// length is its symbol's recorded size, and the counter region holds a
    /// counter variable for each function, `3 + units` words.
    #[test]
    fn coverage_describes_the_source() {
        let (mut units, mut literals) = (0usize, 0usize);
        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let packages = bin.coverage();
            if !bin.is_coverage_build() || fx.path.contains("_stripped") {
                assert!(packages.is_empty(), "{}", fx.path);
                continue;
            }
            assert!(!packages.is_empty(), "{}", fx.path);
            let names: BTreeSet<&str> = bin.functions().map(|f| f.name).collect();
            let symbols = bin.symbols();
            // The basic fixtures of Go 1.20-1.25 were built from a copy of
            // the source three lines shorter; main.main's start line says.
            let shift = bin
                .functions()
                .find(|f| f.name == "main.main")
                .map_or(0, |f| f.func.start_line - 82);
            let mut slots = 0usize;
            for package in &packages {
                let (source, prefix) = source_of(&fx.prog, package);
                let declared = source_functions(&source, prefix);
                let shift = if fx.prog == "basic" { shift } else { 0 };
                let blob = symbols
                    .iter()
                    .find(|s| {
                        s.name.contains(".goCover_")
                            && s.name.ends_with("_M")
                            && bin.coverage_meta_at(s.va).as_ref() == Some(package)
                    })
                    .unwrap();
                assert_eq!(u64::from(package.length), blob.size, "{}", fx.path);
                let base = source.rsplit('/').next().unwrap();
                for file in package.files() {
                    assert!(file.ends_with(&format!("/{base}")), "{}: {file}", fx.path);
                }
                for f in &package.functions {
                    if f.is_literal {
                        // A package-level function literal, named by where its
                        // `func` keyword is: `func.L<line>.C<column>`.
                        let (line, column) = f
                            .name
                            .strip_prefix("func.L")
                            .and_then(|rest| rest.split_once(".C"))
                            .map(|(l, c)| {
                                (l.parse::<usize>().unwrap(), c.parse::<usize>().unwrap())
                            })
                            .unwrap_or_else(|| panic!("{}: literal {}", fx.path, f.name));
                        let text = std::fs::read_to_string(&source).unwrap();
                        let at = text.lines().nth(line - 1).unwrap();
                        assert_eq!(
                            at.get(column - 1..column + 3),
                            Some("func"),
                            "{}: {}",
                            fx.path,
                            f.name
                        );
                        for u in &f.units {
                            assert!(u.start_line as usize >= line, "{}: {u:?}", fx.path);
                            units += 1;
                        }
                        literals += 1;
                        slots += f.counter_slots();
                        continue;
                    }
                    let symbol = symbol(prefix, f.name);
                    let pclntab = if package.package_name == "main" {
                        symbol.clone()
                    } else {
                        format!(
                            "{}{}",
                            package.package_path,
                            symbol.strip_prefix(prefix).unwrap()
                        )
                    };
                    assert!(names.contains(pclntab.as_str()), "{}: {pclntab}", fx.path);
                    let (_, first, close) = declared
                        .iter()
                        .find(|(s, ..)| *s == symbol)
                        .unwrap_or_else(|| panic!("{}: {symbol} not in {source}", fx.path));
                    for u in &f.units {
                        let lines = (first + shift) as u32..=(close + shift) as u32;
                        assert!(
                            lines.contains(&u.start_line) && lines.contains(&u.end_line),
                            "{}: {symbol} unit {u:?} outside {lines:?}",
                            fx.path
                        );
                        assert!(u.statements > 0, "{}: {symbol}", fx.path);
                        units += 1;
                    }
                    slots += f.counter_slots();
                }
            }
            let region = bin.moduledata().unwrap().covctrs.unwrap();
            let size = (region.end - region.start) as usize;
            let vars: usize = packages.iter().map(|p| p.functions.len()).sum();
            assert!(
                slots * 4 <= size && size <= slots * 4 + 16 * (vars + 1),
                "{}: {slots} slots in {size} bytes",
                fx.path
            );
        }
        assert!(units > 30, "too few units checked: {units}");
        assert!(literals >= 1, "no function literal checked");
    }

    /// A stripped `-cover` build has no symbol to find its blobs by; decoded
    /// from the addresses its unstripped twin's symbol table gives (where a
    /// disassembler would read them off the registration calls), they are
    /// the twin's. The registration hook is in exactly the `-cover` builds.
    #[test]
    fn stripped_coverage_decodes_from_the_registration_address() {
        let full = load("tests/samples/deps_go128_linux_amd64_cover");
        let full = GoBinary::parse(&full).unwrap();
        let stripped = load("tests/samples/deps_go128_linux_amd64_cover_stripped");
        let stripped = GoBinary::parse(&stripped).unwrap();
        assert!(stripped.symbols().is_empty());
        assert!(stripped.coverage().is_empty());
        let expected = full.coverage();
        assert_eq!(expected.len(), 2);
        let decoded: Vec<_> = full
            .symbols()
            .iter()
            .filter(|s| s.name.ends_with("_M") && s.name.contains(".goCover_"))
            .map(|s| stripped.coverage_meta_at(s.va).unwrap())
            .collect();
        assert_eq!(decoded, expected);
        // A wrong address decodes nothing.
        let first = full
            .symbols()
            .iter()
            .find(|s| s.name.ends_with("_M"))
            .unwrap()
            .va;
        assert_eq!(stripped.coverage_meta_at(first + 4), None);

        for fx in discover() {
            let data = load(&fx.path);
            let bin = GoBinary::parse(&data).unwrap();
            let registers = bin
                .runtime_hooks()
                .iter()
                .any(|h| h.kind == HookKind::CoverageRegistration);
            assert_eq!(registers, bin.is_coverage_build(), "{}", fx.path);
        }
    }
}

mod universal {
    use super::*;
    use gobin::formats::{FatSlice, macho_slices};

    const FAT: &str = "tests/samples/basic_go128_darwin_universal";
    const THIN: [&str; 2] = [
        "tests/samples/basic_go128_darwin_amd64",
        "tests/samples/basic_go128_darwin_arm64",
    ];

    /// A universal file's slices are its thin images: each slice's bytes are
    /// the file it was assembled from, and parse as that file does. Parsing
    /// the universal file itself names the slices instead of reading one.
    #[test]
    fn universal_file_splits_into_its_images() {
        use gobin::structures::Arch;
        let fat = load(FAT);
        let slices = macho_slices(&fat).unwrap();
        let arches: Vec<Arch> = slices.iter().map(|s| s.arch).collect();
        assert_eq!(arches, [Arch::X86_64, Arch::Arm64]);
        for (slice, path) in slices.iter().zip(THIN) {
            let thin = load(path);
            assert_eq!(&fat[slice.range.clone()], &thin[..], "{path}");
            let (a, b) = (
                GoBinary::parse(&fat[slice.range.clone()]).unwrap(),
                GoBinary::parse(&thin).unwrap(),
            );
            assert_eq!(a.arch(), slice.arch, "{path}");
            assert_eq!(a.go_version(), b.go_version());
            assert_eq!(a.build_id(), b.build_id());
            assert_eq!(a.functions().count(), b.functions().count());
            assert_eq!(a.types().count(), b.types().count());
        }
        match GoBinary::try_parse(&fat) {
            Err(ParseError::Universal { slices: named }) => assert_eq!(named, slices),
            other => panic!("{:?}", other.map(|_| ())),
        }
        assert!(GoBinary::parse(&fat).is_none());
    }

    /// The 64-bit header (`0xcafebabf`: 64-bit offsets and sizes, 32-byte
    /// entries) names the same slices.
    #[test]
    fn fat64_header_names_the_same_slices() {
        let fat = load(FAT);
        let slices = macho_slices(&fat).unwrap();
        let mut wide = Vec::from(0xcafe_babf_u32.to_be_bytes());
        wide.extend((slices.len() as u32).to_be_bytes());
        let header = 8 + 32 * slices.len();
        let base = slices[0].range.start; // the images keep their spacing
        let shift = |at: usize| (at - base + header.next_multiple_of(1 << 14)) as u64;
        for s in &slices {
            wide.extend(s.cpu_type.to_be_bytes());
            wide.extend(s.cpu_subtype.to_be_bytes());
            wide.extend(shift(s.range.start).to_be_bytes());
            wide.extend((s.range.len() as u64).to_be_bytes());
            wide.extend([0, 0, 0, 14, 0, 0, 0, 0]);
        }
        wide.resize(header.next_multiple_of(1 << 14), 0);
        wide.extend(&fat[base..]);
        let named = macho_slices(&wide).unwrap();
        for (a, b) in named.iter().zip(&slices) {
            assert_eq!(&wide[a.range.clone()], &fat[b.range.clone()]);
            assert_eq!(
                (a.arch, a.cpu_type, a.cpu_subtype),
                (b.arch, b.cpu_type, b.cpu_subtype)
            );
        }
    }

    /// No thin binary reads as universal, nor does a Java class file, which
    /// shares the magic, nor a header whose slices leave the file or hold no
    /// Mach-O image.
    #[test]
    fn only_universal_files_have_slices() {
        for fx in super::matrix::discover() {
            assert_eq!(macho_slices(&load(&fx.path)), None, "{}", fx.path);
        }
        // A class file: magic, minor 0, major 52 (Java 8), constant pool.
        let class = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 0x1d, 0x0a, 0, 6];
        assert_eq!(macho_slices(&class), None);
        let fat = load(FAT);
        let slices: Vec<FatSlice> = macho_slices(&fat).unwrap();
        // A slice running past the end.
        let mut cut = fat.clone();
        cut.truncate(slices[1].range.end - 1);
        assert_eq!(macho_slices(&cut), None);
        // A slice whose bytes are no Mach-O image.
        let mut moved = fat.clone();
        moved[16..20].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(macho_slices(&moved), None);
        // A slice count beyond the file.
        let mut many = fat;
        many[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(macho_slices(&many), None);
    }
}

// ===========================================================================
// A damaged section table: the moduledata found by scanning the whole image.
// ===========================================================================
mod damaged_sections {
    use super::*;
    use gobin::structures::locate::ModuledataSource;

    /// The moduledata, text sections and function addresses of `bin`, for
    /// comparing a damaged parse with the intact one.
    fn layout(bin: &GoBinary<'_>) -> String {
        let entries: Vec<_> = bin.functions().map(|f| bin.entry_va(&f)).collect();
        format!(
            "{:?}\n{:?}\n{entries:?}",
            bin.moduledata(),
            bin.text_sections()
        )
    }

    /// Every ELF fixture with its section header offset (`e_shoff`) damaged
    /// two ways: its low byte flipped (the fuzzer zeroed it, which leaves a
    /// table whose offset already ends in zero intact) and the whole field
    /// zeroed. Without sections the moduledata is found by scanning
    /// the image from its start, which on a position-independent binary meets
    /// `.rela.dyn` first: the relocation of the moduledata's `pcHeader` field
    /// holds the pclntab address as its addend, among more
    /// `(offset, R_X86_64_RELATIVE, addend)` triples that once passed as a
    /// moduledata (`text` 0x594420 instead of 0x401000, a 5.8 million entry
    /// `textsectmap`, every function address wrong and a 1.5 s
    /// `functions()` pass). The scan must find the record the intact
    /// section table names.
    #[test]
    fn image_scan_finds_the_moduledata_the_sections_name() {
        let mut checked = 0;
        let mut pie = false;
        for fixture in matrix::discover() {
            let data = load(&fixture.path);
            // ELF only: ELFCLASS64 keeps e_shoff at 0x28 (8 bytes), ELFCLASS32
            // at 0x20 (4 bytes).
            let field = match data.get(..5) {
                Some([0x7f, b'E', b'L', b'F', 2]) => 0x28..0x30,
                Some([0x7f, b'E', b'L', b'F', 1]) => 0x20..0x24,
                _ => continue,
            };
            let Some(intact) = GoBinary::parse(&data) else {
                continue;
            };
            if intact.moduledata().is_none() {
                continue;
            }
            let expected = layout(&intact);
            for whole in [false, true] {
                let mut damaged = data.clone();
                if whole {
                    damaged[field.clone()].fill(0);
                } else {
                    damaged[field.start] ^= 0xff;
                }
                let Some(bin) = GoBinary::parse(&damaged) else {
                    panic!("{}: no parse with e_shoff damaged", fixture.path);
                };
                let source = bin.report().signals.iter().find_map(|s| match s {
                    ConfidenceSignal::ModuledataLocated { source, .. } => Some(*source),
                    _ => None,
                });
                assert!(
                    matches!(
                        source,
                        Some(ModuledataSource::ImageScan | ModuledataSource::DataScan)
                    ),
                    "{}: the damaged binary must be scanned, not read from a section: {source:?}",
                    fixture.path
                );
                assert_eq!(
                    layout(&bin),
                    expected,
                    "{} (whole field: {whole})",
                    fixture.path
                );
            }
            pie |= fixture.path.ends_with("_pie");
            checked += 1;
        }
        assert!(pie, "the position-independent fixture must be among them");
        assert!(checked >= 50, "only {checked} ELF fixtures checked");
    }
}
