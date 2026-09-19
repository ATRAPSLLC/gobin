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
    structures::{Arch, PclntabVersion},
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
        let ParseError::NotAGoBinary { report } = err;
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

    #[test]
    fn function_info_short_name() {
        let f = FunctionInfo {
            name: "net/http.(*Client).Do",
            entry_offset: 0,
            args_size: 0,
            start_line: 0,
            func_id: 0,
            flags: 0,
            deferreturn: 0,
            pcsp: 0,
            pcfile: 0,
            pcln: 0,
            npcdata: 0,
            cu_offset: 0,
            nfuncdata: 0,
            source_file: None,
            end_line: 0,
            frame_size: 0,
        };
        assert_eq!(f.short_name(), "(*Client).Do");
        assert_eq!(f.package(), Some("net/http"));
        assert!(f.is_method());
    }

    #[test]
    fn function_info_closure() {
        let f = FunctionInfo {
            name: "main.main.func1",
            entry_offset: 0,
            args_size: 0,
            start_line: 0,
            func_id: 0,
            flags: 0,
            deferreturn: 0,
            pcsp: 0,
            pcfile: 0,
            pcln: 0,
            npcdata: 0,
            cu_offset: 0,
            nfuncdata: 0,
            source_file: None,
            end_line: 0,
            frame_size: 0,
        };
        assert!(f.is_closure());
        assert!(!f.is_method());
    }

    #[test]
    fn function_info_func_id_names() {
        let f = FunctionInfo {
            name: "runtime.goexit",
            entry_offset: 0,
            args_size: 0,
            start_line: 0,
            func_id: 86,
            flags: 0,
            deferreturn: 0,
            pcsp: 0,
            pcfile: 0,
            pcln: 0,
            npcdata: 0,
            cu_offset: 0,
            nfuncdata: 0,
            source_file: None,
            end_line: 0,
            frame_size: 0,
        };
        assert_eq!(f.func_id_name(), Some("goexit"));

        let normal = FunctionInfo {
            name: "main.main",
            entry_offset: 0,
            args_size: 0,
            start_line: 0,
            func_id: 0,
            flags: 0,
            deferreturn: 0,
            pcsp: 0,
            pcfile: 0,
            pcln: 0,
            npcdata: 0,
            cu_offset: 0,
            nfuncdata: 0,
            source_file: None,
            end_line: 0,
            frame_size: 0,
        };
        assert_eq!(normal.func_id_name(), None);
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
        assert!(main_fn.start_line > 0, "start_line should be positive");
        assert!(
            main_fn.end_line >= main_fn.start_line,
            "end_line ({}) should be >= start_line ({})",
            main_fn.end_line,
            main_fn.start_line
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
    fn has_cgo_and_uses_concurrency_run_without_panic() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let _ = bin.has_cgo();
        let _ = bin.uses_concurrency();
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
        let pcl = bin.pclntab().unwrap();

        // Walk every function; expect at least one to expose inlined frames.
        let mut total_entries = 0usize;
        let mut saw_named = false;
        let mut max_depth = 0u32;
        for (_, func_off) in pcl.func_entries() {
            let func = match pcl.parse_func(func_off) {
                Some(f) => f,
                None => continue,
            };
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
        let pcl = bin.pclntab().unwrap();

        // Find a function with no funcdata (typically asm helpers or trivial leaves)
        // and verify the iterator is empty rather than panicking.
        for (_, func_off) in pcl.func_entries() {
            let func = match pcl.parse_func(func_off) {
                Some(f) => f,
                None => continue,
            };
            if func.nfuncdata == 0 {
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
        let main_va = text_va + main_fn.entry_offset as u64;
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
            let pcl = bin.pclntab().unwrap();
            let (_, func_off) = pcl.func_entries().next().unwrap();
            let func = pcl.parse_func(func_off).unwrap();

            let manual = text_va + func.entry_off as u64;
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
        let pcl = bin.pclntab().unwrap();
        let (_, func_off) = pcl.func_entries().next().unwrap();
        let func = pcl.parse_func(func_off).unwrap();

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
            let pcl = bin.pclntab().unwrap();
            let (_, func_off) = pcl.func_entries().next().unwrap();
            let func = pcl.parse_func(func_off).unwrap();
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
            BuildMode::Other("custom-future".to_string()),
        ];
        for mode in cases {
            let s = mode.as_str();
            let round = BuildMode::parse(&s);
            assert_eq!(round, mode, "as_str → parse must round-trip for {mode:?}");
            // Display must agree with as_str so schema serialization is stable.
            assert_eq!(format!("{mode}"), s.as_ref());
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
            for va in bin.itab_methods(&pair) {
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
        let pcl = bin.pclntab().unwrap();

        let mut total_entries = 0usize;
        for (_, off) in pcl.func_entries().take(200) {
            let func = match pcl.parse_func(off) {
                Some(f) => f,
                None => continue,
            };
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
    fn decode_pcln_with_files_attributes_source_file_per_line() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let pcl = bin.pclntab().unwrap();

        // Find a function with both pcln and pcfile entries.
        let mut joined_total = 0usize;
        let mut at_least_one_function = false;
        for (_, off) in pcl.func_entries() {
            let f = match pcl.parse_func(off) {
                Some(f) => f,
                None => continue,
            };

            // Reference data: per-PC pcln + the latest-≤-pc pcfile resolution.
            let pcfile: Vec<(u32, u32)> = pcl.decode_pcfile(&f).collect();
            if pcfile.is_empty() {
                continue;
            }
            at_least_one_function = true;

            // Joined iterator must agree with the manual lockstep walk on every
            // emitted (pc, line, path) tuple.
            for (pc, line, path) in pcl.decode_pcln_with_files(&f) {
                joined_total += 1;

                // Expected file index = latest pcfile transition with t_pc ≤ pc.
                let expected_idx = pcfile
                    .iter()
                    .rev()
                    .find(|(t_pc, _)| *t_pc <= pc)
                    .map(|(_, idx)| *idx)
                    .unwrap();
                let expected_path = pcl.resolve_file_via_cu(f.cu_offset, expected_idx).unwrap();
                assert_eq!(path, expected_path, "joined path mismatch at pc={pc}");

                // Line must be a sane source line (not absurdly large).
                assert!((0..1_000_000).contains(&line), "implausible line {line}");

                if joined_total > 50 {
                    break;
                }
            }
            if joined_total > 50 {
                break;
            }
        }
        assert!(at_least_one_function, "expected pcfile entries somewhere");
        assert!(joined_total > 0, "joined iterator yielded nothing");
    }

    #[test]
    fn decode_pcfile_returns_unsigned_indices() {
        let data = load(BASIC_NORMAL);
        let bin = GoBinary::parse(&data).unwrap();
        let pcl = bin.pclntab().unwrap();

        let mut saw_indices = false;
        let mut saw_resolved = false;
        for (_, func_off) in pcl.func_entries() {
            let func = match pcl.parse_func(func_off) {
                Some(f) => f,
                None => continue,
            };
            if pcl.decode_pcfile(&func).next().is_some() {
                saw_indices = true;
            }
            if pcl.decode_pcfile_paths(&func).next().is_some() {
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
        structures::{Arch, PclntabVersion, moduledata::ModuledataVersion},
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
            let core = ["_stripped", "_cover", "_fips", "_pie"]
                .iter()
                .find_map(|v| name.strip_suffix(v))
                .unwrap_or(name);
            let parts: Vec<&str> = core.split('_').collect();
            // <prog>_go<NN>_<goos>_<goarch>
            if parts.len() != 4 || !parts[1].starts_with("go") {
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
            "wasip1" => BinaryFormat::Wasm,
            _ => BinaryFormat::Elf,
        }
    }

    fn expected_arch(goarch: &str) -> Arch {
        match goarch {
            "amd64" => Arch::X86_64,
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
            "go117", "go118", "go120", "go121", "go124", "go126", "go127",
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
            let va = text + u64::from(main.entry_offset);
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
                        info.cgo_enabled().is_some(),
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
            assert!(main.entry_offset > 0, "{}: main entry_offset", fx.path);

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
        // The same Go version built for different native formats must report an
        // identical go_version string and pclntab layout. Wasm is excluded: its
        // reconstructed-linear-memory metadata legitimately differs (e.g. the
        // version string drops the gotip `-devel` suffix).
        let mut by_tag: std::collections::BTreeMap<String, Vec<Fixture>> =
            std::collections::BTreeMap::new();
        for fx in basics().into_iter().filter(|f| f.goarch != "wasm") {
            by_tag.entry(fx.gotag.clone()).or_default().push(fx);
        }
        for (tag, group) in by_tag.iter().filter(|(_, g)| g.len() > 1) {
            let parsed: Vec<_> = group.iter().map(|fx| (fx, load(&fx.path))).collect();
            let bins: Vec<_> = parsed
                .iter()
                .map(|(fx, d)| (*fx, GoBinary::parse(d).unwrap()))
                .collect();
            let (_, first) = &bins[0];
            let v0 = first.go_version();
            let p0 = first.pclntab().map(|p| p.version);
            for (fx, bin) in &bins[1..] {
                assert_eq!(
                    bin.go_version(),
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
                    bin.build_info().and_then(|bi| bi.cgo_enabled()),
                    Some(true),
                    "{path}: CGO_ENABLED not reported"
                );
            }
        }
    }
}
