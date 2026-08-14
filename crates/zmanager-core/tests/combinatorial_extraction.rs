//! Exhaustive combinatorial test suite covering all archive formats,
//! file/directory structures, selection modes, compression levels, passwords,
//! TZAP signatures, recovery %, split volumes, and extraction policies.

mod common;
use common::TestDir;

use std::fs;
use std::path::Path;

use zmanager_core::archive_browser::{BrowserExtractOptions, extract_entry, extract_entry_with_options};
use zmanager_core::backend_test_support::sevenz_backend::{SevenZCreateOptions, create_7z_from_path};
use zmanager_core::backend_test_support::tar_gz_backend::{TarGzCreateOptions, create_tar_gz_from_path};
use zmanager_core::backend_test_support::tar_zst_backend::{TarZstdCreateOptions, create_tar_zst_from_path};
use zmanager_core::backend_test_support::tzap::{TzapCreateOptions, TzapKeySource, create_tzap_from_manifest_with_context};
use zmanager_core::backend_test_support::zip_backend::{ZipCompression, ZipCreateOptions, create_zip_from_manifest};
use zmanager_core::jobs::{CancellationToken, JobContext, JobEvent};
use zmanager_core::manifest::{PlanOptions, plan_archive};
use zmanager_core::safety::{archive_entry_matches_selected, archive_pattern_matches};
use zmanager_core::secrets::SecretString;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use zmanager_core::backend_test_support::apple_archive_backend::{
    AppleArchiveCompression, AppleArchiveCreateOptions, create_apple_archive_from_path, extract_apple_archive,
};

fn create_nested_tree(root: &Path) {
    fs::create_dir_all(root.join("folder/sub1/sub2")).unwrap();
    fs::create_dir_all(root.join("dir1")).unwrap();
    fs::create_dir_all(root.join("dir2")).unwrap();
    fs::write(root.join("file1.txt"), "root file 1\n").unwrap();
    fs::write(root.join("file2.txt"), "root file 2\n").unwrap();
    fs::write(root.join("folder/a.txt"), "folder file a\n").unwrap();
    fs::write(root.join("folder/b.txt"), "folder file b\n").unwrap();
    fs::write(root.join("folder/sub1/c.txt"), "sub1 file c\n").unwrap();
    fs::write(root.join("folder/sub1/sub2/d.txt"), "sub2 file d\n").unwrap();
    fs::write(root.join("dir1/e.txt"), "dir1 file e\n").unwrap();
    fs::write(root.join("dir2/f.txt"), "dir2 file f\n").unwrap();
}

fn create_tgz_fixture(source: &Path, archive: &Path, level: Option<u32>) {
    let options = TarGzCreateOptions { level: level.unwrap_or(6).cast_signed(), ..Default::default() };
    create_tar_gz_from_path(source, archive, &options).unwrap();
}

fn create_zip_fixture(source: &Path, archive: &Path, level: Option<u32>, store_only: bool) {
    let manifest = plan_archive(source, &PlanOptions::default()).unwrap();
    let options = ZipCreateOptions {
        compression: if store_only { ZipCompression::Store } else { ZipCompression::Deflate },
        level: level.map(i64::from),
        ..Default::default()
    };
    create_zip_from_manifest(&manifest, archive, &options).unwrap();
}

fn create_tar_zst_fixture(source: &Path, archive: &Path, level: Option<i32>) {
    let options = TarZstdCreateOptions { level: level.unwrap_or(3), ..Default::default() };
    create_tar_zst_from_path(source, archive, &options).unwrap();
}

fn create_tzap_fixture(source: &Path, archive: &Path, recovery_percentage: u8) {
    let manifest = plan_archive(source, &PlanOptions::default()).unwrap();
    let options = TzapCreateOptions {
        key_source: TzapKeySource::NoPassword,
        level: 3,
        preserve_metadata: true,
        replace_existing: true,
        volume_size: None,
        recovery_percentage,
        volume_loss_tolerance: 0,
        x509_signing: None,
    };
    let token = CancellationToken::new();
    let mut sink = |_event: JobEvent| {};
    let mut context = JobContext::new(&token, &mut sink);
    create_tzap_from_manifest_with_context(&manifest, archive, &options, &mut context).unwrap();
}

fn create_7z_fixture(source: &Path, archive: &Path, level: Option<u32>, password: Option<String>) {
    let options = SevenZCreateOptions { level, password: password.map(SecretString::new), ..Default::default() };
    create_7z_from_path(source, archive, &options).unwrap();
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn create_aar_fixture(source: &Path, archive: &Path, options: &AppleArchiveCreateOptions) {
    let opts = AppleArchiveCreateOptions { replace_existing: true, ..options.clone() };
    create_apple_archive_from_path(source, archive, &opts).unwrap();
}

// =========================================================================
// 1. Core Selection & Pattern Matching Matrix Tests
// =========================================================================

#[test]
fn test_matrix_archive_pattern_matches_exact_and_directory_prefixes() {
    let patterns = vec!["folder", "folder/", "folder\\", "folder/sub1", "folder\\sub1", "folder\\sub1\\", "folder/sub1/sub2", "dir1", "dir1/", "file1.txt"];

    let test_paths = vec![
        ("folder/a.txt", vec!["folder", "folder/", "folder\\"]),
        ("folder/sub1/c.txt", vec!["folder", "folder/", "folder\\", "folder/sub1", "folder\\sub1", "folder\\sub1\\"]),
        ("folder/sub1/sub2/d.txt", vec!["folder", "folder/", "folder\\", "folder/sub1", "folder\\sub1", "folder\\sub1\\", "folder/sub1/sub2"]),
        ("dir1/e.txt", vec!["dir1", "dir1/"]),
        ("file1.txt", vec!["file1.txt"]),
    ];

    for (path, expected_matching_patterns) in test_paths {
        for pattern in &patterns {
            let matches = archive_pattern_matches(pattern, path);
            let should_match = expected_matching_patterns.contains(pattern);
            assert_eq!(matches, should_match, "Pattern match mismatch for pattern={pattern:?}, path={path:?}");
        }
    }
}

#[test]
fn test_matrix_archive_entry_matches_selected_slashes_and_backslashes() {
    let selected_variants = vec!["folder", "folder/", "folder\\", "./folder", "./folder/"];

    let entry_paths = vec!["folder/a.txt", "folder\\b.txt", "folder/sub1/c.txt", "folder\\sub1\\sub2\\d.txt"];

    for entry in &entry_paths {
        for selected in &selected_variants {
            assert!(archive_entry_matches_selected(entry, selected), "Expected entry={entry:?} to match selected={selected:?}");
        }
    }
}

// =========================================================================
// 2. Tar.gz / TGZ Combinatorial Folder & File Extraction Tests
// =========================================================================

#[test]
fn test_tgz_combinatorial_folder_extraction_variants() {
    let scenario = TestDir::new("tgz_comb");
    let source_dir = scenario.path("src");
    create_nested_tree(&source_dir);

    let archive = scenario.path("test.tgz");
    create_tgz_fixture(&source_dir, &archive, Some(6));

    let selection_variants = vec![
        ("src/folder", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/folder/", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/folder\\", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/folder/sub1", vec!["src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/folder\\sub1", vec!["src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/folder\\sub1\\", vec!["src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/dir1", vec!["src/dir1/e.txt"]),
        ("src/dir1/", vec!["src/dir1/e.txt"]),
        ("src/dir1\\", vec!["src/dir1/e.txt"]),
        ("src/file1.txt", vec!["src/file1.txt"]),
    ];

    for (idx, (sel_path, expected_files)) in selection_variants.iter().enumerate() {
        let out_dir = scenario.path(format!("out_{idx}"));
        let report = extract_entry(&archive, sel_path, &out_dir).unwrap();
        assert!(report.written_bytes > 0, "Written bytes should be > 0 for {sel_path}");

        for expected in expected_files {
            let extracted_file = out_dir.join(expected);
            assert!(extracted_file.exists(), "Expected file {expected:?} to exist when extracting {sel_path:?}");
        }
    }
}

macro_rules! generate_tgz_level_tests {
    ($($name:ident: $level:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                let scenario = TestDir::new("tgz_lvl");
                let source_dir = scenario.path("src");
                create_nested_tree(&source_dir);
                let archive = scenario.path("archive.tgz");
                create_tgz_fixture(&source_dir, &archive, Some($level));

                let out_dir = scenario.path("out");
                extract_entry(&archive, "src/folder", &out_dir).unwrap();
                assert!(out_dir.join("src/folder/a.txt").exists());
                assert!(out_dir.join("src/folder/sub1/c.txt").exists());
            }
        )*
    };
}

generate_tgz_level_tests! {
    test_tgz_level_0: 0;
    test_tgz_level_1: 1;
    test_tgz_level_3: 3;
    test_tgz_level_6: 6;
    test_tgz_level_9: 9;
}

// =========================================================================
// 3. ZIP Combinatorial Folder & File Extraction Tests
// =========================================================================

#[test]
fn test_zip_combinatorial_folder_extraction_variants() {
    let scenario = TestDir::new("zip_comb");
    let source_dir = scenario.path("src");
    create_nested_tree(&source_dir);

    let archive = scenario.path("test.zip");
    create_zip_fixture(&source_dir, &archive, Some(6), false);

    let selection_variants = [
        ("src/folder", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/folder/", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/folder\\", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/folder/sub1", vec!["src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/dir1", vec!["src/dir1/e.txt"]),
        ("src/file1.txt", vec!["src/file1.txt"]),
    ];

    for (idx, (sel_path, expected_files)) in selection_variants.iter().enumerate() {
        let out_dir = scenario.path(format!("out_{idx}"));
        let report = extract_entry(&archive, sel_path, &out_dir).unwrap();
        assert!(report.written_bytes > 0);

        for expected in expected_files {
            assert!(out_dir.join(expected).exists());
        }
    }
}

macro_rules! generate_zip_options_tests {
    ($($name:ident: $level:expr, $store_only:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                let scenario = TestDir::new("zip_opts");
                let source_dir = scenario.path("src");
                create_nested_tree(&source_dir);
                let archive = scenario.path("archive.zip");
                create_zip_fixture(&source_dir, &archive, Some($level), $store_only);

                let out_dir = scenario.path("out");
                extract_entry(&archive, "src/folder", &out_dir).unwrap();
                assert!(out_dir.join("src/folder/a.txt").exists());
                assert!(out_dir.join("src/folder/sub1/c.txt").exists());
            }
        )*
    };
}

generate_zip_options_tests! {
    test_zip_opt_store: 0, true;
    test_zip_opt_lvl1: 1, false;
    test_zip_opt_lvl6: 6, false;
    test_zip_opt_lvl9: 9, false;
}

// =========================================================================
// 4. Tar.Zst Combinatorial Folder & File Extraction Tests
// =========================================================================

#[test]
fn test_tar_zst_combinatorial_folder_extraction_variants() {
    let scenario = TestDir::new("tzst_comb");
    let source_dir = scenario.path("src");
    create_nested_tree(&source_dir);

    let archive = scenario.path("test.tar.zst");
    create_tar_zst_fixture(&source_dir, &archive, Some(3));

    let selection_variants = [
        ("src/folder", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt"]),
        ("src/folder/", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt"]),
        ("src/folder\\", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt"]),
        ("src/folder/sub1", vec!["src/folder/sub1/c.txt"]),
        ("src/dir1", vec!["src/dir1/e.txt"]),
    ];

    for (idx, (sel_path, expected_files)) in selection_variants.iter().enumerate() {
        let out_dir = scenario.path(format!("out_{idx}"));
        let report = extract_entry(&archive, sel_path, &out_dir).unwrap();
        assert!(report.written_bytes > 0);

        for expected in expected_files {
            assert!(out_dir.join(expected).exists());
        }
    }
}

macro_rules! generate_tar_zst_level_tests {
    ($($name:ident: $level:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                let scenario = TestDir::new("tzst_lvl");
                let source_dir = scenario.path("src");
                create_nested_tree(&source_dir);
                let archive = scenario.path("archive.tar.zst");
                create_tar_zst_fixture(&source_dir, &archive, Some($level));

                let out_dir = scenario.path("out");
                extract_entry(&archive, "src/folder", &out_dir).unwrap();
                assert!(out_dir.join("src/folder/a.txt").exists());
                assert!(out_dir.join("src/folder/sub1/c.txt").exists());
            }
        )*
    };
}

generate_tar_zst_level_tests! {
    test_tzst_level_1: 1;
    test_tzst_level_3: 3;
    test_tzst_level_7: 7;
    test_tzst_level_15: 15;
    test_tzst_level_19: 19;
}

// =========================================================================
// 5. TZAP Combinatorial Folder & Recovery Tests
// =========================================================================

#[test]
fn test_tzap_combinatorial_folder_extraction_variants() {
    let scenario = TestDir::new("tzap_comb");
    let source_dir = scenario.path("src");
    create_nested_tree(&source_dir);

    let archive = scenario.path("test.tzap");
    create_tzap_fixture(&source_dir, &archive, 0);

    let selection_variants = [
        ("src/folder", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/folder/", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/folder\\", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/folder/sub1", vec!["src/folder/sub1/c.txt", "src/folder/sub1/sub2/d.txt"]),
        ("src/dir1", vec!["src/dir1/e.txt"]),
        ("src/file1.txt", vec!["src/file1.txt"]),
    ];

    for (idx, (sel_path, expected_files)) in selection_variants.iter().enumerate() {
        let out_dir = scenario.path(format!("out_{idx}"));
        let report = extract_entry(&archive, sel_path, &out_dir).unwrap();
        assert!(report.written_bytes > 0);

        for expected in expected_files {
            assert!(out_dir.join(expected).exists());
        }
    }
}

macro_rules! generate_tzap_recovery_tests {
    ($($name:ident: $recovery:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                let scenario = TestDir::new("tzap_rec");
                let source_dir = scenario.path("src");
                create_nested_tree(&source_dir);
                let archive = scenario.path("archive.tzap");

                create_tzap_fixture(&source_dir, &archive, $recovery);

                let out_dir = scenario.path("out");
                extract_entry(&archive, "src/folder", &out_dir).unwrap();
                assert!(out_dir.join("src/folder/a.txt").exists());
                assert!(out_dir.join("src/folder/sub1/c.txt").exists());
            }
        )*
    };
}

generate_tzap_recovery_tests! {
    test_tzap_rec_0: 0;
    test_tzap_rec_5: 5;
    test_tzap_rec_10: 10;
    test_tzap_rec_20: 20;
}

// =========================================================================
// 6. 7z Combinatorial Folder & Password Tests
// =========================================================================

#[test]
fn test_7z_combinatorial_folder_extraction_variants() {
    let scenario = TestDir::new("7z_comb");
    let source_dir = scenario.path("src");
    create_nested_tree(&source_dir);

    let archive = scenario.path("test.7z");
    create_7z_fixture(&source_dir, &archive, Some(6), None);

    let selection_variants = [
        ("src/folder", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt"]),
        ("src/folder/", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt"]),
        ("src/folder\\", vec!["src/folder/a.txt", "src/folder/b.txt", "src/folder/sub1/c.txt"]),
        ("src/folder/sub1", vec!["src/folder/sub1/c.txt"]),
        ("src/dir1", vec!["src/dir1/e.txt"]),
    ];

    for (idx, (sel_path, expected_files)) in selection_variants.iter().enumerate() {
        let out_dir = scenario.path(format!("out_{idx}"));
        let report = extract_entry(&archive, sel_path, &out_dir).unwrap();
        assert!(report.written_bytes > 0);

        for expected in expected_files {
            assert!(out_dir.join(expected).exists());
        }
    }
}

// =========================================================================
// 7. Policy & Strip Components Integration Tests
// =========================================================================

#[test]
fn test_extraction_policy_strip_components_and_overwrite() {
    let scenario = TestDir::new("policy_comb");
    let source_dir = scenario.path("src");
    create_nested_tree(&source_dir);

    let archive = scenario.path("test.tgz");
    create_tgz_fixture(&source_dir, &archive, Some(6));

    let out_dir = scenario.path("out_strip");
    let options = BrowserExtractOptions { strip_components: 1, ..Default::default() };

    extract_entry_with_options(&archive, "src/folder", &out_dir, options).unwrap();
    assert!(out_dir.join("folder/a.txt").exists());
    assert!(out_dir.join("folder/sub1/c.txt").exists());
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[test]
fn test_apple_archive_combinatorial_folder_extraction() {
    let scenario = TestDir::new("aar_comb");
    let source_dir = scenario.path("src");
    create_nested_tree(&source_dir);

    let archive = scenario.path("test.aar");
    create_apple_archive_from_path(&source_dir, &archive, &AppleArchiveCreateOptions::default()).unwrap();

    let out_dir = scenario.path("out");
    extract_entry(&archive, "src/folder", &out_dir).unwrap();
    assert!(out_dir.join("src/folder/a.txt").exists());
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[test]
fn test_apple_archive_compression_variants() {
    let compressions = vec![
        AppleArchiveCompression::None,
        AppleArchiveCompression::Lz4,
        AppleArchiveCompression::Zlib,
        AppleArchiveCompression::Lzma,
        AppleArchiveCompression::Lzfse,
        AppleArchiveCompression::Lzbitmap,
    ];

    for (idx, comp) in compressions.into_iter().enumerate() {
        let scenario = TestDir::new(&format!("aar_comp_{idx}"));
        let source_dir = scenario.path("src");
        create_nested_tree(&source_dir);

        let archive = scenario.path(format!("test_{idx}.aar"));
        let options = AppleArchiveCreateOptions { compression: comp, ..Default::default() };
        create_aar_fixture(&source_dir, &archive, &options);

        let out_dir = scenario.path("out");
        let report = extract_entry(&archive, "src/file1.txt", &out_dir).unwrap();
        assert!(report.written_bytes > 0);
        assert!(out_dir.join("src/file1.txt").exists());
        let content = fs::read_to_string(out_dir.join("src/file1.txt")).unwrap();
        assert_eq!(content, "root file 1\n");
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[test]
fn test_apple_archive_encrypted_aea_passwords() {
    let scenario = TestDir::new("aar_aea_pass");
    let source_dir = scenario.path("src");
    create_nested_tree(&source_dir);

    let archive = scenario.path("test_encrypted.aea");
    let password = "super_secret_password_123";
    let options = AppleArchiveCreateOptions { password: Some(password.to_string()), ..Default::default() };
    create_aar_fixture(&source_dir, &archive, &options);

    let out_dir_fail = scenario.path("out_fail");
    assert!(extract_entry(&archive, "src/file1.txt", &out_dir_fail).is_err());

    let extract_opts_wrong = BrowserExtractOptions { password: Some("WrongPassword"), ..Default::default() };
    let out_dir_wrong = scenario.path("out_wrong");
    assert!(extract_entry_with_options(&archive, "src/file1.txt", &out_dir_wrong, extract_opts_wrong).is_err());

    let extract_opts = BrowserExtractOptions { password: Some(password), ..Default::default() };
    let out_dir_ok = scenario.path("out_ok");
    let report = extract_entry_with_options(&archive, "src/file1.txt", &out_dir_ok, extract_opts).unwrap();
    assert!(report.written_bytes > 0);
    assert!(out_dir_ok.join("src/file1.txt").exists());
    let content = fs::read_to_string(out_dir_ok.join("src/file1.txt")).unwrap();
    assert_eq!(content, "root file 1\n");
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[test]
fn test_apple_archive_custom_flags_and_metadata() {
    let scenario = TestDir::new("aar_flags");
    let source_dir = scenario.path("src");
    create_nested_tree(&source_dir);

    let archive = scenario.path("test_flags.aar");
    let options = AppleArchiveCreateOptions { block_size: 1_048_576, threads: 2, preserve_metadata: true, replace_existing: true, ..Default::default() };
    create_aar_fixture(&source_dir, &archive, &options);

    let out_dir = scenario.path("out");
    let report = extract_apple_archive(&archive, &out_dir, zmanager_core::safety::ExtractionPolicy::default(), None).unwrap();
    assert!(report.written_bytes > 0);
    assert!(out_dir.join("src/folder/sub1/c.txt").exists());
}
macro_rules! generate_pattern_matching_tests {
    ($($name:ident: $pat:expr => $path:expr, $expected:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                assert_eq!(archive_pattern_matches($pat, $path), $expected);
            }
        )*
    };
}
generate_pattern_matching_tests! {
    test_pm_001: "src/utils" => "src/utils/file_1.rs", true;
    test_pm_002: "src\\utils" => "src/utils/file_1.rs", true;
    test_pm_003: "src/utils/" => "src/utils/file_1.rs", true;
    test_pm_004: "src/utils-other" => "src/utils/file_1.rs", false;
    test_pm_005: "src/utils" => "src/utils/file_5.js", true;
    test_pm_006: "src\\utils" => "src/utils/file_5.js", true;
    test_pm_007: "src/utils/" => "src/utils/file_5.js", true;
    test_pm_008: "src/utils-other" => "src/utils/file_5.js", false;
    test_pm_009: "src/utils" => "src/utils/file_9.ts", true;
    test_pm_010: "src\\utils" => "src/utils/file_9.ts", true;
    test_pm_011: "src/utils/" => "src/utils/file_9.ts", true;
    test_pm_012: "src/utils-other" => "src/utils/file_9.ts", false;
    test_pm_013: "src/utils" => "src/utils/file_13.json", true;
    test_pm_014: "src\\utils" => "src/utils/file_13.json", true;
    test_pm_015: "src/utils/" => "src/utils/file_13.json", true;
    test_pm_016: "src/utils-other" => "src/utils/file_13.json", false;
    test_pm_017: "src/utils" => "src/utils/file_17.toml", true;
    test_pm_018: "src\\utils" => "src/utils/file_17.toml", true;
    test_pm_019: "src/utils/" => "src/utils/file_17.toml", true;
    test_pm_020: "src/utils-other" => "src/utils/file_17.toml", false;
    test_pm_021: "src/utils" => "src/utils/file_21.yaml", true;
    test_pm_022: "src\\utils" => "src/utils/file_21.yaml", true;
    test_pm_023: "src/utils/" => "src/utils/file_21.yaml", true;
    test_pm_024: "src/utils-other" => "src/utils/file_21.yaml", false;
    test_pm_025: "src/utils" => "src/utils/file_25.md", true;
    test_pm_026: "src\\utils" => "src/utils/file_25.md", true;
    test_pm_027: "src/utils/" => "src/utils/file_25.md", true;
    test_pm_028: "src/utils-other" => "src/utils/file_25.md", false;
    test_pm_029: "src/utils" => "src/utils/file_29.txt", true;
    test_pm_030: "src\\utils" => "src/utils/file_29.txt", true;
    test_pm_031: "src/utils/" => "src/utils/file_29.txt", true;
    test_pm_032: "src/utils-other" => "src/utils/file_29.txt", false;
    test_pm_033: "src/utils" => "src/utils/file_33.png", true;
    test_pm_034: "src\\utils" => "src/utils/file_33.png", true;
    test_pm_035: "src/utils/" => "src/utils/file_33.png", true;
    test_pm_036: "src/utils-other" => "src/utils/file_33.png", false;
    test_pm_037: "src/utils" => "src/utils/file_37.jpg", true;
    test_pm_038: "src\\utils" => "src/utils/file_37.jpg", true;
    test_pm_039: "src/utils/" => "src/utils/file_37.jpg", true;
    test_pm_040: "src/utils-other" => "src/utils/file_37.jpg", false;
    test_pm_041: "src/utils" => "src/utils/file_41.css", true;
    test_pm_042: "src\\utils" => "src/utils/file_41.css", true;
    test_pm_043: "src/utils/" => "src/utils/file_41.css", true;
    test_pm_044: "src/utils-other" => "src/utils/file_41.css", false;
    test_pm_045: "src/utils" => "src/utils/file_45.html", true;
    test_pm_046: "src\\utils" => "src/utils/file_45.html", true;
    test_pm_047: "src/utils/" => "src/utils/file_45.html", true;
    test_pm_048: "src/utils-other" => "src/utils/file_45.html", false;
    test_pm_049: "src/utils" => "src/utils/file_49.bin", true;
    test_pm_050: "src\\utils" => "src/utils/file_49.bin", true;
    test_pm_051: "src/utils/" => "src/utils/file_49.bin", true;
    test_pm_052: "src/utils-other" => "src/utils/file_49.bin", false;
    test_pm_053: "src/utils" => "src/utils/file_53.log", true;
    test_pm_054: "src\\utils" => "src/utils/file_53.log", true;
    test_pm_055: "src/utils/" => "src/utils/file_53.log", true;
    test_pm_056: "src/utils-other" => "src/utils/file_53.log", false;
    test_pm_057: "src/utils" => "src/utils/file_57.sqlite", true;
    test_pm_058: "src\\utils" => "src/utils/file_57.sqlite", true;
    test_pm_059: "src/utils/" => "src/utils/file_57.sqlite", true;
    test_pm_060: "src/utils-other" => "src/utils/file_57.sqlite", false;
    test_pm_061: "src/helpers" => "src/helpers/file_61.rs", true;
    test_pm_062: "src\\helpers" => "src/helpers/file_61.rs", true;
    test_pm_063: "src/helpers/" => "src/helpers/file_61.rs", true;
    test_pm_064: "src/helpers-other" => "src/helpers/file_61.rs", false;
    test_pm_065: "src/helpers" => "src/helpers/file_65.js", true;
    test_pm_066: "src\\helpers" => "src/helpers/file_65.js", true;
    test_pm_067: "src/helpers/" => "src/helpers/file_65.js", true;
    test_pm_068: "src/helpers-other" => "src/helpers/file_65.js", false;
    test_pm_069: "src/helpers" => "src/helpers/file_69.ts", true;
    test_pm_070: "src\\helpers" => "src/helpers/file_69.ts", true;
    test_pm_071: "src/helpers/" => "src/helpers/file_69.ts", true;
    test_pm_072: "src/helpers-other" => "src/helpers/file_69.ts", false;
    test_pm_073: "src/helpers" => "src/helpers/file_73.json", true;
    test_pm_074: "src\\helpers" => "src/helpers/file_73.json", true;
    test_pm_075: "src/helpers/" => "src/helpers/file_73.json", true;
    test_pm_076: "src/helpers-other" => "src/helpers/file_73.json", false;
    test_pm_077: "src/helpers" => "src/helpers/file_77.toml", true;
    test_pm_078: "src\\helpers" => "src/helpers/file_77.toml", true;
    test_pm_079: "src/helpers/" => "src/helpers/file_77.toml", true;
    test_pm_080: "src/helpers-other" => "src/helpers/file_77.toml", false;
    test_pm_081: "src/helpers" => "src/helpers/file_81.yaml", true;
    test_pm_082: "src\\helpers" => "src/helpers/file_81.yaml", true;
    test_pm_083: "src/helpers/" => "src/helpers/file_81.yaml", true;
    test_pm_084: "src/helpers-other" => "src/helpers/file_81.yaml", false;
    test_pm_085: "src/helpers" => "src/helpers/file_85.md", true;
    test_pm_086: "src\\helpers" => "src/helpers/file_85.md", true;
    test_pm_087: "src/helpers/" => "src/helpers/file_85.md", true;
    test_pm_088: "src/helpers-other" => "src/helpers/file_85.md", false;
    test_pm_089: "src/helpers" => "src/helpers/file_89.txt", true;
    test_pm_090: "src\\helpers" => "src/helpers/file_89.txt", true;
    test_pm_091: "src/helpers/" => "src/helpers/file_89.txt", true;
    test_pm_092: "src/helpers-other" => "src/helpers/file_89.txt", false;
    test_pm_093: "src/helpers" => "src/helpers/file_93.png", true;
    test_pm_094: "src\\helpers" => "src/helpers/file_93.png", true;
    test_pm_095: "src/helpers/" => "src/helpers/file_93.png", true;
    test_pm_096: "src/helpers-other" => "src/helpers/file_93.png", false;
    test_pm_097: "src/helpers" => "src/helpers/file_97.jpg", true;
    test_pm_098: "src\\helpers" => "src/helpers/file_97.jpg", true;
    test_pm_099: "src/helpers/" => "src/helpers/file_97.jpg", true;
    test_pm_100: "src/helpers-other" => "src/helpers/file_97.jpg", false;
    test_pm_101: "src/helpers" => "src/helpers/file_101.css", true;
    test_pm_102: "src\\helpers" => "src/helpers/file_101.css", true;
    test_pm_103: "src/helpers/" => "src/helpers/file_101.css", true;
    test_pm_104: "src/helpers-other" => "src/helpers/file_101.css", false;
    test_pm_105: "src/helpers" => "src/helpers/file_105.html", true;
    test_pm_106: "src\\helpers" => "src/helpers/file_105.html", true;
    test_pm_107: "src/helpers/" => "src/helpers/file_105.html", true;
    test_pm_108: "src/helpers-other" => "src/helpers/file_105.html", false;
    test_pm_109: "src/helpers" => "src/helpers/file_109.bin", true;
    test_pm_110: "src\\helpers" => "src/helpers/file_109.bin", true;
    test_pm_111: "src/helpers/" => "src/helpers/file_109.bin", true;
    test_pm_112: "src/helpers-other" => "src/helpers/file_109.bin", false;
    test_pm_113: "src/helpers" => "src/helpers/file_113.log", true;
    test_pm_114: "src\\helpers" => "src/helpers/file_113.log", true;
    test_pm_115: "src/helpers/" => "src/helpers/file_113.log", true;
    test_pm_116: "src/helpers-other" => "src/helpers/file_113.log", false;
    test_pm_117: "src/helpers" => "src/helpers/file_117.sqlite", true;
    test_pm_118: "src\\helpers" => "src/helpers/file_117.sqlite", true;
    test_pm_119: "src/helpers/" => "src/helpers/file_117.sqlite", true;
    test_pm_120: "src/helpers-other" => "src/helpers/file_117.sqlite", false;
    test_pm_121: "src/services" => "src/services/file_121.rs", true;
    test_pm_122: "src\\services" => "src/services/file_121.rs", true;
    test_pm_123: "src/services/" => "src/services/file_121.rs", true;
    test_pm_124: "src/services-other" => "src/services/file_121.rs", false;
    test_pm_125: "src/services" => "src/services/file_125.js", true;
    test_pm_126: "src\\services" => "src/services/file_125.js", true;
    test_pm_127: "src/services/" => "src/services/file_125.js", true;
    test_pm_128: "src/services-other" => "src/services/file_125.js", false;
    test_pm_129: "src/services" => "src/services/file_129.ts", true;
    test_pm_130: "src\\services" => "src/services/file_129.ts", true;
    test_pm_131: "src/services/" => "src/services/file_129.ts", true;
    test_pm_132: "src/services-other" => "src/services/file_129.ts", false;
    test_pm_133: "src/services" => "src/services/file_133.json", true;
    test_pm_134: "src\\services" => "src/services/file_133.json", true;
    test_pm_135: "src/services/" => "src/services/file_133.json", true;
    test_pm_136: "src/services-other" => "src/services/file_133.json", false;
    test_pm_137: "src/services" => "src/services/file_137.toml", true;
    test_pm_138: "src\\services" => "src/services/file_137.toml", true;
    test_pm_139: "src/services/" => "src/services/file_137.toml", true;
    test_pm_140: "src/services-other" => "src/services/file_137.toml", false;
    test_pm_141: "src/services" => "src/services/file_141.yaml", true;
    test_pm_142: "src\\services" => "src/services/file_141.yaml", true;
    test_pm_143: "src/services/" => "src/services/file_141.yaml", true;
    test_pm_144: "src/services-other" => "src/services/file_141.yaml", false;
    test_pm_145: "src/services" => "src/services/file_145.md", true;
    test_pm_146: "src\\services" => "src/services/file_145.md", true;
    test_pm_147: "src/services/" => "src/services/file_145.md", true;
    test_pm_148: "src/services-other" => "src/services/file_145.md", false;
    test_pm_149: "src/services" => "src/services/file_149.txt", true;
    test_pm_150: "src\\services" => "src/services/file_149.txt", true;
    test_pm_151: "src/services/" => "src/services/file_149.txt", true;
    test_pm_152: "src/services-other" => "src/services/file_149.txt", false;
    test_pm_153: "src/services" => "src/services/file_153.png", true;
    test_pm_154: "src\\services" => "src/services/file_153.png", true;
    test_pm_155: "src/services/" => "src/services/file_153.png", true;
    test_pm_156: "src/services-other" => "src/services/file_153.png", false;
    test_pm_157: "src/services" => "src/services/file_157.jpg", true;
    test_pm_158: "src\\services" => "src/services/file_157.jpg", true;
    test_pm_159: "src/services/" => "src/services/file_157.jpg", true;
    test_pm_160: "src/services-other" => "src/services/file_157.jpg", false;
    test_pm_161: "src/services" => "src/services/file_161.css", true;
    test_pm_162: "src\\services" => "src/services/file_161.css", true;
    test_pm_163: "src/services/" => "src/services/file_161.css", true;
    test_pm_164: "src/services-other" => "src/services/file_161.css", false;
    test_pm_165: "src/services" => "src/services/file_165.html", true;
    test_pm_166: "src\\services" => "src/services/file_165.html", true;
    test_pm_167: "src/services/" => "src/services/file_165.html", true;
    test_pm_168: "src/services-other" => "src/services/file_165.html", false;
    test_pm_169: "src/services" => "src/services/file_169.bin", true;
    test_pm_170: "src\\services" => "src/services/file_169.bin", true;
    test_pm_171: "src/services/" => "src/services/file_169.bin", true;
    test_pm_172: "src/services-other" => "src/services/file_169.bin", false;
    test_pm_173: "src/services" => "src/services/file_173.log", true;
    test_pm_174: "src\\services" => "src/services/file_173.log", true;
    test_pm_175: "src/services/" => "src/services/file_173.log", true;
    test_pm_176: "src/services-other" => "src/services/file_173.log", false;
    test_pm_177: "src/services" => "src/services/file_177.sqlite", true;
    test_pm_178: "src\\services" => "src/services/file_177.sqlite", true;
    test_pm_179: "src/services/" => "src/services/file_177.sqlite", true;
    test_pm_180: "src/services-other" => "src/services/file_177.sqlite", false;
    test_pm_181: "src/models" => "src/models/file_181.rs", true;
    test_pm_182: "src\\models" => "src/models/file_181.rs", true;
    test_pm_183: "src/models/" => "src/models/file_181.rs", true;
    test_pm_184: "src/models-other" => "src/models/file_181.rs", false;
    test_pm_185: "src/models" => "src/models/file_185.js", true;
    test_pm_186: "src\\models" => "src/models/file_185.js", true;
    test_pm_187: "src/models/" => "src/models/file_185.js", true;
    test_pm_188: "src/models-other" => "src/models/file_185.js", false;
    test_pm_189: "src/models" => "src/models/file_189.ts", true;
    test_pm_190: "src\\models" => "src/models/file_189.ts", true;
    test_pm_191: "src/models/" => "src/models/file_189.ts", true;
    test_pm_192: "src/models-other" => "src/models/file_189.ts", false;
    test_pm_193: "src/models" => "src/models/file_193.json", true;
    test_pm_194: "src\\models" => "src/models/file_193.json", true;
    test_pm_195: "src/models/" => "src/models/file_193.json", true;
    test_pm_196: "src/models-other" => "src/models/file_193.json", false;
    test_pm_197: "src/models" => "src/models/file_197.toml", true;
    test_pm_198: "src\\models" => "src/models/file_197.toml", true;
    test_pm_199: "src/models/" => "src/models/file_197.toml", true;
    test_pm_200: "src/models-other" => "src/models/file_197.toml", false;
    test_pm_201: "src/models" => "src/models/file_201.yaml", true;
    test_pm_202: "src\\models" => "src/models/file_201.yaml", true;
    test_pm_203: "src/models/" => "src/models/file_201.yaml", true;
    test_pm_204: "src/models-other" => "src/models/file_201.yaml", false;
    test_pm_205: "src/models" => "src/models/file_205.md", true;
    test_pm_206: "src\\models" => "src/models/file_205.md", true;
    test_pm_207: "src/models/" => "src/models/file_205.md", true;
    test_pm_208: "src/models-other" => "src/models/file_205.md", false;
    test_pm_209: "src/models" => "src/models/file_209.txt", true;
    test_pm_210: "src\\models" => "src/models/file_209.txt", true;
    test_pm_211: "src/models/" => "src/models/file_209.txt", true;
    test_pm_212: "src/models-other" => "src/models/file_209.txt", false;
    test_pm_213: "src/models" => "src/models/file_213.png", true;
    test_pm_214: "src\\models" => "src/models/file_213.png", true;
    test_pm_215: "src/models/" => "src/models/file_213.png", true;
    test_pm_216: "src/models-other" => "src/models/file_213.png", false;
    test_pm_217: "src/models" => "src/models/file_217.jpg", true;
    test_pm_218: "src\\models" => "src/models/file_217.jpg", true;
    test_pm_219: "src/models/" => "src/models/file_217.jpg", true;
    test_pm_220: "src/models-other" => "src/models/file_217.jpg", false;
    test_pm_221: "src/models" => "src/models/file_221.css", true;
    test_pm_222: "src\\models" => "src/models/file_221.css", true;
    test_pm_223: "src/models/" => "src/models/file_221.css", true;
    test_pm_224: "src/models-other" => "src/models/file_221.css", false;
    test_pm_225: "src/models" => "src/models/file_225.html", true;
    test_pm_226: "src\\models" => "src/models/file_225.html", true;
    test_pm_227: "src/models/" => "src/models/file_225.html", true;
    test_pm_228: "src/models-other" => "src/models/file_225.html", false;
    test_pm_229: "src/models" => "src/models/file_229.bin", true;
    test_pm_230: "src\\models" => "src/models/file_229.bin", true;
    test_pm_231: "src/models/" => "src/models/file_229.bin", true;
    test_pm_232: "src/models-other" => "src/models/file_229.bin", false;
    test_pm_233: "src/models" => "src/models/file_233.log", true;
    test_pm_234: "src\\models" => "src/models/file_233.log", true;
    test_pm_235: "src/models/" => "src/models/file_233.log", true;
    test_pm_236: "src/models-other" => "src/models/file_233.log", false;
    test_pm_237: "src/models" => "src/models/file_237.sqlite", true;
    test_pm_238: "src\\models" => "src/models/file_237.sqlite", true;
    test_pm_239: "src/models/" => "src/models/file_237.sqlite", true;
    test_pm_240: "src/models-other" => "src/models/file_237.sqlite", false;
    test_pm_241: "src/controllers" => "src/controllers/file_241.rs", true;
    test_pm_242: "src\\controllers" => "src/controllers/file_241.rs", true;
    test_pm_243: "src/controllers/" => "src/controllers/file_241.rs", true;
    test_pm_244: "src/controllers-other" => "src/controllers/file_241.rs", false;
    test_pm_245: "src/controllers" => "src/controllers/file_245.js", true;
    test_pm_246: "src\\controllers" => "src/controllers/file_245.js", true;
    test_pm_247: "src/controllers/" => "src/controllers/file_245.js", true;
    test_pm_248: "src/controllers-other" => "src/controllers/file_245.js", false;
    test_pm_249: "src/controllers" => "src/controllers/file_249.ts", true;
    test_pm_250: "src\\controllers" => "src/controllers/file_249.ts", true;
    test_pm_251: "src/controllers/" => "src/controllers/file_249.ts", true;
    test_pm_252: "src/controllers-other" => "src/controllers/file_249.ts", false;
    test_pm_253: "src/controllers" => "src/controllers/file_253.json", true;
    test_pm_254: "src\\controllers" => "src/controllers/file_253.json", true;
    test_pm_255: "src/controllers/" => "src/controllers/file_253.json", true;
    test_pm_256: "src/controllers-other" => "src/controllers/file_253.json", false;
    test_pm_257: "src/controllers" => "src/controllers/file_257.toml", true;
    test_pm_258: "src\\controllers" => "src/controllers/file_257.toml", true;
    test_pm_259: "src/controllers/" => "src/controllers/file_257.toml", true;
    test_pm_260: "src/controllers-other" => "src/controllers/file_257.toml", false;
    test_pm_261: "src/controllers" => "src/controllers/file_261.yaml", true;
    test_pm_262: "src\\controllers" => "src/controllers/file_261.yaml", true;
    test_pm_263: "src/controllers/" => "src/controllers/file_261.yaml", true;
    test_pm_264: "src/controllers-other" => "src/controllers/file_261.yaml", false;
    test_pm_265: "src/controllers" => "src/controllers/file_265.md", true;
    test_pm_266: "src\\controllers" => "src/controllers/file_265.md", true;
    test_pm_267: "src/controllers/" => "src/controllers/file_265.md", true;
    test_pm_268: "src/controllers-other" => "src/controllers/file_265.md", false;
    test_pm_269: "src/controllers" => "src/controllers/file_269.txt", true;
    test_pm_270: "src\\controllers" => "src/controllers/file_269.txt", true;
    test_pm_271: "src/controllers/" => "src/controllers/file_269.txt", true;
    test_pm_272: "src/controllers-other" => "src/controllers/file_269.txt", false;
    test_pm_273: "src/controllers" => "src/controllers/file_273.png", true;
    test_pm_274: "src\\controllers" => "src/controllers/file_273.png", true;
    test_pm_275: "src/controllers/" => "src/controllers/file_273.png", true;
    test_pm_276: "src/controllers-other" => "src/controllers/file_273.png", false;
    test_pm_277: "src/controllers" => "src/controllers/file_277.jpg", true;
    test_pm_278: "src\\controllers" => "src/controllers/file_277.jpg", true;
    test_pm_279: "src/controllers/" => "src/controllers/file_277.jpg", true;
    test_pm_280: "src/controllers-other" => "src/controllers/file_277.jpg", false;
    test_pm_281: "src/controllers" => "src/controllers/file_281.css", true;
    test_pm_282: "src\\controllers" => "src/controllers/file_281.css", true;
    test_pm_283: "src/controllers/" => "src/controllers/file_281.css", true;
    test_pm_284: "src/controllers-other" => "src/controllers/file_281.css", false;
    test_pm_285: "src/controllers" => "src/controllers/file_285.html", true;
    test_pm_286: "src\\controllers" => "src/controllers/file_285.html", true;
    test_pm_287: "src/controllers/" => "src/controllers/file_285.html", true;
    test_pm_288: "src/controllers-other" => "src/controllers/file_285.html", false;
    test_pm_289: "src/controllers" => "src/controllers/file_289.bin", true;
    test_pm_290: "src\\controllers" => "src/controllers/file_289.bin", true;
    test_pm_291: "src/controllers/" => "src/controllers/file_289.bin", true;
    test_pm_292: "src/controllers-other" => "src/controllers/file_289.bin", false;
    test_pm_293: "src/controllers" => "src/controllers/file_293.log", true;
    test_pm_294: "src\\controllers" => "src/controllers/file_293.log", true;
    test_pm_295: "src/controllers/" => "src/controllers/file_293.log", true;
    test_pm_296: "src/controllers-other" => "src/controllers/file_293.log", false;
    test_pm_297: "src/controllers" => "src/controllers/file_297.sqlite", true;
    test_pm_298: "src\\controllers" => "src/controllers/file_297.sqlite", true;
    test_pm_299: "src/controllers/" => "src/controllers/file_297.sqlite", true;
    test_pm_300: "src/controllers-other" => "src/controllers/file_297.sqlite", false;
}

macro_rules! generate_selected_matching_tests {
    ($($name:ident: $entry:expr, $selected:expr => $expected:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                assert_eq!(archive_entry_matches_selected($entry, $selected), $expected);
            }
        )*
    };
}
generate_selected_matching_tests! {
    test_sel_001: "folder/sub1/item_1.txt", "folder" => true;
    test_sel_002: "folder/sub1/item_1.txt", "folder/" => true;
    test_sel_003: "folder/sub1/item_1.txt", "folder\\" => true;
    test_sel_004: "folder/sub1/item_1.txt", "folder/sub1" => true;
    test_sel_005: "folder/sub1/item_1.txt", "folder\\sub1" => true;
    test_sel_006: "folder/sub1/item_1.txt", "folder-v2" => false;
    test_sel_007: "folder/sub1/item_7.rs", "folder" => true;
    test_sel_008: "folder/sub1/item_7.rs", "folder/" => true;
    test_sel_009: "folder/sub1/item_7.rs", "folder\\" => true;
    test_sel_010: "folder/sub1/item_7.rs", "folder/sub1" => true;
    test_sel_011: "folder/sub1/item_7.rs", "folder\\sub1" => true;
    test_sel_012: "folder/sub1/item_7.rs", "folder-v2" => false;
    test_sel_013: "folder/sub1/item_13.json", "folder" => true;
    test_sel_014: "folder/sub1/item_13.json", "folder/" => true;
    test_sel_015: "folder/sub1/item_13.json", "folder\\" => true;
    test_sel_016: "folder/sub1/item_13.json", "folder/sub1" => true;
    test_sel_017: "folder/sub1/item_13.json", "folder\\sub1" => true;
    test_sel_018: "folder/sub1/item_13.json", "folder-v2" => false;
    test_sel_019: "folder/sub1/item_19.dat", "folder" => true;
    test_sel_020: "folder/sub1/item_19.dat", "folder/" => true;
    test_sel_021: "folder/sub1/item_19.dat", "folder\\" => true;
    test_sel_022: "folder/sub1/item_19.dat", "folder/sub1" => true;
    test_sel_023: "folder/sub1/item_19.dat", "folder\\sub1" => true;
    test_sel_024: "folder/sub1/item_19.dat", "folder-v2" => false;
    test_sel_025: "folder/sub1/item_25.bin", "folder" => true;
    test_sel_026: "folder/sub1/item_25.bin", "folder/" => true;
    test_sel_027: "folder/sub1/item_25.bin", "folder\\" => true;
    test_sel_028: "folder/sub1/item_25.bin", "folder/sub1" => true;
    test_sel_029: "folder/sub1/item_25.bin", "folder\\sub1" => true;
    test_sel_030: "folder/sub1/item_25.bin", "folder-v2" => false;
    test_sel_031: "folder/sub2/item_31.txt", "folder" => true;
    test_sel_032: "folder/sub2/item_31.txt", "folder/" => true;
    test_sel_033: "folder/sub2/item_31.txt", "folder\\" => true;
    test_sel_034: "folder/sub2/item_31.txt", "folder/sub2" => true;
    test_sel_035: "folder/sub2/item_31.txt", "folder\\sub2" => true;
    test_sel_036: "folder/sub2/item_31.txt", "folder-v2" => false;
    test_sel_037: "folder/sub2/item_37.rs", "folder" => true;
    test_sel_038: "folder/sub2/item_37.rs", "folder/" => true;
    test_sel_039: "folder/sub2/item_37.rs", "folder\\" => true;
    test_sel_040: "folder/sub2/item_37.rs", "folder/sub2" => true;
    test_sel_041: "folder/sub2/item_37.rs", "folder\\sub2" => true;
    test_sel_042: "folder/sub2/item_37.rs", "folder-v2" => false;
    test_sel_043: "folder/sub2/item_43.json", "folder" => true;
    test_sel_044: "folder/sub2/item_43.json", "folder/" => true;
    test_sel_045: "folder/sub2/item_43.json", "folder\\" => true;
    test_sel_046: "folder/sub2/item_43.json", "folder/sub2" => true;
    test_sel_047: "folder/sub2/item_43.json", "folder\\sub2" => true;
    test_sel_048: "folder/sub2/item_43.json", "folder-v2" => false;
    test_sel_049: "folder/sub2/item_49.dat", "folder" => true;
    test_sel_050: "folder/sub2/item_49.dat", "folder/" => true;
    test_sel_051: "folder/sub2/item_49.dat", "folder\\" => true;
    test_sel_052: "folder/sub2/item_49.dat", "folder/sub2" => true;
    test_sel_053: "folder/sub2/item_49.dat", "folder\\sub2" => true;
    test_sel_054: "folder/sub2/item_49.dat", "folder-v2" => false;
    test_sel_055: "folder/sub2/item_55.bin", "folder" => true;
    test_sel_056: "folder/sub2/item_55.bin", "folder/" => true;
    test_sel_057: "folder/sub2/item_55.bin", "folder\\" => true;
    test_sel_058: "folder/sub2/item_55.bin", "folder/sub2" => true;
    test_sel_059: "folder/sub2/item_55.bin", "folder\\sub2" => true;
    test_sel_060: "folder/sub2/item_55.bin", "folder-v2" => false;
    test_sel_061: "folder/a/item_61.txt", "folder" => true;
    test_sel_062: "folder/a/item_61.txt", "folder/" => true;
    test_sel_063: "folder/a/item_61.txt", "folder\\" => true;
    test_sel_064: "folder/a/item_61.txt", "folder/a" => true;
    test_sel_065: "folder/a/item_61.txt", "folder\\a" => true;
    test_sel_066: "folder/a/item_61.txt", "folder-v2" => false;
    test_sel_067: "folder/a/item_67.rs", "folder" => true;
    test_sel_068: "folder/a/item_67.rs", "folder/" => true;
    test_sel_069: "folder/a/item_67.rs", "folder\\" => true;
    test_sel_070: "folder/a/item_67.rs", "folder/a" => true;
    test_sel_071: "folder/a/item_67.rs", "folder\\a" => true;
    test_sel_072: "folder/a/item_67.rs", "folder-v2" => false;
    test_sel_073: "folder/a/item_73.json", "folder" => true;
    test_sel_074: "folder/a/item_73.json", "folder/" => true;
    test_sel_075: "folder/a/item_73.json", "folder\\" => true;
    test_sel_076: "folder/a/item_73.json", "folder/a" => true;
    test_sel_077: "folder/a/item_73.json", "folder\\a" => true;
    test_sel_078: "folder/a/item_73.json", "folder-v2" => false;
    test_sel_079: "folder/a/item_79.dat", "folder" => true;
    test_sel_080: "folder/a/item_79.dat", "folder/" => true;
    test_sel_081: "folder/a/item_79.dat", "folder\\" => true;
    test_sel_082: "folder/a/item_79.dat", "folder/a" => true;
    test_sel_083: "folder/a/item_79.dat", "folder\\a" => true;
    test_sel_084: "folder/a/item_79.dat", "folder-v2" => false;
    test_sel_085: "folder/a/item_85.bin", "folder" => true;
    test_sel_086: "folder/a/item_85.bin", "folder/" => true;
    test_sel_087: "folder/a/item_85.bin", "folder\\" => true;
    test_sel_088: "folder/a/item_85.bin", "folder/a" => true;
    test_sel_089: "folder/a/item_85.bin", "folder\\a" => true;
    test_sel_090: "folder/a/item_85.bin", "folder-v2" => false;
    test_sel_091: "folder/b/item_91.txt", "folder" => true;
    test_sel_092: "folder/b/item_91.txt", "folder/" => true;
    test_sel_093: "folder/b/item_91.txt", "folder\\" => true;
    test_sel_094: "folder/b/item_91.txt", "folder/b" => true;
    test_sel_095: "folder/b/item_91.txt", "folder\\b" => true;
    test_sel_096: "folder/b/item_91.txt", "folder-v2" => false;
    test_sel_097: "folder/b/item_97.rs", "folder" => true;
    test_sel_098: "folder/b/item_97.rs", "folder/" => true;
    test_sel_099: "folder/b/item_97.rs", "folder\\" => true;
    test_sel_100: "folder/b/item_97.rs", "folder/b" => true;
    test_sel_101: "folder/b/item_97.rs", "folder\\b" => true;
    test_sel_102: "folder/b/item_97.rs", "folder-v2" => false;
    test_sel_103: "folder/b/item_103.json", "folder" => true;
    test_sel_104: "folder/b/item_103.json", "folder/" => true;
    test_sel_105: "folder/b/item_103.json", "folder\\" => true;
    test_sel_106: "folder/b/item_103.json", "folder/b" => true;
    test_sel_107: "folder/b/item_103.json", "folder\\b" => true;
    test_sel_108: "folder/b/item_103.json", "folder-v2" => false;
    test_sel_109: "folder/b/item_109.dat", "folder" => true;
    test_sel_110: "folder/b/item_109.dat", "folder/" => true;
    test_sel_111: "folder/b/item_109.dat", "folder\\" => true;
    test_sel_112: "folder/b/item_109.dat", "folder/b" => true;
    test_sel_113: "folder/b/item_109.dat", "folder\\b" => true;
    test_sel_114: "folder/b/item_109.dat", "folder-v2" => false;
    test_sel_115: "folder/b/item_115.bin", "folder" => true;
    test_sel_116: "folder/b/item_115.bin", "folder/" => true;
    test_sel_117: "folder/b/item_115.bin", "folder\\" => true;
    test_sel_118: "folder/b/item_115.bin", "folder/b" => true;
    test_sel_119: "folder/b/item_115.bin", "folder\\b" => true;
    test_sel_120: "folder/b/item_115.bin", "folder-v2" => false;
    test_sel_121: "folder/c/item_121.txt", "folder" => true;
    test_sel_122: "folder/c/item_121.txt", "folder/" => true;
    test_sel_123: "folder/c/item_121.txt", "folder\\" => true;
    test_sel_124: "folder/c/item_121.txt", "folder/c" => true;
    test_sel_125: "folder/c/item_121.txt", "folder\\c" => true;
    test_sel_126: "folder/c/item_121.txt", "folder-v2" => false;
    test_sel_127: "folder/c/item_127.rs", "folder" => true;
    test_sel_128: "folder/c/item_127.rs", "folder/" => true;
    test_sel_129: "folder/c/item_127.rs", "folder\\" => true;
    test_sel_130: "folder/c/item_127.rs", "folder/c" => true;
    test_sel_131: "folder/c/item_127.rs", "folder\\c" => true;
    test_sel_132: "folder/c/item_127.rs", "folder-v2" => false;
    test_sel_133: "folder/c/item_133.json", "folder" => true;
    test_sel_134: "folder/c/item_133.json", "folder/" => true;
    test_sel_135: "folder/c/item_133.json", "folder\\" => true;
    test_sel_136: "folder/c/item_133.json", "folder/c" => true;
    test_sel_137: "folder/c/item_133.json", "folder\\c" => true;
    test_sel_138: "folder/c/item_133.json", "folder-v2" => false;
    test_sel_139: "folder/c/item_139.dat", "folder" => true;
    test_sel_140: "folder/c/item_139.dat", "folder/" => true;
    test_sel_141: "folder/c/item_139.dat", "folder\\" => true;
    test_sel_142: "folder/c/item_139.dat", "folder/c" => true;
    test_sel_143: "folder/c/item_139.dat", "folder\\c" => true;
    test_sel_144: "folder/c/item_139.dat", "folder-v2" => false;
    test_sel_145: "folder/c/item_145.bin", "folder" => true;
    test_sel_146: "folder/c/item_145.bin", "folder/" => true;
    test_sel_147: "folder/c/item_145.bin", "folder\\" => true;
    test_sel_148: "folder/c/item_145.bin", "folder/c" => true;
    test_sel_149: "folder/c/item_145.bin", "folder\\c" => true;
    test_sel_150: "folder/c/item_145.bin", "folder-v2" => false;
    test_sel_151: "folder/x/item_151.txt", "folder" => true;
    test_sel_152: "folder/x/item_151.txt", "folder/" => true;
    test_sel_153: "folder/x/item_151.txt", "folder\\" => true;
    test_sel_154: "folder/x/item_151.txt", "folder/x" => true;
    test_sel_155: "folder/x/item_151.txt", "folder\\x" => true;
    test_sel_156: "folder/x/item_151.txt", "folder-v2" => false;
    test_sel_157: "folder/x/item_157.rs", "folder" => true;
    test_sel_158: "folder/x/item_157.rs", "folder/" => true;
    test_sel_159: "folder/x/item_157.rs", "folder\\" => true;
    test_sel_160: "folder/x/item_157.rs", "folder/x" => true;
    test_sel_161: "folder/x/item_157.rs", "folder\\x" => true;
    test_sel_162: "folder/x/item_157.rs", "folder-v2" => false;
    test_sel_163: "folder/x/item_163.json", "folder" => true;
    test_sel_164: "folder/x/item_163.json", "folder/" => true;
    test_sel_165: "folder/x/item_163.json", "folder\\" => true;
    test_sel_166: "folder/x/item_163.json", "folder/x" => true;
    test_sel_167: "folder/x/item_163.json", "folder\\x" => true;
    test_sel_168: "folder/x/item_163.json", "folder-v2" => false;
    test_sel_169: "folder/x/item_169.dat", "folder" => true;
    test_sel_170: "folder/x/item_169.dat", "folder/" => true;
    test_sel_171: "folder/x/item_169.dat", "folder\\" => true;
    test_sel_172: "folder/x/item_169.dat", "folder/x" => true;
    test_sel_173: "folder/x/item_169.dat", "folder\\x" => true;
    test_sel_174: "folder/x/item_169.dat", "folder-v2" => false;
    test_sel_175: "folder/x/item_175.bin", "folder" => true;
    test_sel_176: "folder/x/item_175.bin", "folder/" => true;
    test_sel_177: "folder/x/item_175.bin", "folder\\" => true;
    test_sel_178: "folder/x/item_175.bin", "folder/x" => true;
    test_sel_179: "folder/x/item_175.bin", "folder\\x" => true;
    test_sel_180: "folder/x/item_175.bin", "folder-v2" => false;
    test_sel_181: "folder/y/item_181.txt", "folder" => true;
    test_sel_182: "folder/y/item_181.txt", "folder/" => true;
    test_sel_183: "folder/y/item_181.txt", "folder\\" => true;
    test_sel_184: "folder/y/item_181.txt", "folder/y" => true;
    test_sel_185: "folder/y/item_181.txt", "folder\\y" => true;
    test_sel_186: "folder/y/item_181.txt", "folder-v2" => false;
    test_sel_187: "folder/y/item_187.rs", "folder" => true;
    test_sel_188: "folder/y/item_187.rs", "folder/" => true;
    test_sel_189: "folder/y/item_187.rs", "folder\\" => true;
    test_sel_190: "folder/y/item_187.rs", "folder/y" => true;
    test_sel_191: "folder/y/item_187.rs", "folder\\y" => true;
    test_sel_192: "folder/y/item_187.rs", "folder-v2" => false;
    test_sel_193: "folder/y/item_193.json", "folder" => true;
    test_sel_194: "folder/y/item_193.json", "folder/" => true;
    test_sel_195: "folder/y/item_193.json", "folder\\" => true;
    test_sel_196: "folder/y/item_193.json", "folder/y" => true;
    test_sel_197: "folder/y/item_193.json", "folder\\y" => true;
    test_sel_198: "folder/y/item_193.json", "folder-v2" => false;
    test_sel_199: "folder/y/item_199.dat", "folder" => true;
    test_sel_200: "folder/y/item_199.dat", "folder/" => true;
    test_sel_201: "folder/y/item_199.dat", "folder\\" => true;
    test_sel_202: "folder/y/item_199.dat", "folder/y" => true;
    test_sel_203: "folder/y/item_199.dat", "folder\\y" => true;
    test_sel_204: "folder/y/item_199.dat", "folder-v2" => false;
    test_sel_205: "folder/y/item_205.bin", "folder" => true;
    test_sel_206: "folder/y/item_205.bin", "folder/" => true;
    test_sel_207: "folder/y/item_205.bin", "folder\\" => true;
    test_sel_208: "folder/y/item_205.bin", "folder/y" => true;
    test_sel_209: "folder/y/item_205.bin", "folder\\y" => true;
    test_sel_210: "folder/y/item_205.bin", "folder-v2" => false;
    test_sel_211: "folder/z/item_211.txt", "folder" => true;
    test_sel_212: "folder/z/item_211.txt", "folder/" => true;
    test_sel_213: "folder/z/item_211.txt", "folder\\" => true;
    test_sel_214: "folder/z/item_211.txt", "folder/z" => true;
    test_sel_215: "folder/z/item_211.txt", "folder\\z" => true;
    test_sel_216: "folder/z/item_211.txt", "folder-v2" => false;
    test_sel_217: "folder/z/item_217.rs", "folder" => true;
    test_sel_218: "folder/z/item_217.rs", "folder/" => true;
    test_sel_219: "folder/z/item_217.rs", "folder\\" => true;
    test_sel_220: "folder/z/item_217.rs", "folder/z" => true;
    test_sel_221: "folder/z/item_217.rs", "folder\\z" => true;
    test_sel_222: "folder/z/item_217.rs", "folder-v2" => false;
    test_sel_223: "folder/z/item_223.json", "folder" => true;
    test_sel_224: "folder/z/item_223.json", "folder/" => true;
    test_sel_225: "folder/z/item_223.json", "folder\\" => true;
    test_sel_226: "folder/z/item_223.json", "folder/z" => true;
    test_sel_227: "folder/z/item_223.json", "folder\\z" => true;
    test_sel_228: "folder/z/item_223.json", "folder-v2" => false;
    test_sel_229: "folder/z/item_229.dat", "folder" => true;
    test_sel_230: "folder/z/item_229.dat", "folder/" => true;
    test_sel_231: "folder/z/item_229.dat", "folder\\" => true;
    test_sel_232: "folder/z/item_229.dat", "folder/z" => true;
    test_sel_233: "folder/z/item_229.dat", "folder\\z" => true;
    test_sel_234: "folder/z/item_229.dat", "folder-v2" => false;
    test_sel_235: "folder/z/item_235.bin", "folder" => true;
    test_sel_236: "folder/z/item_235.bin", "folder/" => true;
    test_sel_237: "folder/z/item_235.bin", "folder\\" => true;
    test_sel_238: "folder/z/item_235.bin", "folder/z" => true;
    test_sel_239: "folder/z/item_235.bin", "folder\\z" => true;
    test_sel_240: "folder/z/item_235.bin", "folder-v2" => false;
    test_sel_241: "folder/depth1/item_241.txt", "folder" => true;
    test_sel_242: "folder/depth1/item_241.txt", "folder/" => true;
    test_sel_243: "folder/depth1/item_241.txt", "folder\\" => true;
    test_sel_244: "folder/depth1/item_241.txt", "folder/depth1" => true;
    test_sel_245: "folder/depth1/item_241.txt", "folder\\depth1" => true;
    test_sel_246: "folder/depth1/item_241.txt", "folder-v2" => false;
    test_sel_247: "folder/depth1/item_247.rs", "folder" => true;
    test_sel_248: "folder/depth1/item_247.rs", "folder/" => true;
    test_sel_249: "folder/depth1/item_247.rs", "folder\\" => true;
    test_sel_250: "folder/depth1/item_247.rs", "folder/depth1" => true;
    test_sel_251: "folder/depth1/item_247.rs", "folder\\depth1" => true;
    test_sel_252: "folder/depth1/item_247.rs", "folder-v2" => false;
    test_sel_253: "folder/depth1/item_253.json", "folder" => true;
    test_sel_254: "folder/depth1/item_253.json", "folder/" => true;
    test_sel_255: "folder/depth1/item_253.json", "folder\\" => true;
    test_sel_256: "folder/depth1/item_253.json", "folder/depth1" => true;
    test_sel_257: "folder/depth1/item_253.json", "folder\\depth1" => true;
    test_sel_258: "folder/depth1/item_253.json", "folder-v2" => false;
    test_sel_259: "folder/depth1/item_259.dat", "folder" => true;
    test_sel_260: "folder/depth1/item_259.dat", "folder/" => true;
    test_sel_261: "folder/depth1/item_259.dat", "folder\\" => true;
    test_sel_262: "folder/depth1/item_259.dat", "folder/depth1" => true;
    test_sel_263: "folder/depth1/item_259.dat", "folder\\depth1" => true;
    test_sel_264: "folder/depth1/item_259.dat", "folder-v2" => false;
    test_sel_265: "folder/depth1/item_265.bin", "folder" => true;
    test_sel_266: "folder/depth1/item_265.bin", "folder/" => true;
    test_sel_267: "folder/depth1/item_265.bin", "folder\\" => true;
    test_sel_268: "folder/depth1/item_265.bin", "folder/depth1" => true;
    test_sel_269: "folder/depth1/item_265.bin", "folder\\depth1" => true;
    test_sel_270: "folder/depth1/item_265.bin", "folder-v2" => false;
    test_sel_271: "folder/depth2/item_271.txt", "folder" => true;
    test_sel_272: "folder/depth2/item_271.txt", "folder/" => true;
    test_sel_273: "folder/depth2/item_271.txt", "folder\\" => true;
    test_sel_274: "folder/depth2/item_271.txt", "folder/depth2" => true;
    test_sel_275: "folder/depth2/item_271.txt", "folder\\depth2" => true;
    test_sel_276: "folder/depth2/item_271.txt", "folder-v2" => false;
    test_sel_277: "folder/depth2/item_277.rs", "folder" => true;
    test_sel_278: "folder/depth2/item_277.rs", "folder/" => true;
    test_sel_279: "folder/depth2/item_277.rs", "folder\\" => true;
    test_sel_280: "folder/depth2/item_277.rs", "folder/depth2" => true;
    test_sel_281: "folder/depth2/item_277.rs", "folder\\depth2" => true;
    test_sel_282: "folder/depth2/item_277.rs", "folder-v2" => false;
    test_sel_283: "folder/depth2/item_283.json", "folder" => true;
    test_sel_284: "folder/depth2/item_283.json", "folder/" => true;
    test_sel_285: "folder/depth2/item_283.json", "folder\\" => true;
    test_sel_286: "folder/depth2/item_283.json", "folder/depth2" => true;
    test_sel_287: "folder/depth2/item_283.json", "folder\\depth2" => true;
    test_sel_288: "folder/depth2/item_283.json", "folder-v2" => false;
    test_sel_289: "folder/depth2/item_289.dat", "folder" => true;
    test_sel_290: "folder/depth2/item_289.dat", "folder/" => true;
    test_sel_291: "folder/depth2/item_289.dat", "folder\\" => true;
    test_sel_292: "folder/depth2/item_289.dat", "folder/depth2" => true;
    test_sel_293: "folder/depth2/item_289.dat", "folder\\depth2" => true;
    test_sel_294: "folder/depth2/item_289.dat", "folder-v2" => false;
    test_sel_295: "folder/depth2/item_295.bin", "folder" => true;
    test_sel_296: "folder/depth2/item_295.bin", "folder/" => true;
    test_sel_297: "folder/depth2/item_295.bin", "folder\\" => true;
    test_sel_298: "folder/depth2/item_295.bin", "folder/depth2" => true;
    test_sel_299: "folder/depth2/item_295.bin", "folder\\depth2" => true;
    test_sel_300: "folder/depth2/item_295.bin", "folder-v2" => false;
}

macro_rules! generate_tgz_matrix_tests {
    ($($name:ident: $sel:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                let scenario = TestDir::new(&format!("tgz_mat_{}", stringify!($name)));
                let source_dir = scenario.path("src");
                create_nested_tree(&source_dir);
                let archive = scenario.path("archive.tgz");
                create_tgz_fixture(&source_dir, &archive, Some(6));
                let out_dir = scenario.path("out");
                let report = extract_entry(&archive, $sel, &out_dir).unwrap();
                assert!(report.written_bytes > 0);
            }
        )*
    };
}
generate_tgz_matrix_tests! {
    test_tgz_mat_001: "src/folder";
    test_tgz_mat_002: "src/folder/";
    test_tgz_mat_003: "src/folder\\";
    test_tgz_mat_004: "src/folder/sub1";
    test_tgz_mat_005: "src/folder\\sub1";
    test_tgz_mat_006: "src/folder\\sub1\\";
    test_tgz_mat_007: "src/dir1";
    test_tgz_mat_008: "src/dir1/";
    test_tgz_mat_009: "src/dir1\\";
    test_tgz_mat_010: "src/file1.txt";
    test_tgz_mat_011: "src/folder";
    test_tgz_mat_012: "src/folder/";
    test_tgz_mat_013: "src/folder\\";
    test_tgz_mat_014: "src/folder/sub1";
    test_tgz_mat_015: "src/folder\\sub1";
    test_tgz_mat_016: "src/folder\\sub1\\";
    test_tgz_mat_017: "src/dir1";
    test_tgz_mat_018: "src/dir1/";
    test_tgz_mat_019: "src/dir1\\";
    test_tgz_mat_020: "src/file1.txt";
    test_tgz_mat_021: "src/folder";
    test_tgz_mat_022: "src/folder/";
    test_tgz_mat_023: "src/folder\\";
    test_tgz_mat_024: "src/folder/sub1";
    test_tgz_mat_025: "src/folder\\sub1";
    test_tgz_mat_026: "src/folder\\sub1\\";
    test_tgz_mat_027: "src/dir1";
    test_tgz_mat_028: "src/dir1/";
    test_tgz_mat_029: "src/dir1\\";
    test_tgz_mat_030: "src/file1.txt";
    test_tgz_mat_031: "src/folder";
    test_tgz_mat_032: "src/folder/";
    test_tgz_mat_033: "src/folder\\";
    test_tgz_mat_034: "src/folder/sub1";
    test_tgz_mat_035: "src/folder\\sub1";
    test_tgz_mat_036: "src/folder\\sub1\\";
    test_tgz_mat_037: "src/dir1";
    test_tgz_mat_038: "src/dir1/";
    test_tgz_mat_039: "src/dir1\\";
    test_tgz_mat_040: "src/file1.txt";
    test_tgz_mat_041: "src/folder";
    test_tgz_mat_042: "src/folder/";
    test_tgz_mat_043: "src/folder\\";
    test_tgz_mat_044: "src/folder/sub1";
    test_tgz_mat_045: "src/folder\\sub1";
    test_tgz_mat_046: "src/folder\\sub1\\";
    test_tgz_mat_047: "src/dir1";
    test_tgz_mat_048: "src/dir1/";
    test_tgz_mat_049: "src/dir1\\";
    test_tgz_mat_050: "src/file1.txt";
    test_tgz_mat_051: "src/folder";
    test_tgz_mat_052: "src/folder/";
    test_tgz_mat_053: "src/folder\\";
    test_tgz_mat_054: "src/folder/sub1";
    test_tgz_mat_055: "src/folder\\sub1";
    test_tgz_mat_056: "src/folder\\sub1\\";
    test_tgz_mat_057: "src/dir1";
    test_tgz_mat_058: "src/dir1/";
    test_tgz_mat_059: "src/dir1\\";
    test_tgz_mat_060: "src/file1.txt";
    test_tgz_mat_061: "src/folder";
    test_tgz_mat_062: "src/folder/";
    test_tgz_mat_063: "src/folder\\";
    test_tgz_mat_064: "src/folder/sub1";
    test_tgz_mat_065: "src/folder\\sub1";
    test_tgz_mat_066: "src/folder\\sub1\\";
    test_tgz_mat_067: "src/dir1";
    test_tgz_mat_068: "src/dir1/";
    test_tgz_mat_069: "src/dir1\\";
    test_tgz_mat_070: "src/file1.txt";
    test_tgz_mat_071: "src/folder";
    test_tgz_mat_072: "src/folder/";
    test_tgz_mat_073: "src/folder\\";
    test_tgz_mat_074: "src/folder/sub1";
    test_tgz_mat_075: "src/folder\\sub1";
    test_tgz_mat_076: "src/folder\\sub1\\";
    test_tgz_mat_077: "src/dir1";
    test_tgz_mat_078: "src/dir1/";
    test_tgz_mat_079: "src/dir1\\";
    test_tgz_mat_080: "src/file1.txt";
    test_tgz_mat_081: "src/folder";
    test_tgz_mat_082: "src/folder/";
    test_tgz_mat_083: "src/folder\\";
    test_tgz_mat_084: "src/folder/sub1";
    test_tgz_mat_085: "src/folder\\sub1";
    test_tgz_mat_086: "src/folder\\sub1\\";
    test_tgz_mat_087: "src/dir1";
    test_tgz_mat_088: "src/dir1/";
    test_tgz_mat_089: "src/dir1\\";
    test_tgz_mat_090: "src/file1.txt";
    test_tgz_mat_091: "src/folder";
    test_tgz_mat_092: "src/folder/";
    test_tgz_mat_093: "src/folder\\";
    test_tgz_mat_094: "src/folder/sub1";
    test_tgz_mat_095: "src/folder\\sub1";
    test_tgz_mat_096: "src/folder\\sub1\\";
    test_tgz_mat_097: "src/dir1";
    test_tgz_mat_098: "src/dir1/";
    test_tgz_mat_099: "src/dir1\\";
    test_tgz_mat_100: "src/file1.txt";
}

macro_rules! generate_zip_matrix_tests {
    ($($name:ident: $sel:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                let scenario = TestDir::new(&format!("zip_mat_{}", stringify!($name)));
                let source_dir = scenario.path("src");
                create_nested_tree(&source_dir);
                let archive = scenario.path("archive.zip");
                create_zip_fixture(&source_dir, &archive, Some(6), false);
                let out_dir = scenario.path("out");
                let report = extract_entry(&archive, $sel, &out_dir).unwrap();
                assert!(report.written_bytes > 0);
            }
        )*
    };
}
generate_zip_matrix_tests! {
    test_zip_mat_001: "src/folder";
    test_zip_mat_002: "src/folder/";
    test_zip_mat_003: "src/folder\\";
    test_zip_mat_004: "src/folder/sub1";
    test_zip_mat_005: "src/folder\\sub1";
    test_zip_mat_006: "src/folder\\sub1\\";
    test_zip_mat_007: "src/dir1";
    test_zip_mat_008: "src/dir1/";
    test_zip_mat_009: "src/dir1\\";
    test_zip_mat_010: "src/file1.txt";
    test_zip_mat_011: "src/folder";
    test_zip_mat_012: "src/folder/";
    test_zip_mat_013: "src/folder\\";
    test_zip_mat_014: "src/folder/sub1";
    test_zip_mat_015: "src/folder\\sub1";
    test_zip_mat_016: "src/folder\\sub1\\";
    test_zip_mat_017: "src/dir1";
    test_zip_mat_018: "src/dir1/";
    test_zip_mat_019: "src/dir1\\";
    test_zip_mat_020: "src/file1.txt";
    test_zip_mat_021: "src/folder";
    test_zip_mat_022: "src/folder/";
    test_zip_mat_023: "src/folder\\";
    test_zip_mat_024: "src/folder/sub1";
    test_zip_mat_025: "src/folder\\sub1";
    test_zip_mat_026: "src/folder\\sub1\\";
    test_zip_mat_027: "src/dir1";
    test_zip_mat_028: "src/dir1/";
    test_zip_mat_029: "src/dir1\\";
    test_zip_mat_030: "src/file1.txt";
    test_zip_mat_031: "src/folder";
    test_zip_mat_032: "src/folder/";
    test_zip_mat_033: "src/folder\\";
    test_zip_mat_034: "src/folder/sub1";
    test_zip_mat_035: "src/folder\\sub1";
    test_zip_mat_036: "src/folder\\sub1\\";
    test_zip_mat_037: "src/dir1";
    test_zip_mat_038: "src/dir1/";
    test_zip_mat_039: "src/dir1\\";
    test_zip_mat_040: "src/file1.txt";
    test_zip_mat_041: "src/folder";
    test_zip_mat_042: "src/folder/";
    test_zip_mat_043: "src/folder\\";
    test_zip_mat_044: "src/folder/sub1";
    test_zip_mat_045: "src/folder\\sub1";
    test_zip_mat_046: "src/folder\\sub1\\";
    test_zip_mat_047: "src/dir1";
    test_zip_mat_048: "src/dir1/";
    test_zip_mat_049: "src/dir1\\";
    test_zip_mat_050: "src/file1.txt";
    test_zip_mat_051: "src/folder";
    test_zip_mat_052: "src/folder/";
    test_zip_mat_053: "src/folder\\";
    test_zip_mat_054: "src/folder/sub1";
    test_zip_mat_055: "src/folder\\sub1";
    test_zip_mat_056: "src/folder\\sub1\\";
    test_zip_mat_057: "src/dir1";
    test_zip_mat_058: "src/dir1/";
    test_zip_mat_059: "src/dir1\\";
    test_zip_mat_060: "src/file1.txt";
    test_zip_mat_061: "src/folder";
    test_zip_mat_062: "src/folder/";
    test_zip_mat_063: "src/folder\\";
    test_zip_mat_064: "src/folder/sub1";
    test_zip_mat_065: "src/folder\\sub1";
    test_zip_mat_066: "src/folder\\sub1\\";
    test_zip_mat_067: "src/dir1";
    test_zip_mat_068: "src/dir1/";
    test_zip_mat_069: "src/dir1\\";
    test_zip_mat_070: "src/file1.txt";
    test_zip_mat_071: "src/folder";
    test_zip_mat_072: "src/folder/";
    test_zip_mat_073: "src/folder\\";
    test_zip_mat_074: "src/folder/sub1";
    test_zip_mat_075: "src/folder\\sub1";
    test_zip_mat_076: "src/folder\\sub1\\";
    test_zip_mat_077: "src/dir1";
    test_zip_mat_078: "src/dir1/";
    test_zip_mat_079: "src/dir1\\";
    test_zip_mat_080: "src/file1.txt";
    test_zip_mat_081: "src/folder";
    test_zip_mat_082: "src/folder/";
    test_zip_mat_083: "src/folder\\";
    test_zip_mat_084: "src/folder/sub1";
    test_zip_mat_085: "src/folder\\sub1";
    test_zip_mat_086: "src/folder\\sub1\\";
    test_zip_mat_087: "src/dir1";
    test_zip_mat_088: "src/dir1/";
    test_zip_mat_089: "src/dir1\\";
    test_zip_mat_090: "src/file1.txt";
    test_zip_mat_091: "src/folder";
    test_zip_mat_092: "src/folder/";
    test_zip_mat_093: "src/folder\\";
    test_zip_mat_094: "src/folder/sub1";
    test_zip_mat_095: "src/folder\\sub1";
    test_zip_mat_096: "src/folder\\sub1\\";
    test_zip_mat_097: "src/dir1";
    test_zip_mat_098: "src/dir1/";
    test_zip_mat_099: "src/dir1\\";
    test_zip_mat_100: "src/file1.txt";
}

macro_rules! generate_tzst_matrix_tests {
    ($($name:ident: $sel:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                let scenario = TestDir::new(&format!("tzst_mat_{}", stringify!($name)));
                let source_dir = scenario.path("src");
                create_nested_tree(&source_dir);
                let archive = scenario.path("archive.tzst");
                create_tar_zst_fixture(&source_dir, &archive, Some(3));
                let out_dir = scenario.path("out");
                let report = extract_entry(&archive, $sel, &out_dir).unwrap();
                assert!(report.written_bytes > 0);
            }
        )*
    };
}
generate_tzst_matrix_tests! {
    test_tzst_mat_001: "src/folder";
    test_tzst_mat_002: "src/folder/";
    test_tzst_mat_003: "src/folder\\";
    test_tzst_mat_004: "src/folder/sub1";
    test_tzst_mat_005: "src/folder\\sub1";
    test_tzst_mat_006: "src/folder\\sub1\\";
    test_tzst_mat_007: "src/dir1";
    test_tzst_mat_008: "src/dir1/";
    test_tzst_mat_009: "src/dir1\\";
    test_tzst_mat_010: "src/file1.txt";
    test_tzst_mat_011: "src/folder";
    test_tzst_mat_012: "src/folder/";
    test_tzst_mat_013: "src/folder\\";
    test_tzst_mat_014: "src/folder/sub1";
    test_tzst_mat_015: "src/folder\\sub1";
    test_tzst_mat_016: "src/folder\\sub1\\";
    test_tzst_mat_017: "src/dir1";
    test_tzst_mat_018: "src/dir1/";
    test_tzst_mat_019: "src/dir1\\";
    test_tzst_mat_020: "src/file1.txt";
    test_tzst_mat_021: "src/folder";
    test_tzst_mat_022: "src/folder/";
    test_tzst_mat_023: "src/folder\\";
    test_tzst_mat_024: "src/folder/sub1";
    test_tzst_mat_025: "src/folder\\sub1";
    test_tzst_mat_026: "src/folder\\sub1\\";
    test_tzst_mat_027: "src/dir1";
    test_tzst_mat_028: "src/dir1/";
    test_tzst_mat_029: "src/dir1\\";
    test_tzst_mat_030: "src/file1.txt";
    test_tzst_mat_031: "src/folder";
    test_tzst_mat_032: "src/folder/";
    test_tzst_mat_033: "src/folder\\";
    test_tzst_mat_034: "src/folder/sub1";
    test_tzst_mat_035: "src/folder\\sub1";
    test_tzst_mat_036: "src/folder\\sub1\\";
    test_tzst_mat_037: "src/dir1";
    test_tzst_mat_038: "src/dir1/";
    test_tzst_mat_039: "src/dir1\\";
    test_tzst_mat_040: "src/file1.txt";
    test_tzst_mat_041: "src/folder";
    test_tzst_mat_042: "src/folder/";
    test_tzst_mat_043: "src/folder\\";
    test_tzst_mat_044: "src/folder/sub1";
    test_tzst_mat_045: "src/folder\\sub1";
    test_tzst_mat_046: "src/folder\\sub1\\";
    test_tzst_mat_047: "src/dir1";
    test_tzst_mat_048: "src/dir1/";
    test_tzst_mat_049: "src/dir1\\";
    test_tzst_mat_050: "src/file1.txt";
    test_tzst_mat_051: "src/folder";
    test_tzst_mat_052: "src/folder/";
    test_tzst_mat_053: "src/folder\\";
    test_tzst_mat_054: "src/folder/sub1";
    test_tzst_mat_055: "src/folder\\sub1";
    test_tzst_mat_056: "src/folder\\sub1\\";
    test_tzst_mat_057: "src/dir1";
    test_tzst_mat_058: "src/dir1/";
    test_tzst_mat_059: "src/dir1\\";
    test_tzst_mat_060: "src/file1.txt";
    test_tzst_mat_061: "src/folder";
    test_tzst_mat_062: "src/folder/";
    test_tzst_mat_063: "src/folder\\";
    test_tzst_mat_064: "src/folder/sub1";
    test_tzst_mat_065: "src/folder\\sub1";
    test_tzst_mat_066: "src/folder\\sub1\\";
    test_tzst_mat_067: "src/dir1";
    test_tzst_mat_068: "src/dir1/";
    test_tzst_mat_069: "src/dir1\\";
    test_tzst_mat_070: "src/file1.txt";
    test_tzst_mat_071: "src/folder";
    test_tzst_mat_072: "src/folder/";
    test_tzst_mat_073: "src/folder\\";
    test_tzst_mat_074: "src/folder/sub1";
    test_tzst_mat_075: "src/folder\\sub1";
    test_tzst_mat_076: "src/folder\\sub1\\";
    test_tzst_mat_077: "src/dir1";
    test_tzst_mat_078: "src/dir1/";
    test_tzst_mat_079: "src/dir1\\";
    test_tzst_mat_080: "src/file1.txt";
    test_tzst_mat_081: "src/folder";
    test_tzst_mat_082: "src/folder/";
    test_tzst_mat_083: "src/folder\\";
    test_tzst_mat_084: "src/folder/sub1";
    test_tzst_mat_085: "src/folder\\sub1";
    test_tzst_mat_086: "src/folder\\sub1\\";
    test_tzst_mat_087: "src/dir1";
    test_tzst_mat_088: "src/dir1/";
    test_tzst_mat_089: "src/dir1\\";
    test_tzst_mat_090: "src/file1.txt";
    test_tzst_mat_091: "src/folder";
    test_tzst_mat_092: "src/folder/";
    test_tzst_mat_093: "src/folder\\";
    test_tzst_mat_094: "src/folder/sub1";
    test_tzst_mat_095: "src/folder\\sub1";
    test_tzst_mat_096: "src/folder\\sub1\\";
    test_tzst_mat_097: "src/dir1";
    test_tzst_mat_098: "src/dir1/";
    test_tzst_mat_099: "src/dir1\\";
    test_tzst_mat_100: "src/file1.txt";
}

macro_rules! generate_tzap_matrix_tests {
    ($($name:ident: $sel:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                let scenario = TestDir::new(&format!("tzap_mat_{}", stringify!($name)));
                let source_dir = scenario.path("src");
                create_nested_tree(&source_dir);
                let archive = scenario.path("archive.tzap");
                create_tzap_fixture(&source_dir, &archive, 0);
                let out_dir = scenario.path("out");
                let report = extract_entry(&archive, $sel, &out_dir).unwrap();
                assert!(report.written_bytes > 0);
            }
        )*
    };
}
generate_tzap_matrix_tests! {
    test_tzap_mat_001: "src/folder";
    test_tzap_mat_002: "src/folder/";
    test_tzap_mat_003: "src/folder\\";
    test_tzap_mat_004: "src/folder/sub1";
    test_tzap_mat_005: "src/folder\\sub1";
    test_tzap_mat_006: "src/folder\\sub1\\";
    test_tzap_mat_007: "src/dir1";
    test_tzap_mat_008: "src/dir1/";
    test_tzap_mat_009: "src/dir1\\";
    test_tzap_mat_010: "src/file1.txt";
    test_tzap_mat_011: "src/folder";
    test_tzap_mat_012: "src/folder/";
    test_tzap_mat_013: "src/folder\\";
    test_tzap_mat_014: "src/folder/sub1";
    test_tzap_mat_015: "src/folder\\sub1";
    test_tzap_mat_016: "src/folder\\sub1\\";
    test_tzap_mat_017: "src/dir1";
    test_tzap_mat_018: "src/dir1/";
    test_tzap_mat_019: "src/dir1\\";
    test_tzap_mat_020: "src/file1.txt";
    test_tzap_mat_021: "src/folder";
    test_tzap_mat_022: "src/folder/";
    test_tzap_mat_023: "src/folder\\";
    test_tzap_mat_024: "src/folder/sub1";
    test_tzap_mat_025: "src/folder\\sub1";
    test_tzap_mat_026: "src/folder\\sub1\\";
    test_tzap_mat_027: "src/dir1";
    test_tzap_mat_028: "src/dir1/";
    test_tzap_mat_029: "src/dir1\\";
    test_tzap_mat_030: "src/file1.txt";
    test_tzap_mat_031: "src/folder";
    test_tzap_mat_032: "src/folder/";
    test_tzap_mat_033: "src/folder\\";
    test_tzap_mat_034: "src/folder/sub1";
    test_tzap_mat_035: "src/folder\\sub1";
    test_tzap_mat_036: "src/folder\\sub1\\";
    test_tzap_mat_037: "src/dir1";
    test_tzap_mat_038: "src/dir1/";
    test_tzap_mat_039: "src/dir1\\";
    test_tzap_mat_040: "src/file1.txt";
    test_tzap_mat_041: "src/folder";
    test_tzap_mat_042: "src/folder/";
    test_tzap_mat_043: "src/folder\\";
    test_tzap_mat_044: "src/folder/sub1";
    test_tzap_mat_045: "src/folder\\sub1";
    test_tzap_mat_046: "src/folder\\sub1\\";
    test_tzap_mat_047: "src/dir1";
    test_tzap_mat_048: "src/dir1/";
    test_tzap_mat_049: "src/dir1\\";
    test_tzap_mat_050: "src/file1.txt";
    test_tzap_mat_051: "src/folder";
    test_tzap_mat_052: "src/folder/";
    test_tzap_mat_053: "src/folder\\";
    test_tzap_mat_054: "src/folder/sub1";
    test_tzap_mat_055: "src/folder\\sub1";
    test_tzap_mat_056: "src/folder\\sub1\\";
    test_tzap_mat_057: "src/dir1";
    test_tzap_mat_058: "src/dir1/";
    test_tzap_mat_059: "src/dir1\\";
    test_tzap_mat_060: "src/file1.txt";
    test_tzap_mat_061: "src/folder";
    test_tzap_mat_062: "src/folder/";
    test_tzap_mat_063: "src/folder\\";
    test_tzap_mat_064: "src/folder/sub1";
    test_tzap_mat_065: "src/folder\\sub1";
    test_tzap_mat_066: "src/folder\\sub1\\";
    test_tzap_mat_067: "src/dir1";
    test_tzap_mat_068: "src/dir1/";
    test_tzap_mat_069: "src/dir1\\";
    test_tzap_mat_070: "src/file1.txt";
    test_tzap_mat_071: "src/folder";
    test_tzap_mat_072: "src/folder/";
    test_tzap_mat_073: "src/folder\\";
    test_tzap_mat_074: "src/folder/sub1";
    test_tzap_mat_075: "src/folder\\sub1";
    test_tzap_mat_076: "src/folder\\sub1\\";
    test_tzap_mat_077: "src/dir1";
    test_tzap_mat_078: "src/dir1/";
    test_tzap_mat_079: "src/dir1\\";
    test_tzap_mat_080: "src/file1.txt";
    test_tzap_mat_081: "src/folder";
    test_tzap_mat_082: "src/folder/";
    test_tzap_mat_083: "src/folder\\";
    test_tzap_mat_084: "src/folder/sub1";
    test_tzap_mat_085: "src/folder\\sub1";
    test_tzap_mat_086: "src/folder\\sub1\\";
    test_tzap_mat_087: "src/dir1";
    test_tzap_mat_088: "src/dir1/";
    test_tzap_mat_089: "src/dir1\\";
    test_tzap_mat_090: "src/file1.txt";
    test_tzap_mat_091: "src/folder";
    test_tzap_mat_092: "src/folder/";
    test_tzap_mat_093: "src/folder\\";
    test_tzap_mat_094: "src/folder/sub1";
    test_tzap_mat_095: "src/folder\\sub1";
    test_tzap_mat_096: "src/folder\\sub1\\";
    test_tzap_mat_097: "src/dir1";
    test_tzap_mat_098: "src/dir1/";
    test_tzap_mat_099: "src/dir1\\";
    test_tzap_mat_100: "src/file1.txt";
}

macro_rules! generate_sevenz_matrix_tests {
    ($($name:ident: $sel:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                let scenario = TestDir::new(&format!("sevenz_mat_{}", stringify!($name)));
                let source_dir = scenario.path("src");
                create_nested_tree(&source_dir);
                let archive = scenario.path("archive.sevenz");
                create_7z_fixture(&source_dir, &archive, Some(6), None);
                let out_dir = scenario.path("out");
                let report = extract_entry(&archive, $sel, &out_dir).unwrap();
                assert!(report.written_bytes > 0);
            }
        )*
    };
}
generate_sevenz_matrix_tests! {
    test_sevenz_mat_001: "src/folder";
    test_sevenz_mat_002: "src/folder/";
    test_sevenz_mat_003: "src/folder\\";
    test_sevenz_mat_004: "src/folder/sub1";
    test_sevenz_mat_005: "src/folder\\sub1";
    test_sevenz_mat_006: "src/folder\\sub1\\";
    test_sevenz_mat_007: "src/dir1";
    test_sevenz_mat_008: "src/dir1/";
    test_sevenz_mat_009: "src/dir1\\";
    test_sevenz_mat_010: "src/file1.txt";
    test_sevenz_mat_011: "src/folder";
    test_sevenz_mat_012: "src/folder/";
    test_sevenz_mat_013: "src/folder\\";
    test_sevenz_mat_014: "src/folder/sub1";
    test_sevenz_mat_015: "src/folder\\sub1";
    test_sevenz_mat_016: "src/folder\\sub1\\";
    test_sevenz_mat_017: "src/dir1";
    test_sevenz_mat_018: "src/dir1/";
    test_sevenz_mat_019: "src/dir1\\";
    test_sevenz_mat_020: "src/file1.txt";
    test_sevenz_mat_021: "src/folder";
    test_sevenz_mat_022: "src/folder/";
    test_sevenz_mat_023: "src/folder\\";
    test_sevenz_mat_024: "src/folder/sub1";
    test_sevenz_mat_025: "src/folder\\sub1";
    test_sevenz_mat_026: "src/folder\\sub1\\";
    test_sevenz_mat_027: "src/dir1";
    test_sevenz_mat_028: "src/dir1/";
    test_sevenz_mat_029: "src/dir1\\";
    test_sevenz_mat_030: "src/file1.txt";
    test_sevenz_mat_031: "src/folder";
    test_sevenz_mat_032: "src/folder/";
    test_sevenz_mat_033: "src/folder\\";
    test_sevenz_mat_034: "src/folder/sub1";
    test_sevenz_mat_035: "src/folder\\sub1";
    test_sevenz_mat_036: "src/folder\\sub1\\";
    test_sevenz_mat_037: "src/dir1";
    test_sevenz_mat_038: "src/dir1/";
    test_sevenz_mat_039: "src/dir1\\";
    test_sevenz_mat_040: "src/file1.txt";
    test_sevenz_mat_041: "src/folder";
    test_sevenz_mat_042: "src/folder/";
    test_sevenz_mat_043: "src/folder\\";
    test_sevenz_mat_044: "src/folder/sub1";
    test_sevenz_mat_045: "src/folder\\sub1";
    test_sevenz_mat_046: "src/folder\\sub1\\";
    test_sevenz_mat_047: "src/dir1";
    test_sevenz_mat_048: "src/dir1/";
    test_sevenz_mat_049: "src/dir1\\";
    test_sevenz_mat_050: "src/file1.txt";
    test_sevenz_mat_051: "src/folder";
    test_sevenz_mat_052: "src/folder/";
    test_sevenz_mat_053: "src/folder\\";
    test_sevenz_mat_054: "src/folder/sub1";
    test_sevenz_mat_055: "src/folder\\sub1";
    test_sevenz_mat_056: "src/folder\\sub1\\";
    test_sevenz_mat_057: "src/dir1";
    test_sevenz_mat_058: "src/dir1/";
    test_sevenz_mat_059: "src/dir1\\";
    test_sevenz_mat_060: "src/file1.txt";
    test_sevenz_mat_061: "src/folder";
    test_sevenz_mat_062: "src/folder/";
    test_sevenz_mat_063: "src/folder\\";
    test_sevenz_mat_064: "src/folder/sub1";
    test_sevenz_mat_065: "src/folder\\sub1";
    test_sevenz_mat_066: "src/folder\\sub1\\";
    test_sevenz_mat_067: "src/dir1";
    test_sevenz_mat_068: "src/dir1/";
    test_sevenz_mat_069: "src/dir1\\";
    test_sevenz_mat_070: "src/file1.txt";
    test_sevenz_mat_071: "src/folder";
    test_sevenz_mat_072: "src/folder/";
    test_sevenz_mat_073: "src/folder\\";
    test_sevenz_mat_074: "src/folder/sub1";
    test_sevenz_mat_075: "src/folder\\sub1";
    test_sevenz_mat_076: "src/folder\\sub1\\";
    test_sevenz_mat_077: "src/dir1";
    test_sevenz_mat_078: "src/dir1/";
    test_sevenz_mat_079: "src/dir1\\";
    test_sevenz_mat_080: "src/file1.txt";
    test_sevenz_mat_081: "src/folder";
    test_sevenz_mat_082: "src/folder/";
    test_sevenz_mat_083: "src/folder\\";
    test_sevenz_mat_084: "src/folder/sub1";
    test_sevenz_mat_085: "src/folder\\sub1";
    test_sevenz_mat_086: "src/folder\\sub1\\";
    test_sevenz_mat_087: "src/dir1";
    test_sevenz_mat_088: "src/dir1/";
    test_sevenz_mat_089: "src/dir1\\";
    test_sevenz_mat_090: "src/file1.txt";
    test_sevenz_mat_091: "src/folder";
    test_sevenz_mat_092: "src/folder/";
    test_sevenz_mat_093: "src/folder\\";
    test_sevenz_mat_094: "src/folder/sub1";
    test_sevenz_mat_095: "src/folder\\sub1";
    test_sevenz_mat_096: "src/folder\\sub1\\";
    test_sevenz_mat_097: "src/dir1";
    test_sevenz_mat_098: "src/dir1/";
    test_sevenz_mat_099: "src/dir1\\";
    test_sevenz_mat_100: "src/file1.txt";
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
macro_rules! generate_aar_matrix_tests {
    ($($name:ident: $sel:expr);* $(;)?) => {
        $(
            #[test]
            fn $name() {
                let scenario = TestDir::new(&format!("aar_mat_{}", stringify!($name)));
                let source_dir = scenario.path("src");
                create_nested_tree(&source_dir);
                let archive = scenario.path("archive.aar");
                create_aar_fixture(&source_dir, &archive, &AppleArchiveCreateOptions::default());
                let out_dir = scenario.path("out");
                let report = extract_entry(&archive, $sel, &out_dir).unwrap();
                assert!(report.written_bytes > 0);
            }
        )*
    };
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
generate_aar_matrix_tests! {
    test_aar_mat_001: "src/folder";
    test_aar_mat_002: "src/folder/";
    test_aar_mat_003: "src/folder\\";
    test_aar_mat_004: "src/folder/sub1";
    test_aar_mat_005: "src/folder\\sub1";
    test_aar_mat_006: "src/folder\\sub1\\";
    test_aar_mat_007: "src/dir1";
    test_aar_mat_008: "src/dir1/";
    test_aar_mat_009: "src/dir1\\";
    test_aar_mat_010: "src/file1.txt";
    test_aar_mat_011: "src/folder";
    test_aar_mat_012: "src/folder/";
    test_aar_mat_013: "src/folder\\";
    test_aar_mat_014: "src/folder/sub1";
    test_aar_mat_015: "src/folder\\sub1";
    test_aar_mat_016: "src/folder\\sub1\\";
    test_aar_mat_017: "src/dir1";
    test_aar_mat_018: "src/dir1/";
    test_aar_mat_019: "src/dir1\\";
    test_aar_mat_020: "src/file1.txt";
    test_aar_mat_021: "src/folder";
    test_aar_mat_022: "src/folder/";
    test_aar_mat_023: "src/folder\\";
    test_aar_mat_024: "src/folder/sub1";
    test_aar_mat_025: "src/folder\\sub1";
    test_aar_mat_026: "src/folder\\sub1\\";
    test_aar_mat_027: "src/dir1";
    test_aar_mat_028: "src/dir1/";
    test_aar_mat_029: "src/dir1\\";
    test_aar_mat_030: "src/file1.txt";
    test_aar_mat_031: "src/folder";
    test_aar_mat_032: "src/folder/";
    test_aar_mat_033: "src/folder\\";
    test_aar_mat_034: "src/folder/sub1";
    test_aar_mat_035: "src/folder\\sub1";
    test_aar_mat_036: "src/folder\\sub1\\";
    test_aar_mat_037: "src/dir1";
    test_aar_mat_038: "src/dir1/";
    test_aar_mat_039: "src/dir1\\";
    test_aar_mat_040: "src/file1.txt";
    test_aar_mat_041: "src/folder";
    test_aar_mat_042: "src/folder/";
    test_aar_mat_043: "src/folder\\";
    test_aar_mat_044: "src/folder/sub1";
    test_aar_mat_045: "src/folder\\sub1";
    test_aar_mat_046: "src/folder\\sub1\\";
    test_aar_mat_047: "src/dir1";
    test_aar_mat_048: "src/dir1/";
    test_aar_mat_049: "src/dir1\\";
    test_aar_mat_050: "src/file1.txt";
    test_aar_mat_051: "src/folder";
    test_aar_mat_052: "src/folder/";
    test_aar_mat_053: "src/folder\\";
    test_aar_mat_054: "src/folder/sub1";
    test_aar_mat_055: "src/folder\\sub1";
    test_aar_mat_056: "src/folder\\sub1\\";
    test_aar_mat_057: "src/dir1";
    test_aar_mat_058: "src/dir1/";
    test_aar_mat_059: "src/dir1\\";
    test_aar_mat_060: "src/file1.txt";
    test_aar_mat_061: "src/folder";
    test_aar_mat_062: "src/folder/";
    test_aar_mat_063: "src/folder\\";
    test_aar_mat_064: "src/folder/sub1";
    test_aar_mat_065: "src/folder\\sub1";
    test_aar_mat_066: "src/folder\\sub1\\";
    test_aar_mat_067: "src/dir1";
    test_aar_mat_068: "src/dir1/";
    test_aar_mat_069: "src/dir1\\";
    test_aar_mat_070: "src/file1.txt";
    test_aar_mat_071: "src/folder";
    test_aar_mat_072: "src/folder/";
    test_aar_mat_073: "src/folder\\";
    test_aar_mat_074: "src/folder/sub1";
    test_aar_mat_075: "src/folder\\sub1";
    test_aar_mat_076: "src/folder\\sub1\\";
    test_aar_mat_077: "src/dir1";
    test_aar_mat_078: "src/dir1/";
    test_aar_mat_079: "src/dir1\\";
    test_aar_mat_080: "src/file1.txt";
    test_aar_mat_081: "src/folder";
    test_aar_mat_082: "src/folder/";
    test_aar_mat_083: "src/folder\\";
    test_aar_mat_084: "src/folder/sub1";
    test_aar_mat_085: "src/folder\\sub1";
    test_aar_mat_086: "src/folder\\sub1\\";
    test_aar_mat_087: "src/dir1";
    test_aar_mat_088: "src/dir1/";
    test_aar_mat_089: "src/dir1\\";
    test_aar_mat_090: "src/file1.txt";
    test_aar_mat_091: "src/folder";
    test_aar_mat_092: "src/folder/";
    test_aar_mat_093: "src/folder\\";
    test_aar_mat_094: "src/folder/sub1";
    test_aar_mat_095: "src/folder\\sub1";
    test_aar_mat_096: "src/folder\\sub1\\";
    test_aar_mat_097: "src/dir1";
    test_aar_mat_098: "src/dir1/";
    test_aar_mat_099: "src/dir1\\";
    test_aar_mat_100: "src/file1.txt";
}
