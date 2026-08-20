#![no_main]

use libfuzzer_sys::fuzz_target;
use std::time::Instant;

fuzz_target!(|data: &[u8]| {
    // Split data into pattern and value at the first null byte or mid-point
    let (pattern_bytes, value_bytes) = if let Some(pos) = data.iter().position(|&b| b == 0) {
        (&data[..pos], &data[pos + 1..])
    } else {
        let mid = data.len() / 2;
        (&data[..mid], &data[mid..])
    };

    if let (Ok(pattern_str), Ok(path_str)) = (std::str::from_utf8(pattern_bytes), std::str::from_utf8(value_bytes)) {
        let start = Instant::now();
        let matched = zmanager_core::safety::archive_pattern_matches(pattern_str, path_str);
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 50, "archive_pattern_matches took too long: {elapsed:?}");
        std::hint::black_box(matched);

        let start = Instant::now();
        let any_matched = zmanager_core::safety::archive_pattern_matches_any(path_str, &[pattern_str.to_string()], &[]);
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 50, "archive_pattern_matches_any took too long: {elapsed:?}");
        std::hint::black_box(any_matched);

        if let Some(rule) = zmanager_core::backend_test_support::gitignore::parse_gitignore_rule(pattern_str, "") {
            let start = Instant::now();
            let decision = zmanager_core::backend_test_support::gitignore::gitignore_decision(
                path_str,
                zmanager_core::manifest::ManifestFileType::File,
                &[rule],
            );
            let elapsed = start.elapsed();
            assert!(elapsed.as_millis() < 50, "gitignore_decision took too long: {elapsed:?}");
            std::hint::black_box(decision);
        }
    }
});
