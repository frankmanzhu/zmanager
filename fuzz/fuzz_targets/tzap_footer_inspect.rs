#![no_main]

use libfuzzer_sys::fuzz_target;
use tzap_core::{ReaderOptions, public_no_key_inspect_footer};

fuzz_target!(|data: &[u8]| {
    let _ = public_no_key_inspect_footer(&data.to_vec(), ReaderOptions::default());
});
