#![no_main]
//! Fuzz the SSR share-link parser (`ssr://...`) in isolation.
//!
//! The generic `parse_link` fuzzer reaches this parser only when it happens
//! to generate the `ssr://` scheme; this target prefixes every input with
//! the scheme so the base64 payload decoder, the six-field split and the
//! honest-subset rejections get direct coverage. Like all link parsers, a
//! malformed link must come back as `Err`, never a panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let link = format!("ssr://{text}");
    let _ = zero_config::parse_link(&link);
});
