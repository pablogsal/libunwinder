#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    libunwinder::__fuzz::parse_dwarf(data);
});
