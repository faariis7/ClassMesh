#![no_main]

use classmesh_security::teacher_roster::{UnsignedRoster, inspect_roster};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(claims) = inspect_roster(bytes) {
        assert!(UnsignedRoster::new(&claims).is_ok());
    }
});
