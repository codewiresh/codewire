//! CLI arguments come from the local caller and need not be valid UTF-8. This
//! target never parses or executes a command. Successful preprocessing is
//! idempotent and either preserves the arguments or inserts exactly one `--`;
//! refusals format safely.
//!
//! The target encodes arguments with NUL or newline separators. A final newline
//! is a text-file terminator rather than an empty argument.
#![no_main]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let input = input.strip_suffix(b"\n").unwrap_or(input);
    let mut arguments = vec![OsString::from("cw")];
    arguments.extend(
        input
            .split(|byte| matches!(byte, 0 | b'\n'))
            .map(|argument| OsString::from_vec(argument.to_vec())),
    );
    codewire_cli::fuzzing::preprocess_arguments(arguments);
});
