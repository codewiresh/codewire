//! Command-line entrypoints for the isolated cargo-fuzz workspace.

use std::ffi::OsString;

use clap::CommandFactory as _;

thread_local! {
    static COMMAND: clap::Command = crate::Cli::command();
}

/// Exercise the `run` and `exec` command boundary before Clap parses arguments.
pub fn preprocess_arguments(arguments: Vec<OsString>) {
    COMMAND.with(|command| {
        let original = arguments.clone();
        let arguments = match crate::command_line::separate_command_with(arguments, command) {
            Ok(arguments) => arguments,
            Err(error) => {
                let _diagnostic = error.to_string();
                return;
            }
        };
        let repeated = crate::command_line::separate_command_with(arguments.clone(), command)
            .expect("preprocessed arguments remain valid for preprocessing");
        assert_eq!(repeated, arguments, "argument preprocessing is idempotent");

        match arguments.len().checked_sub(original.len()) {
            Some(0) => assert_eq!(arguments, original, "preprocessing preserves arguments"),
            Some(1) => assert!(
                arguments.iter().enumerate().any(|(at, argument)| {
                    argument.as_os_str() == "--"
                        && arguments[..at] == original[..at]
                        && arguments[at + 1..] == original[at..]
                }),
                "preprocessing only inserts a command separator"
            ),
            _ => panic!("preprocessing changes arguments only by inserting one separator"),
        }
    });
}
