//! Utility function to help obtain a command from user via CLI.
//!
//! Note how we test the CLI:
//! - First we divide the crate into a library and a binary
//! - Then we can test the library! This is a little tricky because we need to
//!   abstract over types that implement the [`std::io::BufRead`] trait in order
//!   to test read behavior.

use crate::menu::CommandError;
use anyhow::{anyhow, Result};
use std::{io, str::FromStr};

// TODO: this loop and match statment plus a return line is probably not
// idiomatic
//
/// Prints instructions and then processes command line input and converts to type `T` as specified
/// by caller. If successful, returns conversion. Otherwise, returns an error.
pub fn process_input<T, E, F, R>(instr: F, mut reader: R) -> Result<T>
where
    T: FromStr<Err = E>,
    // TODO: Understand this
    E: std::error::Error + std::marker::Send + std::marker::Sync + 'static,
    F: Fn(),
    R: io::BufRead,
{
    // Print the instructions
    instr();

    let mut input = String::new();

    reader.read_line(&mut input)?;

    match input.trim().parse::<T>() {
        Ok(t) => Ok(t),
        Err(e) => Err(e.into()),
    }
}

mod tests {
    // TODO: Why is this giving a warning?
    use super::*;
    use crate::menu::ConsentMenu;

    #[test]
    fn assent() {
        let input: &[u8] = b"y";
        let command: ConsentMenu = process_input(|| {}, input).unwrap();
        assert_eq!(command, ConsentMenu::YesKE)
    }

    #[test]
    fn dissent() {
        let input: &[u8] = b"n";
        let command: ConsentMenu = process_input(|| {}, input).unwrap();
        assert_eq!(command, ConsentMenu::NoKE)
    }

    #[test]
    fn consent_error() {
        let input: &[u8] = b"N";
        let error: anyhow::Error =
            process_input::<ConsentMenu, CommandError, _, &[u8]>(|| {}, input).unwrap_err();

        assert_eq!(
            *error.downcast_ref::<CommandError>().unwrap(),
            CommandError("N".to_string())
        )
    }
}
