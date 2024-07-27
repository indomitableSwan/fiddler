//! Utility function to help obtain a command from user via CLI.
//!
//! Note how we test the CLI:
//! - First we divide the crate into a library and a binary
//! - Then we can test the library! This is a little tricky because we need to
//!   abstract over types that implement the [`std::io::BufRead`] trait in order
//!   to test read behavior.

use classical_crypto::errors::EncodingError;
use std::{io, str::FromStr};
use thiserror::Error;

// use anyhow::{anyhow, Result};

#[derive(Error, Debug)]
pub enum ProcessInputError {
    #[error("Error reading input: {0}")]
    InputRead(#[from] io::Error),

    #[error("Parse error: {0}")]
    CryptoParseError(#[from] EncodingError),

    /// The error returned upon failure to parse a [`Command`] from a string.
    #[error("Invalid command: {0}")]
    CommandParseError(String),
}

/// Prints instructions and then processes command line input and converts to
/// type `T` as specified by caller. If successful, returns conversion.
/// Otherwise, returns an error.
pub fn process_input<T, E, F, R>(instr: F, reader: &mut R) -> Result<T, ProcessInputError>
where
    T: FromStr<Err = E>,
    // TODO: Understand this
    E: std::error::Error,
    F: Fn(),
    R: io::BufRead,
    ProcessInputError: std::convert::From<E>,
{
    // Print the instructions
    instr();

    let mut input = String::new();

    reader.read_line(&mut input)?;

    input.trim().parse::<T>().map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    // TODO: Why is this giving a warning?
    use super::*;
    use crate::menu::ConsentMenu;
    use std::io::{BufRead, Read};

    struct MockIoReader {
        mock_input: String,
    }

    impl MockIoReader {
        fn new(mock_input: &str) -> Self {
            Self {
                mock_input: mock_input.to_string(),
            }
        }
    }

    impl Read for MockIoReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            buf.clone_from_slice(self.mock_input.as_bytes());
            Ok(self.mock_input.len())
        }
    }

    impl BufRead for MockIoReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Ok(self.mock_input.as_bytes())
        }

        fn consume(&mut self, amt: usize) {
            let (_, rest) = self.mock_input.split_at(amt);
            self.mock_input = rest.to_string();
        }
    }

    #[test]
    fn assent() {
        let mut mock_reader = MockIoReader::new("y");
        let command: ConsentMenu = process_input(
            || {
                println! {"test"}
            },
            &mut mock_reader,
        )
        .unwrap();
        assert_eq!(command, ConsentMenu::YesKE)
    }

    // #[test]
    // fn dissent() {
    //     let input: &[u8] = b"n";
    //     let command: ConsentMenu = process_input(|| {}, input).unwrap();
    //     assert_eq!(command, ConsentMenu::NoKE)
    // }

    // #[test]
    // fn consent_error() {
    //     let input: &[u8] = b"N";
    //     let error: anyhow::Error =
    //         process_input::<ConsentMenu, CommandError, _, &[u8]>(|| {},
    // input).unwrap_err();

    //     assert_eq!(
    //         *error.downcast_ref::<CommandError>().unwrap(),
    //         CommandError("N".to_string())
    //     )
    // }
}
