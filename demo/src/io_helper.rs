//! Utility function to help obtain a command from user via CLI.
//!
//! Note how we test the CLI:
//! - First we divide the crate into a library and a binary
//! - Then we can test the library! This is a little tricky because we need to
//!   abstract over types that implement the [`std::io::BufRead`] trait in order
//!   to test read behavior.
// TODO: Test stdout behavior

use classical_crypto::errors::EncodingError;
use std::{io, str::FromStr};
use thiserror::Error;

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

// TODO: Is this a good place for a macro? These tests are _very_ repetitive.
#[cfg(test)]
mod tests {
    use classical_crypto::shift::{Ciphertext, Key, Message};

    use super::*;
    use crate::menu::{ConsentMenu, DecryptMenu, MainMenu};
    use std::io::{BufRead, Read};

    // Create a mock object to test reading from `stdin`
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

    // EncodingError tests
    #[test]
    fn ciphertext() {
        let mut mock_reader = MockIoReader::new("AFDSDFE");
        let command: Ciphertext = process_input(|| {}, &mut mock_reader).unwrap();
        assert_eq!(command, Ciphertext::from_str("AFDSDFE").unwrap())
    }
    //
    #[test]
    fn message() {
        let mut mock_reader = MockIoReader::new("thecatishungry");
        let command: Message = process_input(|| {}, &mut mock_reader).unwrap();
        assert_eq!(command, Message::new("thecatishungry").unwrap())
    }
    //
    #[test]
    fn key() {
        let mut mock_reader = MockIoReader::new("3");
        let command: Key = process_input(|| {}, &mut mock_reader).unwrap();
        assert_eq!(command, Key::from_str("3").unwrap())
    }
    //
    #[test]
    fn message_error() {
        let mut mock_reader = MockIoReader::new("N");
        let error: Result<Message, ProcessInputError> = process_input(|| {}, &mut mock_reader);

        assert!(error.is_err());

        assert!(match error.unwrap_err() {
            ProcessInputError::CryptoParseError(e) => e.to_string()
                == "Invalid Message. Failed to encode the following characters as ring elements: N",
            _ => false,
        });
    }
    //
    #[test]
    fn ciphertext_error() {
        let mut mock_reader = MockIoReader::new("ASD;");
        let error: Result<Ciphertext, ProcessInputError> = process_input(|| {}, &mut mock_reader);

        assert!(error.is_err());

        assert!(match error.unwrap_err() {
            ProcessInputError::CryptoParseError(e) => e.to_string() == "Invalid Ciphertext. Failed to encode the following characters as ring elements: ;",
            _ => false,
        }
    );
    }
    //
    #[test]
    fn key_error() {
        let mut mock_reader = MockIoReader::new("65");
        let error: Result<Key, ProcessInputError> = process_input(|| {}, &mut mock_reader);

        assert!(error.is_err());
        let error = error.as_ref().unwrap_err();
        assert_eq!(
            error.to_string(),
            "Parse error: Input \"65\" does not represent a valid key"
        );

        assert!(matches!(error, ProcessInputError::CryptoParseError(_)));
    }

    // ConsentMenu tests
    //
    #[test]
    fn assent() {
        let mut mock_reader = MockIoReader::new("y");
        let command: ConsentMenu = process_input(|| {}, &mut mock_reader).unwrap();
        assert_eq!(command, ConsentMenu::YesKE)
    }
    //
    #[test]
    fn dissent() {
        let mut mock_reader = MockIoReader::new("n");
        let command: ConsentMenu = process_input(|| {}, &mut mock_reader).unwrap();
        assert_eq!(command, ConsentMenu::NoKE)
    }
    //
    #[test]
    fn consent_error() {
        let mut mock_reader = MockIoReader::new("N");
        let error: Result<ConsentMenu, ProcessInputError> = process_input(|| {}, &mut mock_reader);

        assert!(error.is_err());

        assert!(match error.unwrap_err() {
            ProcessInputError::CommandParseError(e) => e == *"N",
            _ => false,
        });
    }

    // DecryptMenu tests
    #[test]
    fn known_key() {
        let mut mock_reader = MockIoReader::new("1");
        let command: DecryptMenu = process_input(|| {}, &mut mock_reader).unwrap();
        assert_eq!(command, DecryptMenu::KnownKey)
    }
    //
    #[test]
    fn brute_force() {
        let mut mock_reader = MockIoReader::new("2");
        let command: DecryptMenu = process_input(|| {}, &mut mock_reader).unwrap();
        assert_eq!(command, DecryptMenu::Bruteforce)
    }
    //
    #[test]
    fn quit_decrypt_menu() {
        let mut mock_reader = MockIoReader::new("3");
        let command: DecryptMenu = process_input(|| {}, &mut mock_reader).unwrap();
        assert_eq!(command, DecryptMenu::Quit)
    }
    //
    #[test]
    fn decrypt_menu_error() {
        let mut mock_reader = MockIoReader::new("N");
        let error: Result<ConsentMenu, ProcessInputError> = process_input(|| {}, &mut mock_reader);

        assert!(error.is_err());

        assert!(match error.unwrap_err() {
            ProcessInputError::CommandParseError(e) => e == *"N",
            _ => false,
        });
    }

    // Test MainMenu
    //
    #[test]
    fn main_gen_key() {
        let mut mock_reader = MockIoReader::new("1");
        let command: MainMenu = process_input(|| {}, &mut mock_reader).unwrap();
        assert_eq!(command, MainMenu::GenKE)
    }
    //
    #[test]
    fn main_encrypt() {
        let mut mock_reader = MockIoReader::new("2");
        let command: MainMenu = process_input(|| {}, &mut mock_reader).unwrap();
        assert_eq!(command, MainMenu::EncryptKE)
    }
    //
    #[test]
    fn main_decrypt() {
        let mut mock_reader = MockIoReader::new("3");
        let command: MainMenu = process_input(|| {}, &mut mock_reader).unwrap();
        assert_eq!(command, MainMenu::DecryptKE)
    }
    //
    #[test]
    fn main_quit() {
        let mut mock_reader = MockIoReader::new("4");
        let command: MainMenu = process_input(|| {}, &mut mock_reader).unwrap();
        assert_eq!(command, MainMenu::QuitKE)
    }
    //
    #[test]
    fn main_error() {
        let mut mock_reader = MockIoReader::new("N");
        let error: Result<MainMenu, ProcessInputError> = process_input(|| {}, &mut mock_reader);

        assert!(error.is_err());

        assert!(match error.unwrap_err() {
            ProcessInputError::CommandParseError(e) => e == *"N",
            _ => false,
        });
    }
}
