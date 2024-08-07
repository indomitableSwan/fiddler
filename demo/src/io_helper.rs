//! Utility function to help obtain a command from user via CLI.
// Note how we test the CLI:
// - First we divide the crate into a library and a binary
// - Then we can test the library! This is a little tricky because we need to
//   abstract over types that implement [`std::io::BufRead`] in order to test
//   read behavior and types that implement [`std::io::Write`] to test write
//   behavior. This decouples the code from stdin and stdout.
//
// This makes the code more complex and less understandable, so there is a
// tradeoff here between readability and testability.
//
// Notes: we don't exhaustively test writes here, we tested printing the main
// menu with user selecting to generate a key in

use anyhow::Result;
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

/// Processes user input and converts to
/// type `T` as specified by caller. If successful, returns conversion.
/// Otherwise, returns a custom error that contains information about the
/// underlying error cause.
// Notes: This is generic over the reader in order to decouple the program from stdin and allow for easier testing.
pub fn process_input<T, E, R>(reader: &mut R) -> Result<T, ProcessInputError>
where
    T: FromStr<Err = E>,
    E: std::error::Error,
    R: io::BufRead,
    ProcessInputError: std::convert::From<E>,
{
    let mut input = String::new();

    reader.read_line(&mut input)?;

    input.trim().parse::<T>().map_err(|e| e.into())
}

// TODO: Is this a good place for a macro? These tests are _very_ repetitive.
// Test notes: these tests test `process_input`, which converts a user input to
// a prespecified type, which are of two kinds in our demo
// - types inherited from the classical_crypto library,
// - commands
#[cfg(test)]
mod tests {
    use classical_crypto::shift::{Ciphertext, Key, Message};
    use io::{Error, ErrorKind};

    use super::*;
    use crate::menu::{ConsentMenu, DecryptMenu, MainMenu, Menu};
    use core::str;
    use std::{
        io::{BufRead, Read, Write},
        str::from_utf8,
    };

    // Create a mock object to test reading from `stdin`
    #[derive(Debug)]
    struct MockIoReader {
        mock_input: String,
    }

    // Create a mock object to test writing to `stdout`
    #[derive(Debug)]
    struct MockIoWriter {
        buffer: Vec<u8>,
        mock_output: String,
    }

    impl MockIoReader {
        fn new(mock_input: &str) -> Self {
            Self {
                mock_input: mock_input.to_string(),
            }
        }
    }

    impl MockIoWriter {
        fn new() -> Self {
            Self {
                buffer: Vec::new(),
                mock_output: "".to_string(),
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

    impl Write for MockIoWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            for item in buf.iter() {
                self.buffer.push(*item)
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            let output = match from_utf8(&self.buffer) {
                Ok(r) => Ok(r),
                Err(_) => Err(Error::new(ErrorKind::Other, "oh no!")),
            };
            self.mock_output.push_str(output.unwrap());
            self.buffer = Vec::new();
            Ok(())
        }
    }

    // Mock Writer test
    // Going full meta here
    #[test]
    fn test_the_writer_mock() -> anyhow::Result<()> {
        let mut writer = MockIoWriter::new();
        write!(writer, "Whatever this means\n\n not that")?;
        assert_eq!(writer.buffer, "Whatever this means\n\n not that".as_bytes());
        writer.flush()?;
        write!(writer, "another")?;
        assert_eq!(writer.buffer, "another".as_bytes());
        writer.flush()?;
        assert_eq!(
            writer.mock_output,
            "Whatever this means\n\n not thatanother"
        );
        Ok(())
    }
    //
    #[test]
    fn test_the_writer_writeln() -> anyhow::Result<()> {
        let mut writer = MockIoWriter::new();
        writeln!(writer, "hi")?;
        assert_eq!(writer.buffer, "hi\n".as_bytes());
        writer.flush()?;
        assert_eq!(writer.mock_output, "hi\n");
        Ok(())
    }

    // Processing Ciphertexts, Messages, Keys
    #[test]
    fn ciphertext() -> anyhow::Result<()> {
        let mut mock_reader = MockIoReader::new("AFDSDFE");
        let mut mock_writer = MockIoWriter::new();

        write!(&mut mock_writer, "test")?;
        mock_writer.flush()?;

        let command: Result<Ciphertext, ProcessInputError> = process_input(&mut mock_reader);

        assert!(command.is_ok());
        let command = command.unwrap();
        assert_eq!(command, Ciphertext::from_str("AFDSDFE")?);
        assert_eq!(mock_writer.mock_output, "test");
        Ok(())
    }
    //
    #[test]
    fn message() {
        let mut mock_reader = MockIoReader::new("thecatishungry");
        let msg: Message = process_input(&mut mock_reader).unwrap();
        assert_eq!(msg, Message::new("thecatishungry").unwrap())
    }
    //
    #[test]
    fn key() {
        let mut mock_reader = MockIoReader::new("3");
        let key: Key = process_input(&mut mock_reader).unwrap();
        assert_eq!(key, Key::from_str("3").unwrap())
    }
    //
    #[test]
    fn message_error() {
        let mut mock_reader = MockIoReader::new("N");
        let error: Result<Message, ProcessInputError> = process_input(&mut mock_reader);

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
        let error: Result<Ciphertext, ProcessInputError> = process_input(&mut mock_reader);

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
        let error: Result<Key, ProcessInputError> = process_input(&mut mock_reader);

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
        let command: ConsentMenu = process_input(&mut mock_reader).unwrap();
        assert_eq!(command, ConsentMenu::YesKE)
    }
    //
    #[test]
    fn dissent() {
        let mut mock_reader = MockIoReader::new("n");
        let command: ConsentMenu = process_input(&mut mock_reader).unwrap();
        assert_eq!(command, ConsentMenu::NoKE)
    }
    //
    #[test]
    fn consent_error() {
        let mut mock_reader = MockIoReader::new("N");
        let error: Result<ConsentMenu, ProcessInputError> = process_input(&mut mock_reader);

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
        let command: DecryptMenu = process_input(&mut mock_reader).unwrap();
        assert_eq!(command, DecryptMenu::KnownKey)
    }
    //
    #[test]
    fn brute_force() {
        let mut mock_reader = MockIoReader::new("2");
        let command: DecryptMenu = process_input(&mut mock_reader).unwrap();
        assert_eq!(command, DecryptMenu::Bruteforce)
    }
    //
    #[test]
    fn quit_decrypt_menu() {
        let mut mock_reader = MockIoReader::new("3");
        let command: DecryptMenu = process_input(&mut mock_reader).unwrap();
        assert_eq!(command, DecryptMenu::Quit)
    }
    //
    #[test]
    fn decrypt_menu_error() {
        let mut mock_reader = MockIoReader::new("N");
        let error: Result<ConsentMenu, ProcessInputError> = process_input(&mut mock_reader);

        assert!(error.is_err());

        assert!(match error.unwrap_err() {
            ProcessInputError::CommandParseError(e) => e == *"N",
            _ => false,
        });
    }

    // Test MainMenu
    //
    // Here we have an example read and write test
    #[test]
    fn main_gen_key() -> anyhow::Result<()> {
        let mut mock_reader = MockIoReader::new("1");
        let mut mock_writer = MockIoWriter::new();

        MainMenu::print_menu(&mut mock_writer)?;

        let command: Result<MainMenu, ProcessInputError> = process_input(&mut mock_reader);
        mock_writer.flush()?;
        assert!(command.is_ok());
        let command = command.unwrap();
        // Test reads
        assert_eq!(command, MainMenu::GenKE);
        // Test writes
        assert_eq!(mock_writer.mock_output, "\nPlease enter one of the following options:\n1: Generate a key.\n2: Encrypt a message.\n3: Decrypt a ciphertext.\n4: Quit\n");
        Ok(())
    }
    //
    #[test]
    fn main_encrypt() {
        let mut mock_reader = MockIoReader::new("2");
        let command: MainMenu = process_input(&mut mock_reader).unwrap();
        assert_eq!(command, MainMenu::EncryptKE)
    }
    //
    #[test]
    fn main_decrypt() {
        let mut mock_reader = MockIoReader::new("3");
        let command: MainMenu = process_input(&mut mock_reader).unwrap();
        assert_eq!(command, MainMenu::DecryptKE)
    }
    //
    #[test]
    fn main_quit() {
        let mut mock_reader = MockIoReader::new("4");
        let command: MainMenu = process_input(&mut mock_reader).unwrap();
        assert_eq!(command, MainMenu::QuitKE)
    }
    //
    #[test]
    fn main_error() {
        let mut mock_reader = MockIoReader::new("N");
        let error: Result<MainMenu, ProcessInputError> = process_input(&mut mock_reader);

        assert!(error.is_err());

        assert!(match error.unwrap_err() {
            ProcessInputError::CommandParseError(e) => e == *"N",
            _ => false,
        });
    }
}
