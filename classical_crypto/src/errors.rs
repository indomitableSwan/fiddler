//! Contains custom error types.
use thiserror::Error;

/// An opaque error type that hides the implementation details of internal
/// errors.
// This is a technique that is easy to use with the `thiserror` crate. The attribute
// `error(transparent)` forwards the source and display methods straight through to the underlying
// internal error representations.
#[derive(Error, Debug, PartialEq)]
#[error(transparent)]
pub struct InternalError(#[from] ErrorRepr);

/// Internal errors.
#[derive(Clone, Debug, PartialEq, Error)]
pub(super) enum ErrorRepr {
    /// Thrown when a conversion between the Latin
    /// Alphabet and the ring of integers modulo [`RingElement::MODULUS`] fails.
    ///
    /// This error should only be thrown if:
    /// - There is a mistake in the definition of the constant
    ///   [`RingElement::ALPH_ENCODING`];
    /// - The input was not a lowercase letter from the Latin Alphabet.
    #[error("Failed to encode the following characters as ring elements: {0}")]
    RingElementEncodingError(String),
}

// TODO: Are these usable for other ciphers?
/// An error type that indicates a failure to parse a string.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum EncodingError {
    /// Error thrown when parsing a string as a message. This error is thrown
    /// when the string included one or more characters that are not
    /// lowercase letters from the Latin Alphabet.
    #[error("Invalid Message. {0}")]
    InvalidMessage(InternalError),
    /// Error thrown when parsing a string as a ciphertext. This error is thrown
    /// when the string included one or more characters that are not letters
    /// from the Latin Alphabet. We allow for strings containing both
    /// capitalized and lowercase letters when parsing as string as a
    /// ciphertext.
    #[error("Invalid Ciphertext. {0}")]
    InvalidCiphertext(InternalError),
    /// Error thrown when parsing a string as a key. This error is thrown when
    /// the string does not represent a number in the appropriate
    /// range. e.g., for the Latin Shift Cipher, keys are in the range 0 to 25,
    /// inclusive.
    #[error("Input \"{0}\" does not represent a valid key")]
    InvalidKey(String),
}
