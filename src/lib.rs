//! This repository is a playground for learning Rust.
//! It is not meant to be used for anything in practice.
//!
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(unused_qualifications, unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![warn(rustdoc::broken_intra_doc_links)]
#![warn(rustdoc::private_intra_doc_links)]
#![warn(rustdoc::private_doc_tests)]
#![warn(rustdoc::invalid_rust_codeblocks)]
#![warn(rustdoc::invalid_codeblock_attributes)]
#![warn(rustdoc::invalid_html_tags)]
#![warn(rustdoc::bare_urls)]
#![warn(rustdoc::unescaped_backticks)]
#![warn(rustdoc::redundant_explicit_links)]

//! Currently we implement the Shift Cipher using the Latin Alphabet.
//! This cipher uses an encoding of the Latin Alphabet in the ring of integers modulo 26, which we denote by &#x2124;/26&#x2124;. That is, the ring &#x2124;/26&#x2124; is both the _plaintext space_ and the _ciphertext space_. As the name implies, ciphertexts are shifts (computed using modular arithmetic) of the corresponding plaintexts, so the _key space_ is &#x2124;/26&#x2124; as well.
//!
//! We allow for messages (and, correspondingly, ciphertexts) of arbitrary length, because in practice we can encrypt (and decrypt) using ordered sequences of ring elements (i.e., plaintexts and ciphertexts, respectively).
// (&#x2124; is Unicode for blackboard bold Z)

use rand::{CryptoRng, Rng};
use std::{
    fmt,
    ops::{Add, Sub},
    str::FromStr,
};

/// The default alphabet encoding for the Latin Shift Cipher.
const ALPH_ENCODING: [(char, i8); 26] = [
    ('a', 0),
    ('b', 1),
    ('c', 2),
    ('d', 3),
    ('e', 4),
    ('f', 5),
    ('g', 6),
    ('h', 7),
    ('i', 8),
    ('j', 9),
    ('k', 10),
    ('l', 11),
    ('m', 12),
    ('n', 13),
    ('o', 14),
    ('p', 15),
    ('q', 16),
    ('r', 17),
    ('s', 18),
    ('t', 19),
    ('u', 20),
    ('v', 21),
    ('w', 22),
    ('x', 23),
    ('y', 24),
    ('z', 25),
];

/// The modulus used to construct the ring of integers used in the given Shift Cipher
/// as the plaintext space, ciphertext space, and key space, i.e., the ring of integers modulo _m_, denoted by &#x2124;/_m_&#x2124;, where the modulus _m_ is drawn directly from [`ALPH_ENCODING`].
// The modulus m for the ring Z/mZ.
// Included in order to make generalizing to other alphabets easier later.
const MODULUS: i8 = ALPH_ENCODING.len() as i8;

/// An implementation of the ring &#x2124;/_m_&#x2124;, where _m_ is set to [`MODULUS`].
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
struct RingElement(i8);

/// A custom error type that is thrown when a conversion between the Latin Alphabet and
/// the ring of integers modulo [`MODULUS`] fails.
///
/// This error should only be thrown if:
/// - There is a mistake in the definition of the constant [`ALPH_ENCODING`];
/// - The input was not a lowercase letter from the Latin Alphabet.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
struct RingElementEncodingError;

impl RingElement {
    /// Returns zero, the additive identity.
    pub const fn zero() -> RingElement {
        RingElement(0)
    }

    /// Returns true if zero and false otherwise.
    pub fn _is_zero(&self) -> bool {
        self.eq(&RingElement::zero())
    }

    /// Convert from a character to a ring element.
    ///
    /// # Errors
    /// This method will return a custom pub(crate) error if the constant [`ALPH_ENCODING`] does not specify a mapping to the ring of integers for the given input. This happens if the input is not from the lowercase Latin Alphabet. For crate users, this error type will get "lifted" to the public error type [`EncodingError`] by the caller, e.g., when parsing a [`Message`] from a string.
    fn from_char(ltr: char) -> Result<Self, RingElementEncodingError> {
        // This constructor uses the encoding defined in `ALPH_ENCODING`.
        ALPH_ENCODING
            .into_iter()
            .find_map(|(x, y)| if x == ltr { Some(RingElement(y)) } else { None })
            .ok_or(RingElementEncodingError)
    }

    /// Convert from a ring element to a character.
    ///
    /// # Panics
    /// This method will never panic unless the library developer has made an error.
    /// For example,
    /// if the library developer does not use a constructor to create a ring element and creates an invalid element such as `RingElement(26)` when representing the Latin Alphabet.
    fn to_char(self) -> char {
        ALPH_ENCODING
            .into_iter()
            .find_map(|(x, y)| if y == self.0 { Some(x) } else { None })
            .expect(
                "Could not map to `char`: The definition of `ALPH_ENCODING` must have an error or there is an invalid `RingElement`.",
            )
    }

    /// Convert from an `i8` to a ring element.
    ///
    /// This function will compute the canonical form of the inner value, i.e.,
    /// it will compute and use the least nonnegative remainder modulo `MODULUS`.
    /// This is meant to reduce the likelihood of future library developers
    /// constructing and using values of ring elements
    /// for which the unchecked routines [`add`](RingElement::add) and [`sub`](RingElement::sub) will fail.
    fn from_i8(int: i8) -> Self {
        Self(int.rem_euclid(MODULUS))
    }

    /// Get the inner value of the ring element.
    fn into_inner(self) -> i8 {
        self.0
    }

    /// Generate a ring element uniformly at random.
    ///
    /// Implementation notes:
    /// 1. This is easy here because we used `i8` as the underlying type for `RingElement`
    /// and choosing uniformly from a range is already implemented for `i8` in `rand`.
    /// But note that in general you must be careful,
    /// e.g., if you pick a `u8` from the uniform distribution
    /// and then reduce mod 26, you will pick each of {24, 25} with probability
    /// 4/128 and all other elements with probability 5/128
    /// 2. `CryptoRng` is a marker trait to indicate generators suitable for crypto,
    /// but user beware.
    fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let elmt: i8 = rng.gen_range(0..MODULUS);
        Self(elmt)
    }
}

impl Default for RingElement {
    fn default() -> Self {
        RingElement::zero()
    }
}

impl Add for RingElement {
    type Output = Self;

    /// Computes the sum of `self` and `other`.
    ///
    /// Library devs: This operation is unchecked!
    fn add(self, other: Self) -> Self {
        Self(if (self.0 + other.0) >= MODULUS  {
            self.0 + other.0 - MODULUS 
        } else {
            self.0 + other.0
        })
    }
}

impl Sub for RingElement {
    type Output = Self;

    /// Computes the difference of `self` and `other`.
    ///
    /// Library devs: This operation is unchecked!
    fn sub(self, other: Self) -> Self {
        Self(if (self.0 - other.0) < 0 {
            self.0 - other.0 + MODULUS 
        } else {
            self.0 - other.0
        })
    }
}

impl fmt::Display for RingElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A plaintext of arbitrary length.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Message(Vec<RingElement>);

/// A ciphertext of arbitrary length.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct CipherText(Vec<RingElement>);

/// A cryptographic key.
///
// Crypto TODO: Keys should always contain context.
// We *could* implement `Copy` and `Clone` here.
// We do not because we want to discourage making copies of secrets.
// However there is a lot more to best practices for handling keys than this.
#[derive(Debug, Eq, PartialEq)]
pub struct Key(RingElement);

impl Message {
    /// Create a new message from a string.
    /// # Examples
    /// ```
    /// // Creating this example shows how awkward our API is.
    /// // We can't use spaces, punctuation, or capital letters.
    /// // That said, humans are very quick at understanding mashed up plaintexts
    /// // without punctuation and spacing.
    /// // Computers have to check dictionaries.
    /// # use fiddler::{CipherText, Key, Message};
    /// # use rand::thread_rng;
    /// let msg = Message::new("thisisanawkwardapichoice").expect("This example is hardcoded; it should work!");
    ///
    /// // We can also print our message as a string:
    /// println!("Our message is {msg}");
    /// ```
    pub fn new(str: &str) -> Result<Message, EncodingError> {
        Message::from_str(str)
    }

    /// Encrypt a message.
    ///
    /// # Examples
    /// ```
    /// # use fiddler::{CipherText, Key, Message};
    /// # use rand::thread_rng;
    /// # let mut rng = thread_rng();
    /// # let key = Key::new(&mut rng);
    /// # let msg = Message::new("thisisanawkwardapichoice").expect("This example is hardcoded; it should work!");
    /// let ciphertxt = Message::encrypt(&msg, &key);
    /// ```
    ///
    pub fn encrypt(&self, key: &Key) -> CipherText {
        self.0.iter().map(|&i| i + key.0).collect()
    }
}

impl CipherText {
    /// Decrypt a ciphertext with a given key.
    ///
    /// # Examples
    /// ```
    /// # use fiddler::{CipherText, Key, Message};
    /// # use rand::thread_rng;
    /// #
    /// # let mut rng = thread_rng();
    /// # let key = Key::new(&mut rng);
    /// # let msg = Message::new("thisisanawkwardapichoice").expect("This example is hardcoded; it should work!");
    /// # let ciphertxt = Message::encrypt(&msg, &key);
    /// let decrypted = CipherText::decrypt(&ciphertxt, &key);
    ///
    /// println!(
    ///    "If we decrypt using the correct key, we get our original
    /// message back: {}", decrypted);
    ///
    /// let wrong_key = Key::new(&mut rng);
    /// if key != wrong_key {
    /// println!("If we decrypt using an incorrect key, we do not get
    ///  our original message back: {}",
    /// CipherText::decrypt(&ciphertxt, &wrong_key));
    /// }
    /// ```
    ///
    /// ```
    /// # use fiddler::{CipherText, Key, Message};
    /// # use rand::thread_rng;
    /// #
    /// # let mut rng = thread_rng();
    /// # let key = Key::new(&mut rng);
    /// #
    /// // With some non-negligible frequency, you won't get nonsense on
    /// // decryption with the wrong key, but the possible message space
    /// // is restricted beyond just the length of the message itself.
    /// // This is because shift ciphers preserve other message patterns,
    /// // too. Note that if the message is very short and you only have
    /// // one sample, one ciphertext may not be enough to definitively
    /// // break the system with a brute force attack. But likely there
    /// // is other context available to validate possible plaintexts.
    /// let small_msg = Message::new("dad").expect("This example is hardcoded; it should work!");
    /// let small_ciphertext = Message::encrypt(&small_msg, &key);
    /// // This will also decrypt the message properly with probability 1/26
    /// // which is of course a huge probability of success.
    /// let small_decryption = CipherText::decrypt(&small_ciphertext,
    ///  &Key::new(&mut rng));
    ///
    /// println!("Here is a small example, where we can more
    /// easily see the preservation of patterns:
    /// \n plaintext is {}, ciphertext is {},
    ///  and decryption under a random key gives {}",
    /// small_msg, small_ciphertext,
    /// small_decryption)
    /// ```
    ///
    pub fn decrypt(&self, key: &Key) -> Message {
        self.0.iter().map(|&i| i - key.0).collect()
    }
}

/// An error type that indicates a failure to parse a string.
///
/// This is likely because the string violates one of the constraints
/// for the desired value type. That is:
///
/// - For [`Message`]: The string included
/// one or more characters that are not lowercase letters from the Latin Alphabet.
/// - For [`CipherText`]: The string included
/// one or more characters that are not letters from the Latin Alphabet. We allow for strings containing both capitalized and lowercase letters when parsing as string as a ciphertext.
/// - For [`Key`]: The string does not represent a number in the appropriate range.
/// For the Latin Alphabet, this range is 0 to 25, inclusive.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct EncodingError;

/// Parse a message from a string.
///
/// # Errors
/// This trait implementation returns an error when parsing a string that contains an invalid character, i.e., if there is some `char` that is not from the lowercase Latin Alphabet.
impl FromStr for Message {
    type Err = EncodingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.chars()
            .map(|i| RingElement::from_char(i).or(Err(EncodingError)))
            .collect()
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let txt: String = self.0.iter().map(|i| i.to_char()).collect();

        write!(f, "{txt}")
    }
}
// Question: Can I do something generic here that covers both Message and  Ciphertext?
impl FromIterator<RingElement> for Message {
    fn from_iter<I: IntoIterator<Item = RingElement>>(iter: I) -> Self {
        let mut c = Vec::new();

        for i in iter {
            c.push(i);
        }

        Message(c)
    }
}

/// Parse a ciphertext from a string.
///
/// # Errors
/// This trait implementation returns an error when parsing a string that contains an invalid character, i.e., if there is some `char` that is not from the Latin Alphabet. Although the library generally follows the convention that ciphertexts are represented as ALL CAPS strings, this implementation ignores case, so parsing a string that includes lowercase letters may succeed.
impl FromStr for CipherText {
    type Err = EncodingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_lowercase()
            .chars()
            .map(|i| RingElement::from_char(i).or(Err(EncodingError)))
            .collect()
    }
}

impl fmt::Display for CipherText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let txt: String = self.0.iter().map(|i| RingElement::to_char(*i)).collect();

        write!(f, "{ }", txt.to_uppercase()) // Following Stinson's convention, ciphertexts are ALL CAPS
    }
}

impl FromIterator<RingElement> for CipherText {
    fn from_iter<I: IntoIterator<Item = RingElement>>(iter: I) -> Self {
        let mut c = Vec::new();

        for i in iter {
            c.push(i);
        }

        CipherText(c)
    }
}

/// Parse a key from a string.
///
/// # Errors
/// This implementation will produce an error if the input string does not represent an integer in the key space, i.e., an integer between 0 and 25, inclusive. While it would be a simple matter to accept _any_ integer as input and map to the ring of integers, we chose not to do so for clarity of use.
impl FromStr for Key {
    type Err = EncodingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = match i8::from_str(s) {
            Ok(num) => num,
            Err(_) => return Err(EncodingError),
        };

        match key {
            x if (0..=25).contains(&x) => Ok(Key::from(RingElement::from_i8(key))),
            _ => Err(EncodingError),
        }
    }
}

impl Key {
    /// Generate a cryptographic key uniformly at random from the key space.
    ///
    /// Note that the mathematical description of the Latin Shift Cipher, as well as this implementation,
    /// does not disallow a key of 0, so sometimes the encryption algorithm is just the identity function.
    ///
    /// This is, after all, a cryptosystem designed for use by humans and not computers. Humans are not
    ///  as good at computers at picking a value mod 26 uniformly at random, but we tend not to pick a key of 0
    /// and send our private messages to their recipients in plaintext. Oh wait ...  
    /// we do this all the time, in the form of emails.
    ///
    /// # Examples
    /// ```
    /// # use fiddler::{CipherText, Key, Message};
    /// // Don't forget to include the `rand` crate!
    /// use rand::thread_rng;
    /// //
    /// // Initialize a cryptographic rng.
    /// let mut rng = thread_rng();
    /// //
    /// // Generate a key
    /// let key = Key::new(&mut rng);
    /// ```
    ///
    // Note: Keys must always be chosen according to a uniform distribution on the
    // underlying key space, i.e., the ring Z/26Z for the Latin Alphabet cipher.
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self(RingElement::new(rng))
    }

    /// Export the key
    ///
    /// # Examples
    /// ```
    /// # use fiddler::{CipherText, Key, Message};
    /// # // Don't forget to include the `rand` crate!
    /// # use rand::thread_rng;
    /// # //
    /// # // Initialize a cryptographic rng.
    /// # let mut rng = thread_rng();
    /// # //
    /// # // Generate a key
    /// # let key = Key::new(&mut rng);
    /// //
    /// // We can export a key for external storage or other uses.
    /// // This method does not do anything special for secure key
    /// // handling, which is another, more complicated
    /// // and error-prone topic.
    /// // Use caution.
    /// println!("Here is our key value: {}", key.insecure_export());
    /// ```
    pub fn insecure_export(&self) -> String {
        self.0.into_inner().to_string()
    }
}

impl From<RingElement> for Key {
    fn from(item: RingElement) -> Self {
        Key(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    // Create a test seed for reproducible tests.
    // Notes:
    // 1. This sets us up to make tests (with randomness) that are reproducible.
    // 2. We use `ChaCha12Rng` directly here, in order to not rely on `StdRng`, since
    // the documentation of the latter warns that `StdRng` is not guaranteed to be
    // reproducible, i.e., they might change the underlying algorithm, and why not
    // just show this concretely in order to remember for codebases where this actually
    // matters.
    pub const TEST_SEED: [u8; 32] = *b"MY DISTRIBUTION IS NOT UNIFORM!!";
    pub fn reprod_rng() -> impl Rng {
        ChaCha12Rng::from_seed(TEST_SEED)
    }

    // Data for our running example/test.
    // Note: This is an attempt at global constants for the tests. If it would be better to use std::cell::OnceCell, I'm not sure
    // I understand how to do that properly.
    // Encoded "wewillmeetatmidnight" message from Example 1.1, Stinson 3rd Edition, Example 2.1 Stinson 4th Edition
    thread_local! (static MSG0: Message = Message(vec![RingElement(22), RingElement(4), 
            RingElement(22), RingElement(8), RingElement(11), RingElement(11),
            RingElement(12), RingElement(4), RingElement(4), RingElement(19),
            RingElement(0), RingElement(19),
            RingElement(12), RingElement(8), RingElement(3), RingElement(13), RingElement(8), RingElement(6), RingElement(7), RingElement(19)]));

    // Encrypted "wewillmeetatmidnight" message with key=11, from Example 1.1, Stinson 3rd Edition, Example 2.1 Stinson 4th Edition
    thread_local! (static CIPH0: CipherText = CipherText(vec![RingElement(7), RingElement(15), 
            RingElement(7), RingElement(19), RingElement(22), RingElement(22),
            RingElement(23), RingElement(15), RingElement(15), RingElement(4),
            RingElement(11), RingElement(4),
            RingElement(23), RingElement(19), RingElement(14), RingElement(24), RingElement(19), RingElement(17), RingElement(18), RingElement(4)]));

    // Encrypted "wewillmeetatmidnight" as a string, from Example 1.1 Stinson 3rd Edition, Example 2.1 Stinson 4th Edition
    thread_local!(static CIPH0_STR: String = "HPHTWWXPPELEXTOYTRSE".to_string());

    #[test]
    fn ring_elmnt_default() {
        assert_eq!(RingElement::default(), RingElement(0));
    }

    #[test]
    fn ring_elmnt_into_inner() {
        let x = RingElement(5);
        assert_eq!(x.into_inner(), 5)
    }
    #[test]
    fn ring_elmt_display() {
        // Test Display impl
        let x = RingElement(3);
        assert_eq!(
            format!("The ring element value is {x}"),
            "The ring element value is 3"
        );
    }

    #[test]
    fn ring_elmt_encoding_basics() {
        assert_eq!(RingElement::from_char('g').unwrap().0, 6); // Sanity check `from_char`
        assert_eq!(RingElement::from_char('w').unwrap().0, 22); // Sanity check `from_char`
        assert_eq!(RingElement(5).to_char(), 'f'); // Sanity check `to_char`
        assert_eq!(RingElement(0).to_char(), 'a') // Sanity check to `to_char`
    }

    #[test]
    fn ring_elmt_arithmetic() {
        assert_eq!(RingElement(5) + RingElement(11), RingElement(16)); // Basic addition test
        assert_eq!(RingElement(22) + RingElement(11), RingElement(7)); // Addition test with overflow
        assert_eq!(RingElement(20) + RingElement(6), RingElement(0)); // Addition boundary check

        assert_eq!(RingElement(11) - RingElement(3), RingElement(8)); // Basic subtraction test
        assert_eq!(RingElement(4) - RingElement(11), RingElement(19)); // Subtraction test with overflow
        assert_eq!(RingElement(15) - RingElement(15), RingElement(0)); // Subtraction boundary check
    }

    #[test]
    fn ring_elmt_from_i8() {
        // `from_i8` works as expected
        assert_eq!(RingElement::from_i8(37), RingElement(11));
        assert_eq!(RingElement::from_i8(-28), RingElement(24));
        assert_eq!(RingElement::from_i8(26), RingElement(0));
        assert_eq!(RingElement::from_i8(-3), RingElement(23));
        assert_eq!(RingElement::from_i8(5), RingElement(5));
    }

    #[test]
    fn ring_elmt_encoding_error() {
        assert_eq!(RingElement::from_char('_'), Err(RingElementEncodingError));
        assert_eq!(RingElement::from_char('A'), Err(RingElementEncodingError));
    }

    #[test]
    #[should_panic(
        expected = "Could not map to `char`: The definition of `ALPH_ENCODING` must have an error or there is an invalid `RingElement`."
    )]
    fn ring_elmt_encoding_panic() {
        let _fail = RingElement(26).to_char();
    }

    #[test]
    fn msg_default() {
        assert_eq!(Message::default(), Message(vec![]))
    }
    #[test]
    // Example 1.1, Stinson 3rd Edition, Example 2.1 Stinson 4th Edition
    fn msg_encoding_basic() {
        assert_eq!(
            Message::new("wewillmeetatmidnight").unwrap(),
            MSG0.with(|msg| msg.clone())
        ); // Message maps to ring correctly using `new`

        assert_eq!(
            Message::from_str("wewillmeetatmidnight").unwrap(),
            MSG0.with(|msg| msg.clone())
        ); // Message maps from string correctly using `from_str`

        assert_eq!(
            MSG0.with(|msg| msg.clone()).to_string(),
            "wewillmeetatmidnight"
        ); // Message maps to string correctly
    }

    #[test]
    // Malformed message errors.
    fn msg_encoding_error() {
        assert_eq!(Message::new("we will meet at midnight"), Err(EncodingError))
    }

    #[test]
    fn msg_display() {
        assert_eq!(
            format!("{}", Message::new("wewillmeetatmidnight").unwrap()),
            "wewillmeetatmidnight"
        )
    }

    #[test]
    fn ciphertxt_default() {
        assert_eq!(CipherText::default(), CipherText(vec![]));
    }

    #[test]
    fn ciphertxt_encoding_basic() {
        let ciphertxt = CipherText::from_str("HPHTWWXPPELEXTOYTRSE").unwrap();

        assert_eq!(ciphertxt, CIPH0.with(|ciph| ciph.clone())); // Ciphertext maps from string correctly
        assert_eq!(ciphertxt.to_string(), CIPH0_STR.with(|ciph| ciph.clone())); // Ciphertext maps to string correctly
    }

    #[test]
    fn ciphertxt_display() {
        assert_eq!(
            format!("{}", CipherText::from_str("HPHTWWXPPELEXTOYTRSE").unwrap()),
            "HPHTWWXPPELEXTOYTRSE"
        )
    }

    #[test]
    fn ciphertxt_encoding_error() {
        assert_eq!(CipherText::from_str("a;k"), Err(EncodingError))
    }

    // Example 1.1, Stinson 3rd Edition, Example 2.1 Stinson 4th Edition.
    #[test]
    fn enc_dec_basic() {
        let key0 = Key(RingElement(11));

        let ciph0 = Message::encrypt(&Message::new("wewillmeetatmidnight").unwrap(), &key0);

        assert_eq!(ciph0, CIPH0.with(|ciph| ciph.clone())); // Ciphertext is correct
        assert_eq!(
            CipherText::decrypt(&ciph0, &key0),
            MSG0.with(|msg| msg.clone()) // Ciphertext decrypts correctly
        )
    }

    // Tests with randomly generated keys.
    #[test]
    fn enc_dec_random_keys() {
        let mut rng = rand::thread_rng();

        let key1 = Key::new(&mut rng);
        let key2 = Key::new(&mut rng);

        let msg1 = Message::new("thisisatest").unwrap();
        let msg2 = Message::new("thisisanothertest").unwrap();

        // If you encrypt, then decrypt with the same key used during encryption, you get the same message
        // back.
        assert_eq!(
            CipherText::decrypt(&Message::encrypt(&msg1, &key1), &key1),
            msg1
        );

        // If you encrypt, then try to decrypt with a different key than the one used during encryption,
        // you should not get the same one back. (Note this test won't run if the keys collide, which
        // they will with probability 1/26, i.e., the keyspace for the Latin Shift Cipher system is
        // *tiny*.
        if key1 != key2 {
            assert_ne!(
                CipherText::decrypt(&Message::encrypt(&msg2, &key1), &key2),
                msg2
            )
        }
    }

    // Tests with reproducible randomness
    #[test]
    fn enc_dec_reprod_rand() {
        let mut rng = reprod_rng();

        let key1 = Key(RingElement(rng.gen_range(0..MODULUS )));
        let key2 = Key(RingElement(rng.gen_range(0..MODULUS )));

        let msg1 = Message::new("thisisyetanothertestmessage").unwrap();

        // This test is OK as long you check that it passes once
        assert_ne!(key1, key2);

        // Encrypted message always decrypts correctly
        assert_eq!(
            CipherText::decrypt(&Message::encrypt(&msg1, &key1), &key1),
            msg1
        );
        // Encrypted message won't decrypt correctly without the correct key
        // This test is OK because a manual check has been done to ensure the keys are different.
        assert_ne!(
            CipherText::decrypt(&Message::encrypt(&msg1, &key1), &key2),
            msg1
        )
    }
}
