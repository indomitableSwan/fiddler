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
const MODULUS: usize = ALPH_ENCODING.len();

/// An implementation of the ring &#x2124;/_m_&#x2124;, where _m_ is set to [`MODULUS`].
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
struct RingElement(i8);

/// A custom error type that is thrown when a conversion between the Latin Alphabet and
/// the ring of integers modulo `MODULO`.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct RingElementEncodingError;

impl RingElement {
    /// Convert from a `char` to a `RingElement`.
    fn from_char(ltr: char) -> Result<Self, RingElementEncodingError> {
        ALPH_ENCODING
            .iter()
            .find(|&&x| x.0 == ltr)
            .map(|(_, y)| RingElement(*y))
            .ok_or(RingElementEncodingError)
    }

    /// Convert from a `RingElement` to a `char`.
    // Should never get `None` here unless `ALPH_ENCODING` has an error.
    fn to_char(self) -> Option<char> {
        ALPH_ENCODING.iter().find(|&&x| x.1 == self.0).map(|c| c.0)
    }
    /*
    /// The canonical form of a ring element, i.e., reduced by [`MODULUS`].
    // Note: So far... this isn't used anywhere.
    fn canonical(&self) -> Self {
        Self((self.0).rem_euclid(MODULUS as i8))
    }
    */

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
        let elmt: i8 = rng.gen_range(0..MODULUS as i8);
        Self(elmt)
    }
}

impl Add for RingElement {
    type Output = Self;

    /// Computes the sum of `self` and `other`.
    fn add(self, other: Self) -> Self {
        Self((self.0 + other.0).rem_euclid(MODULUS as i8))
    }
}

impl Sub for RingElement {
    type Output = Self;

    /// Computes the difference of `self` and `other`.
    fn sub(self, other: Self) -> Self {
        Self((self.0 - other.0).rem_euclid(MODULUS as i8))
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
    /// let msg = Message::new("thisisanawkwardapichoice");
    ///
    /// // We can also print our message as a string:
    /// println!("Our message is {msg}");
    /// ```
    pub fn new(str: &str) -> Message {
        Message::from_str(str).expect("Message parsing error")
    }

    /// Encrypt a message.
    ///
    /// # Examples
    /// ```
    /// # use fiddler::{CipherText, Key, Message};
    /// # use rand::thread_rng;
    /// # let mut rng = thread_rng();
    /// # let key = Key::new(&mut rng);
    /// # let msg = Message::new("thisisanawkwardapichoice");
    /// let ciphertxt = Message::encrypt(&msg, &key);
    /// ```
    ///
    pub fn encrypt(&self, key: &Key) -> CipherText {
        let mut ciph_txt: Vec<RingElement> = Vec::new();
        for i in self.0.iter() {
            ciph_txt.push(*i + key.0);
        }
        CipherText(ciph_txt)
    }
}

impl CipherText {
    /// Decrypt a ciphertext with a given key.
    ///
    /// # Examples
    /// ```
    /// # use fiddler::{CipherText, Key, Message};
    /// # use rand::thread_rng;
    /// # let mut rng = thread_rng();
    /// # let key = Key::new(&mut rng);
    /// # let msg = Message::new("thisisanawkwardapichoice");
    /// # let ciphertxt = Message::encrypt(&msg, &key);
    /// let decrypted = CipherText::decrypt(&ciphertxt, &key);
    ///
    /// println!(
    ///    "If we decrypt using the correct key, we get our original
    /// message back: {}", decrypted);
    ///
    /// println!("If we decrypt using an incorrect key, we do not get
    ///  our original message back: {}",
    /// CipherText::decrypt(&ciphertxt, &Key::new(&mut rng)));
    ///
    /// // With some non-negligible frequency, you won't get nonsense on
    /// // decryption with the wrong key, but the possible message space
    /// // is restricted beyond just the length of the message itself.
    /// // This is because shift ciphers preserve other message patterns,
    /// // too. Note that if the message is very short and you only have
    /// // one sample, one ciphertext may not be enough to definitively
    /// // break the system with a brute force attack. But likely there
    /// // is other context available to validate possible plaintexts.
    /// let small_msg = Message::new("dad");
    /// let small_ciphertext = Message::encrypt(&small_msg, &key);
    /// let small_decryption = CipherText::decrypt(&small_ciphertext,
    ///  &Key::new(&mut rng));
    ///
    /// println!("The API makes it hard to make this example work the way
    /// I want consistently, but here is a small example, where we can more
    /// easily see the preservation of patterns:
    /// \n plaintext is {}, ciphertext is {},
    ///  and decryption under a random key gives {}",
    /// small_msg, small_ciphertext,
    /// small_decryption)
    /// ```
    ///
    pub fn decrypt(&self, key: &Key) -> Message {
        let mut msg: Vec<RingElement> = Vec::new();
        for i in self.0.iter() {
            msg.push(*i - key.0);
        }
        Message(msg)
    }
}

/// TODO: Probably doing something wrong with error handling.
impl FromStr for Message {
    type Err = RingElementEncodingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut msg = Vec::new();
        for c in s.chars() {
            msg.push(RingElement::from_char(c)?);
        }
        Ok(Message(msg))
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut txt = String::new();
        for i in self.0.iter() {
            txt.push(match RingElement::to_char(*i) {
                Some(c) => c,
                None => return Err(fmt::Error),
            });
        }
        write!(f, "{txt}")
    }
}

/// TODO: Probably doing something wrong with error handling
impl FromStr for CipherText {
    type Err = RingElementEncodingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ciphertxt = Vec::new();

        let temp = s.to_lowercase();

        for c in temp.chars() {
            ciphertxt.push(RingElement::from_char(c)?);
        }
        Ok(CipherText(ciphertxt))
    }
}

impl fmt::Display for CipherText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut txt: String = String::new();
        for i in self.0.iter() {
            txt.push(match RingElement::to_char(*i) {
                Some(c) => c,
                None => return Err(fmt::Error), // Should never happen
            });
        }
        write!(f, "{ }", txt.to_uppercase()) // Following Stinson's convention, ciphertexts are ALL CAPS
    }
}

impl FromStr for Key {
    type Err = RingElementEncodingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = match i8::from_str(s) {
            Ok(num) => num,
            Err(_) => return Err(RingElementEncodingError),
        };

        match key {
            x if (0..=25).contains(&x) => Ok(Key::from(key)),
            _ => Err(RingElementEncodingError),
        }
    }
}

impl Key {
    /// Returns the value of `Key` as an `i8`.
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
    /// # //
    /// // We can print a key, or print it to a log if we wanted to.
    /// // We shouldn't. Key handling is another, more complicated
    /// // and error-prone topic. Here we print the value of the key
    /// // as an `i8`:
    /// println!("Here is our key value: {}", key.into_i8());
    /// ```
    pub fn into_i8(&self) -> i8 {
        self.0 .0
    }
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
    /// //
    /// // We can print a key, or print it to a log if we wanted to.
    /// // We shouldn't. Key handling is another, more complicated
    /// // and error-prone topic.
    /// println!("Here is our key value: {:?}", key);
    /// ```
    ///
    // Note: Keys must always be chosen according to a uniform distribution on the
    // underlying key space, i.e., the ring Z/26Z for the Latin Alphabet cipher.
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self(RingElement::new(rng))
    }
}

impl From<i8> for Key {
    fn from(item: i8) -> Self {
        Key(RingElement(item))
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
    fn ring_elmt_tests() {
        // Test Display impl
        let x = RingElement(3);
        assert_eq!(
            format!("The ring element value is {x}"),
            "The ring element value is 3"
        );
    }

    #[test]
    fn encoding_0() {
        assert_eq!(RingElement::from_char('g').unwrap().0, 6); // Sanity check on encoding
        assert_eq!(RingElement::from_char('w').unwrap().0, 22); // Sanity check on encoding

        assert_eq!(RingElement(5) + RingElement(11), RingElement(16)); // Basic addition test
        assert_eq!(RingElement(22) + RingElement(11), RingElement(7)); // Addition test with overflow
        assert_eq!(RingElement(48) + RingElement(11), RingElement(7)); // Addition test with non-canonical elements
        assert_eq!(RingElement(-3) + RingElement(11), RingElement(8)); // Addition test with non-canonical elements
        assert_eq!(RingElement(-3) + RingElement(27), RingElement(24)); // Addition test with non-canonical elements
        assert_eq!(RingElement(-3) + RingElement(-4), RingElement(19)); // Addition test with non-canonical elements

        assert_eq!(RingElement(11) - RingElement(3), RingElement(8)); // Basic subtraction test
        assert_eq!(RingElement(4) - RingElement(11), RingElement(19)); // Subtraction test with overflow
        assert_eq!(RingElement(4) - RingElement(37), RingElement(19)); // Subtraction test with non-canonical elements
        assert_eq!(RingElement(29) - RingElement(10), RingElement(19)); // Subtraction test with non-canonical elements
        assert_eq!(RingElement(30) - RingElement(-8), RingElement(12)); // Subtraction test with non-canonical elements

        /*
        // Canonical works as expected
        assert_eq!(RingElement(37).canonical(), RingElement(11));
        assert_eq!(RingElement(-28).canonical(), RingElement(24));
        assert_eq!(RingElement(26).canonical(), RingElement(0));
        assert_eq!(RingElement(0), RingElement(26).canonical());
        */
    }

    #[test]
    fn encoding_1() {
        assert_eq!(RingElement::from_char('_'), Err(RingElementEncodingError));
    }

    #[test]
    // Example 1.1, Stinson 3rd Edition, Example 2.1 Stinson 4th Edition
    fn msg_encoding_0() {
        assert_eq!(
            Message::new("wewillmeetatmidnight"),
            MSG0.with(|msg| msg.clone())
        ) // Message maps to ring correctly
    }

    // Example 1.1, Stinson 3rd Edition, Example 2.1 Stinson 4th Edition.
    #[test]
    fn enc_dec_0() {
        let key0 = Key(RingElement(11));

        let ciph0 = Message::encrypt(&Message::new("wewillmeetatmidnight"), &key0);

        assert_eq!(ciph0, CIPH0.with(|ciph| ciph.clone())); // Ciphertext maps to ring correctly
        assert_eq!(ciph0.to_string(), CIPH0_STR.with(|ciph| ciph.clone())); // Ciphertext maps to string correctly
        assert_eq!(
            CipherText::decrypt(&ciph0, &key0),
            MSG0.with(|msg| msg.clone()) // Ciphertext decrypts correctly
        )
    }

    // Tests with randomly generated keys.
    #[test]
    fn enc_dec_1() {
        let mut rng = rand::thread_rng();

        let key1 = Key::new(&mut rng);
        let key2 = Key::new(&mut rng);

        let msg1 = Message::new("thisisatest");
        let msg2 = Message::new("thisisanothertest");

        // This is a bad test because the key space is so small
        // ie this will fail with probability 1/26
        // TODO: Showing this type of thing experimentally would be nice to know how to do
        // Question: A separate sanity check tests that nothing totally broke on your rng might be better?
        assert_ne!(key1, key2);

        // If you encrypt, then decrypt with the same key used during encryption, you get the same message
        // back.
        assert_eq!(
            CipherText::decrypt(&Message::encrypt(&msg1, &key1), &key1),
            msg1
        );

        // If you encrypt, then try to decrypt with a different key than the one used during encryption,
        // you should not get the same one back. (Note this test would fail if the keys collide, which
        // they will with probability 1/26).
        // TODO: Construct the second key so that it is always different from the first instead.
        assert_ne!(
            CipherText::decrypt(&Message::encrypt(&msg2, &key1), &key2),
            msg2
        )
    }

    // Tests with reproducible randomness
    #[test]
    fn enc_dec_2() {
        let mut rng = reprod_rng();

        let key1 = Key(RingElement(rng.gen_range(0..MODULUS as i8)));
        let key2 = Key(RingElement(rng.gen_range(0..MODULUS as i8)));

        let msg1 = Message::new("thisisyetanothertestmessage");

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
