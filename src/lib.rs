//! This repository is a playground for learning Rust.
//! It is not meant to be used for anything in practice.
//!
//#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(unused_qualifications, unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

//! Currently we implement the Shift Cipher using the Latin Alphabet.
//! This cipher uses an encoding of the Latin Alphabet in the ring &#x2124;/26&#x2124;, i.e.,
//! plaintext messages and ciphertexts are internally represented using elements from &#x2124;/26&#x2124;.
// (&#x2124; is Unicode for blackboard bold Z)

// TODOs:
// - Tests were lazily written and not comprehensive
// - Probably not following API guidelines
// - Data types were inefficiently chosen I think
// - I am not clear on visibility/scope
// - Use of randomness might have problems
// - Doesn't have any attacks implemented yet
// - Doesn't have an examples crate for a demo
// - Probably many other things
// - Doesn't handle inputs nicely, could e.g. handle white spaces in strings either here
// or in example
// What should be a unit test and what should be doc test?
// (De)Serialization?

use rand::{CryptoRng, Rng};
use std::ops::{Add, Sub};

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

// The modulus used to construct the ring Z/mZ, (i.e., m = MODULUS)
// Included in order to make generalizing to other alphabets easier later.
const MODULUS: usize = ALPH_ENCODING.len();

/// The ring Z/mZ where m = 26 for Latin Alphabet.
// TODO: Reconsider data types, work with bytes instead? Or bits via bitvec?
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct RingElement(i8);

impl RingElement {
    /// Convert from a `char` to a `RingElement`.
    pub fn from_char(ltr: char) -> Self {
        RingElement(
            ALPH_ENCODING
                .iter()
                .find(|&&x| x.0 == ltr)
                .expect("Character not from Latin Alphabet")
                .1,
        )
    }

    /// Convert from a [`RingElement`] to a `char`.
    pub fn as_char(&self) -> char {
        ALPH_ENCODING.iter().find(|&&x| x.1 == self.0).unwrap().0
    }

    /// The canonical form of a [`RingElement`], i.e., reduced by the modulus.
    // Note: So far... this isn't used anywhere.
    pub fn canonical(&self) -> Self {
        Self((self.0).rem_euclid(MODULUS as i8))
    }

    /// Pick a ring element uniformly at random.
    // Notes:
    // 1. This is easy here because we used i8 as the underlying type for RingElement
    // and choosing uniformly from a range is already implemented for i8 in rand.
    // But note that in general you must be careful,
    // e.g., if you pick a u8 from the uniform distribution
    // and then reduce mod 26, you will pick each of {24, 25} with probability
    // 4/128 and all other elements with probability 5/128
    // 2. `CryptoRng` is a marker trait to indicate generators suitable for crypto,
    // but user beware.
    pub fn gen<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let elmt: i8 = rng.gen_range(0..MODULUS as i8);
        Self(elmt)
    }
}

impl Add for RingElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self((self.0 + other.0).rem_euclid(MODULUS as i8))
    }
}

impl Sub for RingElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self((self.0 - other.0).rem_euclid(MODULUS as i8))
    }
}

/// A plaintext message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message(Vec<RingElement>);

/// A ciphertext.
#[derive(Clone, Debug, PartialEq)]
pub struct CipherText(Vec<RingElement>);

/// A cryptographic key.
// Crypto TODO: Keys should always contain context.
#[derive(Debug, Eq, PartialEq)]
pub struct Key(RingElement);

impl Message {
    /// Create a new [`Message`] from a [`String`].
    pub fn new(str: String) -> Message {
        let mut msg = Vec::new();
        for c in str.chars() {
            msg.push(RingElement::from_char(c));
        }
        Message(msg)
    }

    /// Convert a [`Message`] to a [`String`].
    pub fn as_string(&self) -> String {
        let mut txt = String::new();
        for i in self.0.iter() {
            txt.push(RingElement::as_char(i));
        }
        txt
    }

    /// Encrypt a [`Message`] with a [`Key`].
    pub fn encrypt(&self, key: &Key) -> CipherText {
        let mut ciph_txt: Vec<RingElement> = Vec::new();
        for i in self.0.iter() {
            ciph_txt.push(*i + key.0);
        }
        CipherText(ciph_txt)
    }
}

impl CipherText {
    /// Decrypt a [`CipherText`] with a [`Key`].
    pub fn decrypt(&self, key: &Key) -> Message {
        let mut msg: Vec<RingElement> = Vec::new();
        for i in self.0.iter() {
            msg.push(*i - key.0);
        }
        Message(msg)
    }

    /// Convert a [`CipherText`] to a [`String`] (of uppercase letters).
    pub fn as_string(&self) -> String {
        let mut txt: String = String::new();
        for i in self.0.iter() {
            txt.push(RingElement::as_char(i));
        }
        txt.to_uppercase()
    }
}

impl Key {
    /// Generate a [`Key`] uniformly at random from the Key Space.
    // Note: Keys must always be chosen according to a uniform distribution on the
    // underlying key space, i.e., the ring Z/26Z for the Latin Alphabet cipher.
    pub fn gen<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self(RingElement::gen(rng))
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
    fn encoding_0() {
        assert_eq!(RingElement::from_char('g').0, 6); // Sanity check on encoding
        assert_eq!(RingElement::from_char('w').0, 22); // Sanity check on encoding

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

        // Canonical works as expected
        assert_eq!(RingElement(37).canonical(), RingElement(11));
        assert_eq!(RingElement(-28).canonical(), RingElement(24));
        assert_eq!(RingElement(26).canonical(), RingElement(0));
        assert_eq!(RingElement(0), RingElement(26).canonical());
    }

    #[test]
    #[should_panic(expected = "Character not from Latin Alphabet")]
    fn encoding_1() {
        let _x = RingElement::from_char('_');
    }

    #[test]
    // Example 1.1, Stinson 3rd Edition, Example 2.1 Stinson 4th Edition
    fn msg_encoding_0() {
        assert_eq!(
            Message::new("wewillmeetatmidnight".to_string()),
            MSG0.with(|msg| msg.clone())
        ) // Message maps to ring correctly
    }

    // Example 1.1, Stinson 3rd Edition, Example 2.1 Stinson 4th Edition.
    #[test]
    fn enc_dec_0() {
        let key0 = Key(RingElement(11));

        let ciph0 = Message::encrypt(&Message::new("wewillmeetatmidnight".to_string()), &key0);

        assert_eq!(ciph0, CIPH0.with(|ciph| ciph.clone())); // Ciphertext maps to ring correctly
        assert_eq!(ciph0.as_string(), CIPH0_STR.with(|ciph| ciph.clone())); // Ciphertext maps to string correctly
        assert_eq!(
            CipherText::decrypt(&ciph0, &key0),
            MSG0.with(|msg| msg.clone()) // Ciphertext decrypts correctly
        )
    }

    // Tests with randomly generated keys.
    #[test]
    fn enc_dec_1() {
        let mut rng = rand::thread_rng();

        let key1 = Key::gen(&mut rng);
        let key2 = Key::gen(&mut rng);

        let msg1 = Message::new("thisisatest".to_string());
        let msg2 = Message::new("thisisanothertest".to_string());

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

        let msg1 = Message::new("thisisyetanothertestmessage".to_string());

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
