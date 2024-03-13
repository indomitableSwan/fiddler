//! This repository is a playground for learning Rust.
//! It is not meant to be used for anything in practice.

//#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(unused_qualifications, unused_results)]
#![warn(future_incompatible)]
#![warn(unused)]
#![forbid(rustdoc::broken_intra_doc_links)]

//! The Shift Cipher using the Latin Alphabet.
use rand::Rng;
use std::ops::{Add, Sub};

const LATIN_ENCODING: [(char, i8); 26] = [
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

const MODULUS: usize = LATIN_ENCODING.len();

// The ring Z/mZ where m = modulus, i.e. 26 for Latin Alphabet.
// TODO: Reconsider data types, work with bytes instead?
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct RingElement(i8);

// Should I have a getter?
impl RingElement {
    pub fn from_char(ltr: char) -> Self {
        RingElement(
            LATIN_ENCODING
                .iter()
                .find(|&&x| x.0 == ltr)
                .expect("Character not from Latin Alphabet")
                .1,
        )
    }

    pub fn as_char(&self) -> char {
        LATIN_ENCODING.iter().find(|&&x| x.1 == self.0).unwrap().0
    }

    // Not sure I need this
    pub fn canonical(&self) -> Self {
        Self((self.0).rem_euclid(MODULUS as i8))
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

#[derive(Clone, Debug, PartialEq)]
pub struct Message(Vec<RingElement>);

#[derive(Clone, Debug, PartialEq)]
pub struct CipherText(Vec<RingElement>);

// TODO: Keys should always contain context
#[derive(Debug, PartialEq)]
pub struct Key(RingElement);

// TODO: Handle whitespaces in inputs
impl Message {
    pub fn new(str: String) -> Message {
        let mut msg = Vec::new();
        for c in str.chars() {
            msg.push(RingElement::from_char(c));
        }
        Message(msg)
    }

    pub fn as_string(&self) -> String {
        let mut txt = String::new();
        for i in self.0.iter() {
            txt.push(RingElement::as_char(i));
        }
        txt
    }

    pub fn encrypt(&self, key: &Key) -> CipherText {
        let mut ciph_txt: Vec<RingElement> = Vec::new();
        for i in self.0.iter() {
            ciph_txt.push(*i + key.0);
        }
        CipherText(ciph_txt)
    }
}

impl CipherText {
    pub fn decrypt(&self, key: &Key) -> Message {
        let mut msg: Vec<RingElement> = Vec::new();
        for i in self.0.iter() {
            msg.push(*i - key.0);
        }
        Message(msg)
    }

    pub fn as_string(&self) -> String {
        let mut txt: String = String::new();
        for i in self.0.iter() {
            txt.push(RingElement::as_char(i));
        }
        txt.to_uppercase()
    }
}

impl Key {
    pub fn gen() -> Self {
        let mut rng = rand::thread_rng();
        let key_material: i8 = rng.gen_range(0..MODULUS as i8);
        Self(RingElement(key_material))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    pub const TEST_SEED: [u8; 32] = *b"MY DISTRIBUTION IS NOT UNIFORM!!";
    pub fn rng() -> impl Rng {
        rand::rngs::StdRng::from_seed(TEST_SEED)
    }

    // Encoded "wewillmeetatmidnight" message from Example 1.1, Stinson 3rd Edition, Example 2.1 Stinson 4th Edition
    thread_local! (static MSG0: Message = 
        Message(vec![RingElement(22), RingElement(4), 
            RingElement(22), RingElement(8), RingElement(11), RingElement(11),
            RingElement(12), RingElement(4), RingElement(4), RingElement(19),
            RingElement(0), RingElement(19),
            RingElement(12), RingElement(8), RingElement(3), RingElement(13), RingElement(8), RingElement(6), RingElement(7), RingElement(19)]));

    // Encrypted "wewillmeetatmidnight" message with key=11, from Example 1.1, Stinson 3rd Edition, Example 2.1 Stinson 4th Edition
    thread_local! (static CIPH0: CipherText = 
        CipherText(vec![RingElement(7), RingElement(15), 
            RingElement(7), RingElement(19), RingElement(22), RingElement(22),
            RingElement(23), RingElement(15), RingElement(15), RingElement(4),
            RingElement(11), RingElement(4),
            RingElement(23), RingElement(19), RingElement(14), RingElement(24), RingElement(19), RingElement(17), RingElement(18), RingElement(4)]));

    // Encrypted "wewillmeetatmidnight" as a string, from Example 1.1 Stinson 3rd Edition, Example 2.1 Stinson 4th Edition
    thread_local!(static CIPH0_STR: String = "HPHTWWXPPELEXTOYTRSE".to_string());

    #[test]
    fn encoding_0() {
        assert_eq!(RingElement::from_char('g').0, 6);
        assert_eq!(RingElement::from_char('w').0, 22);
        assert_eq!(RingElement(22) + RingElement(11), RingElement(7));
        assert_eq!(RingElement(48) + RingElement(11), RingElement(7));
        assert_eq!(RingElement(4) - RingElement(11), RingElement(19));
        assert_eq!(RingElement(4) - RingElement(37), RingElement(19));
        assert_eq!(RingElement(37).canonical(), RingElement(11));
        assert_eq!(RingElement(0), RingElement(26).canonical())
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

    // Example 1.1, Stinson 3rd Edition, Example 2.1 Stinson 4th Edition
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

    // Tests with randomly generated keys
    #[test]
    fn enc_dec_1() {
        let key1 = Key::gen();
        let key2 = Key::gen();

        println!("{:?}", key1.0);
        println!("{:?}", key2.0);

        let msg1 = Message::new("thisisatest".to_string());
        let msg2 = Message::new("thisisanothertest".to_string());

        // This is a bad test because the key space is so small
        // ie this will fail with probability 1/26
        // TODO: Showing this type of thing experimentally would be nice to know how to do
        assert_ne!(key1, key2);
        assert_eq!(
            CipherText::decrypt(&Message::encrypt(&msg1, &key1), &key1),
            msg1
        );
        assert_ne!(
            CipherText::decrypt(&Message::encrypt(&msg2, &key1), &key2),
            msg2
        )
    }

    // Tests with reproducible randomness
    #[test]
    fn enc_dec_2() {
        let mut rng = rng();

        let key1 = Key(RingElement(rng.gen_range(0..MODULUS as i8)));
        println!("{:?}", key1.0);

        let key2 = Key(RingElement(rng.gen_range(0..MODULUS as i8)));
        println!("{:?}", key2.0);

        let msg1 = Message::new("thisisyetanothertestmessage".to_string());

        // This test is OK as long you check that it passes once
        assert_ne!(key1, key2);
        // Encrypted message always decrypts correctly
        assert_eq!(
            CipherText::decrypt(&Message::encrypt(&msg1, &key1), &key1),
            msg1
        );
        // Encrypted message won't decrypt correctly without the correct key
        assert_ne!(
            CipherText::decrypt(&Message::encrypt(&msg1, &key1), &key2),
            msg1
        )
    }
}
