//! This is an implementation of the Latin Shift Cipher.
//! The plaintext and ciphertext space are the ring of integers modulo 26,
//! &#x2124;/26&#x2124;. As the name implies, ciphertexts are shifts (computed
//! using modular arithmetic) of the corresponding plaintexts, so the _key
//! space_ is &#x2124;/26&#x2124;. as well.
use crate::{Cipher, Ciphertext, EncodingError, Key, Message, Ring, RingElement};
use rand::{CryptoRng, Rng};
use std::str::FromStr;

/// The Latin Shift Cipher.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Shift;

// TODO: Should key be a trait too?
/// A cryptographic key.
// Crypto TODO: Keys should always contain context.
// We *could* implement `Copy` and `Clone` here.
// We do not because we want to discourage making copies of secrets.
// However there is a lot more to best practices for handling keys than this.
#[derive(Debug, Eq, PartialEq)]
pub struct ShiftKey(RingElement);

impl Cipher for Shift {
    type Message = Message;
    type Ciphertext = Ciphertext;
    type Key = ShiftKey;

    type EncryptionError = EncryptionError;
    type DecryptionError = DecryptionError;

    /// Encrypt a message.
    ///
    /// # Examples
    /// ```
    /// # use classical_crypto::{Cipher, Key, shift::Shift};
    /// # use rand::thread_rng;
    /// # let mut rng = thread_rng();
    /// # let key = Key::new(&mut rng);
    ///  let msg = <Shift as Cipher>::Message::new("thisisanawkwardapichoice").expect("This example is hardcoded; it should work!");
    /// let ciphertxt = Shift::encrypt(&msg, &key);
    /// ```
    fn encrypt(msg: &Self::Message, key: &Self::Key) -> Self::Ciphertext {
        msg.0.iter().map(|&i| i + key.0).collect()
    }

    // TODO! refactor, generalize
    /// Decrypt a ciphertext with a given key.
    ///
    /// # Examples
    /// ```
    /// # use classical_crypto::{Cipher, Key, shift::Shift};
    /// # use rand::thread_rng;
    /// #
    /// # let mut rng = thread_rng();
    /// # let key = Key::new(&mut rng);
    /// # let msg = <Shift as Cipher>::Message::new("thisisanawkwardapichoice").expect("This example is hardcoded; it should work!");
    /// # let ciphertxt = Shift::encrypt(&msg, &key);
    /// let decrypted = Shift::decrypt(&ciphertxt, &key);
    ///
    /// println!(
    ///    "If we decrypt using the correct key, we get our original
    /// message back: {}", decrypted);
    ///
    /// let wrong_key = Key::new(&mut rng);
    /// if key != wrong_key {
    /// println!("If we decrypt using an incorrect key, we do not get
    ///  our original message back: {}",
    /// Shift::decrypt(&ciphertxt, &wrong_key));
    /// }
    /// ```
    ///
    /// ```
    /// # use classical_crypto::{Cipher, Key, shift::Shift};
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
    /// let small_msg = <Shift as Cipher>::Message::new("dad").expect("This example is hardcoded; it should work!");
    /// let small_ciphertext = Shift::encrypt(&small_msg, &key);
    /// // This will also decrypt the message properly with probability 1/26
    /// // which is of course a huge probability of success.
    /// let small_decryption = Shift::decrypt(&small_ciphertext,
    ///  &Key::new(&mut rng));
    ///
    /// println!("Here is a small example, where we can more
    /// easily see the preservation of patterns:
    /// \n plaintext is {}, ciphertext is {},
    ///  and decryption under a random key gives {}",
    /// small_msg, small_ciphertext,
    /// small_decryption)
    /// ```
    fn decrypt(ciphertxt: &Self::Ciphertext, key: &Self::Key) -> Self::Message {
        ciphertxt.0.iter().map(|&i| i - key.0).collect()
    }
}

// TODO: refactor, prep for Substitution Cipher
impl Key for ShiftKey {
    /// Generate a cryptographic key uniformly at random from the key space.
    ///
    /// Note that the mathematical description of the Latin Shift Cipher, as
    /// well as this implementation, does not disallow a key of 0, so
    /// sometimes the encryption algorithm is just the identity function.
    ///
    /// This is, after all, a cryptosystem designed for use by humans and not
    /// computers. Humans are not as good as computers at picking a value
    /// mod 26 uniformly at random, but we tend not to pick a key of 0
    /// and send our private messages to their recipients in plaintext. Oh wait
    /// ... we do this all the time, in the form of emails.
    ///
    /// # Examples
    /// ```
    /// # use classical_crypto::{Cipher, Key, shift::Shift};
    /// // Don't forget to include the `rand` crate!
    /// use rand::thread_rng;
    /// //
    /// // Initialize a cryptographic rng.
    /// let mut rng = thread_rng();
    /// //
    /// // Generate a key
    /// let key = <Shift as Cipher>::Key::new(&mut rng);
    /// ```
    // Note: Keys must always be chosen according to a uniform distribution on the
    // underlying key space, i.e., the ring Z/26Z for the Latin Alphabet cipher.
    fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self(RingElement::random(rng))
    }
}

impl ShiftKey {
    /// Export the key
    ///
    /// # Examples
    /// ```
    /// # use classical_crypto::{Cipher, Key, shift::Shift};
    /// # // Don't forget to include the `rand` crate!
    /// # use rand::thread_rng;
    /// # //
    /// # // Initialize a cryptographic rng.
    /// # let mut rng = thread_rng();
    /// # //
    /// # // Generate a key
    /// # let key = <Shift as Cipher>::Key::new(&mut rng);
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

// TODO: refactor, prep for Substitution Cipher
/// Parse a key from a string.
///
/// # Errors
/// This implementation will produce an error if the input string does not
/// represent an integer in the key space, i.e., an integer between 0 and 25,
/// inclusive. While it would be a simple matter to accept _any_ integer as
/// input and map to the ring of integers, we chose not to do so for clarity of
/// use.
impl FromStr for ShiftKey {
    type Err = EncodingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = match i8::from_str(s) {
            Ok(num) => num,
            Err(_) => return Err(EncodingError),
        };

        match key {
            x if (0..=25).contains(&x) => Ok(ShiftKey::from(RingElement::from_i8(key))),
            _ => Err(EncodingError),
        }
    }
}

// TODO: refactor, prep for Substitution Cipher
impl From<RingElement> for ShiftKey {
    fn from(item: RingElement) -> Self {
        ShiftKey(item)
    }
}

// TODO: Not implemented yet
/// A custom error type that is returned from [`Shift::encrypt`].
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct EncryptionError;

// TODO: not implemented yet
/// A custom error type that is returned from [`Shift::decrypt`].
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct DecryptionError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RingElement;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    // Create a test seed for reproducible tests.
    // Notes:
    // 1. This sets us up to make tests (with randomness) that are reproducible.
    // 2. We use `ChaCha12Rng` directly here, in order to not rely on `StdRng`,
    //    since
    // the documentation of the latter warns that `StdRng` is not guaranteed to be
    // reproducible, i.e., they might change the underlying algorithm, and why not
    // just show this concretely in order to remember for codebases where this
    // actually matters.
    pub const TEST_SEED: [u8; 32] = *b"MY DISTRIBUTION IS NOT UNIFORM!!";
    pub fn reprod_rng() -> impl Rng {
        ChaCha12Rng::from_seed(TEST_SEED)
    }

    // Data for our running example/test.
    // Note: This is an attempt at global constants for the tests. If it would be
    // better to use std::cell::OnceCell, I'm not sure I understand how to do
    // that properly. Encoded "wewillmeetatmidnight" message from Example 1.1,
    // Stinson 3rd Edition, Example 2.1 Stinson 4th Edition
    thread_local! (static MSG0: Message = Message(vec![RingElement(22), RingElement(4),
            RingElement(22), RingElement(8), RingElement(11), RingElement(11),
            RingElement(12), RingElement(4), RingElement(4), RingElement(19),
            RingElement(0), RingElement(19),
            RingElement(12), RingElement(8), RingElement(3), RingElement(13), RingElement(8), RingElement(6), RingElement(7), RingElement(19)]));

    // Encrypted "wewillmeetatmidnight" message with key=11, from Example 1.1,
    // Stinson 3rd Edition, Example 2.1 Stinson 4th Edition
    thread_local! (static CIPH0: Ciphertext = Ciphertext(vec![RingElement(7), RingElement(15), 
            RingElement(7), RingElement(19), RingElement(22), RingElement(22),
            RingElement(23), RingElement(15), RingElement(15), RingElement(4),
            RingElement(11), RingElement(4),
            RingElement(23), RingElement(19), RingElement(14), RingElement(24), RingElement(19), RingElement(17), RingElement(18), RingElement(4)]));

    // Encrypted "wewillmeetatmidnight" as a string, from Example 1.1 Stinson 3rd
    // Edition, Example 2.1 Stinson 4th Edition
    thread_local!(static CIPH0_STR: String = "HPHTWWXPPELEXTOYTRSE".to_string());

    // Example 1.1, Stinson 3rd Edition, Example 2.1 Stinson 4th Edition.
    #[test]
    fn enc_dec_basic() {
        let key0 = ShiftKey(RingElement(11));

        let ciph0 = Shift::encrypt(&Message::new("wewillmeetatmidnight").unwrap(), &key0);

        assert_eq!(ciph0, CIPH0.with(|ciph| ciph.clone())); // Ciphertext is correct
        assert_eq!(
            Shift::decrypt(&ciph0, &key0),
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

        // If you encrypt, then decrypt with the same key used during encryption, you
        // get the same message back.
        assert_eq!(Shift::decrypt(&Shift::encrypt(&msg1, &key1), &key1), msg1);

        // If you encrypt, then try to decrypt with a different key than the one used
        // during encryption, you should not get the same one back. (Note this
        // test won't run if the keys collide, which they will with probability
        // 1/26, i.e., the keyspace for the Latin Shift Cipher system is *tiny*.
        if key1 != key2 {
            assert_ne!(Shift::decrypt(&Shift::encrypt(&msg2, &key1), &key2), msg2)
        }
    }

    // Tests with reproducible randomness
    #[test]
    fn enc_dec_reprod_rand() {
        let mut rng = reprod_rng();

        let key1 = ShiftKey(RingElement(rng.gen_range(0..RingElement::MODULUS)));
        let key2 = ShiftKey(RingElement(rng.gen_range(0..RingElement::MODULUS)));

        let msg1 = Message::new("thisisyetanothertestmessage").unwrap();

        // This test is OK as long you check that it passes once
        assert_ne!(key1, key2);

        // Encrypted message always decrypts correctly
        assert_eq!(Shift::decrypt(&Shift::encrypt(&msg1, &key1), &key1), msg1);
        // Encrypted message won't decrypt correctly without the correct key
        // This test is OK because a manual check has been done to ensure the keys are
        // different.
        assert_ne!(Shift::decrypt(&Shift::encrypt(&msg1, &key1), &key2), msg1)
    }
}
