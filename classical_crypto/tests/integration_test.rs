//! These integration tests exercise the public API of the crate, but they may
//! not be entirely sensible as integration tests.
use classical_crypto::{shift::Shift, Cipher, Ciphertext, Key, Message};
use rand::thread_rng;
use std::str::FromStr;

#[test]
fn generate_and_use_key() {
    let mut rng = thread_rng();
    let key0 = Key::new(&mut rng);
    let key1 = Key::new(&mut rng);

    // Exercise the `new` associated function.
    let msg = Message::new("thisisanawkwardapichoice").unwrap();
    // We could also have used the `FromStr` implementation for `Message`.
    assert_eq!(msg, Message::from_str("thisisanawkwardapichoice").unwrap());

    // Encrypt the test message.
    let ciphertxt = Shift::encrypt(&msg, &key0);

    // If we decrypt our ciphertext with the correct key, we
    // get our original message back.
    let decrypted = Shift::decrypt(&ciphertxt, &key0);
    assert_eq!(decrypted, msg);

    // If we decrypt using an incorrect key, we do not get
    //  our original message back
    if key0 != key1 {
        assert_ne!(Shift::decrypt(&ciphertxt, &key1), msg);
    }

    // We can create ciphertexts from strings, too
    let garbage_ciphertext = Ciphertext::from_str("THISISNOTGOINGTODECRYPTSENSIBLY").unwrap();
    assert_eq!(
        garbage_ciphertext.to_string(),
        "THISISNOTGOINGTODECRYPTSENSIBLY"
    );
}

#[test]
fn short_msg_example() {
    // With some non-negligible frequency, you won't get nonsense on
    // decryption with the wrong key, but the possible message space
    // is restricted beyond just the length of the message itself.
    // This is because shift ciphers preserve other message patterns,
    // too. Note that if the message is very short and you only have
    // one sample, one ciphertext may not be enough to definitively
    // break the system with a brute force attack. But likely there
    // is other context available to validate possible plaintexts.
    let small_msg_0 = Message::from_str("mom");
    let small_msg_1 = Message::from_str("gig");

    // Message encoding should work
    assert!(small_msg_0.is_ok());
    assert!(small_msg_1.is_ok());

    // Unwrap messages
    let small_msg_0 = small_msg_0.unwrap();
    let small_msg_1 = small_msg_1.unwrap();

    // Set two fixed keys in order to reiterate how patterns are preserved
    // in Latin shift cipher.
    let fixed_key_0 = Key::from_str("3");
    let fixed_key_1 = Key::from_str("9");

    // Key encoding should work
    assert!(&fixed_key_0.is_ok());
    assert!(&fixed_key_1.is_ok());

    // Unwrap keys
    let fixed_key_0 = fixed_key_0.unwrap();
    let fixed_key_1 = fixed_key_1.unwrap();

    let small_ciphertext = Shift::encrypt(&small_msg_0, &fixed_key_0);
    let small_decryption = Shift::decrypt(&small_ciphertext, &fixed_key_0);

    // Encryption followed by decryption with the correct gets us back the original
    // message
    assert_eq!(small_decryption, small_msg_0);
    assert_eq!(small_decryption.to_string(), small_msg_0.to_string());

    // Encryption followed by decryption with an incorrect key gets us back a still
    // intelligible message somtimes.
    assert_eq!(Shift::decrypt(&small_ciphertext, &fixed_key_1), small_msg_1);
}
