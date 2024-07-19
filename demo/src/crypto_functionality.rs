//! Cryptography-related I/O functionality.
use crate::{
    io_helper::process_input,
    menu::{ConsentMenu, DecryptMenu, Menu},
};
use classical_crypto::{Cipher, Key, ShiftCipher};
use rand::thread_rng;
use std::error::Error;

/// Creates keys and prints the key to standard output.
pub fn make_key() -> Result<(), Box<dyn Error>> {
    // Set up an rng.
    let mut rng = thread_rng();

    loop {
        // Generate a key
        let key = <ShiftCipher as Cipher>::Key::new(&mut rng);

        println!("\nWe generated your key successfully!.");
        println!("\nWe shouldn't export your key (or say, save it in logs), but we can!");
        println!("Here it is: {}", ShiftCipher::insecure_key_export(&key));
        println!("\nAre you happy with your key?");
        ConsentMenu::print_menu();

        let command: ConsentMenu = process_input(ConsentMenu::print_menu)?;

        match command {
            ConsentMenu::NoKE => continue,
            ConsentMenu::YesKE => {
                println!("\nGreat! We don't have a file system implemented (much less a secure one), so please \nremember your key in perpetuity!");
                break Ok(());
            }
        };
    }
}

/// Takes in a key and a message and encrypts, then prints
/// the result.
pub fn encrypt() -> Result<(), Box<dyn Error>> {
    println!("\nPlease enter the message you want to encrypt:");

    let msg: <ShiftCipher as Cipher>::Message = process_input(|| {
        println!("\nWe only accept lowercase letters from the Latin Alphabet, in one of the most awkward \nAPI decisions ever.");
    })?;

    println!("\nNow, do you have a key that was generated uniformly at random that you remember and \nwould like to use? If yes, please enter your key. Otherwise, please pick a fresh key \nuniformly at random from the ring of integers modulo 26 yourself. \n\nYou won't be as good at this as a computer, but if you understand the cryptosystem \nyou are using (something we cryptographers routinely assume about other people, while \npretending that we aren't assuming this), you will probably not pick a key of 0, \nwhich is equivalent to sending your messages \"in the clear\", i.e., unencrypted. Good \nluck! \n\nGo ahead and enter your key now:");

    let key: <ShiftCipher as Cipher>::Key = process_input(|| {
        println!("{KEY_PROMPT}");
    })?;

    println!("\nYour ciphertext is {}", ShiftCipher::encrypt(&msg, &key));
    println!("\nLook for patterns in your ciphertext. Could you definitively figure out the key and \noriginal plaintext message if you didn't already know it?");

    Ok(())
}

/// Takes in a ciphertext and attempts to decrypt and
/// print result.
pub fn decrypt(command: DecryptMenu) -> Result<(), Box<dyn Error>> {
    println!("\nEnter your ciphertext. Ciphertexts use characters only from the Latin Alphabet:");

    let ciphertxt: <ShiftCipher as Cipher>::Ciphertext = process_input(|| {
        println!("\nCiphertext must contain characters from the Latin Alphabet only.");
    })?;

    // Attempt decryption or stop trying
    match command {
        DecryptMenu::Bruteforce => {
            computer_chosen_key(&ciphertxt)?;
            Ok(())
        }
        DecryptMenu::KnownKey => {
            chosen_key(&ciphertxt)?;
            Ok(())
        }
        DecryptMenu::Quit => Ok(()),
    }
}

/// Gets key from stdin and attempts to decrypt.
pub fn chosen_key(ciphertxt: &<ShiftCipher as Cipher>::Ciphertext) -> Result<(), Box<dyn Error>> {
    loop {
        println!("\nOK. Please enter a key now:");
        let key: <ShiftCipher as Cipher>::Key = process_input(|| {
            println!("{KEY_PROMPT}");
        })?;
        match try_decrypt(ciphertxt, key) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    Ok(())
}

/// Has computer choose key uniformly at random and attempts to decrypt.
pub fn computer_chosen_key(
    ciphertxt: &<ShiftCipher as Cipher>::Ciphertext,
) -> Result<(), Box<dyn Error>> {
    let mut rng = thread_rng();

    loop {
        let key = <ShiftCipher as Cipher>::Key::new(&mut rng);
        match try_decrypt(ciphertxt, key) {
            Ok(_) => break,
            Err(_) => continue, // TODO: How to handle different errors independently?
        }
    }
    Ok(())
}

/// Decrypt with given key and ask whether to try again or not.
pub fn try_decrypt(
    ciphertxt: &<ShiftCipher as Cipher>::Ciphertext,
    key: <ShiftCipher as Cipher>::Key,
) -> Result<(), Box<dyn Error>> {
    println!(
        "\nYour computed plaintext is {}\n",
        ShiftCipher::decrypt(ciphertxt, &key)
    );
    println!("\nAre you happy with this decryption?");
    ConsentMenu::print_menu();

    let command: ConsentMenu = process_input(ConsentMenu::print_menu)?;

    match command {
        ConsentMenu::NoKE => Err("try again".into()),
        ConsentMenu::YesKE => Ok(()),
    }
}

const KEY_PROMPT: &str = "\nA key is a number between 0 and 25 inclusive.";
