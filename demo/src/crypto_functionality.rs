//! Cryptography-related I/O functionality.
use crate::{
    io_helper::process_input,
    menu::{ConsentMenu, DecryptMenu, Menu},
};
use classical_crypto::{
    shift::{Ciphertext, Key, Message, ShiftCipher},
    CipherTrait, KeyTrait,
};
use rand::thread_rng;
use std::error::Error;

/// Creates keys and prints the key to standard output.
pub fn make_key() -> Result<(), Box<dyn Error>> {
    // Set up an rng.
    let mut rng = thread_rng();

    loop {
        // Generate a key
        let key = Key::new(&mut rng);

        println!("\nWe generated your key successfully!.");
        println!("\nWe shouldn't export your key (or say, save it in logs), but we can!");
        println!("Here it is: {}\n", ShiftCipher::insecure_key_export(&key));
                
        let command: ConsentMenu = process_input(|| {
            println!("\nAre you happy with your key?");
            ConsentMenu::print_menu()
    })?;

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
    
    let msg: Message = process_input(|| println!("\nPlease enter the message you want to encrypt:"))?;

    println!("\nNow, do you have a key that was generated uniformly at random that you remember and \nwould like to use? If yes, please enter your key. Otherwise, please pick a fresh key \nuniformly at random from the ring of integers modulo 26 yourself. \n\nYou won't be as good at this as a computer, but if you understand the cryptosystem \nyou are using (something we cryptographers routinely assume about other people, while \npretending that we aren't assuming this), you will probably not pick a key of 0, \nwhich is equivalent to sending your messages \"in the clear\", i.e., unencrypted. Good \nluck! \n");

    let key: Key = process_input(|| println!("\nGo ahead and enter your key now:"))?;

    println!("\nYour ciphertext is {}", ShiftCipher::encrypt(&msg, &key));
    println!("\nLook for patterns in your ciphertext. Could you definitively figure out the key and \noriginal plaintext message if you didn't already know it?");

    Ok(())
}

/// Takes in a ciphertext and attempts to decrypt and
/// print result.
pub fn decrypt(command: DecryptMenu) -> Result<(), Box<dyn Error>> {
    let ciphertxt: Ciphertext = process_input(|| println!("\nEnter your ciphertext. Ciphertexts use characters only from the Latin Alphabet:"))?;

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
pub fn chosen_key(ciphertxt: &Ciphertext) -> Result<(), Box<dyn Error>> {
    loop {
        let key: Key = process_input(|| println!("\nPlease enter a key now. Keys are numbers between 0 and 25 inclusive."))?;
        match try_decrypt(ciphertxt, key) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    Ok(())
}

/// Has computer choose key uniformly at random and attempts to decrypt.
pub fn computer_chosen_key(ciphertxt: &Ciphertext) -> Result<(), Box<dyn Error>> {
    let mut rng = thread_rng();

    loop {
        let key = Key::new(&mut rng);
        match try_decrypt(ciphertxt, key) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    Ok(())
}

/// Decrypt with given key and ask whether to try again or not.
pub fn try_decrypt(ciphertxt: &Ciphertext, key: Key) -> Result<(), Box<dyn Error>> {
    println!(
        "\nYour computed plaintext is {}\n",
        ShiftCipher::decrypt(ciphertxt, &key)
    );
      
    let command: ConsentMenu = process_input(|| {
        println!("\nAre you happy with this decryption?");ConsentMenu::print_menu()
    })?;

    match command {
        ConsentMenu::NoKE => Err("try again".into()),
        ConsentMenu::YesKE => Ok(()),
    }
}
