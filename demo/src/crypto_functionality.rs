use crate::menu::decryption_menu;
use crate::{
    menu::{ConsentMenu, Menu},
    process_input,
};
use classical_crypto::{CipherText, Key, Message};
use rand::thread_rng;
use std::error::Error;

// Creates keys and prints the key to standard output.
pub(crate) fn make_key() -> Result<(), Box<dyn Error>> {
    // Set up an rng.
    let mut rng = thread_rng();

    loop {
        // Generate a key
        let key = Key::new(&mut rng);

        println!("\nWe generated your key successfully!.");
        println!("\nWe shouldn't export your key (or say, save it in logs), but we can!");
        println!("Here it is: {}", key.insecure_export());
        println!("\nAre you happy with your key?");
        ConsentMenu::print_menu()?;

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

// Takes in a key and a message and encrypts, then prints
// the result.
pub(crate) fn encrypt() -> Result<(), Box<dyn Error>> {
    println!("\nPlease enter the message you want to encrypt:");

    let msg: Message = process_input(print_msg_instr)?;

    println!("\nNow, do you have a key that was generated uniformly at random that you remember and \nwould like to use? If yes, please enter your key. Otherwise, please pick a fresh key \nuniformly at random from the ring of integers modulo 26 yourself. \n\nYou won't be as good at this as a computer, but if you understand the cryptosystem \nyou are using (something we cryptographers routinely assume about other people, while \npretending that we aren't assuming this), you will probably not pick a key of 0, \nwhich is equivalent to sending your messages \"in the clear\", i.e., unencrypted. Good \nluck! \n\nGo ahead and enter your key now:");

    let key: Key = process_input(print_key_instr)?;

    println!("\nYour ciphertext is {}", msg.encrypt(&key));
    println!("\nLook for patterns in your ciphertext. Could you definitively figure out the key and \noriginal plaintext message if you didn't already know it?");

    fn print_msg_instr() -> Result<(), Box<dyn Error>> {
        println!("\nWe only accept lowercase letters from the Latin Alphabet, in one of the most awkward \nAPI decisions ever.");
        Ok(())
    }

    Ok(())
}

// Takes in a ciphertext and attempts to decrypt and
// print result.
pub(crate) fn decrypt() -> Result<(), Box<dyn Error>> {
    println!("\nEnter your ciphertext. Ciphertexts use characters only from the Latin Alphabet:");

    let ciphertxt: CipherText = process_input(print_ciphertxt_instr)?;

    println!("\nGreat, let's work on decrypting your ciphertext.");
    println!(
        "If you know what key was used to encrypt this message, this should only take one try."
    );
    println!(
    "If not, don't despair. Just guess! On average, you can expect success using this \nsimple brute force attack method after trying 13 keys chosen uniformly at random."
    );

    decryption_menu(&ciphertxt)?;

    fn print_ciphertxt_instr() -> Result<(), Box<dyn Error>> {
        println!("\nCiphertext must contain characters from the Latin Alphabet only.");
        Ok(())
    }

    Ok(())
}

// Gets key from stdin and attempts to decrypt
pub(crate) fn chosen_key(ciphertxt: &CipherText) -> Result<(), Box<dyn Error>> {
    loop {
        println!("\nOK. Please enter a key now:");
        let key: Key = process_input(print_key_instr)?;
        match try_decrypt(ciphertxt, key) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    Ok(())
}

// Has computer choose key uniformly at random and attempts to decrypt
pub(crate) fn computer_chosen_key(ciphertxt: &CipherText) -> Result<(), Box<dyn Error>> {
    let mut rng = thread_rng();

    loop {
        let key = Key::new(&mut rng);
        match try_decrypt(ciphertxt, key) {
            Ok(_) => break,
            Err(_) => continue, // TODO: How to handle different errors independently?
        }
    }
    Ok(())
}

// Decrypt with given key and ask whether to try again or not
pub(crate) fn try_decrypt(ciphertxt: &CipherText, key: Key) -> Result<(), Box<dyn Error>> {
    println!("\nYour computed plaintext is {}\n", ciphertxt.decrypt(&key));
    println!("\nAre you happy with this decryption?");
    ConsentMenu::print_menu()?;

    let command: ConsentMenu = process_input(ConsentMenu::print_menu)?;

    match command {
        ConsentMenu::NoKE => Err("try again".into()),
        ConsentMenu::YesKE => Ok(()),
    }
}

fn print_key_instr() -> Result<(), Box<dyn Error>> {
    println!("\nA key is a number between 0 and 25 inclusive.");
    Ok(())
}
