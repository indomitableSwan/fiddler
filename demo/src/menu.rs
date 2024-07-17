//! Menu related functionality.
use crate::crypto_functionality::{chosen_key, computer_chosen_key, decrypt, encrypt, make_key};
use crate::{process_input, DecryptMenu, MainMenu, Menu};
use classical_crypto::CipherText;
use std::error::Error;

// Prints menu of user options and matches on user input to do one of:
// Generate a key, encrypt a message, decrypt a message, quit program
pub fn menu() -> Result<(), Box<dyn Error>> {
    loop {
        MainMenu::print_menu()?;

        let command: MainMenu = process_input(MainMenu::print_menu)?;

        match command {
            MainMenu::GenKE => make_key()?,
            MainMenu::EncryptKE => encrypt()?,
            MainMenu::DecryptKE => decrypt()?,
            MainMenu::QuitKE => break Ok(()),
        };
    }
}

// Prints menu of user options and matches on user input to do one of:
// Decrypt using a known key, computer-aided brute force attack, return
// to main menu
pub(crate) fn decryption_menu(ciphertxt: &CipherText) -> Result<(), Box<dyn Error>> {
    DecryptMenu::print_menu()?;

    let command: DecryptMenu = process_input(DecryptMenu::print_menu)?;

    match command {
        DecryptMenu::Bruteforce => {
            computer_chosen_key(ciphertxt)?;
            Ok(())
        }
        DecryptMenu::KnownKey => {
            chosen_key(ciphertxt)?;
            Ok(())
        }
        DecryptMenu::Quit => Ok(()),
    }
}
