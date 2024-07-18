//! The demo libary crate, containing functionality supporting the demo CLI.
use std::error::Error;

pub mod crypto_functionality;
pub mod menu;

use crate::crypto_functionality::{decrypt, encrypt, make_key};
use crate::io_helper::process_input;
use crate::menu::{DecryptMenu, MainMenu, Menu};

/// Prints menu of user options and matches on user input to do one of:
/// - Generate a key;
/// - Encrypt a message;
/// - Decrypt a message;
/// - Quit the CLI application.
pub fn menu() -> Result<(), Box<dyn Error>> {
    loop {
        // Print the main menu
        MainMenu::print_menu();

        // Get menu selection from user
        let command: MainMenu = process_input(MainMenu::print_menu)?;

        // Process menu selection from user
        match command {
            // Generate a key
            MainMenu::GenKE => make_key()?,
            // Encrypt a message
            MainMenu::EncryptKE => encrypt()?,
            // Attempt to decrypt a ciphertext
            MainMenu::DecryptKE => {
                // Print decryption menu and get user selection
                let command = decryption_menu()?;
                // Proceed with decryption as specified by user
                decrypt(command)?;
            }
            // Quit the CLI application
            MainMenu::QuitKE => break Ok(()),
        };
    }
}

/// Prints menu of user decryption options and matches on user input to do one
/// of:
/// - Decrypt using a known key;
/// - Computer-aided brute force attack;
/// - Quit decryption menu.
pub fn decryption_menu() -> Result<DecryptMenu, Box<dyn Error>> {
    println!("\nGreat, let's work on decrypting your ciphertext.");
    println!(
        "If you know what key was used to encrypt this message, this should only take one try."
    );
    println!(
    "If not, don't despair. Just guess! On average, you can expect success using this \nsimple brute force attack method after trying 13 keys chosen uniformly at random."
    );
    println!("Pick one of the following options:");

    DecryptMenu::print_menu();

    let command: DecryptMenu = process_input(DecryptMenu::print_menu)?;
    Ok(command)
}

mod io_helper {
    use std::{error::Error, io, str::FromStr};
    // TODO: this loop and match statment plus a return line is probably not
    // idiomatic
    //
    /// Processes command line input and converts to type `T` as specified
    /// by caller. If successful, returns conversion. If not, prints clarifying
    /// instructions so that the person can try again.
    pub fn process_input<T, F>(instr: F) -> Result<T, Box<dyn Error>>
    where
        T: FromStr,
        F: Fn(),
    {
        loop {
            let mut input = String::new();

            io::stdin().read_line(&mut input)?;

            let result: T = match input.trim().parse::<T>() {
                Ok(txt) => txt,
                Err(_) => {
                    instr();
                    println!("\nPlease try again:");
                    continue;
                }
            };

            return Ok(result);
        }
    }
}
