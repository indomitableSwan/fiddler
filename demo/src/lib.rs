//! The demo libary crate, containing functionality supporting the demo CLI.
// TODO: handle errors properly instead of allowing panicking (partially
// completed, but many suboptions from main menu will still panic if user inputs
// something invalid)
use anyhow::Result;
use std::io::{BufRead, BufReader};

pub mod crypto_functionality;
mod io_helper;
pub mod menu;

use crate::crypto_functionality::{decrypt, encrypt, make_key};
use crate::io_helper::process_input;
use crate::menu::{DecryptMenu, MainMenu, Menu};

/// Presents main menu and runs user selection.
///
/// Prints main menu of user options and matches on user input to do one of:
/// - Generate a key;
/// - Encrypt a message;
/// - Decrypt a message;
/// - Quit the CLI application.
pub fn menu() -> Result<()> {
    loop {
        {
            let mut reader = BufReader::new(std::io::stdin());

            // Get menu selection from user
            let command = process_input(MainMenu::print_menu, &mut reader);

            match command {
                // Process menu selection from user

                // Generate a key
                Ok(MainMenu::GenKE) => make_key(&mut reader)?,
                // Encrypt a message
                Ok(MainMenu::EncryptKE) => encrypt(&mut reader)?,
                // Attempt to decrypt a ciphertext
                Ok(MainMenu::DecryptKE) => {
                    // Print decryption menu and get user selection
                    let command = decryption_menu(&mut reader)?;
                    // Proceed with decryption as specified by user
                    decrypt(command, &mut reader)?;
                }
                // Quit the CLI application
                Ok(MainMenu::QuitKE) => break Ok(()),
                Err(_) => continue,
            };
        }
    }
}

/// Presents decryption menu and runs user selection.
///
/// Prints menu of user decryption options and matches on user input to do one
/// of:
/// - Decrypt using a known key;
/// - Computer-aided brute force attack;
/// - Quit decryption menu.
pub fn decryption_menu(mut reader: impl BufRead) -> Result<DecryptMenu> {
    println!("\nGreat, let's work on decrypting your ciphertext.");
    println!(
        "If you know what key was used to encrypt this message, this should only take one try."
    );
    println!(
    "If not, don't despair. Just guess! On average, you can expect success using this \nsimple brute force attack method after trying 13 keys chosen uniformly at random."
    );

    let command: DecryptMenu = process_input(DecryptMenu::print_menu, &mut reader)?;
    Ok(command)
}
