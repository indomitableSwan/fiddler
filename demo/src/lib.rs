//! The demo libary crate, containing functionality supporting the demo CLI.
use anyhow::Result;

pub mod crypto_functionality;
pub mod menu;
mod io_helper;

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

/// Presents decryption menu and runs user selection.
///
/// Prints menu of user decryption options and matches on user input to do one
/// of:
/// - Decrypt using a known key;
/// - Computer-aided brute force attack;
/// - Quit decryption menu.
pub fn decryption_menu() -> Result<DecryptMenu> {
    println!("\nGreat, let's work on decrypting your ciphertext.");
    println!(
        "If you know what key was used to encrypt this message, this should only take one try."
    );
    println!(
    "If not, don't despair. Just guess! On average, you can expect success using this \nsimple brute force attack method after trying 13 keys chosen uniformly at random."
    );

    let command: DecryptMenu = process_input(DecryptMenu::print_menu)?;
    Ok(command)
}

