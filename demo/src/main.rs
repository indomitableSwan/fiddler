//! This example implements a small command line application that
//! allows key generation, message encryption, and ciphertext decryption
//! (including a computer-aided brute force attack) using the Latin Shift
//! Cipher.
use demo::menu::menu;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("\nWelcome to the Latin Shift Cipher Demo!");
    menu().inspect_err(|e| eprintln!("Application error: {e}"))
}
