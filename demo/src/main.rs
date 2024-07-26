//! This example implements a small command line application that
//! allows key generation, message encryption, and ciphertext decryption
//! (including a computer-aided brute force attack) using the Latin Shift
//! Cipher.
use anyhow::Result;
use demo::menu;

fn main() -> Result<()> {
    println!("\nWelcome to the Latin Shift Cipher Demo!");
    menu()?;
    Ok(())
}
