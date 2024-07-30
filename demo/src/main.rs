//! This example implements a small command line application that
//! allows key generation, message encryption, and ciphertext decryption
//! (including a computer-aided brute force attack) using the Latin Shift
//! Cipher.
use std::io::{BufReader, BufWriter};

use anyhow::Result;
use demo::menu;

fn main() -> Result<()> {
    println!("\nWelcome to the Latin Shift Cipher Demo!");

    // The demo library crate is decoupled from stdin and stdout through the use of
    // dependency injection
    let reader = BufReader::new(std::io::stdin());
    let writer = BufWriter::new(std::io::stdout());

    menu(reader, writer)?;
    Ok(())
}
