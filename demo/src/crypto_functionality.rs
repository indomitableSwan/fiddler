//! Cryptography-related I/O functionality.
use crate::{
    io_helper::process_input,
    menu::{ConsentMenu, DecryptMenu, Menu},
};
use anyhow::{anyhow, Result};
use classical_crypto::{
    shift::{Ciphertext, Key, Message, ShiftCipher},
    CipherTrait, KeyTrait,
};
use rand::thread_rng;
use std::io::{BufRead, Write};

/// Creates keys and prints the key to standard output.
pub fn make_key(mut reader: impl BufRead, mut writer: impl Write) -> Result<()> {
    // Set up an rng.
    let mut rng = thread_rng();

    'outer: loop {
        // Generate a key
        let key = Key::new(&mut rng);

        println!("\nWe generated your key successfully!.");
        println!("\nWe shouldn't export your key (or say, save it in logs), but we can!");
        println!("Here it is: {}\n", ShiftCipher::insecure_key_export(&key));

        'inner: loop {
            match process_input(
                || -> Result<(), std::io::Error> {
                    writeln!(writer, "\nAre you happy with your key?")?;
                    ConsentMenu::print_menu(writer.by_ref())
                },
                &mut reader,
            ) {
                Ok(ConsentMenu::NoKE) => continue 'outer,
                Ok(ConsentMenu::YesKE) => {
                    writeln!(writer, "\nGreat! We don't have a file system implemented (much less a secure one), so please \nremember your key in perpetuity!")?;

                    break 'outer Ok(());
                }
                Err(_) => continue 'inner,
            };
        }
    }
}

/// Takes in a key and a message and encrypts, then prints
/// the result.
pub fn encrypt(mut reader: impl BufRead, mut writer: impl Write) -> Result<()> {
    let msg: Message = process_input(
        || writeln!(writer, "\nPlease enter the message you want to encrypt:"),
        &mut reader,
    )?;

    writeln!(writer, "\nNow, do you have a key that was generated uniformly at random that you remember and \nwould like to use? If yes, please enter your key. Otherwise, please pick a fresh key \nuniformly at random from the ring of integers modulo 26 yourself. \n\nYou won't be as good at this as a computer, but if you understand the cryptosystem \nyou are using (something we cryptographers routinely assume about other people, while \npretending that we aren't assuming this), you will probably not pick a key of 0, \nwhich is equivalent to sending your messages \"in the clear\", i.e., unencrypted. Good \nluck! \n")?;

    let key: Key = process_input(
        || {
            writeln!(
                writer,
                "\nPlease enter a key now. Keys are numbers between 0 and 25 inclusive."
            )
        },
        &mut reader,
    )?;

    writeln!(
        writer,
        "\nYour ciphertext is {}",
        ShiftCipher::encrypt(&msg, &key)
    )?;

    writeln!(writer, "\nLook for patterns in your ciphertext. Could you definitively figure out the key and \noriginal plaintext message if you didn't already know it?")?;

    Ok(())
}

/// Takes in a ciphertext and attempts to decrypt and
/// print result.
pub fn decrypt(
    command: DecryptMenu,
    mut reader: impl BufRead,
    mut writer: impl Write,
) -> Result<()> {
    let ciphertxt: Ciphertext = process_input(
        || {
            writeln!(
                writer,
                "\nEnter your ciphertext. Ciphertexts use characters only from the Latin Alphabet:"
            )
        },
        &mut reader,
    )?;

    // Attempt decryption or stop trying
    match command {
        DecryptMenu::Bruteforce => {
            computer_chosen_key(&ciphertxt, &mut reader, writer)?;
            Ok(())
        }
        DecryptMenu::KnownKey => {
            chosen_key(&ciphertxt, &mut reader, writer)?;
            Ok(())
        }
        DecryptMenu::Quit => Ok(()),
    }
}

/// Gets key from stdin and attempts to decrypt.
pub fn chosen_key(
    ciphertxt: &Ciphertext,
    mut reader: impl BufRead,
    mut writer: impl Write,
) -> Result<()> {
    loop {
        let key: Key = process_input(
            || {
                writeln!(
                    writer,
                    "\nPlease enter a key now. Keys are numbers between 0 and 25 inclusive."
                )
            },
            &mut reader,
        )?;
        match try_decrypt(ciphertxt, key, &mut reader, writer.by_ref()) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    Ok(())
}

/// Has computer choose key uniformly at random and attempts to decrypt.
pub fn computer_chosen_key(
    ciphertxt: &Ciphertext,
    mut reader: impl BufRead,
    mut writer: impl Write,
) -> Result<()> {
    let mut rng = thread_rng();

    loop {
        let key = Key::new(&mut rng);
        match try_decrypt(ciphertxt, key, &mut reader, writer.by_ref()) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    Ok(())
}

/// Decrypt with given key and ask whether to try again or not.
pub fn try_decrypt(
    ciphertxt: &Ciphertext,
    key: Key,
    mut reader: impl BufRead,
    mut writer: impl Write,
) -> Result<()> {
    println!(
        "\nYour computed plaintext is {}\n",
        ShiftCipher::decrypt(ciphertxt, &key)
    );

    let command: ConsentMenu = process_input(
        || {
            writeln!(writer, "\nAre you happy with this decryption?")?;
            ConsentMenu::print_menu(writer.by_ref())
        },
        &mut reader,
    )?;

    match command {
        ConsentMenu::NoKE => Err(anyhow!("try again")),
        ConsentMenu::YesKE => Ok(()),
    }
}
