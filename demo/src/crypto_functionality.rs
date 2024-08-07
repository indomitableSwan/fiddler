//! Cryptography-related I/O functionality.
use crate::{
    io_helper::{process_input, ProcessInputError},
    menu::{ConsentMenu, DecryptMenu, Menu},
};
use anyhow::{anyhow, Result};
use classical_crypto::{
    errors::EncodingError,
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
            writeln!(writer, "\nAre you happy with your key?")?;
            ConsentMenu::print_menu(writer.by_ref())?;

            match process_input(&mut reader) {
                Ok(ConsentMenu::NoKE) => continue 'outer,
                Ok(ConsentMenu::YesKE) => {
                    writeln!(writer, "\nGreat! We don't have a file system implemented (much less a secure one), so please \nremember your key in perpetuity!")?;

                    break 'outer Ok(());
                }
                Err(e) => {
                    writeln!(writer, "Error: {}", e)?;
                    continue 'inner;
                }
            };
        }
    }
}

/// Takes in a key and a message and encrypts, then prints
/// the result.
pub fn encrypt(mut reader: impl BufRead, mut writer: impl Write) -> Result<()> {
    let msg = loop {
        writeln!(writer, "\nPlease enter the message you want to encrypt:")?;

        let msg = process_input::<Message, EncodingError, _>(&mut reader);

        match msg {
            Ok(msg) => break msg,
            Err(e) => {
                writeln!(writer, "Error: {}", e)?;
                continue;
            }
        }
    };

    writeln!(writer, "\nNow, do you have a key that was generated uniformly at random that you remember and \nwould like to use? If yes, please enter your key. Otherwise, please pick a fresh key \nuniformly at random from the ring of integers modulo 26 yourself. \n\nYou won't be as good at this as a computer, but if you understand the cryptosystem \nyou are using (something we cryptographers routinely assume about other people, while \npretending that we aren't assuming this), you will probably not pick a key of 0, \nwhich is equivalent to sending your messages \"in the clear\", i.e., unencrypted. Good \nluck! \n")?;

    let key = loop {
        writeln!(
            writer,
            "\nPlease enter a key now. Keys are numbers between 0 and 25 inclusive."
        )?;

        let key = process_input::<Key, EncodingError, _>(&mut reader);

        match key {
            Ok(key) => break key,
            Err(e) => {
                writeln! {writer, "Error: {}", e}?;
                continue;
            }
        }
    };

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
    let ciphertxt = loop {
        writeln!(
            writer,
            "\nEnter your ciphertext. Ciphertexts use characters only from the Latin Alphabet:"
        )?;

        let ciphertxt = process_input::<Ciphertext, EncodingError, _>(&mut reader);

        match ciphertxt {
            Ok(ciphertxt) => break ciphertxt,
            Err(e) => {
                writeln!(writer, "Error: {}", e)?;
                continue;
            }
        }
    };

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
        writeln!(
            writer,
            "\nPlease enter a key now. Keys are numbers between 0 and 25 inclusive."
        )?;

        let key = loop {
            let key = process_input::<Key, EncodingError, _>(&mut reader);

            match key {
                Ok(key) => break key,
                Err(e) => {
                    writeln!(writer, "Error: {}", e)?;
                    continue;
                }
            }
        };

        match try_decrypt(ciphertxt, key, &mut reader, writer.by_ref()) {
            Ok(_) => break Ok(()),
            Err(_) => continue,
        }
    }
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

    let command = loop {
        writeln!(writer, "\nAre you happy with this decryption?")?;
        ConsentMenu::print_menu(writer.by_ref())?;

        let command = process_input::<ConsentMenu, ProcessInputError, _>(&mut reader);

        match command {
            Ok(command) => break command,
            Err(e) => {
                writeln!(writer, "Error: {}", e)?;
                continue;
            }
        }
    };

    match command {
        ConsentMenu::NoKE => Err(anyhow!("try again")),
        ConsentMenu::YesKE => Ok(()),
    }
}
