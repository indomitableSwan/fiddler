//! This example implements a small command line application that
//! allows key generation, message encryption, and ciphertext decryption
//! using the Latin Shift Cipher.
//!
//! This example does not really satisfy the desired criterion for an
//! example, in that it does not really showcase "proper" usage of the crate.
//! It does highlight where the provided library API fails a basic use case, though:
//! we have to use the `Debug` impl to print `Key` values to sdout because I couldn't decide
//! how the library ought to handle keys.

use fiddler::{CipherText, Key, Message};
use rand::thread_rng;
use std::{error::Error, io, process, str::FromStr};

type CommandPtr<T> = fn(T) -> Result<(), Box<dyn Error>>;

// A struct that represents a possible user action.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct Command<'a, T> {
    key: u8,
    menu_msg: &'a str,
    function: Option<CommandPtr<T>>,
}
fn main() {
    println!("\nWelcome to the Latin Shift Cipher Demo!");
    if let Err(e) = menu() {
        eprintln!("Application error: {e}");
        process::exit(1);
    }
}

// Prints menu of user options and matches on user input to do one of:
// Generate a key, encrypt a message, decrypt a message.
fn menu() -> Result<(), Box<dyn Error>> {
    let menu: [Command<()>; 4] = [
        Command {
            key: 1,
            menu_msg: "Generate a key.",
            function: Some(make_key as CommandPtr<()>),
        },
        Command {
            key: 2,
            menu_msg: "Encrypt a message.",
            function: Some(encrypt as CommandPtr<()>),
        },
        Command {
            key: 3,
            menu_msg: "Decrypt a ciphertext.",
            function: Some(decrypt as CommandPtr<()>),
        },
        Command {
            key: 4,
            menu_msg: "Quit",
            function: None,
        },
    ];

    loop {
        println!("\nPlease enter one of the following options:");
        for item in menu {
            println!("{}: {}", item.key, item.menu_msg)
        }

        let command: u8 = process_input("")?;

        // Find and extract command in `MENU` that matches
        // the command line input
        let command = match menu.into_iter().find(|&x| x.key == command) {
            Some(x) => x,
            // If no match, restart loop to ask user again
            None => continue,
        };

        // Extract the command's associated function and run it,
        // Break the loop and exit if there is no such function
        match command.function {
            Some(x) => x(())?,
            None => break Ok(()),
        }
    }
}

// Prints menu of user options and matches on user input to do one of:
// Generate a key, encrypt a message, decrypt a message.
fn decryption_menu(ciphertxt: &CipherText) -> Result<(), Box<dyn Error>> {
    let menu: [Command<&CipherText>; 4] = [
        Command {
            key: 1,
            menu_msg: "Decrypt with a known key.",
            function: Some(chosen_key as CommandPtr<&CipherText>),
        },
        Command {
            key: 2,
            menu_msg: "Brute force by manually guessing keys. (Choose this option if you want to try \nsampling from the uniform distribution.)",
            function: Some(chosen_key as CommandPtr<&CipherText>),
        },
        Command {
            key: 3,
            menu_msg: "Brute force by having the computer guess keys. (Choose this option once you realize \nhow difficult it is to reliably sample from the uniform distribution.)",
            function: Some(computer_chosen_key as CommandPtr<&CipherText>),
        },
        Command {
            key: 4,
            menu_msg: "Quit.",
            function: None,
        },
    ];

    loop {
        println!("\nPlease enter one of the following options:");
        for item in menu {
            println!("{}: {}", item.key, item.menu_msg)
        }

        let command: u8 = process_input("")?;

        // Find and extract command in `MENU` that matches
        // the command line input
        let command = match menu.into_iter().find(|x| x.key == command) {
            Some(x) => x,
            // If no match, restart loop to ask user again
            None => continue,
        };

        // Extract the command's associated function and run it,
        // Break the loop and exit if there is no such function
        match command.function {
            Some(x) => {
                x(ciphertxt)?;
                break Ok(());
            }
            None => break Ok(()),
        }
    }
}

// Creates keys and prints the key to standard output.
fn make_key(_: ()) -> Result<(), Box<dyn Error>> {
    // Set up an rng.
    let mut rng = thread_rng();

    loop {
        // Generate a key
        let key = Key::new(&mut rng);

        println!("\nWe generated your key successfully!.");
        println!("\nWe shouldn't export your key (or say, save it in logs), but we can!");
        println!("Here it is: {}", key.insecure_export());
        println!("Are you happy with your key? Enter Y for yes and N for no:");

        let instr: Instr = process_input("Enter 'Y' for yes or 'N' for no:")?;

        match instr {
            Instr::No => continue,
            Instr::Yes => {
                println!("\nGreat! We don't have a file system implemented (much less a secure one), so please \nremember your key in perpetuity!");
                break Ok(());
            }
        };
    }
}

enum Instr {
    Yes,
    No,
}

struct InstrError;

impl FromStr for Instr {
    type Err = InstrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Y" => Ok(Instr::Yes),
            "N" => Ok(Instr::No),
            _ => Err(InstrError),
        }
    }
}

// Takes in a key and a message and encrypts, then prints
// the result.
fn encrypt(_: ()) -> Result<(), Box<dyn Error>> {
    println!("\nPlease enter the message you want to encrypt:");

    let msg: Message = process_input("\nWe only accept lowercase letters from the Latin Alphabet, in one of the most awkward \nAPI decisions ever.")?;

    println!("\nNow, do you have a key that was generated uniformly at random that you remember and \nwould like to use? If yes, please enter your key. Otherwise, please pick a fresh key \nuniformly at random from the ring of integers modulo 26 yourself. \n\nYou won't be as good at this as a computer, but if you understand the cryptosystem \nyou are using (something we cryptographers routinely assume about other people, while \npretending that we aren't assuming this), you will probably not pick a key of 0, \nwhich is equivalent to sending your messages \"in the clear\", i.e., unencrypted. Good \nluck! \n\nGo ahead and enter your key now:");

    let key: Key = process_input("A key is a number between 0 and 25 inclusive.")?;

    println!("\nYour ciphertext is {}", msg.encrypt(&key));
    println!("\nLook for patterns in your ciphertext. Could you definitively figure out the key and \noriginal plaintext message if you didn't already know it?");

    Ok(())
}

// Takes in a ciphertext and attempts to decrypt and
// print result.
fn decrypt(_: ()) -> Result<(), Box<dyn Error>> {
    println!("\nEnter your ciphertext. Ciphertexts use characters only from the Latin Alphabet:");

    let ciphertxt: CipherText =
        process_input("Ciphertext must contain characters from the Latin Alphabet only.")?;

    println!("\nGreat, let's work on decrypting your ciphertext.");
    println!(
        "If you know what key was used to encrypt this message, this should only take one try."
    );
    println!(
    "If not, don't despair. Just guess! On average, you can expect success using this \nsimple brute force attack method after trying 13 keys chosen uniformly at random. \n(How good are you at choosing uniformly at random?)"
    );

    decryption_menu(&ciphertxt)?;

    Ok(())
}

// Gets key from stdin and attempts to decrypt
fn chosen_key(ciphertxt: &CipherText) -> Result<(), Box<dyn Error>> {
    loop {
        println!("\nOK. Please enter a key now:");
        let key: Key = process_input("A key is a number between 0 and 25 inclusive.")?;
        match try_decrypt(ciphertxt, key) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    Ok(())
}

// Has computer choose key uniformly at random and attempts to decrypt
fn computer_chosen_key(ciphertxt: &CipherText) -> Result<(), Box<dyn Error>> {
    let mut rng = thread_rng();

    loop {
        let key = Key::new(&mut rng);
        match try_decrypt(ciphertxt, key) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    Ok(())
}

// Decrypt with given key and ask whether to try again or not
fn try_decrypt(ciphertxt: &CipherText, key: Key) -> Result<(), Box<dyn Error>> {
    println!("\nYour computed plaintext is {}\n", ciphertxt.decrypt(&key));
    println!("\nAre you happy with this decryption? Enter Y for yes N for no:");

    let instr: Instr = process_input("Enter 'Y' for yes or 'N' for no.")?;

    match instr {
        Instr::No => Err("try again".into()),
        Instr::Yes => Ok(()),
    }
}

// TODO: this loop and match statment plus a return line is probably not idiomatic
// Processes command line input and converts to type `T` as specified by caller
// If successful, returns conversion. If not, prints clarifying instructions
// so that the person can try again
fn process_input<T: FromStr>(instructions: &str) -> Result<T, Box<dyn Error>> {
    loop {
        let mut input = String::new();

        io::stdin().read_line(&mut input)?;

        let result: T = match input.trim().parse::<T>() {
            Ok(txt) => txt,
            Err(_) => {
                println!("{instructions}");
                println!("Please try again:");
                continue;
            }
        };

        return Ok(result);
    }
}
