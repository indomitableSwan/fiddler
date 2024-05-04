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

fn main() {
    println!("\nWelcome to the Latin Shift Cipher Demo!");
    if let Err(e) = menu() {
        eprintln!("Application error: {e}");
        process::exit(1);
    }
}

// A struct that represents a menu of user options
struct MenuArray<'a, const N: usize>([Command<'a>; N]);

// Should this be an enum instead with different menu types?
enum MainMenu {
    GenKE,
    EncryptKE,
    DecryptKE,
    QuitKE,
}

impl<'a> MainMenu {
    // Key Events
    const GEN_KE: &'static str = "1"; // Key Event for "Generate a key" menu option
    const ENCRYPT_KE: &'static str = "2"; // Key Event for "encrypt a message" menu option
    const DECRYPT_KE: &'static str = "3"; // Key Event for "decrypt" menu option
    const QUIT_KE: &'static str = "4"; // Key Event for "quit" menu option

    // Main Menu commands
    //
    const GEN: Command<'static> = Command {
        key: Self::GEN_KE,
        menu_msg: "Generate a key.",
    };

    // Command to encrypt a message
    const ENCRYPT: Command<'static> = Command {
        key: Self::ENCRYPT_KE,
        menu_msg: "Encrypt a message.",
    };

    // Command to decrypt a message
    const DECRYPT: Command<'static> = Command {
        key: Self::DECRYPT_KE,
        menu_msg: "Decrypt a ciphertext.",
    };

    // Command to quit
    const QUIT: Command<'static> = Command {
        key: Self::QUIT_KE,
        menu_msg: "Quit",
    };

    fn menu_array() -> MenuArray<'a, 4> {
        MenuArray([Self::GEN, Self::ENCRYPT, Self::DECRYPT, Self::QUIT])
    }

    fn print_menu() -> Result<(), Box<dyn Error>> {
        println!("\nPlease enter one of the following options:");
        for item in MainMenu::menu_array().0 {
            println!("{}: {}", item.key, item.menu_msg)
        }
        Ok(())
    }
}

impl FromStr for MainMenu {
    type Err = CommandError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            MainMenu::GEN_KE => Ok(MainMenu::GenKE),
            MainMenu::ENCRYPT_KE => Ok(MainMenu::EncryptKE),
            MainMenu::DECRYPT_KE => Ok(MainMenu::DecryptKE),
            MainMenu::QUIT_KE => Ok(MainMenu::QuitKE),
            _ => Err(CommandError),
        }
    }
}

enum ConsentMenu {
    YesKE,
    NoKE,
}

impl ConsentMenu {
    const YES_KE: &'static str = "y";
    const NO_KE: &'static str = "n";

    fn print_menu() -> Result<(), Box<dyn Error>> {
        println!("\nEnter 'y' for yes and 'n' for no.");
        Ok(())
    }
}

impl FromStr for ConsentMenu {
    type Err = CommandError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            ConsentMenu::YES_KE => Ok(ConsentMenu::YesKE),
            ConsentMenu::NO_KE => Ok(ConsentMenu::NoKE),
            _ => Err(CommandError),
        }
    }
}

enum DecryptMenu {
    KnownKey,
    Bruteforce,
    Quit,
}

impl<'a> DecryptMenu {
    // Define Key Events
    const KNOWN_KEY_KE: &'static str = "1";
    const BRUTE_FORCE_KE: &'static str = "2";
    const QUIT_KE: &'static str = "3";

    // Decryption Menu commands
    //
    const KNOWN_KEY: Command<'a> = Command {
        key: Self::KNOWN_KEY_KE,
        menu_msg: "Decrypt with a known key.",
    };

    const BRUTE_FORCE: Command<'static> = Command {
        key: Self::BRUTE_FORCE_KE,
        menu_msg: "Brute force by having the computer guess keys and provide possible plaintexts.",
    };

    const QUIT: Command<'static> = Command {
        key: Self::QUIT_KE,
        menu_msg: "Return to main menu.",
    };

    fn menu_array() -> MenuArray<'a, 3> {
        MenuArray([Self::KNOWN_KEY, Self::BRUTE_FORCE, Self::QUIT])
    }

    fn print_menu() -> Result<(), Box<dyn Error>> {
        println!("\nPlease enter one of the following options:");
        for item in DecryptMenu::menu_array().0 {
            println!("{}: {}", item.key, item.menu_msg)
        }
        Ok(())
    }
}

impl FromStr for DecryptMenu {
    type Err = CommandError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            DecryptMenu::KNOWN_KEY_KE => Ok(DecryptMenu::KnownKey),
            DecryptMenu::BRUTE_FORCE_KE => Ok(DecryptMenu::Bruteforce),
            DecryptMenu::QUIT_KE => Ok(DecryptMenu::Quit),
            _ => Err(CommandError),
        }
    }
}

// A struct that represents a possible user action
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct Command<'a> {
    key: &'a str,
    menu_msg: &'a str,
}

struct CommandError;

// Prints menu of user options and matches on user input to do one of:
// Generate a key, encrypt a message, decrypt a message
fn menu() -> Result<(), Box<dyn Error>> {
    loop {
        MainMenu::print_menu()?;

        let command: MainMenu = process_input(MainMenu::print_menu as Instr)?;

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
fn decryption_menu(ciphertxt: &CipherText) -> Result<(), Box<dyn Error>> {
    DecryptMenu::print_menu()?;

    let command: DecryptMenu = process_input(DecryptMenu::print_menu as Instr)?;

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

// Creates keys and prints the key to standard output.
fn make_key() -> Result<(), Box<dyn Error>> {
    // Set up an rng.
    let mut rng = thread_rng();

    loop {
        // Generate a key
        let key = Key::new(&mut rng);

        println!("\nWe generated your key successfully!.");
        println!("\nWe shouldn't export your key (or say, save it in logs), but we can!");
        println!("Here it is: {}", key.insecure_export());
        println!("\nAre you happy with your key?");
        ConsentMenu::print_menu()?;

        let command: ConsentMenu = process_input(ConsentMenu::print_menu as Instr)?;

        match command {
            ConsentMenu::NoKE => continue,
            ConsentMenu::YesKE => {
                println!("\nGreat! We don't have a file system implemented (much less a secure one), so please \nremember your key in perpetuity!");
                break Ok(());
            }
        };
    }
}

// Takes in a key and a message and encrypts, then prints
// the result.
fn encrypt() -> Result<(), Box<dyn Error>> {
    println!("\nPlease enter the message you want to encrypt:");

    let msg: Message = process_input(print_msg_instr as Instr)?;

    println!("\nNow, do you have a key that was generated uniformly at random that you remember and \nwould like to use? If yes, please enter your key. Otherwise, please pick a fresh key \nuniformly at random from the ring of integers modulo 26 yourself. \n\nYou won't be as good at this as a computer, but if you understand the cryptosystem \nyou are using (something we cryptographers routinely assume about other people, while \npretending that we aren't assuming this), you will probably not pick a key of 0, \nwhich is equivalent to sending your messages \"in the clear\", i.e., unencrypted. Good \nluck! \n\nGo ahead and enter your key now:");

    let key: Key = process_input(print_key_instr as Instr)?;

    println!("\nYour ciphertext is {}", msg.encrypt(&key));
    println!("\nLook for patterns in your ciphertext. Could you definitively figure out the key and \noriginal plaintext message if you didn't already know it?");

    fn print_msg_instr() -> Result<(), Box<dyn Error>> {
        println!("\nWe only accept lowercase letters from the Latin Alphabet, in one of the most awkward \nAPI decisions ever.");
        Ok(())
    }

    Ok(())
}

// Takes in a ciphertext and attempts to decrypt and
// print result.
fn decrypt() -> Result<(), Box<dyn Error>> {
    println!("\nEnter your ciphertext. Ciphertexts use characters only from the Latin Alphabet:");

    let ciphertxt: CipherText = process_input(print_ciphertxt_instr as Instr)?;

    println!("\nGreat, let's work on decrypting your ciphertext.");
    println!(
        "If you know what key was used to encrypt this message, this should only take one try."
    );
    println!(
    "If not, don't despair. Just guess! On average, you can expect success using this \nsimple brute force attack method after trying 13 keys chosen uniformly at random."
    );

    decryption_menu(&ciphertxt)?;

    fn print_ciphertxt_instr() -> Result<(), Box<dyn Error>> {
        println!("\nCiphertext must contain characters from the Latin Alphabet only.");
        Ok(())
    }

    Ok(())
}

// Gets key from stdin and attempts to decrypt
fn chosen_key(ciphertxt: &CipherText) -> Result<(), Box<dyn Error>> {
    loop {
        println!("\nOK. Please enter a key now:");
        let key: Key = process_input(print_key_instr as Instr)?;
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
            Err(_) => continue, // TODO: How to handle different errors independently?
        }
    }
    Ok(())
}

// Decrypt with given key and ask whether to try again or not
fn try_decrypt(ciphertxt: &CipherText, key: Key) -> Result<(), Box<dyn Error>> {
    println!("\nYour computed plaintext is {}\n", ciphertxt.decrypt(&key));
    println!("\nAre you happy with this decryption?");
    ConsentMenu::print_menu()?;

    let command: ConsentMenu = process_input(ConsentMenu::print_menu as Instr)?;

    match command {
        ConsentMenu::NoKE => Err("try again".into()),
        ConsentMenu::YesKE => Ok(()),
    }
}

type Instr = fn() -> Result<(), Box<dyn Error>>;

// TODO: this loop and match statment plus a return line is probably not idiomatic
// Processes command line input and converts to type `T` as specified by caller
// If successful, returns conversion. If not, prints clarifying instructions
// so that the person can try again
fn process_input<T: FromStr>(instr: Instr) -> Result<T, Box<dyn Error>> {
    loop {
        let mut input = String::new();

        io::stdin().read_line(&mut input)?;

        let result: T = match input.trim().parse::<T>() {
            Ok(txt) => txt,
            Err(_) => {
                instr()?;
                println!("\nPlease try again:");
                continue;
            }
        };

        return Ok(result);
    }
}

fn print_key_instr() -> Result<(), Box<dyn Error>> {
    println!("\nA key is a number between 0 and 25 inclusive.");
    Ok(())
}
