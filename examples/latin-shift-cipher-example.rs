use fiddler::{CipherText, Key, Message};
use rand::thread_rng;
use std::io;

fn main() {
    println!("\nWelcome to the Latin Shift Cipher Demo!");

    menu();
}

// Prints menu of user options and matches on user input to do one of:
// Generate a key, encrypt a message, decrypt a message.
fn menu() {
    loop {
        println!("\nPlease enter one of the following options:");
        println!("1: Generate a key");
        println!("2: Encrypt a message");
        println!("3: Decrypt a ciphertext");
        println!("4: Quit");

        let mut input = String::new();

        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line"); // Crashing the program instead of handling errors is suboptimal.

        // Use shadowing to convert String to u8.
        // `trim`` eliminates white space and newlines/carriage returns at beginning and end.
        // `parse` converts a string to another type.
        let input: u8 = match input.trim().parse() {
            Ok(num) => num,
            Err(_) => continue,
        };

        println!("\nYou entered {input}.");

        match input {
            1 => {
                make_key();
            }
            2 => {
                encrypt();
            }
            3 => {
                decrypt();
            }
            4 => break,
            // all other u8s
            _ => continue,
        }
    }
}

// Creates keys and prints the key to standard output.
fn make_key() {
    // Set up an rng.
    let mut rng = thread_rng();

    'outer: loop {
        // Generate a key
        let key = Key::new(&mut rng);

        println!("\nWe generated your key successfully!");
        println!(
            "\nWe shouldn't print your key (or say, save it in logs), but we can! Here it is: {}",
            key.into_i8()
        );
        println!("\nAre you happy with your key? Enter Y for yes and N for no.");

        loop {
            let mut input = String::new();

            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read line");

            let input: char = match input.trim().parse() {
                Ok(c) => c,
                Err(_) => continue,
            };

            match input {
                'N' => break,
                'Y' => {
                    println!("\nGreat! We don't have a file system implemented (much less a secure one), so please remember your key in perpetuity!");
                    break 'outer;
                }
                // all other chars
                _ => {
                    println!("\nYou entered {input}.");
                    println!("Enter Y for yes and N for no.");
                    continue;
                }
            }
        }
    }
}

fn encrypt() {
    println!("\nDo you have a key that was generated uniformly at random that you remember and would like to use? If yes, please enter your key. Otherwise, please pick a fresh key uniformly at random from the ring of integers modulo 26 yourself. \n\nYou won't be as good at this as a computer, but if you understand the cryptosystem you are using (something we cryptographers routinely assume about other people, while pretending that we aren't assuming this), you will probably not pick a key of 0, which is equivalent to sending your messages \"in the clear\", i.e., unencrypted. Good luck! \n\nGo ahead and enter your key now:");

    let key = process_key();

    println!("\nNow enter the message you want to encrypt:");

    let msg = process_msg();

    println!("\nYour ciphertext is {}", msg.encrypt(&key));
    println!("\nLook for patterns in your ciphertext. Could you definitively figure out the key and original plaintext message if you didn't already know it?");
}

fn decrypt() {
    let ciphertxt = process_ciphertext();

    println!("\nGreat, let's work on decrypting your ciphertext.");
    println!("Do you know what key was used to encrypt this message?. If so, enter it now. If not, feel free to guess!");

    let key = process_key();

    println!("\nYour plaintext is {}\n", ciphertxt.decrypt(&key));
}

// Reads a value from standard input and converts to a `Key`.
// Loops until user enters a valid key value.
// TODO: check loops and match statements, these are weird rn
fn process_key() -> Key {
    loop {
        let mut input = String::new();

        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        let key: i8 = match input.trim().parse() {
            Ok(num) => num,
            Err(_) => {
                println!(
                    "A key is a number between 0 and 25 inclusive. Please enter your key value:"
                );
                continue;
            }
        };

        match key {
            x if (0..=25).contains(&x) => {
                break Key::from(key);
            }
            _ => {
                println!(
                    "Keys are a number between 0 and 25 inclusive. Please enter your key value:"
                );
                continue;
            }
        }
    }
}

// Reads a value from standard input and converts to a `Message`.
// TODO: This code can still panic because lib.rs doesn't do any error handling.
// TODO: this loop and match statment plus a return line is probably nto idiomatic
fn process_msg() -> Message {
    loop {
        let mut input = String::new();

        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        let msg: Message = match input.trim().parse() {
            Ok(txt) => txt,
            Err(_) => {
                println!("\nWe only accept lowercase letters from the Latin Alphabet, in one of the most awkward API decisions ever:");
                continue;
            }
        };
        return msg;
    }
}

// TODO: This code can still panic because the underlying lib functions can (and do) panic
// TODO: Doesn't seem idiomatic
fn process_ciphertext() -> CipherText {
    println!("\nEnter your ciphertext. Ciphertexts use characters only from the Latin Alphabet:");
    loop {
        let mut input = String::new();

        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        let ciphertxt: CipherText = match input.trim().parse() {
            Ok(txt) => txt,
            Err(_) => {
                println!("Ciphertext must only contain characters from the Latin Alphabet");
                continue;
            }
        };

        println!("\nYou wrote the ciphertext: {}", ciphertxt);
        return ciphertxt;
    }
}
