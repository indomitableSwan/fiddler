use fiddler::{CipherText, Key, Message};
use rand::thread_rng;
use std::io;

fn main() {
    println!(
        "\nWelcome to the Latin Shift Cipher Demo! Please enter one of the following options:"
    );
    println!("1: Generate a key");
    println!("2: Enter a message to encrypt");
    println!("3: Decrypt a message with a key");

    process_menu_option();
}

// Creates a key and prints the key to standard output.
fn make_key() {
    // Set up an rng.
    let mut rng = thread_rng();

    // Generate a key
    let key = Key::gen(&mut rng);

    println!("\nWe generated your key successfully!");
    println!(
        "\nWe shouldn't print your key (or say, save it in logs), but we can! Here it is: {}",
        key.into_i8()
    );
    println!("\nAre you happy with your key? Enter Y for yes and N for no.");

    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let input: char = input.trim().parse().expect("Please type Y or N!");
    println!("You chose {input}.");

    match input {
        'N' => {make_key();}, // Note that we will reinitialize our rng, which is a bit silly.
        'Y' => println!("\nGreat! We don't have a file system implemented (much less a secure one), so please remember your key in perpetuity!"),
        // all other numbers
        _ => panic!(),
    }
    main()
}

fn encrypt() {
    println!("\nDo you have a key that was generated uniformly at random that you remember and would like to use? If yes, please enter your key. Otherwise, please pick a fresh key uniformly at random from the ring of integers modulo 26 yourself. \n\nYou won't be as good at this as a computer, but if you understand the cryptosystem you are using (something we cryptographers routinely assume about other people, while pretending that we aren't assuming this), you will probably not pick a key of 0, which is equivalent to sending your messages \"in the clear\", i.e., unencrypted. Good luck! \n\nGo ahead and enter your key now:");

    let key = process_key();

    let msg = process_msg();

    let ciphertxt = Message::encrypt(&msg, &key);

    println!("\nCiphertexts are always printed in ALL CAPS to avoid confusion with plaintexts.");
    println!("\nYour ciphertext is {}", ciphertxt.as_string());
    println!("\nLook for patterns in your ciphertext. Could you definitively figure out the key and original plaintext message if you didn't already know it?");
}

fn decrypt() {
    let ciphertext = process_ciphertext();

    println!("\nGreat, let's work on decrypting your ciphertext. Do you know what key was used to encrypt this message?. If so, enter it now. If not, feel free to guess!");

    let key = process_key();

    let msg = CipherText::decrypt(&ciphertext, &key);
    println!("\nYour plaintext is {}", msg.as_string());

    main()
}

// Matches on the option input by the user to either generate a key, encrypt a message, or decrypt a message.
fn process_menu_option() {
    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line"); // Crashing the program instead of handling errors is suboptimal.

    // Use shadowing to convert String to u8.
    // `trim`` eliminates white space and newlines/carriage returns at beginning and end.
    // `parse` converts a string to another type.
    let input: u8 = input.trim().parse().expect("Please type 1, 2, or 3!");
    println!("\nYou chose option {input}.");

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
        // all other numbers
        _ => panic!(),
    }
}

// Reads a value from standard input and converts to a `Key`.
fn process_key() -> Key {
    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let key: i8 = input
        .trim()
        .parse()
        .expect("Please type a number between 0 and 25 (inclusive)");
    println!("Thank you. You entered {key}.");

    match key {
        x if (0..=25).contains(&x) => {
            let key = Key::from(key);
            key
        }
        _ => process_key(),
    }
}

// Reads a value from standard input and converts to a `Message`.
fn process_msg() -> Message {
    println!("\nNow enter the message you want to encrypt. We only accept lowercase letters from the Latin Alphabet, in one of the most awkward API decisions ever:");
    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let msg: Message = Message::new(input.trim().parse().expect(
        "Please only use lowercase letters from the Latin Alphabet to construct your message",
    ));
    println!("\nYou wrote the message: {}", msg.as_string());
    msg
}

fn process_ciphertext() -> CipherText {
    println!("\nEnter your ciphertext. Ciphertexts are always ALL CAPS, with no whitespaces, and use characters only from the Latin Alphabet:");

    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let temp: String = input.trim().parse().expect("Please remember ciphertexts must be ALL CAPS and contain only characters from the Latin Alphabet");
    CipherText::from(temp)
}
