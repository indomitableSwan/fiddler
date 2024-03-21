use fiddler::{CipherText, Key, Message};
use rand::thread_rng;

fn main() {
    // Set up an rng
    let mut rng = thread_rng();

    // Generate a key
    let key = Key::gen(&mut rng);

    // We can print a key, or print it to a log if we wanted to. We shouldn't. Key handling is another, more complicated and error-prone topic.
    //
    // Note that the mathematical description of the Latin Shift Cipher, as well as this implementation, does not disallow a key of 0, so sometimes the encryption algorithm is just the identity function.
    //
    // This is a cryptosystem designed for use by humans and not computers. Humans are not as good at computers at picking a value mod 26 uniformly at random, but they also won't picka  key of 0 and send their private message to their recipient in plaintext. Oh wait, they do this all the time, in the form of emails.
    println!("We can print our key value, but generally speaking we shouldn't. \n Here is our key value: {:?}", key);

    let msg = Message::new("idefinitelydonotwritemymessagesthiswaysoinitialapichoiceswerenotstellarbutitiswhatisinstinson".to_string());

    // Encrypt msg and print Ciphertext as String
    let ciphertxt = Message::encrypt(&msg, &key);

    // We can print our message and corresponding ciphertext as Strings
    println!("Our message is {}", msg.as_string());
    println!("The corresponding ciphertext is {}", ciphertxt.as_string());

    // We can decrypt our ciphertext and print the resulting message. Humans are very quick at understanding mashed up plaintexts without  punctuation and spacing. Computers have to check dictionaries.
    println!(
        "If we decrypt using the correct key, we get our original message back: {}",
        CipherText::decrypt(&ciphertxt, &key).as_string()
    );

    // If we decrypt with the wrong key, we won't get our original message back
    println!(
        "If we decrypt using an incorrect key, we do not get our original message back: {}",
        CipherText::decrypt(&ciphertxt, &Key::gen(&mut rng)).as_string()
    );

    // With some non-negligible frequency, you won't get nonsense on decryption with the wrong key, but the possible message space is restricted beyond just the length of the message itself. This is because shift ciphers preserve other message patterns, too. Note that if the message is very short and you only have one sample, one ciphertext may not be enough to definitively break the system with a brute force attack. But likely there is other context available to validate possible plaintexts.
    let small_msg = Message::new("dad".to_string());
    let small_ciphertext = Message::encrypt(&small_msg, &key);
    let small_decryption = CipherText::decrypt(&small_ciphertext, &Key::gen(&mut rng));

    println!("The API makes it hard to make this example work the way I want, but sometimes decrypting with the incorrect key will still decrypt to something sensible. This is because shift ciphers preserve patterns in the original message in the ciphertext as well. Here is a small example, where we can more easily see this: 
    \n plaintext is {}, ciphertext is {}, and decryption under a random key gives {}", small_msg.as_string(), small_ciphertext.as_string(), small_decryption.as_string())
}
