//! Menus.
use std::str::FromStr;

/// Represents menu functionality.
pub trait Menu<const N: usize> {
    fn menu_array() -> MenuArray<N>;

    fn print_menu() {
        println!("\nPlease enter one of the following options:");
        for item in Self::menu_array().0 {
            println!("{}: {}", item.key, item.menu_msg)
        }
    }
}

/// Represents a set of possible user actions.
pub struct MenuArray<const N: usize>([Command<'static>; N]);

/// Represents the program's main menu options.
pub enum MainMenu {
    /// User wants to generate a key.
    GenKE,
    /// User wants to encrypt a message.
    EncryptKE,
    /// User wants to decrypt a message.
    DecryptKE,
    /// User wants to quit the CLI application.
    QuitKE,
}

impl Menu<4> for MainMenu {
    fn menu_array() -> MenuArray<4> {
        MenuArray([Self::GEN, Self::ENCRYPT, Self::DECRYPT, Self::QUIT])
    }
}

impl MainMenu {
    // Key Events
    const GEN_KE: &'static str = "1"; // Key Event for "Generate a key"
    const ENCRYPT_KE: &'static str = "2"; // Key Event for "encrypt a message"
    const DECRYPT_KE: &'static str = "3"; // Key Event for "decrypt"
    const QUIT_KE: &'static str = "4"; // Key Event for "quit"

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

/// Represents user assent or dissent.
pub enum ConsentMenu {
    /// User assents.
    YesKE,
    /// User dissents.
    NoKE,
}

impl Menu<2> for ConsentMenu {
    fn menu_array() -> MenuArray<2> {
        MenuArray([
            Command {
                key: Self::YES_KE,
                menu_msg: "Yes",
            },
            Command {
                key: Self::NO_KE,
                menu_msg: "No",
            },
        ])
    }
}

impl ConsentMenu {
    const YES_KE: &'static str = "y";
    const NO_KE: &'static str = "n";
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

/// Represents the decryption menu.
pub enum DecryptMenu {
    /// User knows the key.
    KnownKey,
    /// User does not know the key.
    Bruteforce,
    /// User does not want to decrypt.
    Quit,
}

impl Menu<3> for DecryptMenu {
    fn menu_array() -> MenuArray<3> {
        MenuArray([Self::KNOWN_KEY, Self::BRUTE_FORCE, Self::QUIT])
    }
}

impl DecryptMenu {
    // Define Key Events
    const KNOWN_KEY_KE: &'static str = "1";
    const BRUTE_FORCE_KE: &'static str = "2";
    const QUIT_KE: &'static str = "3";

    // Decryption Menu commands
    //
    const KNOWN_KEY: Command<'static> = Command {
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

/// Represents a possible user action.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Command<'a> {
    key: &'a str,
    menu_msg: &'a str,
}

/// The error returned upon failure to parse a [`Command`] from a string.
pub struct CommandError;
