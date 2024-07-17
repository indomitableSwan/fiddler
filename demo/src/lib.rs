//! The demo libary crate, containing functionality supporting the demo CLI.
use std::{error::Error, io, str::FromStr};

pub mod crypto_functionality;
pub mod menu;

// TODO: this loop and match statment plus a return line is probably not
// idiomatic
//
/// Processes command line input and converts to type `T` as specified
/// by caller. If successful, returns conversion. If not, prints clarifying
/// instructions so that the person can try again.
fn process_input<T, F>(instr: F) -> Result<T, Box<dyn Error>>
where
    T: FromStr,
    F: Fn() -> Result<(), Box<dyn Error>>,
{
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
